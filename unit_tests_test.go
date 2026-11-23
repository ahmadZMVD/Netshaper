package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// UT-01: Exact-Port Cleanup — 100 iterations over listener matrix {1080, 10808, 10800, 21080, 10801}.
func TestUT01_ExactPortCleanup(t *testing.T) {
	const selfPID uint32 = 4242

	for iter := 0; iter < 100; iter++ {
		inspector := &mockPortInspector{
			listeners: []TCPListenerEntry{
				{Port: 1080, PID: 1001, Family: "tcp4"},
				{Port: 1080, PID: selfPID, Family: "tcp4"}, // self MUST be excluded
				{Port: 10808, PID: 9716, Family: "tcp4"},   // xray.exe MUST never be touched
				{Port: 10800, PID: 1002, Family: "tcp4"},   // prefix match trap
				{Port: 21080, PID: 1003, Family: "tcp4"},   // suffix match trap
				{Port: 10801, PID: 1004, Family: "tcp6"},   // prefix match trap
				{Port: 1080, PID: 9999, Family: "tcp6"},    // non-whitelisted image on :1080
			},
			images: map[uint32]string{
				1001:    `C:\Tools\NetShaper\NetShaper.exe`,
				selfPID: `C:\Tools\NetShaper\NetShaper.exe`,
				9716:    `C:\Tools\proxy\xray.exe`,
				1002:    `NetShaper.exe`,
				1003:    `ssh.exe`,
				1004:    `gh.exe`,
				9999:    `xray.exe`,
			},
		}

		records, err := CleanTargetPorts(inspector, []uint16{1080}, selfPID, DefaultCleanupAllowedImages, nil)
		if err != nil {
			t.Fatalf("iter %d: CleanTargetPorts error: %v", iter, err)
		}

		killed := inspector.TerminatedCopy()
		if len(killed) != 1 || killed[0] != 1001 {
			t.Fatalf("iter %d: expected ONLY PID 1001 terminated, got %v (records=%+v)", iter, killed, records)
		}

		sawSelfSkip := false
		sawWhitelistSkip := false
		for _, rec := range records {
			if rec.PID == 9716 || rec.PID == 1002 || rec.PID == 1003 || rec.PID == 1004 {
				t.Fatalf("iter %d: non-target port PID %d (port %d) examined!", iter, rec.PID, rec.Port)
			}
			if rec.PID == selfPID && rec.Action == "SKIPPED_SELF" {
				sawSelfSkip = true
			}
			if rec.PID == 9999 && rec.Action == "SKIPPED_WHITELIST" {
				sawWhitelistSkip = true
			}
		}
		if !sawSelfSkip || !sawWhitelistSkip {
			t.Fatalf("iter %d: missing audit skips (self=%v whitelist=%v)", iter, sawSelfSkip, sawWhitelistSkip)
		}
	}
}

// UT-02: Job Object Tree Teardown — spawn parent->grandchild tree inside Job, close Job, assert 0 orphans across 20 runs.
func TestUT02_JobObjectTreeTeardown(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		job, err := NewProcessJob()
		if err != nil {
			t.Fatalf("iter %d: NewProcessJob: %v", iter, err)
		}

		cmd := newHelperCmd("spawn_tree")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			_ = job.Close()
			t.Fatalf("iter %d: StdinPipe: %v", iter, err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = job.Close()
			t.Fatalf("iter %d: StdoutPipe: %v", iter, err)
		}

		if err := cmd.Start(); err != nil {
			_ = job.Close()
			t.Fatalf("iter %d: cmd.Start: %v", iter, err)
		}

		if err := job.Assign(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			_ = job.Close()
			t.Fatalf("iter %d: job.Assign: %v", iter, err)
		}

		_, _ = io.WriteString(stdin, "GO\n")
		_ = stdin.Close()

		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			_ = job.Close()
			_ = cmd.Wait()
			t.Fatalf("iter %d: read PID line: %v", iter, err)
		}

		var parentPID, childPID int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "PARENT=%d CHILD=%d", &parentPID, &childPID); err != nil {
			_ = job.Close()
			_ = cmd.Wait()
			t.Fatalf("iter %d: parse %q: %v", iter, line, err)
		}

		killStart := time.Now()
		if err := job.Close(); err != nil {
			t.Fatalf("iter %d: job.Close: %v", iter, err)
		}
		_ = cmd.Wait()

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if !IsProcessAlive(parentPID) && !IsProcessAlive(childPID) {
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		elapsed := time.Since(killStart)
		if IsProcessAlive(parentPID) || IsProcessAlive(childPID) {
			t.Fatalf("iter %d: orphan process survived after %s (parentAlive=%v childAlive=%v)",
				iter, elapsed, IsProcessAlive(parentPID), IsProcessAlive(childPID))
		}
		if elapsed > 2*time.Second {
			t.Fatalf("iter %d: teardown exceeded 2s SLO: %s", iter, elapsed)
		}
	}
}

// UT-03: Half-Close Propagation + Progress-Resetting Drain Watchdog.
func TestUT03_HalfClosePropagation(t *testing.T) {
	baseG := runtime.NumGoroutine()

	const payloadSize = 1024 * 1024 // 1 MiB
	srv := startMockHalfCloseServer(t, 200*time.Millisecond, payloadSize)
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.IdleTimeout = 10 * time.Second
	cfg.PressureIdleTimeout = 10 * time.Second
	cfg.HalfCloseDrainTimeout = 10 * time.Second
	cfg.DialPaceInterval = 0

	proxy := NewProxyServer(cfg, srv.Addr(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	const totalIters = 100
	const batchConc = 10
	sem := make(chan struct{}, batchConc)
	errCh := make(chan error, totalIters)
	var wg sync.WaitGroup

	for i := 0; i < totalIters; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(iter int) {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				errCh <- fmt.Errorf("iter %d dial: %w", iter, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			if _, err := conn.Write([]byte("GET /halfclose-test HTTP/1.1\r\n\r\n")); err != nil {
				errCh <- fmt.Errorf("iter %d write: %w", iter, err)
				return
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				if err := tc.CloseWrite(); err != nil {
					errCh <- fmt.Errorf("iter %d CloseWrite: %w", iter, err)
					return
				}
			}
			got, err := io.ReadAll(conn)
			if err != nil {
				errCh <- fmt.Errorf("iter %d ReadAll: %w", iter, err)
				return
			}
			if len(got) != payloadSize {
				errCh <- fmt.Errorf("iter %d truncated stream: got %d want %d", iter, len(got), payloadSize)
				return
			}
			if sha256.Sum256(got) != srv.payloadHash {
				errCh <- fmt.Errorf("iter %d SHA-256 mismatch", iter)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
	proxy.Stop(true)
	srv.Close()

	slowSrv := startMockChunkedHalfCloseServer(t, 50*time.Millisecond, 12*64*1024, 64*1024, 120*time.Millisecond)
	defer slowSrv.Close()

	cfgSlow := DefaultConfig()
	cfgSlow.LocalPort = 0
	cfgSlow.IdleTimeout = 10 * time.Second
	cfgSlow.PressureIdleTimeout = 10 * time.Second
	cfgSlow.HalfCloseDrainTimeout = 500 * time.Millisecond
	cfgSlow.DialPaceInterval = 0

	proxySlow := NewProxyServer(cfgSlow, slowSrv.Addr(), nil, nil, nil)
	slowAddr, err := proxySlow.Start(ctx)
	if err != nil {
		t.Fatalf("proxySlow.Start: %v", err)
	}

	c, err := net.DialTimeout("tcp", slowAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("slow dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("GET /slow-download HTTP/1.1\r\n\r\n"))
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	gotSlow, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil {
		t.Fatalf("progress-resetting half-close stream errored: %v", err)
	}
	if len(gotSlow) != len(slowSrv.payload) || sha256.Sum256(gotSlow) != slowSrv.payloadHash {
		t.Fatalf("progress-resetting half-close truncated: got %d want %d", len(gotSlow), len(slowSrv.payload))
	}

	slowSrv.stallForever.Store(true)
	c2, err := net.DialTimeout("tcp", slowAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("stall dial: %v", err)
	}
	stallStart := time.Now()
	_, _ = c2.Write([]byte("GET /stall HTTP/1.1\r\n\r\n"))
	if tc, ok := c2.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_, _ = io.ReadAll(c2)
	_ = c2.Close()
	stallElapsed := time.Since(stallStart)
	if stallElapsed > 1200*time.Millisecond {
		t.Fatalf("stalled half-close peer took %s to reap (expected ~500ms)", stallElapsed)
	}
	stats := proxySlow.SnapshotWindow(false)
	if stats.DrainTimeouts == 0 {
		t.Fatalf("expected DrainTimeouts >= 1 after stalled half-close peer, got %+v", stats)
	}

	proxySlow.Stop(true)
	slowSrv.Close()
	assertNoGoroutineLeak(t, baseG, 4)
}

// UT-04: End-to-End SOCKS5 Readiness + Clean i/o timeout.
func TestUT04_EndToEndSOCKS5Readiness(t *testing.T) {
	ctx := context.Background()

	dummy := startMockSOCKS5Server(t, socksModeTCPOnly)
	defer dummy.Close()
	for i := 0; i < 8; i++ {
		_, err := ProbeSOCKS5(ctx, dummy.Addr(), "1.1.1.1:443", 120*time.Millisecond)
		if err == nil {
			t.Fatalf("iter %d: expected TCP-only dummy listener to be rejected by ProbeSOCKS5", i)
		}
		if strings.Contains(err.Error(), "use of closed network connection") {
			t.Fatalf("iter %d: AfterFunc vs SetDeadline race regression! got: %v", i, err)
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("iter %d: expected clean net.Error Timeout()=true, got: %v", i, err)
		}
	}

	if _, _, err := WaitForTunnelReady(ctx, nil, dummy.Addr(), "1.1.1.1:443", 450*time.Millisecond, 150*time.Millisecond, 50*time.Millisecond, nil); err == nil {
		t.Fatal("expected WaitForTunnelReady to reject TCP-only dummy listener")
	}

	realSrv := startMockSOCKS5Server(t, socksModeNormal)
	defer realSrv.Close()
	start := time.Now()
	rtt, early, err := WaitForTunnelReady(ctx, nil, realSrv.Addr(), "1.1.1.1:443", 2*time.Second, 500*time.Millisecond, 50*time.Millisecond, nil)
	if err != nil || early != nil {
		t.Fatalf("expected WaitForTunnelReady to succeed, err=%v early=%+v", err, early)
	}
	if time.Since(start) >= 500*time.Millisecond {
		t.Fatalf("expected readiness <500ms, took %s", time.Since(start))
	}
	if rtt <= 0 {
		t.Fatalf("expected positive RTT, got %s", rtt)
	}

	exitCh := make(chan ChildExitResult, 1)
	go func() {
		time.Sleep(25 * time.Millisecond)
		exitCh <- ChildExitResult{ExitCode: 255, StderrTail: "Timeout, server not responding."}
	}()
	abortStart := time.Now()
	_, earlyExit, abortErr := WaitForTunnelReady(ctx, exitCh, dummy.Addr(), "1.1.1.1:443", 10*time.Second, 5*time.Second, 100*time.Millisecond, nil)
	abortElapsed := time.Since(abortStart)
	if abortErr != ErrChildExitedDuringBoot || earlyExit == nil || earlyExit.ExitCode != 255 {
		t.Fatalf("expected ErrChildExitedDuringBoot(255), got err=%v early=%+v", abortErr, earlyExit)
	}
	if abortElapsed >= 100*time.Millisecond {
		t.Fatalf("expected early-exit abort in <100ms, took %s", abortElapsed)
	}
}

// UT-05: cmd.Wait() Crash Detection, SSH Arg Order, Stderr Ring & Backoff.
func TestUT05_CmdWaitCrashDetectionAndBackoff(t *testing.T) {
	cfg := DefaultConfig()
	args := BuildGHSSHArgs(cfg)
	joined := strings.Join(args, " ")
	for _, forbidden := range []string{" -q", "IPQoS", "TCPKeepAlive"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("forbidden flag %q present in gh args: %s", forbidden, joined)
		}
	}
	required := "-- -D 127.0.0.1:1081 -N -o AddressFamily=inet -o Compression=no -o Ciphers=aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com -o ConnectTimeout=15 -o LogLevel=ERROR -o ServerAliveInterval=10 -o ServerAliveCountMax=3"
	if !strings.Contains(joined, required) {
		t.Fatalf("missing required ordered args %q in: %s", required, joined)
	}

	rng := rand.New(rand.NewPCG(7, 42))
	expectedCenters := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, center := range expectedCenters {
		d := ComputeBackoff(i+1, 2*time.Second, 30*time.Second, rng)
		lo := time.Duration(float64(center) * 0.8)
		if lo < 2*time.Second {
			lo = 2 * time.Second
		}
		hi := time.Duration(float64(center) * 1.2)
		if hi > 30*time.Second {
			hi = 30 * time.Second
		}
		if d < lo || d > hi {
			t.Fatalf("attempt %d: backoff %s outside [%s, %s]", i+1, d, lo, hi)
		}
	}

	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "ut05.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	supCfg := DefaultConfig()
	supCfg.PoolSize = 1 // single-tunnel lifecycle test
	supCfg.PreflightNetHygiene = false
	supCfg.LocalPort = 0
	supCfg.GHPort = socks.Port(t)
	supCfg.StopOnExit = false
	supCfg.BackoffMin = 500 * time.Millisecond
	supCfg.BackoffMax = 1 * time.Second
	supCfg.ProbeInterval = 5 * time.Second
	supCfg.BootQualitySamples = 1
	supCfg.GitHubMinCallSpacing = 0

	var crashTime atomic.Int64
	reconnCh := make(chan time.Time, 4)

	var spawns atomic.Int32
	sup := NewSupervisor(supCfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 20 * time.Millisecond,
		OnStateChange: func(from, to SupervisorState) {
			if to == StateReconnecting {
				select {
				case reconnCh <- time.Now():
				default:
				}
			}
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			n := spawns.Add(1)
			mode := "sleep_alive"
			extra := []string{}
			if n == 1 {
				mode = "crash_stderr_255"
				extra = append(extra, "HELPER_DELAY_MS=220")
				go func() {
					time.Sleep(220 * time.Millisecond)
					crashTime.Store(time.Now().UnixNano())
				}()
			}
			cmd := newHelperCmd(mode, extra...)
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	select {
	case ts := <-reconnCh:
		ct := crashTime.Load()
		if ct > 0 {
			detectLag := ts.Sub(time.Unix(0, ct))
			if detectLag > 200*time.Millisecond {
				t.Fatalf("crash detection lag too high: %s", detectLag)
			}
		}
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatal("timed out waiting for transition to RECONNECTING after child exit 255")
	}

	tail := sup.LastStderrTail(2048)
	if !strings.Contains(tail, "Timeout, server not responding.") {
		t.Fatalf("expected stderr ring to capture OpenSSH timeout message, got %q", tail)
	}

	cancel()
	<-done
}

// UT-06: Stdin io.EOF Guard — closed pipe MUST exit in <50ms with 0% CPU spin and 0 goroutine leaks.
func TestUT06_StdinEOFGuard(t *testing.T) {
	baseG := runtime.NumGoroutine()
	pr, pw := io.Pipe()
	_ = pw.Close()

	var quitCalled atomic.Bool
	exited := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(exited)
		WatchStdinForQuit(pr, func() { quitCalled.Store(true) })
	}()

	select {
	case <-exited:
		elapsed := time.Since(start)
		if elapsed >= 50*time.Millisecond {
			t.Fatalf("stdin EOF watcher took %s (SLO <50ms)", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stdin EOF watcher hung or spun instead of exiting on io.EOF")
	}
	if quitCalled.Load() {
		t.Fatal("onQuit must NOT be triggered by io.EOF")
	}
	assertNoGoroutineLeak(t, baseG, 2)
}

// UT-07: Zero-Delay Data Path & Buffer Fuzz — sizes {0, 1, 2048, 2049, 32768, 65536, 131072}, added p95 <= 1ms.
func TestUT07_ZeroDelayDataPathAndBufferFuzz(t *testing.T) {
	echoAddr, _, _, stopEcho := startPlainTCPEchoServer(t, 0)
	defer stopEcho()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.DialPaceInterval = 0
	proxy := NewProxyServer(cfg, echoAddr, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop(true)

	sizes := []int{0, 1, 2048, 2049, 32768, 65536, 131072}
	for _, sz := range sizes {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("size %d dial: %v", sz, err)
		}
		payload := makeDeterministicPayload(sz, uint64(sz+100))
		if sz > 0 {
			if _, err := conn.Write(payload); err != nil {
				_ = conn.Close()
				t.Fatalf("size %d write: %v", sz, err)
			}
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		got, err := io.ReadAll(conn)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("size %d read: %v", sz, err)
		}
		if len(got) != sz || sha256.Sum256(got) != sha256.Sum256(payload) {
			t.Fatalf("size %d integrity mismatch (got=%d)", sz, len(got))
		}
	}

	measureRTTs := func(addr string) []time.Duration {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("measure dial %s: %v", addr, err)
		}
		defer conn.Close()
		msg := makeDeterministicPayload(256, 77)
		resp := make([]byte, len(msg))
		for i := 0; i < 5; i++ {
			_, _ = conn.Write(msg)
			_, _ = io.ReadFull(conn, resp)
		}
		rtts := make([]time.Duration, 60)
		for i := range rtts {
			st := time.Now()
			if _, err := conn.Write(msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := io.ReadFull(conn, resp); err != nil {
				t.Fatalf("read: %v", err)
			}
			rtts[i] = time.Since(st)
		}
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		return rtts
	}

	rawRTTs := measureRTTs(echoAddr)
	proxiedRTTs := measureRTTs(proxyAddr)
	p95Idx := int(float64(len(rawRTTs))*0.95) - 1
	addedP95 := proxiedRTTs[p95Idx] - rawRTTs[p95Idx]
	t.Logf("UT-07 latency: raw_p95=%s proxied_p95=%s added_p95=%s", rawRTTs[p95Idx], proxiedRTTs[p95Idx], addedP95)
	if addedP95 > 1*time.Millisecond {
		t.Fatalf("added loopback p95 latency %s exceeded 1ms SLO", addedP95)
	}
}

// UT-08: Bounded Deadlines & Slow-Loris Reaping — 50 stalled connections reaped at <=1.5s, 0 goroutine leak.
func TestUT08_BoundedDeadlinesSlowLorisReaping(t *testing.T) {
	baseG := runtime.NumGoroutine()

	silentUpstream := startMockSOCKS5Server(t, socksModeBlackhole)
	defer silentUpstream.Close()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 128
	cfg.DialPaceInterval = 0
	cfg.IdleTimeout = 1 * time.Second
	cfg.PressureIdleTimeout = 1 * time.Second
	cfg.HalfCloseDrainTimeout = 500 * time.Millisecond

	proxy := NewProxyServer(cfg, silentUpstream.Addr(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	const slowConns = 50
	clients := make([]net.Conn, 0, slowConns)
	start := time.Now()
	for i := 0; i < slowConns; i++ {
		c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	waitUntil(t, 1600*time.Millisecond, "all 50 slow-loris connections reaped", func() bool {
		return proxy.Metrics(false).ActiveConns == 0
	})
	elapsed := time.Since(start)
	if elapsed > 1600*time.Millisecond {
		t.Fatalf("slow-loris reaping took %s (expected <=1.5s)", elapsed)
	}

	proxy.Stop(true)
	silentUpstream.Close()
	assertNoGoroutineLeak(t, baseG, 2)
}

// UT-09: Bounded Shutdown Stop — hanging 60s 'gh codespace stop' aborted cleanly in <2.5s with 0 orphans.
func TestUT09_BoundedShutdownStop(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "ut09.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 1
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = socks.Port(t)
	cfg.StopOnExit = true
	cfg.StopTimeout = 2 * time.Second
	cfg.BootQualitySamples = 1

	var stopPID atomic.Int64
	var stopInvoked atomic.Bool

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 20 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		StopCodespace: func(stopCtx context.Context, c Config) (int, string, error) {
			stopInvoked.Store(true)
			cmd := exec.CommandContext(stopCtx, os.Args[0], "-test.run=^TestHelperProcess$")
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_MODE=hang_60s")
			ConfigureChildCmd(cmd)
			job, _ := NewProcessJob()
			if err := cmd.Start(); err != nil {
				if job != nil {
					_ = job.Close()
				}
				return -1, "failed to start stop cmd", err
			}
			stopPID.Store(int64(cmd.Process.Pid))
			if job != nil {
				_ = job.Assign(cmd.Process.Pid)
				defer job.Close()
			}
			err := cmd.Wait()
			return -1, "context deadline exceeded waiting for codespace stop", err
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 3*time.Second, "supervisor HEALTHY", func() bool {
		return sup.State() == StateHealthy
	})

	shutdownStart := time.Now()
	sup.RequestShutdown("ut09_test")
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung instead of aborting 60s stop command at StopTimeout=2s")
	}
	elapsed := time.Since(shutdownStart)
	if elapsed >= 2500*time.Millisecond {
		t.Fatalf("bounded shutdown took %s (SLO <2.5s)", elapsed)
	}
	if !stopInvoked.Load() {
		t.Fatal("expected StopCodespace to be invoked on shutdown")
	}
	if pid := int(stopPID.Load()); pid > 0 && IsProcessAlive(pid) {
		t.Fatalf("hanging stop subprocess PID %d survived bounded shutdown", pid)
	}

	recs := readJSONLLog(t, logPath)
	foundShutdown := false
	for _, r := range recs {
		if r.Event == "SHUTDOWN_COMPLETE" && r.Fields["stop_codespace_invoked"] == true {
			if out, _ := r.Fields["stop_output"].(string); !strings.Contains(out, "context deadline exceeded") {
				t.Fatalf("expected stop_output in SHUTDOWN_COMPLETE, got %+v", r.Fields)
			}
			foundShutdown = true
		}
	}
	if !foundShutdown {
		t.Fatal("missing SHUTDOWN_COMPLETE with stop_codespace_invoked=true in log")
	}
}

// UT-10: Concurrency Semaphore / FD Guard — 200 simultaneous dials against cap=128 never exceed 128 upstream.
func TestUT10_ConcurrencySemaphoreFDGuard(t *testing.T) {
	echoAddr, _, peakUpstream, stopEcho := startPlainTCPEchoServer(t, 180*time.Millisecond)
	defer stopEcho()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 128
	cfg.MaxQueuedConns = 0
	cfg.SemaphoreWaitTimeout = 80 * time.Millisecond
	cfg.DialPaceInterval = 0

	proxy := NewProxyServer(cfg, echoAddr, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop(true)

	const totalDials = 200
	var succeeded atomic.Int64
	var rejectedOrClosed atomic.Int64
	var wg sync.WaitGroup
	startGate := make(chan struct{})

	for i := 0; i < totalDials; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-startGate
			c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
			if err != nil {
				rejectedOrClosed.Add(1)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			msg := []byte("ping-" + strconv.Itoa(id))
			if _, err := c.Write(msg); err != nil {
				rejectedOrClosed.Add(1)
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			got, err := io.ReadAll(c)
			if err != nil || len(got) != len(msg) {
				rejectedOrClosed.Add(1)
				return
			}
			succeeded.Add(1)
		}(i)
	}
	close(startGate)
	wg.Wait()

	if peak := peakUpstream.Load(); peak > 128 {
		t.Fatalf("FD guard violated: peak upstream concurrency=%d > 128", peak)
	}
	if succeeded.Load() < 100 {
		t.Fatalf("too few connections succeeded under saturation: %d", succeeded.Load())
	}
	t.Logf("UT-10 FD guard: peakUpstream=%d succeeded=%d fastFailed=%d semRejects=%d",
		peakUpstream.Load(), succeeded.Load(), rejectedOrClosed.Load(), proxy.Metrics(false).SemaphoreRejects)

	waitUntil(t, 2*time.Second, "active conns return to 0", func() bool {
		return proxy.Metrics(false).ActiveConns == 0
	})
}

// UT-11: config.json Rule-Order Validator — accepts hardened config.json, rejects shadowed/leaky fixtures.
func TestUT11_ConfigJSONRuleOrderValidator(t *testing.T) {
	raw, err := os.ReadFile("config.json")
	if err != nil {
		t.Fatalf("read delivered config.json: %v", err)
	}
	cfg, err := ParseXrayConfig(raw)
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if err := ValidateXrayRoutingRules(cfg); err != nil {
		t.Fatalf("delivered config.json failed UT-11 rule validation: %v", err)
	}

	brokenShadowed := `{
	  "inbounds": [{"settings": {"udp": true}}],
	  "outbounds": [{"tag": "proxy", "mux": {"enabled": false}}],
	  "routing": {
	    "rules": [
	      {"type": "field", "port": "443", "network": "udp", "outboundTag": "block"},
	      {"type": "field", "port": "0-65535", "outboundTag": "proxy"},
	      {"type": "field", "inboundTag": ["dns-module"], "outboundTag": "proxy"}
	    ]
	  }
	}`
	badCfg1, _ := ParseXrayConfig([]byte(brokenShadowed))
	if err := ValidateXrayRoutingRules(badCfg1); err == nil {
		t.Fatal("UT-11 failed to reject shadowed DNS rule fixture")
	}

	brokenNoQUICBlock := `{
	  "inbounds": [{"settings": {"udp": false}}],
	  "outbounds": [{"tag": "proxy", "mux": {"enabled": false}}],
	  "routing": {
	    "rules": [
	      {"type": "field", "inboundTag": ["dns-module"], "outboundTag": "direct"},
	      {"type": "field", "port": "0-65535", "network": "tcp", "outboundTag": "proxy"}
	    ]
	  }
	}`
	badCfg2, _ := ParseXrayConfig([]byte(brokenNoQUICBlock))
	if err := ValidateXrayRoutingRules(badCfg2); err == nil {
		t.Fatal("UT-11 failed to reject fixture missing udp:443 block at index 0")
	}

	brokenUDPLeak := `{
	  "inbounds": [{"settings": {"udp": true}}],
	  "outbounds": [{"tag": "proxy", "mux": {"enabled": false}}],
	  "routing": {
	    "rules": [
	      {"type": "field", "port": "443", "network": "udp", "outboundTag": "block"},
	      {"type": "field", "inboundTag": ["dns-module"], "outboundTag": "direct"},
	      {"type": "field", "port": "0-65535", "outboundTag": "proxy"}
	    ]
	  }
	}`
	badCfg3, _ := ParseXrayConfig([]byte(brokenUDPLeak))
	if err := ValidateXrayRoutingRules(badCfg3); err == nil {
		t.Fatal("UT-11 failed to reject fixture allowing UDP to reach proxy")
	}
}

// UT-12: config.json DNS Validator — accepts DoH 1.1.1.1 & 8.8.8.8 (& 9.9.9.9), rejects plaintext UDP:53 & DoT:853.
func TestUT12_ConfigJSONDNSValidator(t *testing.T) {
	raw, err := os.ReadFile("config.json")
	if err != nil {
		t.Fatalf("read delivered config.json: %v", err)
	}
	cfg, err := ParseXrayConfig(raw)
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if err := ValidateXrayDNSConfig(cfg); err != nil {
		t.Fatalf("delivered config.json failed UT-12 DNS validation: %v", err)
	}

	badFixtures := map[string]string{
		"plaintext_udp53": `{"dns": {"servers": ["8.8.8.8", "https://1.1.1.1/dns-query"]}}`,
		"alibaba_223":     `{"dns": {"servers": [{"address": "223.5.5.5"}, "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]}}`,
		"dot_853":         `{"dns": {"servers": ["tls://1.1.1.1:853", "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]}}`,
		"missing_google":  `{"dns": {"servers": ["https://1.1.1.1/dns-query"]}}`,
		"use_ipv6":        `{"dns": {"queryStrategy": "UseIPv6", "servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]}}`,
	}
	for name, fixture := range badFixtures {
		bad, err := ParseXrayConfig([]byte(fixture))
		if err != nil {
			t.Fatalf("fixture %s parse error: %v", name, err)
		}
		if err := ValidateXrayDNSConfig(bad); err == nil {
			t.Fatalf("UT-12 failed to reject invalid DNS fixture %q", name)
		}
	}
}

// UT-13: EventLogger 32-Goroutine Concurrent Log() + Close() Stress.
func TestUT13_LoggerConcurrentLogAndCloseNoPanic(t *testing.T) {
	baseG := runtime.NumGoroutine()
	dir := t.TempDir()

	for round := 0; round < 10; round++ {
		logPath := filepath.Join(dir, fmt.Sprintf("ut13_round_%d.log", round))
		logger, err := NewEventLogger(logPath)
		if err != nil {
			t.Fatalf("round %d NewEventLogger: %v", round, err)
		}

		const writers = 32
		var wg sync.WaitGroup
		startGate := make(chan struct{})
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-startGate
				for i := 0; i < 150; i++ {
					logger.Log("STRESS_EVT", map[string]any{
						"worker": id,
						"seq":    i,
					})
				}
			}(w)
		}
		close(startGate)

		time.Sleep(time.Duration(1+round%4) * time.Millisecond)
		if err := logger.Close(); err != nil {
			t.Fatalf("round %d Close: %v", round, err)
		}
		_ = logger.Close()
		wg.Wait()

		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("round %d read: %v", round, err)
		}
		if len(strings.TrimSpace(string(data))) > 0 {
			_ = readJSONLLog(t, logPath)
		}
	}
	assertNoGoroutineLeak(t, baseG, 2)
}

// UT-14: Async Probe Immediate Abort (<100ms) on childExitCh During 10s Stalled Probe + Anti-Ping-Pong.
func TestUT14_AsyncProbeAbortOnChildExitAndNoDialOKPingPong(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "ut14.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 1
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = socks.Port(t)
	cfg.StopOnExit = false
	cfg.ProbeInterval = 120 * time.Millisecond
	cfg.DegradedProbeInterval = 120 * time.Millisecond
	cfg.ProbeTimeout = 10 * time.Second
	cfg.BreakerThreshold = 5
	cfg.BreakerMinWindow = 30 * time.Second
	cfg.BackoffMin = 300 * time.Millisecond
	cfg.BackoffMax = 500 * time.Millisecond
	cfg.BootQualitySamples = 1
	cfg.GitHubMinCallSpacing = 0

	var probeCall atomic.Int32
	stallStarted := make(chan struct{}, 4)
	reconnCh := make(chan time.Time, 4)

	var firstChildMu sync.Mutex
	var firstChild *exec.Cmd
	var spawns atomic.Int32

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 20 * time.Millisecond,
		OnStateChange: func(from, to SupervisorState) {
			if to == StateReconnecting {
				select {
				case reconnCh <- time.Now():
				default:
				}
			}
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if spawns.Add(1) == 1 {
				firstChildMu.Lock()
				firstChild = cmd
				firstChildMu.Unlock()
			}
			return cmd, nil
		},
		ProbeFunc: func(pctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error) {
			n := probeCall.Add(1)
			switch n {
			case 1:
				return 15 * time.Millisecond, nil
			case 2:
				return 0, errors.New("simulated transient WAN timeout")
			case 3:
				select {
				case stallStarted <- struct{}{}:
				default:
				}
				select {
				case <-pctx.Done():
					return 0, pctx.Err()
				case <-time.After(10 * time.Second):
					return 0, errors.New("10s stall expired without cancellation")
				}
			default:
				return 15 * time.Millisecond, nil
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 3*time.Second, "UT-14 enters DEGRADED after failed probe #2", func() bool {
		return sup.State() == StateDegraded
	})

	c, err := net.DialTimeout("tcp", sup.BoundLocalAddr(), 1*time.Second)
	if err == nil {
		_ = c.Close()
	}
	time.Sleep(40 * time.Millisecond)
	if st := sup.State(); st != StateDegraded {
		cancel()
		<-done
		t.Fatalf("UT-14 dialOKCh ping-pong regression: expected DEGRADED, got %s", st)
	}

	select {
	case <-stallStarted:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("UT-14 timed out waiting for 10s stalled probe to start")
	}

	killAt := time.Now()
	firstChildMu.Lock()
	_ = firstChild.Process.Kill()
	firstChildMu.Unlock()

	select {
	case ts := <-reconnCh:
		abortLag := ts.Sub(killAt)
		t.Logf("UT-14 async probe aborted & transitioned to RECONNECTING in %s during 10s stall", abortLag)
		if abortLag >= 100*time.Millisecond {
			cancel()
			<-done
			t.Fatalf("UT-14 event loop was blocked by in-flight probe! abortLag=%s (SLO <100ms)", abortLag)
		}
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("UT-14 timed out waiting for RECONNECTING after child kill")
	}

	cancel()
	<-done
}

// UT-15: Pre-Traffic Boot Quality Gate — fast boot acceptance, cold-boot preservation, poisoned boot re-roll.
func TestUT15_BootQualityGateAndSlowBootParity(t *testing.T) {
	cfg := DefaultConfig()

	fastRep := EvaluateBootQuality(cfg, 7*time.Second, []time.Duration{210 * time.Millisecond, 230 * time.Millisecond, 240 * time.Millisecond}, 0)
	if !fastRep.Accepted || fastRep.SlowBoot || fastRep.Reason != "ok" {
		t.Fatalf("expected fast clean boot accepted, got %+v", fastRep)
	}

	coldRep := EvaluateBootQuality(cfg, 20800*time.Millisecond, []time.Duration{216 * time.Millisecond, 225 * time.Millisecond, 240 * time.Millisecond}, 0)
	if !coldRep.Accepted || !coldRep.SlowBoot || coldRep.Reason != "ok" {
		t.Fatalf("expected healthy cold VM boot accepted, got %+v", coldRep)
	}

	slowBadRTT := EvaluateBootQuality(cfg, 14500*time.Millisecond, []time.Duration{620 * time.Millisecond, 710 * time.Millisecond, 760 * time.Millisecond}, 0)
	if slowBadRTT.Accepted || slowBadRTT.Reason != "slow_boot_elevated_rtt" {
		t.Fatalf("expected slow_boot_elevated_rtt rejection, got %+v", slowBadRTT)
	}

	slowBadJitter := EvaluateBootQuality(cfg, 14500*time.Millisecond, []time.Duration{220 * time.Millisecond, 310 * time.Millisecond, 700 * time.Millisecond}, 0)
	if slowBadJitter.Accepted || slowBadJitter.Reason != "slow_boot_elevated_jitter" {
		t.Fatalf("expected slow_boot_elevated_jitter rejection, got %+v", slowBadJitter)
	}

	fastBadRTT := EvaluateBootQuality(cfg, 8*time.Second, []time.Duration{920 * time.Millisecond, 1050 * time.Millisecond, 1100 * time.Millisecond}, 0)
	if fastBadRTT.Accepted || fastBadRTT.Reason != "idle_rtt_exceeded" {
		t.Fatalf("expected idle_rtt_exceeded rejection, got %+v", fastBadRTT)
	}

	failRep := EvaluateBootQuality(cfg, 7*time.Second, []time.Duration{210 * time.Millisecond}, 1)
	if failRep.Accepted || failRep.Reason != "qualification_probe_failed" {
		t.Fatalf("expected qualification_probe_failed rejection, got %+v", failRep)
	}

	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "ut15_reroll.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	supCfg := DefaultConfig()
	supCfg.PoolSize = 1
	supCfg.PreflightNetHygiene = false
	supCfg.LocalPort = 0
	supCfg.GHPort = socks.Port(t)
	supCfg.StopOnExit = false
	supCfg.BootQualitySamples = 3
	supCfg.BootQualityMaxRetries = 2
	supCfg.BootQualityMaxRTT = 600 * time.Millisecond
	supCfg.BootQualityMaxJitter = 400 * time.Millisecond
	supCfg.ProbeInterval = 5 * time.Second
	supCfg.GitHubMinCallSpacing = 0

	var spawns atomic.Int32
	var openedDuringFirstAttempt atomic.Bool
	sup := NewSupervisor(supCfg, logger, SupervisorDeps{
		PortInspector:          &mockPortInspector{},
		BootPollDelay:          15 * time.Millisecond,
		BootQualitySampleDelay: 15 * time.Millisecond,
		BootQualityRetryDelay:  30 * time.Millisecond,
		LookupWANRemote: func(pid uint32) string {
			if spawns.Load() == 1 {
				return "20.1.1.1:443"
			}
			return "20.2.2.2:443"
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			spawns.Add(1)
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		ProbeFunc: func(pctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error) {
			if spawns.Load() == 1 {
				return 1150 * time.Millisecond, nil
			}
			return 185 * time.Millisecond, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 4*time.Second, "UT-15 re-rolls attempt 1 and enters HEALTHY on attempt 2", func() bool {
		if spawns.Load() == 1 && sup.BoundLocalAddr() != "" {
			openedDuringFirstAttempt.Store(true)
		}
		return spawns.Load() == 2 && sup.State() == StateHealthy
	})

	if openedDuringFirstAttempt.Load() {
		cancel()
		<-done
		t.Fatal("UT-15 :1080 opened during rejected attempt 1!")
	}
	if rc := sup.ReconnectCount(); rc != 0 {
		cancel()
		<-done
		t.Fatalf("UT-15 pre-traffic quality re-roll must not increment ReconnectCount, got %d", rc)
	}

	cancel()
	<-done

	recs := readJSONLLog(t, logPath)
	sawReject := false
	sawBootReadyWithRetry := false
	for _, r := range recs {
		if r.Event == "BOOT_QUALITY_REJECT" && r.Fields["reason"] == "idle_rtt_exceeded" {
			sawReject = true
		}
		if r.Event == "BOOT_READY" {
			if retries, ok := r.Fields["boot_quality_retries"].(float64); ok && int(retries) == 1 {
				sawBootReadyWithRetry = true
			}
		}
	}
	if !sawReject || !sawBootReadyWithRetry {
		t.Fatalf("UT-15 missing expected boot quality telemetry (reject=%v bootReadyRetry=%v)", sawReject, sawBootReadyWithRetry)
	}

	logPath2 := filepath.Join(t.TempDir(), "ut15_cap.log")
	logger2, err := NewEventLogger(logPath2)
	if err != nil {
		t.Fatalf("NewEventLogger2: %v", err)
	}
	capCfg := supCfg
	capCfg.BootQualityMaxRetries = 1
	var capSpawns atomic.Int32
	sup2 := NewSupervisor(capCfg, logger2, SupervisorDeps{
		PortInspector:          &mockPortInspector{},
		BootPollDelay:          15 * time.Millisecond,
		BootQualitySampleDelay: 15 * time.Millisecond,
		BootQualityRetryDelay:  30 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			capSpawns.Add(1)
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		ProbeFunc: func(pctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error) {
			return 1400 * time.Millisecond, nil
		},
	})
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- sup2.Run(ctx2) }()

	waitUntil(t, 4*time.Second, "UT-15 cap enters HEALTHY best-effort after 1 retry", func() bool {
		return capSpawns.Load() == 2 && sup2.State() == StateHealthy
	})
	cancel2()
	<-done2

	recs2 := readJSONLLog(t, logPath2)
	sawBestEffort := false
	for _, r := range recs2 {
		if r.Event == "BOOT_QUALITY_ACCEPTED_BEST_EFFORT" {
			sawBestEffort = true
		}
	}
	if !sawBestEffort {
		t.Fatal("UT-15 expected BOOT_QUALITY_ACCEPTED_BEST_EFFORT when max retries exhausted")
	}
}

// UT-16: Phase-5 Regression Suite — wanProgressRecent bounded veto, EcoQoS hooks, ProxyServer.Stop(true) <300ms.
func TestUT16_Phase5Regressions_WanVeto_ChildQoS_FastStop(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "ut16.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 1
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = socks.Port(t)
	cfg.StopOnExit = false
	cfg.BootQualitySamples = 1
	cfg.ProbeInterval = 120 * time.Millisecond
	cfg.DegradedProbeInterval = 120 * time.Millisecond
	cfg.ProbeTimeout = 150 * time.Millisecond
	cfg.BreakerThreshold = 3
	cfg.BreakerMinWindow = 500 * time.Millisecond
	cfg.BackoffMin = 100 * time.Millisecond
	cfg.BackoffMax = 200 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	var (
		spawns          atomic.Int32
		tunedChildCalls atomic.Int32
		tunedTreeCalls  atomic.Int32
		forceProbeFail  atomic.Bool
	)

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 20 * time.Millisecond,
		TuneChildProcess: func(pid int) error {
			if pid > 0 {
				tunedChildCalls.Add(1)
			}
			return nil
		},
		TuneProcessTree: func(rootPID int) int {
			if rootPID > 0 {
				tunedTreeCalls.Add(1)
				return 2
			}
			return 0
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			n := spawns.Add(1)
			if n >= 2 {
				forceProbeFail.Store(false)
			}
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		ProbeFunc: func(pctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error) {
			if forceProbeFail.Load() {
				return 0, errors.New("simulated blackhole")
			}
			return ProbeSOCKS5(pctx, ghAddr, target, timeout)
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 3*time.Second, "UT-16 initial HEALTHY", func() bool {
		return sup.State() == StateHealthy
	})
	if tunedChildCalls.Load() < 1 || tunedTreeCalls.Load() < 1 {
		cancel()
		<-done
		t.Fatalf("UT-16 expected child+tree QoS hooks called, got child=%d tree=%d", tunedChildCalls.Load(), tunedTreeCalls.Load())
	}

	forceProbeFail.Store(true)
	waitUntil(t, 2*time.Second, "UT-16 enters DEGRADED after failure #1", func() bool {
		return sup.State() == StateDegraded
	})

	if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), []byte("stray-wan-packet-12345"), 2*time.Second); err != nil {
		cancel()
		<-done
		t.Fatalf("UT-16 stray WAN transfer failed: %v", err)
	}

	waitUntil(t, 4*time.Second, "UT-16 trips breaker despite earlier stray WAN packet", func() bool {
		return spawns.Load() >= 2 && sup.State() == StateHealthy
	})

	cancel()
	<-done

	recs := readJSONLLog(t, logPath)
	sawTrip := false
	sawTuned := false
	for _, r := range recs {
		if r.Event == "ZOMBIE_BREAKER_TRIP" && r.Fields["reason"] == "sustained_e2e_blackhole" {
			sawTrip = true
		}
		if r.Event == "BOOT_READY" {
			if n, ok := r.Fields["child_ecoqos_tuned"].(float64); ok && int(n) == 2 {
				sawTuned = true
			}
		}
	}
	if !sawTrip || !sawTuned {
		t.Fatalf("UT-16 missing expected records (sawTrip=%v sawTuned=%v)", sawTrip, sawTuned)
	}

	echoAddr, _, _, stopEcho := startPlainTCPEchoServer(t, 2*time.Second)
	defer stopEcho()

	pCfg := DefaultConfig()
	pCfg.LocalPort = 0
	pCfg.MaxActiveConns = 1
	pCfg.SemaphoreWaitTimeout = 5 * time.Second

	proxy := NewProxyServer(pCfg, echoAddr, nil, nil, nil)
	parentCtx := context.Background()
	proxyAddr, err := proxy.Start(parentCtx)
	if err != nil {
		t.Fatalf("UT-16 proxy.Start: %v", err)
	}

	var conns []net.Conn
	for i := 0; i < 6; i++ {
		c, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if err != nil {
			t.Fatalf("UT-16 dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	time.Sleep(80 * time.Millisecond)

	stopStart := time.Now()
	proxy.Stop(true)
	stopElapsed := time.Since(stopStart)
	if stopElapsed > 300*time.Millisecond {
		t.Fatalf("UT-16 ProxyServer.Stop(true) stalled %s waiting on semaphore/dial (SLO <300ms)", stopElapsed)
	}
}

// UT-17: Upstream concurrency shaping + dial pacing.
func TestUT17_UpstreamConcurrencyShapingAndDialPacing(t *testing.T) {
	const (
		clients = 40
		maxOpen = 10
		minGap  = 20 * time.Millisecond
	)
	payload := makeDeterministicPayload(2048, 1717)

	runBurst := func(t *testing.T, cfg Config, up *shapingSensitiveUpstream, clientTimeout time.Duration) (int, *ProxyServer, func()) {
		t.Helper()
		proxy := NewProxyServer(cfg, up.Addr(), nil, nil, nil)
		ctx, cancel := context.WithCancel(context.Background())
		proxyAddr, err := proxy.Start(ctx)
		if err != nil {
			cancel()
			t.Fatalf("proxy.Start: %v", err)
		}
		var ok atomic.Int64
		var wg sync.WaitGroup
		gate := make(chan struct{})
		for i := 0; i < clients; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				if err := shapingEchoClient(proxyAddr, payload, clientTimeout); err == nil {
					ok.Add(1)
				}
			}()
		}
		close(gate)
		wg.Wait()
		return int(ok.Load()), proxy, func() { proxy.Stop(true); cancel() }
	}

	t.Run("control_v4_stampede_collapses", func(t *testing.T) {
		up := startShapingSensitiveUpstream(t, maxOpen, minGap, 40*time.Millisecond)
		defer up.Close()
		cfg := DefaultConfig()
		cfg.LocalPort = 0
		cfg.MaxActiveConns = 128
		cfg.MaxQueuedConns = 0
		cfg.SemaphoreWaitTimeout = 500 * time.Millisecond
		cfg.DialPaceInterval = 0
		ok, _, stop := runBurst(t, cfg, up, 1500*time.Millisecond)
		defer stop()
		if ok >= clients || up.violations.Load() == 0 {
			t.Fatalf("control run did not reproduce the collapse (ok=%d/%d violations=%d peak=%d)",
				ok, clients, up.violations.Load(), up.peak.Load())
		}
		t.Logf("UT-17 control (v4 shape): ok=%d/%d violations=%d peakUpstream=%d", ok, clients, up.violations.Load(), up.peak.Load())
	})

	t.Run("v5_shaped_40_of_40", func(t *testing.T) {
		up := startShapingSensitiveUpstream(t, maxOpen, minGap, 40*time.Millisecond)
		defer up.Close()
		cfg := DefaultConfig()
		cfg.LocalPort = 0
		cfg.MaxActiveConns = 8
		cfg.MaxQueuedConns = 40
		cfg.SemaphoreWaitTimeout = 15 * time.Second
		cfg.DialPaceInterval = 35 * time.Millisecond
		ok, proxy, stop := runBurst(t, cfg, up, 20*time.Second)
		defer stop()

		if ok != clients {
			t.Fatalf("UT-17 expected %d/%d transfers, got %d (violations=%d peakUpstream=%d minGap=%s)",
				clients, clients, ok, up.violations.Load(), up.peak.Load(), up.MinSeenGap())
		}
		if v := up.violations.Load(); v != 0 {
			t.Fatalf("UT-17 upstream saw %d shaping violations (peak=%d minGap=%s)", v, up.peak.Load(), up.MinSeenGap())
		}
		if peak := up.peak.Load(); peak > 8 {
			t.Fatalf("UT-17 peakUpstream=%d > 8", peak)
		}
		m := proxy.Metrics(false)
		if m.SemaphoreRejects != 0 {
			t.Fatalf("UT-17 SemaphoreRejects=%d, want 0", m.SemaphoreRejects)
		}
		if m.PeakConns > 8 {
			t.Fatalf("UT-17 proxy PeakConns=%d > 8", m.PeakConns)
		}
		if g := up.MinSeenGap(); g < minGap {
			t.Fatalf("UT-17 min observed upstream dial gap %s < %s", g, minGap)
		}
		t.Logf("UT-17 shaped: ok=%d/%d peakUpstream=%d proxyPeak=%d minDialGap=%s rejects=%d",
			ok, clients, up.peak.Load(), m.PeakConns, up.MinSeenGap(), m.SemaphoreRejects)
	})

	t.Run("stop_true_aborts_queued_waiters", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("blackhole upstream listen: %v", err)
		}
		var holdWG sync.WaitGroup
		var holdMu sync.Mutex
		var held []net.Conn
		holdWG.Add(1)
		go func() {
			defer holdWG.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				holdMu.Lock()
				held = append(held, c)
				holdMu.Unlock()
				go func() { _, _ = io.Copy(io.Discard, c) }()
			}
		}()
		defer func() {
			_ = ln.Close()
			holdWG.Wait()
			holdMu.Lock()
			for _, c := range held {
				_ = c.Close()
			}
			holdMu.Unlock()
		}()

		cfg := DefaultConfig()
		cfg.LocalPort = 0
		cfg.MaxActiveConns = 1
		cfg.SemaphoreWaitTimeout = 15 * time.Second
		cfg.DialPaceInterval = 25 * time.Millisecond
		proxy := NewProxyServer(cfg, ln.Addr().String(), nil, nil, nil)
		proxyAddr, err := proxy.Start(context.Background())
		if err != nil {
			t.Fatalf("proxy.Start: %v", err)
		}

		const queued = 8
		var clientConns []net.Conn
		for i := 0; i < 1+queued; i++ {
			c, err := net.DialTimeout("tcp", proxyAddr, time.Second)
			if err != nil {
				t.Fatalf("dial %d: %v", i, err)
			}
			clientConns = append(clientConns, c)
			_, _ = c.Write([]byte("x"))
		}
		defer func() {
			for _, c := range clientConns {
				_ = c.Close()
			}
		}()
		waitUntil(t, 3*time.Second, "1 active + 8 queued waiters", func() bool {
			m := proxy.Metrics(false)
			return m.ActiveConns == 1 && m.QueuedConns == queued
		})

		start := time.Now()
		proxy.Stop(true)
		elapsed := time.Since(start)
		if elapsed > 300*time.Millisecond {
			t.Fatalf("UT-17 Stop(true) took %s aborting queued waiters (SLO <300ms)", elapsed)
		}
		if rej := proxy.Metrics(false).SemaphoreRejects; rej != 0 {
			t.Fatalf("UT-17 orderly Stop(true) must not count as saturation rejects, got %d", rej)
		}
		for i, c := range clientConns {
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			var b [1]byte
			_, err := c.Read(b[:])
			var ne net.Error
			if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
				t.Fatalf("UT-17 client %d was not closed by Stop(true): err=%v", i, err)
			}
		}
		t.Logf("UT-17 Stop(true) aborted 1 active + %d queued in %s", queued, elapsed)
	})
}

// UT-18: Probe-skip blindness is eliminated.
func TestUT18_ProbeNotBlindedByTrickleTraffic(t *testing.T) {
	base := ProxySignals{ActiveConns: 3, MaxConns: 8}
	cases := []struct {
		name      string
		cur, prev ProxySignals
		skips     int
		wantSkip  bool
		wantWhy   string
	}{
		{"quiet_first_skip_allowed", base, base, 0, true, ""},
		{"second_consecutive_skip_forbidden", base, base, 1, false, "max_consecutive_skips"},
		{"saturated", ProxySignals{ActiveConns: 8, MaxConns: 8}, base, 0, false, "proxy_saturated"},
		{"queueing", ProxySignals{ActiveConns: 8, MaxConns: 8, QueuedConns: 5}, base, 0, false, "proxy_saturated"},
		{"queueing_below_cap", ProxySignals{ActiveConns: 3, MaxConns: 8, QueuedConns: 1}, base, 0, false, "proxy_queueing"},
		{"rejects_increased", ProxySignals{ActiveConns: 3, MaxConns: 8, SemaphoreRejects: 1}, base, 0, false, "semaphore_rejects_increased"},
		{"drain_abrupt_spike", ProxySignals{ActiveConns: 3, MaxConns: 8, DrainTimeouts: 2, AbruptErrors: 3}, base, 0, false, "drain_or_abrupt_spike"},
		{"small_error_delta_allowed", ProxySignals{ActiveConns: 3, MaxConns: 8, AbruptErrors: probeStressSpikeThreshold - 1}, base, 0, true, ""},
	}
	for _, tc := range cases {
		gotSkip, why := probeSkipDecision(tc.cur, tc.prev, tc.skips)
		if gotSkip != tc.wantSkip || why != tc.wantWhy {
			t.Fatalf("UT-18 %s: got skip=%v why=%q, want skip=%v why=%q", tc.name, gotSkip, why, tc.wantSkip, tc.wantWhy)
		}
	}

	type run struct {
		sup       *Supervisor
		logPath   string
		probes    *atomic.Int64
		stopAll   func()
		proxyAddr string
	}
	start := func(t *testing.T, name string, mutate func(*Config)) *run {
		t.Helper()
		socks := startMockSOCKS5Server(t, socksModeNormal)
		logPath := filepath.Join(t.TempDir(), name+".log")
		logger, err := NewEventLogger(logPath)
		if err != nil {
			socks.Close()
			t.Fatalf("NewEventLogger: %v", err)
		}
		cfg := DefaultConfig()
		cfg.PoolSize = 1
		cfg.PreflightNetHygiene = false
		cfg.LocalPort = 0
		cfg.GHPort = socks.Port(t)
		cfg.StopOnExit = false
		cfg.BootQualitySamples = 1
		cfg.ProbeInterval = 300 * time.Millisecond
		cfg.DegradedProbeInterval = 300 * time.Millisecond
		cfg.ProbeTimeout = 400 * time.Millisecond
		cfg.DialPaceInterval = 0
		cfg.BackoffMin = 100 * time.Millisecond
		cfg.BackoffMax = 200 * time.Millisecond
		cfg.GitHubMinCallSpacing = 0
		if mutate != nil {
			mutate(&cfg)
		}
		var probes atomic.Int64
		sup := NewSupervisor(cfg, logger, SupervisorDeps{
			PortInspector: &mockPortInspector{},
			BootPollDelay: 20 * time.Millisecond,
			StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
				cmd := newHelperCmd("sleep_alive")
				cmd.Stderr = stderr
				return cmd, cmd.Start()
			},
			ProbeFunc: func(pctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error) {
				probes.Add(1)
				return ProbeSOCKS5(pctx, ghAddr, target, timeout)
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- sup.Run(ctx) }()
		waitUntil(t, 3*time.Second, name+" initial HEALTHY", func() bool { return sup.State() == StateHealthy })
		return &run{
			sup:       sup,
			logPath:   logPath,
			probes:    &probes,
			proxyAddr: sup.BoundLocalAddr(),
			stopAll: func() {
				cancel()
				<-done
				socks.Close()
			},
		}
	}

	t.Run("trickle_cannot_skip_probes_indefinitely", func(t *testing.T) {
		r := start(t, "ut18b", nil)
		stopTrickle := make(chan struct{})
		var tw sync.WaitGroup
		tw.Add(1)
		go func() {
			defer tw.Done()
			for {
				select {
				case <-stopTrickle:
					return
				default:
				}
				_ = performSOCKS5EchoTransfer(r.proxyAddr, []byte("x"), 2*time.Second)
				time.Sleep(25 * time.Millisecond)
			}
		}()
		var once sync.Once
		shutdown := func() {
			once.Do(func() {
				close(stopTrickle)
				tw.Wait()
				r.stopAll()
			})
		}
		defer shutdown()

		time.Sleep(60 * time.Millisecond)
		baseline := r.probes.Load()
		budget := 2*r.sup.cfg.ProbeInterval + 600*time.Millisecond
		waitUntil(t, budget, "E2E probe runs despite continuous trickle (<= 2*ProbeInterval)", func() bool {
			return r.probes.Load() >= baseline+1
		})
		if lm := r.sup.activeProxyLastMoved(); lm.IsZero() || time.Since(lm) > r.sup.cfg.ProbeInterval {
			t.Fatalf("UT-18 trickle precondition failed: WAN progress not fresh (lastMoved=%v)", lm)
		}
		shutdown()
		if !hasProbeForced(t, r.logPath, "max_consecutive_skips") {
			t.Fatalf("UT-18 expected PROBE_FORCED reason=max_consecutive_skips in telemetry")
		}
	})

	t.Run("saturation_forces_probe", func(t *testing.T) {
		r := start(t, "ut18c", func(c *Config) {
			c.MaxActiveConns = 2
			c.SemaphoreWaitTimeout = 30 * time.Millisecond
		})
		stopHold := make(chan struct{})
		var hw sync.WaitGroup
		for i := 0; i < 2; i++ {
			hw.Add(1)
			go func() {
				defer hw.Done()
				holdSOCKS5Session(r.proxyAddr, 40*time.Millisecond, stopHold)
			}()
		}
		var once sync.Once
		shutdown := func() {
			once.Do(func() {
				close(stopHold)
				hw.Wait()
				r.stopAll()
			})
		}
		defer shutdown()

		r.sup.proxyMu.Lock()
		p := r.sup.activeProxy
		r.sup.proxyMu.Unlock()
		waitUntil(t, 2*time.Second, "proxy saturated (active == max)", func() bool {
			return p.Metrics(false).ActiveConns >= 2
		})
		baseline := r.probes.Load()
		waitUntil(t, r.sup.cfg.ProbeInterval+600*time.Millisecond, "probe forced while saturated", func() bool {
			return r.probes.Load() >= baseline+1
		})
		shutdown()
		if !hasProbeForced(t, r.logPath, "proxy_saturated") {
			t.Fatalf("UT-18 expected PROBE_FORCED reason=proxy_saturated in telemetry")
		}
	})
}

func hasProbeForced(t *testing.T, logPath, reason string) bool {
	t.Helper()
	for _, r := range readJSONLLog(t, logPath) {
		if r.Event == "PROBE_FORCED" && r.Fields["reason"] == reason {
			return true
		}
	}
	return false
}
