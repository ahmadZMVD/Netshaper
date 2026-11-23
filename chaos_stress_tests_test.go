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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ST-01: Concurrency Burst + Soak — 150 concurrent SOCKS5 transfers under -race, semaphore <=128, 0 leaks.
func TestST01_ConcurrencyBurstAndSoak(t *testing.T) {
	baseG := runtime.NumGoroutine()

	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 128
	cfg.MaxQueuedConns = 0
	cfg.SemaphoreWaitTimeout = 2 * time.Second
	cfg.DialPaceInterval = 0

	proxy := NewProxyServer(cfg, socks.Addr(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	const clients = 150
	payload := makeDeterministicPayload(32*1024, 9001)
	errCh := make(chan error, clients)
	var wg sync.WaitGroup

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if err := performSOCKS5EchoTransfer(proxyAddr, payload, 8*time.Second); err != nil {
				errCh <- fmt.Errorf("client %d: %w", id, err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	if peak := socks.maxInFlight.Load(); peak > 128 {
		t.Fatalf("ST-01 upstream concurrency exceeded 128 guard: peak=%d", peak)
	}
	waitUntil(t, 2*time.Second, "ST-01 active conns drain to 0", func() bool {
		return proxy.Metrics(false).ActiveConns == 0 && socks.inFlight.Load() == 0
	})

	proxy.Stop(true)
	socks.Close()
	assertNoGoroutineLeak(t, baseG, 4)
}

// ST-02: Randomized Cellular Markov-Chain Handover Survival.
func TestST02_RandomizedCellularMarkovHandoverSurvival(t *testing.T) {
	seed := testSeed(t)
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0xa5a5a5a55a5a5a5a))

	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	relay := startMockBloatedRelay(t, socks.Addr(), 0, 0, 0)
	defer relay.Close()

	logPath := filepath.Join(t.TempDir(), "st02_markov.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 1
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = relay.Port(t)
	cfg.StopOnExit = false
	cfg.ProbeInterval = 3 * time.Second
	cfg.DegradedProbeInterval = 4 * time.Second
	cfg.ProbeTimeout = 12 * time.Second
	cfg.DegradedRTTThreshold = 4000 * time.Millisecond
	cfg.BreakerThreshold = 5
	cfg.BreakerMinWindow = 45 * time.Second
	cfg.BootQualitySamples = 1

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 30 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 4*time.Second, "ST-02 initial HEALTHY", func() bool {
		return sup.State() == StateHealthy
	})

	trafficCtx, stopTraffic := context.WithCancel(ctx)
	var completedOK atomic.Int64
	var trafficWG sync.WaitGroup
	for w := 0; w < 4; w++ {
		trafficWG.Add(1)
		go func(id int) {
			defer trafficWG.Done()
			wRNG := rand.New(rand.NewPCG(uint64(seed)+uint64(id+1), uint64(id+99)))
			for trafficCtx.Err() == nil {
				sz := 128
				if wRNG.IntN(3) == 0 {
					sz = 32 * 1024
				}
				payload := makeDeterministicPayload(sz, wRNG.Uint64())
				if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), payload, 8*time.Second); err == nil {
					completedOK.Add(1)
				}
				time.Sleep(time.Duration(100+wRNG.IntN(200)) * time.Millisecond)
			}
		}(w)
	}

	type radioState int
	const (
		radioGood radioState = iota
		radioBloat
		radioLoss
	)
	curState := radioBloat
	steps := 4
	if testing.Short() {
		steps = 2
	}
	for step := 0; step < steps; step++ {
		switch curState {
		case radioGood:
			relay.SetProfile(120, 180, 0, true, false)
			t.Logf("ST-02 Markov step %d: GOOD (120-180ms)", step)
			time.Sleep(1500 * time.Millisecond)
		case radioBloat:
			minMS := int64(750 + rng.IntN(500))
			maxMS := minMS + int64(750+rng.IntN(750))
			relay.SetProfile(minMS, maxMS, 5, true, false)
			t.Logf("ST-02 Markov step %d: BUFFERBLOAT (%d-%dms per hop)", step, minMS, maxMS)
			time.Sleep(2500 * time.Millisecond)
		case radioLoss:
			loss := int64(10 + rng.IntN(16))
			relay.SetProfile(300, 900, loss, true, false)
			t.Logf("ST-02 Markov step %d: BURST_LOSS (%d%%)", step, loss)
			time.Sleep(2000 * time.Millisecond)
		}
		r := rng.IntN(100)
		if r < 30 {
			curState = radioGood
		} else if r < 65 {
			curState = radioBloat
		} else {
			curState = radioLoss
		}
	}

	blackoutSec := 12 + rng.IntN(5)
	if testing.Short() {
		blackoutSec = 4
	}
	t.Logf("ST-02 injecting %ds total cellular radio blackout...", blackoutSec)
	relay.SetProfile(0, 0, 0, false, true)
	time.Sleep(time.Duration(blackoutSec) * time.Second)

	t.Logf("ST-02 radio recovered after %ds blackout", blackoutSec)
	relay.SetProfile(20, 80, 0, true, false)

	waitUntil(t, 20*time.Second, "ST-02 recovers to HEALTHY after Markov storm + blackout", func() bool {
		return sup.State() == StateHealthy
	})

	stopTraffic()
	trafficWG.Wait()

	if rc := sup.ReconnectCount(); rc != 0 {
		cancel()
		<-done
		t.Fatalf("ST-02 false tunnel suicide during cellular handover! ReconnectCount=%d (want 0)", rc)
	}

	if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), makeDeterministicPayload(64*1024, uint64(seed)), 5*time.Second); err != nil {
		cancel()
		<-done
		t.Fatalf("ST-02 post-handover transfer failed: %v", err)
	}
	t.Logf("ST-02 survived Markov storm + %ds blackout with ReconnectCount=0 (completedOK=%d)", blackoutSec, completedOK.Load())

	cancel()
	<-done
}

// ST-03: Mid-Session Child Kill — SIGKILL mock child mid-traffic; :1080 refuses in <1s, auto-recovers <3s.
func TestST03_MidSessionChildKill(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "st03.log")
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
	cfg.BackoffMin = 200 * time.Millisecond
	cfg.BackoffMax = 400 * time.Millisecond
	cfg.ProbeInterval = 5 * time.Second
	cfg.BootQualitySamples = 1
	cfg.GitHubMinCallSpacing = 0

	var firstChildMu sync.Mutex
	var firstChild *exec.Cmd
	var spawnNum atomic.Int32

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 25 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if spawnNum.Add(1) == 1 {
				firstChildMu.Lock()
				firstChild = cmd
				firstChildMu.Unlock()
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 3*time.Second, "ST-03 initial HEALTHY", func() bool {
		return sup.State() == StateHealthy
	})
	firstAddr := sup.BoundLocalAddr()

	killAt := time.Now()
	firstChildMu.Lock()
	_ = firstChild.Process.Kill()
	firstChildMu.Unlock()

	closedAt := time.Time{}
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		probeStart := time.Now()
		c, err := net.DialTimeout("tcp", firstAddr, 500*time.Millisecond)
		if err != nil {
			if time.Since(probeStart) > 500*time.Millisecond {
				t.Fatalf("ST-03 probe hung %s instead of fast-refusing", time.Since(probeStart))
			}
			closedAt = time.Now()
			break
		}
		_ = c.Close()
		time.Sleep(25 * time.Millisecond)
	}
	if closedAt.IsZero() {
		cancel()
		<-done
		t.Fatal("ST-03 :1080 listener remained open >1s after child kill")
	}
	t.Logf("ST-03 :1080 fast-closed in %s after SIGKILL", closedAt.Sub(killAt))

	waitUntil(t, 3*time.Second, "ST-03 auto-recovered HEALTHY with child #2", func() bool {
		return spawnNum.Load() >= 2 && sup.State() == StateHealthy && sup.BoundLocalAddr() != ""
	})
	if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), []byte("post-kill-ok"), 2*time.Second); err != nil {
		cancel()
		<-done
		t.Fatalf("ST-03 post-recovery traffic failed: %v", err)
	}

	cancel()
	<-done
}

// ST-04: Transient 10s Blackout Survival vs Sustained Blackhole Circuit Breaker.
func TestST04_TransientBlackoutVsSustainedBlackholeBreaker(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "st04.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	transientDur := 10 * time.Second
	minWin := 14 * time.Second
	probeInt := 1500 * time.Millisecond
	probeTO := 1200 * time.Millisecond
	if testing.Short() {
		transientDur = 1200 * time.Millisecond
		minWin = 2500 * time.Millisecond
		probeInt = 300 * time.Millisecond
		probeTO = 300 * time.Millisecond
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 1
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = socks.Port(t)
	cfg.StopOnExit = false
	cfg.ProbeInterval = probeInt
	cfg.DegradedProbeInterval = probeInt
	cfg.ProbeTimeout = probeTO
	cfg.BreakerThreshold = 4
	cfg.BreakerMinWindow = minWin
	cfg.BackoffMin = 150 * time.Millisecond
	cfg.BackoffMax = 300 * time.Millisecond
	cfg.BootQualitySamples = 1
	cfg.GitHubMinCallSpacing = 0

	var spawns atomic.Int32
	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 25 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			n := spawns.Add(1)
			if n >= 2 {
				socks.SetMode(socksModeNormal)
			}
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 3*time.Second, "ST-04 initial HEALTHY", func() bool {
		return sup.State() == StateHealthy
	})

	t.Logf("ST-04 Phase A: injecting transient %s blackout (BreakerMinWindow=%s)", transientDur, minWin)
	socks.SetMode(socksModeBlackhole)
	waitUntil(t, probeInt+probeTO+2*time.Second, "ST-04 Phase A enters DEGRADED", func() bool {
		return sup.State() == StateDegraded
	})
	if waitRem := transientDur - (probeInt + probeTO); waitRem > 0 {
		time.Sleep(waitRem)
	}
	socks.SetMode(socksModeNormal)

	waitUntil(t, probeInt+3*time.Second, "ST-04 Phase A recovers HEALTHY without reconnect", func() bool {
		return sup.State() == StateHealthy
	})
	if rc := sup.ReconnectCount(); rc != 0 {
		cancel()
		<-done
		t.Fatalf("ST-04 Phase A false kill during transient %s blackout: reconnects=%d", transientDur, rc)
	}

	t.Logf("ST-04 Phase B: injecting sustained zombie blackhole (> %s)", minWin)
	oldAddr := sup.BoundLocalAddr()
	tripStart := time.Now()
	socks.SetMode(socksModeBlackhole)

	waitUntil(t, minWin+10*time.Second, "ST-04 Phase B trips breaker and recycles to HEALTHY", func() bool {
		return spawns.Load() >= 2 && sup.State() == StateHealthy
	})
	t.Logf("ST-04 Phase B zombie blackhole detected & recycled in %s (oldAddr=%s)", time.Since(tripStart), oldAddr)

	cancel()
	<-done

	recs := readJSONLLog(t, logPath)
	sawBreaker := false
	sawRecovery := false
	for _, r := range recs {
		if r.Event == "ZOMBIE_BREAKER_TRIP" {
			sawBreaker = true
		}
		if r.Event == "RECOVERY_FROM_DEGRADED" {
			sawRecovery = true
		}
	}
	if !sawRecovery {
		t.Fatal("ST-04 expected RECOVERY_FROM_DEGRADED from Phase A transient blackout")
	}
	if !sawBreaker {
		t.Fatal("ST-04 expected ZOMBIE_BREAKER_TRIP from Phase B sustained blackhole")
	}
}

// ST-05: Rapid Short-Lived Churn — 1,000 connection-per-request HTTP/1.1 transfers, 1000/1000 OK, 0 leaks.
func TestST05_RapidShortLivedChurn(t *testing.T) {
	baseG := runtime.NumGoroutine()

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = w.Write([]byte("OK-CHURN"))
	}))
	defer httpSrv.Close()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 128
	cfg.DialPaceInterval = 0

	proxy := NewProxyServer(cfg, strings.TrimPrefix(httpSrv.URL, "http://"), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	const totalReqs = 1000
	const workers = 20
	jobs := make(chan int, totalReqs)
	for i := 0; i < totalReqs; i++ {
		jobs <- i
	}
	close(jobs)

	var completed atomic.Int64
	errCh := make(chan error, totalReqs)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
				if err != nil {
					errCh <- fmt.Errorf("req %d dial: %w", id, err)
					continue
				}
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
				if err != nil {
					_ = conn.Close()
					errCh <- fmt.Errorf("req %d write: %w", id, err)
					continue
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					_ = conn.Close()
					errCh <- fmt.Errorf("req %d read resp: %w", id, err)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				_ = conn.Close()
				if resp.StatusCode != 200 || string(body) != "OK-CHURN" {
					errCh <- fmt.Errorf("req %d bad response: status=%d body=%q", id, resp.StatusCode, string(body))
					continue
				}
				completed.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
	if completed.Load() != totalReqs {
		t.Fatalf("ST-05 completed %d/%d", completed.Load(), totalReqs)
	}
	waitUntil(t, 2*time.Second, "ST-05 active conns drain to 0", func() bool {
		return proxy.Metrics(false).ActiveConns == 0
	})

	proxy.Stop(true)
	httpSrv.Close()
	assertNoGoroutineLeak(t, baseG, 6)
}

// ST-06: Mixed-Privilege Startup — :10808 (xray.exe) under High-IL and equal-IL permutations.
func TestST06_MixedPrivilegeStartup(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "st06.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	const selfPID uint32 = 5555

	for cycle := 0; cycle < 20; cycle++ {
		highILMode := cycle%2 == 0
		imgErrs := map[uint32]error{}
		termErrs := map[uint32]error{}
		if highILMode {
			imgErrs[9716] = errors.New("Access is denied")
			termErrs[9716] = errors.New("Access is denied")
		}

		inspector := &mockPortInspector{
			listeners: []TCPListenerEntry{
				{Port: 10808, PID: 9716, Family: "tcp4"},
				{Port: 1080, PID: selfPID, Family: "tcp4"},
				{Port: 1080, PID: 2001, Family: "tcp4"},
				{Port: 1081, PID: 2002, Family: "tcp4"},
				{Port: 1081, PID: 2003, Family: "tcp6"},
			},
			images: map[uint32]string{
				9716:    `C:\Tools\proxy\xray.exe`,
				selfPID: `C:\VPN\NetShaper.exe`,
				2001:    `C:\VPN\NetShaper.exe`,
				2002:    `C:\WINDOWS\System32\OpenSSH\ssh.exe`,
				2003:    `C:\Program Files\Other\sqlservr.exe`,
			},
			imageErrs: imgErrs,
			termErrs:  termErrs,
		}

		_, err := CleanTargetPorts(inspector, []uint16{1080, 1081}, selfPID, DefaultCleanupAllowedImages, logger)
		if err != nil {
			t.Fatalf("cycle %d: CleanTargetPorts: %v", cycle, err)
		}

		killed := inspector.TerminatedCopy()
		for _, pid := range killed {
			if pid == 9716 {
				t.Fatalf("cycle %d (highIL=%v): COLLATERAL KILL attempt on xray.exe (PID 9716)!", cycle, highILMode)
			}
			if pid == selfPID {
				t.Fatalf("cycle %d: SELF-KILL attempt on NetShaper (PID %d)!", cycle, selfPID)
			}
			if pid == 2003 {
				t.Fatalf("cycle %d: non-whitelisted PID 2003 killed!", cycle)
			}
		}
		if len(killed) != 2 {
			t.Fatalf("cycle %d: expected exactly 2 stale kills (2001, 2002), got %v", cycle, killed)
		}
	}

	_ = logger.Close()
	recs := readJSONLLog(t, logPath)
	auditCount := 0
	for _, r := range recs {
		if r.Event == "PORT_CLEANUP_AUDIT" {
			auditCount++
		}
	}
	if auditCount < 60 {
		t.Fatalf("ST-06 expected >=60 PORT_CLEANUP_AUDIT records, got %d", auditCount)
	}
}

// ST-07: Accelerated Soak with Resets & Append-Only Persistent Log Verification.
func TestST07_AcceleratedSoakWithResetsAndPersistentLog(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "netshaper_history.log")

	for session := 1; session <= 2; session++ {
		logger, err := NewEventLogger(logPath)
		if err != nil {
			t.Fatalf("session %d NewEventLogger: %v", session, err)
		}

		cfg := DefaultConfig()
		cfg.PoolSize = 1
		cfg.PreflightNetHygiene = false
		cfg.LocalPort = 0
		cfg.GHPort = socks.Port(t)
		cfg.StopOnExit = true
		cfg.StopTimeout = 1 * time.Second
		cfg.BackoffMin = 120 * time.Millisecond
		cfg.BackoffMax = 250 * time.Millisecond
		cfg.ProbeInterval = 400 * time.Millisecond
		cfg.BootQualitySamples = 1
		cfg.GitHubMaxCallsPer5Min = 20
		cfg.GitHubMaxCallsPerHour = 60
		cfg.GitHubMinCallSpacing = 0

		var childMu sync.Mutex
		var curChild *exec.Cmd
		var spawns atomic.Int32

		sup := NewSupervisor(cfg, logger, SupervisorDeps{
			PortInspector: &mockPortInspector{},
			BootPollDelay: 20 * time.Millisecond,
			StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
				cmd := newHelperCmd("sleep_alive")
				cmd.Stderr = stderr
				if err := cmd.Start(); err != nil {
					return nil, err
				}
				childMu.Lock()
				curChild = cmd
				childMu.Unlock()
				spawns.Add(1)
				return cmd, nil
			},
			StopCodespace: func(stopCtx context.Context, c Config) (int, string, error) {
				return 0, "stopped ok", nil
			},
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- sup.Run(ctx) }()

		waitUntil(t, 3*time.Second, fmt.Sprintf("session %d HEALTHY", session), func() bool {
			return sup.State() == StateHealthy
		})

		if session == 1 {
			for drop := 1; drop <= 4; drop++ {
				targetSpawns := int32(drop + 1)
				childMu.Lock()
				c := curChild
				childMu.Unlock()
				if c != nil && c.Process != nil {
					_ = c.Process.Kill()
				}
				waitUntil(t, 3*time.Second, fmt.Sprintf("drop %d auto-recovery", drop), func() bool {
					return spawns.Load() >= targetSpawns && sup.State() == StateHealthy
				})
				if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), []byte(fmt.Sprintf("soak-%d", drop)), 2*time.Second); err != nil {
					cancel()
					<-done
					t.Fatalf("drop %d post-recovery transfer failed: %v", drop, err)
				}
			}
		}

		sup.RequestShutdown(fmt.Sprintf("soak_session_%d_end", session))
		cancel()
		<-done
	}

	recs := readJSONLLog(t, logPath)
	seenSessions := make(map[string]bool)
	counts := map[string]int{}
	for _, r := range recs {
		seenSessions[r.SessionID] = true
		counts[r.Event]++
	}
	if len(seenSessions) != 2 {
		t.Fatalf("ST-07 expected 2 preserved sessions in append-only log, got %d", len(seenSessions))
	}
	if counts["SESSION_START"] != 2 || counts["SHUTDOWN_COMPLETE"] != 2 {
		t.Fatalf("ST-07 unexpected lifecycle counts: %+v", counts)
	}
	if counts["RECONNECT_COMPLETE"] < 4 {
		t.Fatalf("ST-07 expected >=4 RECONNECT_COMPLETE events, got %d", counts["RECONNECT_COMPLETE"])
	}
}

// ST-08: Dead-WAN Ctrl+C Shutdown — blackhole WAN + hanging 60s stop command; <5.5s, 0 orphans.
func TestST08_DeadWANCtrlCShutdown(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	relay := startMockBloatedRelay(t, socks.Addr(), 0, 0, 0)
	defer relay.Close()

	logPath := filepath.Join(t.TempDir(), "st08.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 1
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = relay.Port(t)
	cfg.StopOnExit = true
	cfg.StopTimeout = 2 * time.Second
	cfg.BootQualitySamples = 1

	var parentPID, grandchildPID, stopPID atomic.Int64
	var stopInvoked atomic.Bool

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 25 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("spawn_tree")
			cmd.Stderr = stderr
			stdin, err := cmd.StdinPipe()
			if err != nil {
				return nil, err
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return nil, err
			}
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			go func() {
				time.Sleep(40 * time.Millisecond)
				_, _ = io.WriteString(stdin, "GO\n")
				_ = stdin.Close()
				line, err := bufio.NewReader(stdout).ReadString('\n')
				if err == nil {
					var p, g int
					if _, serr := fmt.Sscanf(strings.TrimSpace(line), "PARENT=%d CHILD=%d", &p, &g); serr == nil {
						parentPID.Store(int64(p))
						grandchildPID.Store(int64(g))
					}
				}
			}()
			return cmd, nil
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
				return -1, "start err", err
			}
			stopPID.Store(int64(cmd.Process.Pid))
			if job != nil {
				_ = job.Assign(cmd.Process.Pid)
				defer job.Close()
			}
			err := cmd.Wait()
			return -1, "aborted after StopTimeout on dead WAN", err
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 3*time.Second, "ST-08 HEALTHY and grandchild spawned", func() bool {
		return sup.State() == StateHealthy && grandchildPID.Load() > 0
	})

	relay.SetBlackhole(true)

	sigAt := time.Now()
	sup.RequestShutdown("signal:interrupt")
	cancel()

	select {
	case <-done:
	case <-time.After(5500 * time.Millisecond):
		t.Fatal("ST-08 dead-WAN Ctrl+C shutdown exceeded 5.5s SLO")
	}
	elapsed := time.Since(sigAt)
	if elapsed >= 5500*time.Millisecond {
		t.Fatalf("ST-08 shutdown elapsed %s >= 5.5s", elapsed)
	}
	if !stopInvoked.Load() {
		t.Fatal("ST-08 stop command was NOT invoked")
	}

	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		pAlive := IsProcessAlive(int(parentPID.Load()))
		gAlive := IsProcessAlive(int(grandchildPID.Load()))
		sAlive := IsProcessAlive(int(stopPID.Load()))
		if !pAlive && !gAlive && !sAlive {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if IsProcessAlive(int(parentPID.Load())) || IsProcessAlive(int(grandchildPID.Load())) || IsProcessAlive(int(stopPID.Load())) {
		t.Fatalf("ST-08 orphan process survived: parent=%v grandchild=%v stop=%v",
			IsProcessAlive(int(parentPID.Load())),
			IsProcessAlive(int(grandchildPID.Load())),
			IsProcessAlive(int(stopPID.Load())))
	}
	t.Logf("ST-08 dead-WAN Ctrl+C full chain teardown completed in %s (0 orphans)", elapsed)
}

// ST-09: Randomized 40-Worker Mixed Workload Chaos.
func TestST09_Randomized40WorkerMixedWorkloadChaos(t *testing.T) {
	seed := testSeed(t)
	baseG := runtime.NumGoroutine()

	const dlSize = 1024 * 1024
	dlPayload := makeDeterministicPayload(dlSize, uint64(seed)^0x12345678)
	dlHash := sha256.Sum256(dlPayload)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ST-09 server listen: %v", err)
	}
	var srvWG sync.WaitGroup
	srvWG.Add(1)
	go func() {
		defer srvWG.Done()
		var connIdx atomic.Uint64
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id := connIdx.Add(1)
			srvWG.Add(1)
			go func(conn net.Conn, cid uint64) {
				defer srvWG.Done()
				defer conn.Close()
				cRNG := rand.New(rand.NewPCG(uint64(seed)+cid, cid^0xfeedface))
				br := bufio.NewReader(conn)
				cmd, err := br.ReadString('\n')
				if err != nil {
					return
				}
				switch strings.TrimSpace(cmd) {
				case "DL":
					_, _ = io.Copy(io.Discard, br)
					const chunk = 64 * 1024
					for off := 0; off < len(dlPayload); off += chunk {
						end := off + chunk
						if end > len(dlPayload) {
							end = len(dlPayload)
						}
						if _, werr := conn.Write(dlPayload[off:end]); werr != nil {
							return
						}
						if end < len(dlPayload) {
							time.Sleep(time.Duration(95+cRNG.IntN(45)) * time.Millisecond)
						}
					}
					if cw, ok := conn.(closeWriter); ok {
						_ = cw.CloseWrite()
					}
				case "PING":
					var body [64]byte
					if _, rerr := io.ReadFull(br, body[:]); rerr != nil {
						return
					}
					jitterMS := 150 + cRNG.IntN(450)
					if testing.Short() {
						jitterMS = 80 + cRNG.IntN(120)
					}
					time.Sleep(time.Duration(jitterMS) * time.Millisecond)
					_, _ = conn.Write(body[:])
					if cw, ok := conn.(closeWriter); ok {
						_ = cw.CloseWrite()
					}
				case "RST":
					for i := 0; i < 32; i++ {
						if _, werr := conn.Write(dlPayload[:8192]); werr != nil {
							return
						}
						time.Sleep(25 * time.Millisecond)
					}
				}
			}(c, id)
		}
	}()
	defer func() {
		_ = ln.Close()
		srvWG.Wait()
	}()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 40
	cfg.DialPaceInterval = 0
	cfg.IdleTimeout = 10 * time.Second
	cfg.PressureIdleTimeout = 10 * time.Second
	cfg.HalfCloseDrainTimeout = 1200 * time.Millisecond

	proxy := NewProxyServer(cfg, ln.Addr().String(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("ST-09 proxy.Start: %v", err)
	}

	const workers = 40
	var (
		dlOK     atomic.Int64
		pingOK   atomic.Int64
		abruptOK atomic.Int64
		errCh    = make(chan error, workers*4)
		wg       sync.WaitGroup
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			wRNG := rand.New(rand.NewPCG(uint64(seed)+uint64(id*37+11), uint64(id+1)))
			for iter := 0; iter < 2; iter++ {
				mode := (id + iter + wRNG.IntN(3)) % 3
				if iter == 0 {
					mode = id % 3
				}
				switch mode {
				case 0:
					c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
					if err != nil {
						errCh <- fmt.Errorf("w%d DL dial: %w", id, err)
						return
					}
					_ = c.SetDeadline(time.Now().Add(10 * time.Second))
					if _, err := io.WriteString(c, "DL\n"); err != nil {
						_ = c.Close()
						errCh <- fmt.Errorf("w%d DL write: %w", id, err)
						return
					}
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					got, err := io.ReadAll(c)
					_ = c.Close()
					if err != nil {
						errCh <- fmt.Errorf("w%d DL read: %w", id, err)
						return
					}
					if len(got) != dlSize || sha256.Sum256(got) != dlHash {
						errCh <- fmt.Errorf("w%d DL SHA-256/len mismatch: got %d want %d", id, len(got), dlSize)
						return
					}
					dlOK.Add(1)

				case 1:
					c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
					if err != nil {
						errCh <- fmt.Errorf("w%d PING dial: %w", id, err)
						return
					}
					_ = c.SetDeadline(time.Now().Add(8 * time.Second))
					msg := makeDeterministicPayload(64, wRNG.Uint64())
					if _, err := c.Write(append([]byte("PING\n"), msg...)); err != nil {
						_ = c.Close()
						errCh <- fmt.Errorf("w%d PING write: %w", id, err)
						return
					}
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					got, err := io.ReadAll(c)
					_ = c.Close()
					if err != nil || len(got) != 64 || sha256.Sum256(got) != sha256.Sum256(msg) {
						errCh <- fmt.Errorf("w%d PING mismatch: err=%v len=%d", id, err, len(got))
						return
					}
					pingOK.Add(1)

				case 2:
					c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
					if err != nil {
						errCh <- fmt.Errorf("w%d RST dial: %w", id, err)
						return
					}
					_, _ = io.WriteString(c, "RST\n")
					var sink [1024]byte
					_, _ = c.Read(sink[:])
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.SetLinger(0)
					}
					_ = c.Close()
					abruptOK.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	waitUntil(t, 3*time.Second, "ST-09 active conns drain to 0", func() bool {
		return proxy.Metrics(false).ActiveConns == 0
	})
	stats := proxy.SnapshotWindow(false)
	t.Logf("ST-09 completed: dlOK=%d pingOK=%d abruptOK=%d halfCloseClean=%d abruptErrors=%d bytesDown=%d",
		dlOK.Load(), pingOK.Load(), abruptOK.Load(), stats.HalfCloseClean, stats.AbruptErrors, stats.TotalBytesDown)

	proxy.Stop(true)
	_ = ln.Close()
	srvWG.Wait()
	assertNoGoroutineLeak(t, baseG, 6)
}

// ST-10: Rich Telemetry Verification Across Restarts.
func TestST10_RichTelemetryVerificationAcrossRestarts(t *testing.T) {
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	logPath := filepath.Join(t.TempDir(), "netshaper_history.log")

	for session := 1; session <= 2; session++ {
		logger, err := NewEventLogger(logPath)
		if err != nil {
			t.Fatalf("session %d NewEventLogger: %v", session, err)
		}

		cfg := DefaultConfig()
		cfg.PoolSize = 1
		cfg.PreflightNetHygiene = false
		cfg.LocalPort = 0
		cfg.GHPort = socks.Port(t)
		cfg.StopOnExit = true
		cfg.StopTimeout = 2 * time.Second
		cfg.ProbeInterval = 200 * time.Millisecond
		cfg.DegradedProbeInterval = 150 * time.Millisecond
		cfg.ProbeTimeout = 500 * time.Millisecond
		cfg.SummaryLogInterval = 350 * time.Millisecond
		cfg.BreakerThreshold = 5
		cfg.BreakerMinWindow = 10 * time.Second
		cfg.BootQualitySamples = 1
		cfg.GitHubMinCallSpacing = 0

		var probeCalls atomic.Int32
		sup := NewSupervisor(cfg, logger, SupervisorDeps{
			PortInspector: &mockPortInspector{},
			BootPollDelay: 20 * time.Millisecond,
			LookupWANRemote: func(pid uint32) string {
				return "20.50.80.10:443"
			},
			StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
				cmd := newHelperCmd("sleep_alive")
				cmd.Stderr = stderr
				return cmd, cmd.Start()
			},
			StopCodespace: func(stopCtx context.Context, c Config) (int, string, error) {
				return 0, fmt.Sprintf("codespace stopped cleanly (session=%d)", session), nil
			},
			ProbeFunc: func(pctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error) {
				n := probeCalls.Add(1)
				if session == 1 && n == 2 {
					return 0, errors.New("simulated transient cellular glitch")
				}
				return ProbeSOCKS5(pctx, ghAddr, target, timeout)
			},
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- sup.Run(ctx) }()

		waitUntil(t, 3*time.Second, fmt.Sprintf("ST-10 session %d HEALTHY", session), func() bool {
			return sup.State() == StateHealthy
		})

		if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), makeDeterministicPayload(16*1024, uint64(session)), 3*time.Second); err != nil {
			cancel()
			<-done
			t.Fatalf("ST-10 session %d transfer failed: %v", session, err)
		}

		if session == 1 {
			waitUntil(t, 4*time.Second, "ST-10 session 1 completes DEGRADED->HEALTHY recovery", func() bool {
				return probeCalls.Load() >= 3 && sup.State() == StateHealthy
			})
		}
		time.Sleep(450 * time.Millisecond)

		sup.RequestShutdown(fmt.Sprintf("st10_session_%d", session))
		cancel()
		<-done
	}

	recs := readJSONLLog(t, logPath)
	sessions := map[string]bool{}
	var (
		sawBootReady    bool
		sawSummary      bool
		sawRecovery     bool
		shutdownCount   int
		summaryFieldsOK bool
	)

	requiredSummaryKeys := []string{
		"active_conns", "peak_conns_window", "semaphore_rejects",
		"goroutines", "heap_alloc_mb", "gc_count", "dropped_logs",
		"bytes_up_window", "bytes_down_window", "throughput_up_kbps", "throughput_down_kbps",
		"total_conns_window", "dial_ok", "dial_fail", "dial_rtt_p50_ms", "dial_rtt_p95_ms",
		"half_close_clean", "drain_timeouts", "idle_reaps", "pressure_reaps", "abrupt_errors",
		"state", "probe_ok_window", "probe_fail_window", "probe_skipped_active_traffic",
		"probe_rtt_min_ms", "probe_rtt_p50_ms", "probe_rtt_p95_ms", "probe_rtt_max_ms",
		"gh_wan_remote", "gh_api_calls_last_5m", "gh_api_calls_last_hr",
	}

	for _, r := range recs {
		sessions[r.SessionID] = true
		switch r.Event {
		case "BOOT_READY":
			sawBootReady = true
			if r.Fields["gh_wan_remote"] != "20.50.80.10:443" {
				t.Fatalf("ST-10 BOOT_READY missing gh_wan_remote: %+v", r.Fields)
			}
			for _, bk := range []string{"gh_pid", "boot_phase_port_open_ms", "boot_phase_socks5_ms", "boot_quality_p50_ms", "boot_quality_jitter_ms", "child_ecoqos_tuned"} {
				if _, ok := r.Fields[bk]; !ok {
					t.Fatalf("ST-10 BOOT_READY missing %s: %+v", bk, r.Fields)
				}
			}
		case "PROBE_SUMMARY":
			sawSummary = true
			missing := []string{}
			for _, k := range requiredSummaryKeys {
				if _, ok := r.Fields[k]; !ok {
					missing = append(missing, k)
				}
			}
			if len(missing) > 0 {
				t.Fatalf("ST-10 PROBE_SUMMARY missing required fields %v: %+v", missing, r.Fields)
			}
			if r.Fields["gh_wan_remote"] != "20.50.80.10:443" {
				t.Fatalf("ST-10 PROBE_SUMMARY bad gh_wan_remote: %+v", r.Fields)
			}
			summaryFieldsOK = true
		case "RECOVERY_FROM_DEGRADED":
			sawRecovery = true
			if _, ok := r.Fields["degraded_duration_ms"]; !ok {
				t.Fatalf("ST-10 RECOVERY_FROM_DEGRADED missing degraded_duration_ms: %+v", r.Fields)
			}
			if _, ok := r.Fields["recovery_probe_rtt_ms"]; !ok {
				t.Fatalf("ST-10 RECOVERY_FROM_DEGRADED missing recovery_probe_rtt_ms: %+v", r.Fields)
			}
		case "SHUTDOWN_COMPLETE":
			shutdownCount++
			out, _ := r.Fields["stop_output"].(string)
			if !strings.Contains(out, "codespace stopped cleanly") {
				t.Fatalf("ST-10 SHUTDOWN_COMPLETE missing stop_output: %+v", r.Fields)
			}
			for _, k := range []string{"total_bytes_up", "total_bytes_down", "total_reconnects", "session_uptime_ms"} {
				if _, ok := r.Fields[k]; !ok {
					t.Fatalf("ST-10 SHUTDOWN_COMPLETE missing %s: %+v", k, r.Fields)
				}
			}
		}
	}

	if len(sessions) != 2 {
		t.Fatalf("ST-10 expected 2 preserved sessions in append-only log, got %d", len(sessions))
	}
	if !sawBootReady || !sawSummary || !summaryFieldsOK || !sawRecovery || shutdownCount != 2 {
		t.Fatalf("ST-10 telemetry incomplete: boot=%v summary=%v summaryOK=%v recovery=%v shutdowns=%d",
			sawBootReady, sawSummary, summaryFieldsOK, sawRecovery, shutdownCount)
	}
}
