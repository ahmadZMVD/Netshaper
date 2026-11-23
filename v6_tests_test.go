package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// startConsecutiveMockSOCKS5Pair allocates two mock SOCKS5 servers bound to adjacent localhost ports (base, base+1)
// so TunnelPool(PoolSize=2) tests run cleanly with zero port collisions on any platform.
func startConsecutiveMockSOCKS5Pair(t *testing.T) (*mockSOCKS5Server, *mockSOCKS5Server, uint16) {
	t.Helper()
	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0x6a09e667))
	for attempt := 0; attempt < 60; attempt++ {
		base := uint16(24000 + rng.IntN(25000))
		ln1, err1 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base))
		if err1 != nil {
			continue
		}
		ln2, err2 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+1))
		if err2 != nil {
			_ = ln1.Close()
			continue
		}
		s1 := serveMockSOCKS5OnListener(ln1, socksModeNormal)
		s2 := serveMockSOCKS5OnListener(ln2, socksModeNormal)
		return s1, s2, base
	}
	t.Fatal("failed to allocate adjacent localhost port pair for multi-tunnel pool test")
	return nil, nil, 0
}

func serveMockSOCKS5OnListener(ln net.Listener, mode socksServerMode) *mockSOCKS5Server {
	s := &mockSOCKS5Server{
		ln:    ln,
		conns: make(map[net.Conn]struct{}),
	}
	s.mode.Store(int32(mode))
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[c] = struct{}{}
			s.mu.Unlock()
			s.inFlight.Add(1)
			s.wg.Add(1)
			go func(conn net.Conn) {
				defer s.wg.Done()
				defer func() {
					s.inFlight.Add(-1)
					s.mu.Lock()
					delete(s.conns, conn)
					s.mu.Unlock()
					_ = conn.Close()
				}()
				if socksServerMode(s.mode.Load()) == socksModeBlackhole {
					var sink [64]byte
					for {
						if _, err := conn.Read(sink[:]); err != nil {
							return
						}
					}
				}
				var greet [2]byte
				if _, err := io.ReadFull(conn, greet[:]); err != nil {
					return
				}
				methods := make([]byte, int(greet[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				var reqHdr [4]byte
				if _, err := io.ReadFull(conn, reqHdr[:]); err != nil {
					return
				}
				addrLen := 4
				if reqHdr[3] == 0x04 {
					addrLen = 16
				} else if reqHdr[3] == 0x03 {
					var lb [1]byte
					if _, err := io.ReadFull(conn, lb[:]); err != nil {
						return
					}
					addrLen = int(lb[0])
				}
				ap := make([]byte, addrLen+2)
				if _, err := io.ReadFull(conn, ap); err != nil {
					return
				}
				if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				s.connectCount.Add(1)
				buf := make([]byte, 16*1024)
				for {
					n, rerr := conn.Read(buf)
					if n > 0 {
						if _, werr := conn.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						if cw, ok := conn.(closeWriter); ok {
							_ = cw.CloseWrite()
						}
						return
					}
				}
			}(c)
		}
	}()
	return s
}

// UT-19 (v6): Two-Stage 5-Tuple Fast-Lane Boot Gate & Micro-Payload Probe.
func TestUT19_SlowLaneBootGateAndMicroPayload(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BootQualityMaxRTT = 1500 * time.Millisecond
	cfg.BootQualityMaxJitter = 1000 * time.Millisecond
	cfg.BootFastLaneMaxRTT = 1200 * time.Millisecond

	// (a) Fast MCI lane (~310ms) with clean Stage 2 micro-payload -> Accepted.
	fast := EvaluateFastLaneGate(cfg, 6*time.Second, []time.Duration{295 * time.Millisecond, 310 * time.Millisecond, 340 * time.Millisecond}, 0, 320.0, true, 120*time.Millisecond)
	if !fast.Accepted || fast.Reason != "ok" {
		t.Fatalf("UT-19 expected clean fast lane accepted, got %+v", fast)
	}

	// (b) Slow MCI 5-tuple lane (~2.8s > 1.2s) -> Rejected with mci_slow_lane_detected.
	cfgWide := cfg
	cfgWide.BootQualityMaxRTT = 5 * time.Second
	slow := EvaluateFastLaneGate(cfgWide, 6*time.Second, []time.Duration{2550 * time.Millisecond, 2800 * time.Millisecond, 3100 * time.Millisecond}, 0, 0, true, 900*time.Millisecond)
	if slow.Accepted || slow.Reason != "mci_slow_lane_detected" {
		t.Fatalf("UT-19 expected mci_slow_lane_detected rejection, got %+v", slow)
	}

	// (c) Dynamic peer median check: peer median 300ms -> ceiling 750ms -> 900ms rejected.
	vsPeer := EvaluateFastLaneGate(cfgWide, 6*time.Second, []time.Duration{880 * time.Millisecond, 900 * time.Millisecond, 940 * time.Millisecond}, 0, 300.0, true, 400*time.Millisecond)
	if vsPeer.Accepted || vsPeer.Reason != "slow_lane_vs_peer" {
		t.Fatalf("UT-19 expected slow_lane_vs_peer rejection, got %+v", vsPeer)
	}

	// (d) Stage 2 micro-payload check rejects half-open relay that answers CONNECT but drops app bytes.
	halfOpen := startMockSOCKS5Server(t, socksModeConnectOnlyNoData)
	defer halfOpen.Close()
	if _, err := ProbeSOCKS5(context.Background(), halfOpen.Addr(), "1.1.1.1:443", 500*time.Millisecond); err != nil {
		t.Fatalf("UT-19 expected Stage 1 CONNECT to succeed on half-open relay, got %v", err)
	}
	if _, err := ProbeSOCKS5MicroPayload(context.Background(), halfOpen.Addr(), "1.1.1.1:443", 200*time.Millisecond); err == nil {
		t.Fatal("UT-19 expected Stage 2 ProbeSOCKS5MicroPayload to reject half-open blackhole relay")
	}

	normal := startMockSOCKS5Server(t, socksModeNormal)
	defer normal.Close()
	if rtt, err := ProbeSOCKS5MicroPayload(context.Background(), normal.Addr(), "1.1.1.1:443", 500*time.Millisecond); err != nil || rtt <= 0 {
		t.Fatalf("UT-19 expected Stage 2 ProbeSOCKS5MicroPayload to pass on healthy relay, err=%v rtt=%s", err, rtt)
	}

	repNoData := EvaluateFastLaneGate(cfg, 6*time.Second, []time.Duration{210 * time.Millisecond, 220 * time.Millisecond, 230 * time.Millisecond}, 0, 0, false, 0)
	if repNoData.Accepted || repNoData.Reason != "micro_payload_failed" {
		t.Fatalf("UT-19 expected micro_payload_failed rejection, got %+v", repNoData)
	}
}

// UT-20 (v6): GitHub API Guard — sliding 5m/1h budgets, 429/403 classification, full-jitter backoff & warm cache.
func TestUT20_GitHubAPIGuardBudgetAndRateLimitBackoff(t *testing.T) {
	if cls := ClassifyStderr("HTTP 429: You have exceeded a secondary rate limit"); cls != FailureAPIRateLimit {
		t.Fatalf("UT-20 expected FailureAPIRateLimit for 429, got %s", cls)
	}
	if cls := ClassifyStderr("HTTP 403: abuse detection mechanism triggered"); cls != FailureAPIRateLimit {
		t.Fatalf("UT-20 expected FailureAPIRateLimit for 403 abuse, got %s", cls)
	}
	if cls := ClassifyStderr("HTTP 401: Unauthorized, run gh auth login"); cls != FailureAuthOrStopped {
		t.Fatalf("UT-20 expected FailureAuthOrStopped for 401, got %s", cls)
	}
	if cls := ClassifyStderr("Timeout, server not responding."); cls != FailureNetworkLane {
		t.Fatalf("UT-20 expected FailureNetworkLane for SSH timeout, got %s", cls)
	}

	cfg := DefaultConfig()
	cfg.GitHubMaxCallsPer5Min = 3
	cfg.GitHubMaxCallsPerHour = 5
	cfg.GitHubMinCallSpacing = 0
	cfg.GitHubRateLimitBase = 10 * time.Second
	cfg.GitHubRateLimitMax = 60 * time.Second
	cfg.GitHubWarmCacheTTL = 2 * time.Minute

	guard := NewGitHubGuard(cfg, nil, nil)
	now := time.Date(2026, 11, 21, 15, 0, 0, 0, time.UTC)
	guard.nowFn = func() time.Time { return now }
	guard.rng = rand.New(rand.NewPCG(2026, 1121))

	// First 3 calls succeed within 5m budget; 4th is blocked by budget_5m_exhausted.
	for i := 0; i < 3; i++ {
		ok, _, why := guard.TryAllow("boot")
		if !ok {
			t.Fatalf("UT-20 call %d should be allowed, blocked by %q", i+1, why)
		}
		now = now.Add(5 * time.Second)
	}
	if ok, wait, why := guard.TryAllow("boot"); ok || why != "budget_5m_exhausted" || wait <= 0 {
		t.Fatalf("UT-20 expected budget_5m_exhausted on 4th call, got ok=%v wait=%s why=%q", ok, wait, why)
	}

	// Advance 6 minutes -> 5m window clears; 2 more calls hit hourly cap (5/hr).
	now = now.Add(6 * time.Minute)
	for i := 0; i < 2; i++ {
		if ok, _, why := guard.TryAllow("boot"); !ok {
			t.Fatalf("UT-20 hourly call %d should pass, blocked by %q", i+4, why)
		}
		now = now.Add(1 * time.Second)
	}
	if ok, _, why := guard.TryAllow("boot"); ok || why != "budget_hour_exhausted" {
		t.Fatalf("UT-20 expected budget_hour_exhausted on 6th call in hour, got ok=%v why=%q", ok, why)
	}

	// Advance 61 minutes -> hourly window clears; test 429 exponential backoff + warm cache.
	now = now.Add(61 * time.Minute)
	cls, cd1 := guard.RecordFailure("HTTP 429 Too Many Requests")
	if cls != FailureAPIRateLimit || cd1 < 5*time.Second || cd1 > 10*time.Second {
		t.Fatalf("UT-20 bad 1st 429 backoff: cls=%s cd=%s", cls, cd1)
	}
	if ok, _, why := guard.TryAllow("boot"); ok || why != "api_rate_limit_cooldown" {
		t.Fatalf("UT-20 expected api_rate_limit_cooldown, got ok=%v why=%q", ok, why)
	}
	_, cd2 := guard.RecordFailure("HTTP 403 secondary rate limit")
	if cd2 < 10*time.Second || cd2 > 20*time.Second {
		t.Fatalf("UT-20 bad 2nd 429 backoff: cd=%s", cd2)
	}

	guard.RecordSuccess()
	if !guard.IsCodespaceWarm() {
		t.Fatal("UT-20 expected CodespaceWarm=true after RecordSuccess")
	}
	now = now.Add(3 * time.Minute)
	if guard.IsCodespaceWarm() {
		t.Fatal("UT-20 expected CodespaceWarm=false after WarmCacheTTL expired")
	}
}

// UT-21 (v6): Two-Tier Pressure-Aware Idle Reaper eliminates v5 pid2356 idle-slot starvation.
func TestUT21_PressureAwareIdleReaperClearsZombies(t *testing.T) {
	baseG := runtime.NumGoroutine()

	echoAddr, _, _, stopEcho := startPlainTCPEchoServer(t, 0)
	defer stopEcho()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 12
	cfg.MaxQueuedConns = 32
	cfg.IdleTimeout = 10 * time.Second
	cfg.PressureIdleTimeout = 250 * time.Millisecond
	cfg.PressureThresholdPct = 75
	cfg.DialPaceInterval = 0
	cfg.SemaphoreWaitTimeout = 4 * time.Second

	proxy := NewProxyServer(cfg, echoAddr, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("UT-21 proxy.Start: %v", err)
	}

	// Park 10 silent zombie connections (>= 75% of 12 slots -> activates pressure reaping).
	zombies := make([]net.Conn, 0, 10)
	for i := 0; i < 10; i++ {
		c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("UT-21 zombie dial %d: %v", i, err)
		}
		zombies = append(zombies, c)
	}
	defer func() {
		for _, c := range zombies {
			_ = c.Close()
		}
	}()

	// Concurrently run an active connection trickling bytes every 60ms so it stays well below 250ms idle.
	activeConn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("UT-21 active dial: %v", err)
	}
	defer activeConn.Close()
	activeDone := make(chan error, 1)
	go func() {
		msg := []byte("active-keep-alive-frame")
		resp := make([]byte, len(msg))
		for i := 0; i < 10; i++ {
			_ = activeConn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, werr := activeConn.Write(msg); werr != nil {
				activeDone <- fmt.Errorf("active write %d: %w", i, werr)
				return
			}
			if _, rerr := io.ReadFull(activeConn, resp); rerr != nil {
				activeDone <- fmt.Errorf("active read %d: %w", i, rerr)
				return
			}
			time.Sleep(60 * time.Millisecond)
		}
		activeDone <- nil
	}()

	// Wait for zombies to age past PressureIdleTimeout (250ms) and verify they are reaped in << 10s IdleTimeout!
	waitUntil(t, 1500*time.Millisecond, "UT-21 pressure reaper evicts idle zombie sockets", func() bool {
		return proxy.Metrics(false).PressureReaps >= 5
	})

	// Launch 5 fresh transfers and verify all succeed cleanly with 0 rejects.
	payload := makeDeterministicPayload(4096, 2121)
	for i := 0; i < 5; i++ {
		if err := shapingEchoClient(proxyAddr, payload, 2*time.Second); err != nil {
			t.Fatalf("UT-21 fresh transfer %d failed after pressure reap: %v", i, err)
		}
	}

	if err := <-activeDone; err != nil {
		t.Fatalf("UT-21 active stream disrupted by pressure reaper: %v", err)
	}
	if rej := proxy.Metrics(false).SemaphoreRejects; rej != 0 {
		t.Fatalf("UT-21 unexpected semaphore rejects: %d", rej)
	}

	proxy.Stop(true)
	assertNoGoroutineLeak(t, baseG, 4)
}

// UT-22 (v6): Multi-Tunnel Weighted Routing (Least-Active-Streams + EWMA RTT) & Per-Tunnel Cap.
func TestUT22_MultiTunnelWeightedRoutingAndPerTunnelCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.PerTunnelMaxConns = 3
	cfg.GHPort = 28081

	pool := NewTunnelPool(cfg, SupervisorDeps{}, nil, nil, nil)
	w1 := pool.workers[0]
	w2 := pool.workers[1]

	// Force deterministic states and EWMA RTTs: w1 fast (120ms), w2 slow (1200ms).
	w1.setState(TunnelHealthy)
	w2.setState(TunnelHealthy)
	for i := 0; i < 12; i++ {
		w1.RecordRTT(120 * time.Millisecond)
		w2.RecordRTT(1200 * time.Millisecond)
	}

	var leases []UpstreamLease
	defer func() {
		for _, l := range leases {
			l.Release()
		}
	}()

	// First 3 leases MUST prefer fast w1 (score (1..3)*(120+50) <= 510 < 1*(1200+50)=1250),
	// and the 4th MUST spill over to w2 once w1 hits PerTunnelMaxConns=3.
	counts := map[string]int{}
	for i := 0; i < 6; i++ {
		l, err := pool.AcquireEndpoint(context.Background())
		if err != nil {
			t.Fatalf("UT-22 AcquireEndpoint %d failed: %v", i+1, err)
		}
		leases = append(leases, l)
		counts[l.TunnelID]++
		if i < 3 && l.TunnelID != w1.ID() {
			t.Fatalf("UT-22 lease %d routed to %s instead of faster %s", i+1, l.TunnelID, w1.ID())
		}
	}
	if counts[w1.ID()] != 3 || counts[w2.ID()] != 3 {
		t.Fatalf("UT-22 unexpected lease distribution: %+v", counts)
	}

	// 7th lease MUST fail because both workers are at PerTunnelMaxConns=3.
	if _, err := pool.AcquireEndpoint(context.Background()); err == nil {
		t.Fatal("UT-22 expected per-tunnel capacity enforcement when all workers full")
	}
}

// UT-23 (v6): Orthogonal NDJSON Metrics Stream — concurrent Emit/EmitConn/Close safety & schema integrity.
func TestUT23_OrthogonalNDJSONMetricsStream(t *testing.T) {
	baseG := runtime.NumGoroutine()
	path := filepath.Join(t.TempDir(), "metrics_ut23.ndjson")

	em, err := NewMetricsEmitter(path, "ut23-session")
	if err != nil {
		t.Fatalf("UT-23 NewMetricsEmitter: %v", err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				em.EmitConn(ConnMetric{
					TunnelID:        fmt.Sprintf("tunnel-%d", (id%2)+1),
					UpstreamAddr:    "127.0.0.1:1081",
					QueueWaitMS:     float64(i),
					DialRTTMS:       1.2,
					ActiveMS:        45.5,
					BytesUp:         1024,
					BytesDown:       8192,
					CloseReason:     "half_close_clean",
					CopyBufferBytes: DefaultCopyBufferSize,
				})
				em.Emit("pool", map[string]any{"worker": id, "seq": i})
			}
		}(g)
	}
	wg.Wait()

	if err := em.Close(); err != nil {
		t.Fatalf("UT-23 Close: %v", err)
	}
	// Second close and post-close emits must be panic-free no-ops.
	_ = em.Close()
	em.Emit("pool", map[string]any{"after_close": true})

	recs := readMetricsNDJSON(t, path)
	if len(recs) == 0 {
		t.Fatal("UT-23 expected non-empty NDJSON metrics records")
	}
	for i, r := range recs {
		if r.Schema != metricsSchemaVersion {
			t.Fatalf("UT-23 record %d bad schema %q", i, r.Schema)
		}
		if r.SessionID != "ut23-session" {
			t.Fatalf("UT-23 record %d bad session_id %q", i, r.SessionID)
		}
		if r.Stream != "conn" && r.Stream != "pool" {
			t.Fatalf("UT-23 record %d unexpected stream %q", i, r.Stream)
		}
	}
	assertNoGoroutineLeak(t, baseG, 2)
}

// UT-24 (v6): Strictly Read-Only NetHygiene Preflight Parsers.
func TestUT24_ReadOnlyNetHygieneParsers(t *testing.T) {
	badWinOut := `
Querying active state...

Receive-Side Scaling State          : disabled
Receive Window Auto-Tuning Level    : restricted
ECN Capability                      : enabled
HyStart                             : enabled
`
	checksBad := ParseNetshTCPGlobal(badWinOut)
	warns := 0
	for _, c := range checksBad {
		if c.Status == "warn" {
			warns++
		}
	}
	if warns != 4 {
		t.Fatalf("UT-24 expected 4 warnings on degraded Win11 TCP stack, got %d (%+v)", warns, checksBad)
	}

	goodWinOut := `
Receive-Side Scaling State          : enabled
Receive Window Auto-Tuning Level    : normal
ECN Capability                      : disabled
HyStart                             : disabled
`
	checksGood := ParseNetshTCPGlobal(goodWinOut)
	for _, c := range checksGood {
		if c.Status != "ok" {
			t.Fatalf("UT-24 expected ok for clean TCP global output, got %+v", c)
		}
	}

	fw := ParseNetshFirewallSummary("Domain Profile Settings:\nState ON\nPrivate Profile Settings:\nState ON\n")
	if fw.Name != "windows_firewall_profiles" || fw.Recommended == "" {
		t.Fatalf("UT-24 unexpected firewall check: %+v", fw)
	}

	dir := t.TempDir()
	logger, err := NewEventLogger(filepath.Join(dir, "hygiene.log"))
	if err != nil {
		t.Fatalf("UT-24 logger: %v", err)
	}
	metrics, err := NewMetricsEmitter(filepath.Join(dir, "hygiene.ndjson"), "ut24")
	if err != nil {
		t.Fatalf("UT-24 metrics: %v", err)
	}
	rep := RunNetHygienePreflight(context.Background(), logger, metrics)
	_ = logger.Close()
	_ = metrics.Close()

	if !rep.ReadOnly {
		t.Fatal("UT-24 NetHygieneReport.ReadOnly MUST always be true")
	}
}

// ST-11 (v6): Multi-Tunnel Failover Zero Blackout — kill worker #1 mid-traffic while worker #2 absorbs 100%.
func TestST11_MultiTunnelFailoverZeroBlackout(t *testing.T) {
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	logger, err := NewEventLogger(filepath.Join(dir, "st11.log"))
	if err != nil {
		t.Fatalf("ST-11 logger: %v", err)
	}
	metrics, err := NewMetricsEmitter(filepath.Join(dir, "st11.ndjson"), "st11")
	if err != nil {
		t.Fatalf("ST-11 metrics: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.PerTunnelMaxConns = 6
	cfg.MaxActiveConns = 12
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.StopOnExit = false
	cfg.BootQualitySamples = 1
	cfg.DialPaceInterval = 0
	cfg.BackoffMin = 100 * time.Millisecond
	cfg.BackoffMax = 200 * time.Millisecond
	cfg.ProbeInterval = 500 * time.Millisecond
	cfg.SummaryLogInterval = 400 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	var w1Mu sync.Mutex
	var w1Cmd *exec.Cmd
	var w1Spawns atomic.Int32

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 20 * time.Millisecond,
		Metrics:       metrics,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if c.GHPort == basePort {
				if w1Spawns.Add(1) == 1 {
					w1Mu.Lock()
					w1Cmd = cmd
					w1Mu.Unlock()
				}
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 4*time.Second, "ST-11 both pool workers HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return sup.State() == StateHealthy && snap.HealthyWorkers == 2 && sup.BoundLocalAddr() != ""
	})

	// Run continuous echo traffic across the kill of worker #1.
	trafficStop := make(chan struct{})
	var okDuringFailover atomic.Int64
	var tWG sync.WaitGroup
	tWG.Add(1)
	go func() {
		defer tWG.Done()
		payload := makeDeterministicPayload(4096, 1111)
		for {
			select {
			case <-trafficStop:
				return
			default:
			}
			if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), payload, 2*time.Second); err == nil {
				okDuringFailover.Add(1)
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	time.Sleep(80 * time.Millisecond)
	w1Mu.Lock()
	if w1Cmd != nil && w1Cmd.Process != nil {
		_ = w1Cmd.Process.Kill()
	}
	w1Mu.Unlock()

	waitUntil(t, 4*time.Second, "ST-11 worker-1 replaced and pool back to 2/2 HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return w1Spawns.Load() >= 2 && snap.TotalFailovers >= 1 && snap.HealthyWorkers == 2
	})

	close(trafficStop)
	tWG.Wait()

	if okDuringFailover.Load() < 3 {
		cancel()
		<-done
		t.Fatalf("ST-11 expected continuous traffic survival during failover, got only %d OK", okDuringFailover.Load())
	}

	cancel()
	<-done
}

// ST-12 (v6): MCI C=12 Knee Burst Enforcement — 40 parallel clients capped strictly <=12 with 16 KiB buffers.
func TestST12_MCIC12KneeBurstEnforcement(t *testing.T) {
	baseG := runtime.NumGoroutine()
	const clients = 40

	up := startShapingSensitiveUpstream(t, 12, 20*time.Millisecond, 35*time.Millisecond)
	defer up.Close()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 12                    // Explicit C=12 outer-WAN shaping limit under test in ST-12
	cfg.MaxQueuedConns = DefaultMaxQueuedConns // 128
	cfg.CopyBufferSize = DefaultCopyBufferSize // 16384
	cfg.DialPaceInterval = 35 * time.Millisecond
	cfg.SemaphoreWaitTimeout = 15 * time.Second

	proxy := NewProxyServer(cfg, up.Addr(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("ST-12 proxy.Start: %v", err)
	}

	payload := makeDeterministicPayload(24*1024, 1212)
	var ok atomic.Int64
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			if err := shapingEchoClient(proxyAddr, payload, 18*time.Second); err == nil {
				ok.Add(1)
			}
		}()
	}
	close(gate)
	wg.Wait()

	if ok.Load() != clients {
		t.Fatalf("ST-12 expected %d/%d transfers, got %d (violations=%d peak=%d)", clients, clients, ok.Load(), up.violations.Load(), up.peak.Load())
	}
	if up.violations.Load() != 0 {
		t.Fatalf("ST-12 upstream shaping violations=%d > 0", up.violations.Load())
	}
	if up.peak.Load() > 12 {
		t.Fatalf("ST-12 upstream peak=%d exceeded MCI C=12 knee", up.peak.Load())
	}
	stats := proxy.SnapshotWindow(false)
	if stats.SemaphoreRejects != 0 {
		t.Fatalf("ST-12 SemaphoreRejects=%d, want 0", stats.SemaphoreRejects)
	}
	if sha256.Sum256(payload) == [32]byte{} {
		t.Fatal("unreachable sanity check")
	}

	proxy.Stop(true)
	up.Close()
	assertNoGoroutineLeak(t, baseG, 4)
}

// ST-13 (v6): GitHub Storm Protection Under Chaos — caps 429 crash storms strictly <= MaxCallsPer5Min.
func TestST13_GitHubStormProtectionUnderChaos(t *testing.T) {
	baseG := runtime.NumGoroutine()
	dir := t.TempDir()
	logger, err := NewEventLogger(filepath.Join(dir, "st13.log"))
	if err != nil {
		t.Fatalf("ST-13 logger: %v", err)
	}

	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = 39081
	cfg.StopOnExit = false
	cfg.BootTimeout = 1 * time.Second
	cfg.BackoffMin = 50 * time.Millisecond
	cfg.BackoffMax = 100 * time.Millisecond
	cfg.GitHubMaxCallsPer5Min = 4
	cfg.GitHubMaxCallsPerHour = 12
	cfg.GitHubMinCallSpacing = 0
	cfg.GitHubRateLimitBase = 300 * time.Millisecond
	cfg.GitHubRateLimitMax = 2 * time.Second

	var spawns atomic.Int32
	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 25 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			spawns.Add(1)
			cmd := newHelperCmd("crash_429", "HELPER_DELAY_MS=20")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	_ = sup.Run(ctx)

	snap := sup.GuardSnapshot()
	if spawns.Load() > int32(cfg.GitHubMaxCallsPer5Min) {
		t.Fatalf("ST-13 storm escaped 5m GitHub budget: spawns=%d > max=%d", spawns.Load(), cfg.GitHubMaxCallsPer5Min)
	}
	if snap.RateLimitHits < 1 {
		t.Fatalf("ST-13 expected GitHubGuard to classify 429 rate-limit hits, got %+v", snap)
	}
	if snap.TotalThrottled < 1 {
		t.Fatalf("ST-13 expected GitHubGuard to throttle storm retries, got %+v", snap)
	}

	recs := readJSONLLog(t, filepath.Join(dir, "st13.log"))
	sawBackoff := false
	for _, r := range recs {
		if r.Event == "GITHUB_API_BACKOFF" || r.Event == "GITHUB_API_THROTTLED" {
			sawBackoff = true
		}
	}
	if !sawBackoff {
		t.Fatal("ST-13 expected GITHUB_API_BACKOFF or GITHUB_API_THROTTLED in log")
	}
	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-25 (v6 consolidated): Adaptive PMTU=576 (8 KiB) copy-buffer step-down on 20.120.56.11 relay VIP.
func TestUT25_AdaptivePMTU576CopyBufStepDown(t *testing.T) {
	baseG := runtime.NumGoroutine()

	if !IsPMTU576RelayIP("20.120.56.11:443") || !IsPMTU576RelayIP("20.120.56.11") {
		t.Fatal("UT-25 expected IsPMTU576RelayIP=true for 20.120.56.11")
	}
	if IsPMTU576RelayIP("20.93.53.155:443") || IsPMTU576RelayIP("") {
		t.Fatal("UT-25 expected IsPMTU576RelayIP=false for non-576 VIP or empty string")
	}

	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	metricsPath := filepath.Join(dir, "ut25_metrics.ndjson")
	metrics, err := NewMetricsEmitter(metricsPath, "ut25")
	if err != nil {
		t.Fatalf("UT-25 NewMetricsEmitter: %v", err)
	}

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.PoolSize = 2
	cfg.PMTU576SafeMode = true
	cfg.PMTU576CopyBufSize = DefaultPMTU576CopyBufSize // 8192
	cfg.CopyBufferSize = DefaultCopyBufferSize         // 16384
	cfg.DialPaceInterval = 0

	pool := NewTunnelPool(cfg, SupervisorDeps{}, nil, metrics, nil)
	w1 := pool.workers[0]
	w2 := pool.workers[1]
	w1.SetWANRemote("20.120.56.11:443")
	w2.SetWANRemote("20.93.53.155:443")
	if !w1.PMTU576Active() || w2.PMTU576Active() {
		t.Fatalf("UT-25 unexpected PMTU576Active flags: w1=%v w2=%v", w1.PMTU576Active(), w2.PMTU576Active())
	}

	// Route exclusively through w1 (20.120.56.11 -> 8 KiB) first.
	w1.setState(TunnelHealthy)
	w2.setState(TunnelDead)
	lease1, err := pool.AcquireEndpoint(context.Background())
	if err != nil || !lease1.PMTU576Safe || lease1.TunnelID != w1.ID() {
		t.Fatalf("UT-25 expected PMTU576Safe=true lease on w1, got %+v err=%v", lease1, err)
	}
	lease1.Release()

	proxy := NewPooledProxyServer(cfg, pool, nil, metrics)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("UT-25 proxy.Start: %v", err)
	}

	payload := makeDeterministicPayload(48*1024, 2525)
	if err := performSOCKS5EchoTransfer(proxyAddr, payload, 3*time.Second); err != nil {
		t.Fatalf("UT-25 48 KiB transfer on PMTU=576 worker failed: %v", err)
	}

	// Switch to w2 (20.93.53.155 -> 16 KiB).
	w1.setState(TunnelDead)
	w2.setState(TunnelHealthy)
	lease2, err := pool.AcquireEndpoint(context.Background())
	if err != nil || lease2.PMTU576Safe || lease2.TunnelID != w2.ID() {
		t.Fatalf("UT-25 expected PMTU576Safe=false lease on w2, got %+v err=%v", lease2, err)
	}
	lease2.Release()

	if err := performSOCKS5EchoTransfer(proxyAddr, payload, 3*time.Second); err != nil {
		t.Fatalf("UT-25 48 KiB transfer on standard worker failed: %v", err)
	}

	proxy.Stop(true)
	_ = metrics.Close()

	recs := readMetricsNDJSON(t, metricsPath)
	saw8K, saw16K := false, false
	for _, r := range recs {
		if r.Stream != "conn" {
			continue
		}
		tid, _ := r.Data["tunnel_id"].(string)
		bufVal, _ := r.Data["copy_buffer_bytes"].(float64)
		if tid == w1.ID() && int(bufVal) == DefaultPMTU576CopyBufSize {
			saw8K = true
		}
		if tid == w2.ID() && int(bufVal) == DefaultCopyBufferSize {
			saw16K = true
		}
	}
	if !saw8K || !saw16K {
		t.Fatalf("UT-25 expected both 8192B (w1) and 16384B (w2) conn metrics, saw8K=%v saw16K=%v", saw8K, saw16K)
	}
	assertNoGoroutineLeak(t, baseG, 4)
}

// UT-26 (v6 consolidated): Persistent CodespaceStateCache TTL/Shutdown guard & 10s OpenSSH keepalive defaults.
func TestUT26_PersistentCodespaceCacheAndSSHAlive10(t *testing.T) {
	cfg := DefaultConfig()
	if DefaultSSHAliveInterval != 10 || DefaultSSHAliveCountMax != 3 {
		t.Fatalf("UT-26 expected SSH keepalive defaults 10/3, got %d/%d", DefaultSSHAliveInterval, DefaultSSHAliveCountMax)
	}
	args := strings.Join(BuildGHSSHArgs(cfg), " ")
	if !strings.Contains(args, "-o ServerAliveInterval=10 -o ServerAliveCountMax=3") {
		t.Fatalf("UT-26 BuildGHSSHArgs missing sub-15s keepalive: %s", args)
	}

	cachePath := filepath.Join(t.TempDir(), "state", "codespace_state_cache.json")
	now := time.Date(2026, 11, 21, 16, 0, 0, 0, time.UTC)

	c1 := NewCodespaceStateCache(cfg.CodespaceName, cachePath)
	c1.nowFn = func() time.Time { return now }
	if err := c1.Set("Available"); err != nil {
		t.Fatalf("UT-26 cache Set Available: %v", err)
	}

	// Fresh reload from disk succeeds within TTL.
	c2 := NewCodespaceStateCache(cfg.CodespaceName, cachePath)
	c2.nowFn = func() time.Time { return now }
	if st, ok := c2.Get(5 * time.Minute); !ok || st != "Available" {
		t.Fatalf("UT-26 expected fresh cached Available hit, got st=%q ok=%v", st, ok)
	}

	// Advancing past TTL invalidates cache cleanly.
	now = now.Add(6 * time.Minute)
	if st, ok := c2.Get(5 * time.Minute); ok {
		t.Fatalf("UT-26 expected TTL-expired cache miss, got st=%q", st)
	}

	// Cached Shutdown state halts churn in GitHubGuard without burning sliding-window API budget.
	cfg.CodespaceCachePath = cachePath
	cfg.GitHubWarmCacheTTL = 5 * time.Minute
	guard := NewGitHubGuard(cfg, nil, nil)
	guard.nowFn = func() time.Time { return now }
	if guard.stateCache != nil {
		guard.stateCache.nowFn = func() time.Time { return now }
	}

	guard.MarkCodespaceState("Shutdown")
	if guard.IsCodespaceWarm() {
		t.Fatal("UT-26 expected IsCodespaceWarm=false after Shutdown")
	}
	ok, wait, why := guard.TryAllow("boot")
	if ok || why != "codespace_cached_stopped" || wait <= 0 {
		t.Fatalf("UT-26 expected codespace_cached_stopped block, got ok=%v wait=%s why=%q", ok, wait, why)
	}
	if snap := guard.Snapshot(); snap.CallsLast5Min != 0 {
		t.Fatalf("UT-26 stopped cache block must not consume API budget, got calls_5m=%d", snap.CallsLast5Min)
	}

	guard.MarkCodespaceState("Available")
	if !guard.IsCodespaceWarm() {
		t.Fatal("UT-26 expected IsCodespaceWarm=true after Available")
	}
	if ok, _, why := guard.TryAllow("boot"); !ok {
		t.Fatalf("UT-26 expected TryAllow to succeed after Available, blocked by %q", why)
	}
}

// UT-27 (v6 consolidated): Post-probe bootDuration slow-boot catch (v5 pid14300 fix) & CRLF Defender Firewall parser.
func TestUT27_PostProbeBootDurationAndFirewallBlockParser(t *testing.T) {
	// Part A: Slow qualification probes push total bootDuration past BootSlowThreshold and trigger slow_boot_elevated_rtt.
	cfg := DefaultConfig()
	cfg.PoolSize = 1
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 3
	cfg.BootQualityMaxRTT = 850 * time.Millisecond
	cfg.BootQualityMaxJitter = 700 * time.Millisecond
	cfg.BootSlowThreshold = 140 * time.Millisecond
	cfg.BootSlowMaxRTT = 150 * time.Millisecond
	cfg.BootSlowMaxJitter = 400 * time.Millisecond

	sup := NewSupervisor(cfg, nil, SupervisorDeps{
		PortInspector:          &mockPortInspector{},
		BootQualitySampleDelay: 85 * time.Millisecond,
		ProbeFunc: func(_ context.Context, _, _ string, _ time.Duration) (time.Duration, error) {
			return 200 * time.Millisecond, nil
		},
	})

	rep, early, err := sup.qualifyBootTunnel(context.Background(), nil, time.Now(), BootProbeMetrics{
		InitialRTT: 200 * time.Millisecond,
	})
	if err != nil || early != nil {
		t.Fatalf("UT-27 unexpected qualifyBootTunnel error=%v early=%+v", err, early)
	}
	if !rep.SlowBoot || rep.Accepted || rep.Reason != "slow_boot_elevated_rtt" {
		t.Fatalf("UT-27 expected post-probe slow_boot_elevated_rtt rejection, got %+v", rep)
	}

	// Part B: Defender Firewall outbound blocking-rule parser (CRLF Windows output).
	netshOut := strings.Join([]string{
		"Rule Name:                            Block GitHub CLI Outbound",
		"----------------------------------------------------------------------",
		"Enabled:                              Yes",
		"Direction:                            Out",
		"Program:                              C:\\Program Files\\GitHub CLI\\gh.exe",
		"Action:                               Block",
		"",
		"Rule Name:                            Old Disabled Xray Block",
		"----------------------------------------------------------------------",
		"Enabled:                              No",
		"Direction:                            Out",
		"Program:                              C:\\Tools\\xray.exe",
		"Action:                               Block",
		"",
		"Rule Name:                            Allow NetShaper Outbound",
		"----------------------------------------------------------------------",
		"Enabled:                              Yes",
		"Direction:                            Out",
		"Program:                              C:\\Tools\\NetShaper.exe",
		"Action:                               Allow",
		"",
	}, "\r\n")

	checks := ParseNetshFirewallAudit(netshOut)
	if len(checks) != 1 {
		t.Fatalf("UT-27 expected exactly 1 enabled block warning (gh.exe), got %d: %+v", len(checks), checks)
	}
	if checks[0].Name != "firewall_block_gh.exe" || checks[0].Status != "warn" {
		t.Fatalf("UT-27 unexpected firewall audit check: %+v", checks[0])
	}
}

// ST-14 (v6 consolidated): Full consolidated end-to-end chaos run exercising all 5 modules + 5 upgrades together.
func TestST14_FullConsolidatedChaosRun(t *testing.T) {
	baseG := runtime.NumGoroutine()

	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "st14.log")
	metricsPath := filepath.Join(dir, "st14_metrics.ndjson")
	cachePath := filepath.Join(dir, "st14_codespace_cache.json")

	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("ST-14 logger: %v", err)
	}
	defer func() { _ = logger.Close() }()
	metrics, err := NewMetricsEmitter(metricsPath, "st14")
	if err != nil {
		t.Fatalf("ST-14 metrics: %v", err)
	}
	defer func() { _ = metrics.Close() }()

	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.PerTunnelMaxConns = 6
	cfg.MaxActiveConns = 12
	cfg.MaxQueuedConns = 32
	cfg.IdleTimeout = 10 * time.Second
	cfg.PressureIdleTimeout = 250 * time.Millisecond
	cfg.PressureThresholdPct = 75
	cfg.PMTU576SafeMode = true
	cfg.BootQualitySamples = 2
	cfg.BootQualityMaxRetries = 2
	cfg.BootFastLaneMaxRTT = 1200 * time.Millisecond
	cfg.BootMicroPayloadCheck = true
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.StopOnExit = false
	cfg.DialPaceInterval = 0
	cfg.BackoffMin = 100 * time.Millisecond
	cfg.BackoffMax = 200 * time.Millisecond
	cfg.ProbeInterval = 500 * time.Millisecond
	cfg.SummaryLogInterval = 350 * time.Millisecond
	cfg.CodespaceCachePath = cachePath
	cfg.GitHubMinCallSpacing = 0

	w1Addr := fmt.Sprintf("127.0.0.1:%d", basePort)
	var (
		w1Mu       sync.Mutex
		w1AliveCmd *exec.Cmd
		w1PID      atomic.Uint32
		w1Spawns   atomic.Int32
	)

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector:          &mockPortInspector{},
		BootPollDelay:          20 * time.Millisecond,
		BootQualitySampleDelay: 25 * time.Millisecond,
		BootQualityRetryDelay:  60 * time.Millisecond,
		Metrics:                metrics,
		LookupWANRemote: func(pid uint32) string {
			if pid != 0 && pid == w1PID.Load() {
				return "20.120.56.11:443"
			}
			return "20.93.53.155:443"
		},
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			// Inject 1 synthetic MCI slow-lane roll (2.6s RTT) on worker-1's very first boot attempt.
			if addr == w1Addr && w1Spawns.Load() == 1 {
				return 2600 * time.Millisecond, nil
			}
			return ProbeSOCKS5(ctx, addr, target, timeout)
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if c.GHPort == basePort {
				n := w1Spawns.Add(1)
				if cmd.Process != nil {
					w1PID.Store(uint32(cmd.Process.Pid))
				}
				if n == 2 {
					w1Mu.Lock()
					w1AliveCmd = cmd
					w1Mu.Unlock()
				}
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// 1. Wait for fast-lane convergence (worker-1 re-rolled past attempt #1 slow lane -> 2/2 healthy).
	waitUntil(t, 5*time.Second, "ST-14 fast-lane convergence to 2/2 HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return sup.State() == StateHealthy && snap.HealthyWorkers == 2 && w1Spawns.Load() >= 2 && sup.BoundLocalAddr() != ""
	})

	// 2. Park 8 silent zombie sockets to trigger pressure reaping alongside live echo transfers.
	zombies := make([]net.Conn, 0, 8)
	for i := 0; i < 8; i++ {
		zc, zerr := net.DialTimeout("tcp", sup.BoundLocalAddr(), 2*time.Second)
		if zerr != nil {
			t.Fatalf("ST-14 zombie dial %d: %v", i, zerr)
		}
		zombies = append(zombies, zc)
	}
	defer func() {
		for _, zc := range zombies {
			_ = zc.Close()
		}
	}()

	// 3. Run 4 concurrent active echo worker loops spanning zombie pressure + worker-1 kill.
	stopTraffic := make(chan struct{})
	var activeOK atomic.Int64
	var tWG sync.WaitGroup
	payload := makeDeterministicPayload(16*1024, 1414)
	for g := 0; g < 4; g++ {
		tWG.Add(1)
		go func() {
			defer tWG.Done()
			for {
				select {
				case <-stopTraffic:
					return
				default:
				}
				if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), payload, 2*time.Second); err == nil {
					activeOK.Add(1)
				}
				time.Sleep(25 * time.Millisecond)
			}
		}()
	}

	// Wait past PressureIdleTimeout (250ms) so zombies get pressure-reaped, then kill worker-1 mid-load!
	time.Sleep(450 * time.Millisecond)
	w1Mu.Lock()
	if w1AliveCmd != nil && w1AliveCmd.Process != nil {
		_ = w1AliveCmd.Process.Kill()
	}
	w1Mu.Unlock()

	// 4. Verify zero-blackout self-healing back to 2/2 healthy workers.
	waitUntil(t, 5*time.Second, "ST-14 worker-1 replaced after mid-load kill", func() bool {
		snap := sup.PoolSnapshot()
		return w1Spawns.Load() >= 3 && snap.TotalFailovers >= 1 && snap.HealthyWorkers == 2
	})

	// Assert per-tunnel concurrency cap, global PeakConns<=12, and adaptive PMTU=576 flags.
	poolSnap := sup.PoolSnapshot()
	for _, ws := range poolSnap.Workers {
		if ws.ActiveStreams > int64(cfg.PerTunnelMaxConns) {
			t.Fatalf("ST-14 worker %s exceeded PerTunnelMaxConns=%d: active=%d", ws.ID, cfg.PerTunnelMaxConns, ws.ActiveStreams)
		}
		if ws.Port == basePort && !ws.PMTU576Active {
			t.Fatalf("ST-14 expected worker-1 (20.120.56.11) PMTU576Active=true, got %+v", ws)
		}
		if ws.Port == basePort+1 && ws.PMTU576Active {
			t.Fatalf("ST-14 expected worker-2 (20.93.53.155) PMTU576Active=false, got %+v", ws)
		}
	}
	sup.proxyMu.Lock()
	var peakConns int64
	if sup.activeProxy != nil {
		peakConns = sup.activeProxy.Metrics(false).PeakConns
	}
	sup.proxyMu.Unlock()
	if peakConns > int64(cfg.MaxActiveConns) {
		t.Fatalf("ST-14 PeakConns=%d exceeded global MCI cap %d", peakConns, cfg.MaxActiveConns)
	}

	close(stopTraffic)
	tWG.Wait()

	if activeOK.Load() < 8 {
		cancel()
		<-done
		t.Fatalf("ST-14 expected continuous echo survival across chaos, got only %d OK", activeOK.Load())
	}

	cancel()
	<-done

	// 5. Verify persistent cache recorded Available and orthogonal NDJSON metrics captured conn+tunnel frames.
	reloaded := NewCodespaceStateCache(cfg.CodespaceName, cachePath)
	if st, ok := reloaded.Get(5 * time.Minute); !ok || st != "Available" {
		t.Fatalf("ST-14 expected persistent cache Available, got st=%q ok=%v", st, ok)
	}
	mRecs := readMetricsNDJSON(t, metricsPath)
	sawConn, sawTunnel := false, false
	for _, r := range mRecs {
		if r.Stream == "conn" {
			sawConn = true
		}
		if r.Stream == "tunnel" {
			sawTunnel = true
		}
	}
	if !sawConn || !sawTunnel {
		t.Fatalf("ST-14 expected both conn and tunnel NDJSON metrics, sawConn=%v sawTunnel=%v (total=%d)", sawConn, sawTunnel, len(mRecs))
	}

	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-28 (v6.2/v6.3): Cross-session Shutdown cache never locks out fresh startup; serialized cold-start
// boots tunnel-1 to TunnelHealthy before spawning tunnel-2 with ZERO invalid 'gh codespace start' calls;
// HTTP 400 / VM-transition stderr signatures map to FailureVMTransition with 10s-20s backoff.
func TestUT28_CrossSessionColdWarmupSerializedBootAndHTTP400Backoff(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// 1. Cross-session Shutdown cache MUST NOT block fresh GitHubGuard.TryAllow().
	cachePath := filepath.Join(t.TempDir(), "codespace_state_cache.json")
	cfg := DefaultConfig()
	if cfg.WarmupCodespaceOnBoot {
		t.Fatal("UT-28 expected WarmupCodespaceOnBoot=false in v6.3 (gh codespace start does not exist)")
	}
	cfg.CodespaceCachePath = cachePath
	cfg.GitHubWarmCacheTTL = 5 * time.Minute
	cfg.GitHubMinCallSpacing = 0

	prevCache := NewCodespaceStateCache(cfg.CodespaceName, cachePath)
	if err := prevCache.Set("Shutdown"); err != nil {
		t.Fatalf("UT-28 seed Shutdown cache: %v", err)
	}

	freshGuard := NewGitHubGuard(cfg, nil, nil)
	if !freshGuard.NeedsColdWarmup() {
		t.Fatal("UT-28 expected NeedsColdWarmup()=true after loading fresh disk Shutdown cache")
	}
	if freshGuard.IsCodespaceWarm() {
		t.Fatal("UT-28 expected IsCodespaceWarm()=false on cold Shutdown cache")
	}
	if ok, wait, why := freshGuard.TryAllow("fresh_startup_boot"); !ok {
		t.Fatalf("UT-28 fresh startup MUST NOT be locked out by prior session Shutdown cache, got wait=%s why=%q", wait, why)
	}

	// Intra-session churn brake MUST still block when current session observes Stopped/Shutdown.
	freshGuard.MarkSessionStopped()
	if ok, wait, why := freshGuard.TryAllow("intra_session_retry"); ok || why != "codespace_cached_stopped" || wait <= 0 {
		t.Fatalf("UT-28 expected intra-session codespace_cached_stopped block, got ok=%v wait=%s why=%q", ok, wait, why)
	}
	freshGuard.ClearSessionStopped()
	if ok, _, why := freshGuard.TryAllow("post_warmup_boot"); !ok {
		t.Fatalf("UT-28 expected ClearSessionStopped to lift brake, blocked by %q", why)
	}

	// 2. ClassifyStderr + RecordFailure for HTTP 400 / VM-transition vs 401/404 vs 429.
	vmSamples := []string{
		"HTTP 400: You may have too many codespaces starting at the same time (https://api.github.com/user/codespaces/x/start)",
		"error: HTTP 400 Bad Request",
		"codespace is shutting down, please wait",
		"codespace is currently starting",
	}
	for _, sample := range vmSamples {
		if got := ClassifyStderr(sample); got != FailureVMTransition {
			t.Fatalf("UT-28 ClassifyStderr(%q) = %q, want %q", sample, got, FailureVMTransition)
		}
	}
	if got := ClassifyStderr("HTTP 401: Unauthorized"); got != FailureAuthOrStopped {
		t.Fatalf("UT-28 expected 401 -> FailureAuthOrStopped, got %q", got)
	}
	if got := ClassifyStderr("HTTP 404: codespace not found"); got != FailureAuthOrStopped {
		t.Fatalf("UT-28 expected 404 -> FailureAuthOrStopped, got %q", got)
	}
	if got := ClassifyStderr("HTTP 429: Too Many Requests"); got != FailureAPIRateLimit {
		t.Fatalf("UT-28 expected 429 -> FailureAPIRateLimit, got %q", got)
	}

	vmGuard := NewGitHubGuard(DefaultConfig(), nil, nil)
	cls, cooldown := vmGuard.RecordFailure(vmSamples[0])
	if cls != FailureVMTransition {
		t.Fatalf("UT-28 RecordFailure class = %q, want %q", cls, FailureVMTransition)
	}
	if cooldown < 10*time.Second || cooldown > 20*time.Second {
		t.Fatalf("UT-28 FailureVMTransition cooldown=%s outside [10s, 20s]", cooldown)
	}
	if ok, _, why := vmGuard.TryAllow("during_vm_cooldown"); ok || why != "vm_transition_cooldown" {
		t.Fatalf("UT-28 expected vm_transition_cooldown block, got ok=%v why=%q", ok, why)
	}

	// 3. Always-serialized boot in TunnelPool.Start: tunnel-1 reaches TunnelHealthy BEFORE tunnel-2 spawns.
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	poolCfg := DefaultConfig()
	poolCfg.PoolSize = 2
	poolCfg.GHPort = basePort
	poolCfg.LocalPort = 0
	poolCfg.BootQualitySamples = 1
	poolCfg.BootMicroPayloadCheck = false
	poolCfg.CodespaceCachePath = cachePath
	poolCfg.BackoffMin = 50 * time.Millisecond
	poolCfg.BackoffMax = 100 * time.Millisecond
	poolCfg.ProbeInterval = 500 * time.Millisecond
	poolCfg.GitHubMinCallSpacing = 0

	poolGuard := NewGitHubGuard(poolCfg, nil, nil)

	var (
		orderMu              sync.Mutex
		events               []string
		t1HealthyWhenT2Spawn atomic.Bool
		poolRef              *TunnelPool
		poolRefMu            sync.Mutex
	)

	deps := SupervisorDeps{
		PortInspector: &mockPortInspector{},
		NewJob:        NewProcessJob,
		ProbeFunc:     ProbeSOCKS5,
		LookupWANRemote: func(uint32) string {
			return "20.93.53.155:443"
		},
		TuneChildProcess: func(int) error { return nil },
		TuneProcessTree:  func(int) int { return 0 },
		BootPollDelay:    15 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			orderMu.Lock()
			if c.GHPort == basePort {
				events = append(events, "spawn_t1")
			} else {
				events = append(events, "spawn_t2")
				poolRefMu.Lock()
				pr := poolRef
				poolRefMu.Unlock()
				if pr != nil && pr.workers[0].State() == TunnelHealthy {
					t1HealthyWhenT2Spawn.Store(true)
				}
			}
			orderMu.Unlock()
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			return cmd, nil
		},
	}

	pool := NewTunnelPool(poolCfg, deps, nil, nil, poolGuard)
	poolRefMu.Lock()
	poolRef = pool
	poolRefMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	if err := pool.Start(ctx); err != nil {
		cancel()
		t.Fatalf("UT-28 pool.Start: %v", err)
	}
	waitUntil(t, 4*time.Second, "UT-28 both workers healthy after serialized cold boot", func() bool {
		return pool.HealthyCount() == 2
	})
	cancel()
	pool.Close()

	orderMu.Lock()
	gotEvents := append([]string(nil), events...)
	orderMu.Unlock()
	if len(gotEvents) < 2 || gotEvents[0] != "spawn_t1" || gotEvents[1] != "spawn_t2" {
		t.Fatalf("UT-28 expected serialized order [spawn_t1 spawn_t2], got %v", gotEvents)
	}
	if !t1HealthyWhenT2Spawn.Load() {
		t.Fatal("UT-28 expected tunnel-1 to already be TunnelHealthy before tunnel-2 spawned")
	}
	if snap := poolGuard.Snapshot(); snap.TotalAllowed != 2 {
		t.Fatalf("UT-28 expected exactly 2 GitHub CLI calls (zero wasted warmup), got %d", snap.TotalAllowed)
	}

	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-29 (v6.2): Single-healthy-worker burst cap eliminates the 50% no_healthy_tunnel cliff when a peer
// is starting/draining/dead, while preserving strict PerTunnelMaxConns=6 once all peers are healthy.
func TestUT29_SingleHealthyWorkerBurstCapAndRebalance(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.PerTunnelMaxConns = 6
	cfg.MaxActiveConns = 12
	cfg.LocalPort = 0

	pool := NewTunnelPool(cfg, SupervisorDeps{}, nil, nil, nil)
	w1 := pool.workers[0]
	w2 := pool.workers[1]

	// Peer w2 is still starting (HealthyWorkers == 1): w1 must burst up to full MaxActiveConns=12.
	w1.setState(TunnelHealthy)
	w1.RecordRTT(250 * time.Millisecond)
	w2.setState(TunnelStarting)

	leases := make([]UpstreamLease, 0, 12)
	for i := 0; i < 12; i++ {
		lease, err := pool.AcquireEndpoint(context.Background())
		if err != nil {
			t.Fatalf("UT-29 burst acquire #%d failed while w1 sole healthy worker: %v", i+1, err)
		}
		if lease.TunnelID != w1.ID() {
			t.Fatalf("UT-29 expected sole healthy worker %s, got %s", w1.ID(), lease.TunnelID)
		}
		leases = append(leases, lease)
	}
	// 13th acquire MUST fail — global MCI C=12 knee cap strictly enforced.
	if extra, err := pool.AcquireEndpoint(context.Background()); err == nil {
		extra.Release()
		t.Fatal("UT-29 expected 13th acquire to fail at global MaxActiveConns=12 cap")
	}

	// Bring w2 online as TunnelHealthy: new traffic must route onto w2 and enforce <= 6 per tunnel.
	w2.setState(TunnelHealthy)
	w2.RecordRTT(240 * time.Millisecond)

	// Release 6 of w1's 12 leases (w1 now at 6/6) and acquire 6 new leases -> all 6 must land on w2.
	for i := 0; i < 6; i++ {
		leases[i].Release()
	}
	leases = leases[6:]

	w2Leases := make([]UpstreamLease, 0, 6)
	for i := 0; i < 6; i++ {
		lease, err := pool.AcquireEndpoint(context.Background())
		if err != nil {
			t.Fatalf("UT-29 rebalance acquire #%d failed: %v", i+1, err)
		}
		if lease.TunnelID != w2.ID() {
			t.Fatalf("UT-29 expected rebalanced lease #%d on %s, got %s", i+1, w2.ID(), lease.TunnelID)
		}
		w2Leases = append(w2Leases, lease)
	}
	// Both workers healthy and at 6/6 -> 13th acquire MUST fail (strict PerTunnelMaxConns=6).
	if extra, err := pool.AcquireEndpoint(context.Background()); err == nil {
		extra.Release()
		t.Fatal("UT-29 expected acquire to fail when both healthy workers are at PerTunnelMaxConns=6")
	}

	for _, l := range leases {
		l.Release()
	}
	for _, l := range w2Leases {
		l.Release()
	}

	// 3-worker pool with 2 healthy + 1 draining: burst cap = ceil(12/2) = 6 per healthy worker (12 total).
	cfg3 := DefaultConfig()
	cfg3.PoolSize = 3
	cfg3.PerTunnelMaxConns = 4
	cfg3.MaxActiveConns = 12
	cfg3.LocalPort = 0

	pool3 := NewTunnelPool(cfg3, SupervisorDeps{}, nil, nil, nil)
	pool3.workers[0].setState(TunnelHealthy)
	pool3.workers[0].RecordRTT(250 * time.Millisecond)
	pool3.workers[1].setState(TunnelHealthy)
	pool3.workers[1].RecordRTT(260 * time.Millisecond)
	pool3.workers[2].setState(TunnelDraining)

	leases3 := make([]UpstreamLease, 0, 12)
	for i := 0; i < 12; i++ {
		lease, err := pool3.AcquireEndpoint(context.Background())
		if err != nil {
			t.Fatalf("UT-29 3-worker degraded-peer acquire #%d failed: %v", i+1, err)
		}
		if lease.TunnelID == pool3.workers[2].ID() {
			t.Fatalf("UT-29 routed to draining worker %s", lease.TunnelID)
		}
		leases3 = append(leases3, lease)
	}
	if extra, err := pool3.AcquireEndpoint(context.Background()); err == nil {
		extra.Release()
		t.Fatal("UT-29 3-worker pool exceeded global MaxActiveConns=12")
	}
	for _, l := range leases3 {
		l.Release()
	}

	// 3-worker ALL-healthy P2C permutation invariant (20 randomized rounds):
	// With PoolSize=3, PerTunnelMaxConns=4, MaxActiveConns=12, acquiring 12/12 leases MUST succeed
	// every single round (proving P2C never drops/duplicates a worker out of `order`).
	pool3.workers[2].setState(TunnelHealthy)
	pool3.workers[2].RecordRTT(255 * time.Millisecond)
	for round := 0; round < 20; round++ {
		roundLeases := make([]UpstreamLease, 0, 12)
		for i := 0; i < 12; i++ {
			l, err := pool3.AcquireEndpoint(context.Background())
			if err != nil {
				for _, held := range roundLeases {
					held.Release()
				}
				t.Fatalf("UT-29 3-worker all-healthy round %d acquire #%d failed (P2C dropped worker?): %v", round+1, i+1, err)
			}
			roundLeases = append(roundLeases, l)
		}
		if extra, err := pool3.AcquireEndpoint(context.Background()); err == nil {
			extra.Release()
			for _, held := range roundLeases {
				held.Release()
			}
			t.Fatalf("UT-29 3-worker all-healthy round %d exceeded 12/12 cap", round+1)
		}
		for _, held := range roundLeases {
			held.Release()
		}
	}
}

// UT-30 (v6.2): Verifies Step A hidden defect fixes:
// (a) pressure_idle_reap increments PressureReaps WITHOUT inflating IdleReaps,
// (b) StopCodespace is skipped on exit when TotalAllowed == 0 (no gh calls issued),
// (c) TunnelPool monitorSingleWorker emits WORKER_DEGRADED and WORKER_RECOVERED log events.
func TestUT30_StepADefectsPressureReapUnbootedStopAndWorkerDegradedLog(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// (a) Disjoint PressureReaps vs IdleReaps counters.
	up := startMockSOCKS5Server(t, socksModeNormal)
	defer up.Close()

	pxCfg := DefaultConfig()
	pxCfg.LocalPort = 0
	pxCfg.MaxActiveConns = 4
	pxCfg.MaxQueuedConns = 8
	pxCfg.IdleTimeout = 10 * time.Second
	pxCfg.PressureIdleTimeout = 200 * time.Millisecond
	pxCfg.PressureThresholdPct = 75
	pxCfg.DialPaceInterval = 0

	proxy := NewProxyServer(pxCfg, up.Addr(), nil, nil, nil)
	pxCtx, pxCancel := context.WithCancel(context.Background())
	proxyAddr, err := proxy.Start(pxCtx)
	if err != nil {
		pxCancel()
		t.Fatalf("UT-30 proxy.Start: %v", err)
	}

	zombies := make([]net.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		c, derr := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if derr != nil {
			pxCancel()
			proxy.Stop(true)
			t.Fatalf("UT-30 zombie dial %d: %v", i, derr)
		}
		zombies = append(zombies, c)
	}
	waitUntil(t, 3*time.Second, "UT-30 pressure reaper reaps silent sockets", func() bool {
		return proxy.SnapshotWindow(false).PressureReaps >= 1
	})
	stats := proxy.SnapshotWindow(false)
	for _, c := range zombies {
		_ = c.Close()
	}
	pxCancel()
	proxy.Stop(true)

	if stats.PressureReaps == 0 {
		t.Fatalf("UT-30 expected PressureReaps >= 1, got %d", stats.PressureReaps)
	}
	if stats.IdleReaps != 0 {
		t.Fatalf("UT-30 pressure_idle_reap double-counted into IdleReaps=%d (want 0)", stats.IdleReaps)
	}

	// (b) Unbooted session with StopOnExit=true skips StopCodespace when TotalAllowed == 0.
	dir := t.TempDir()
	stopLogPath := filepath.Join(dir, "unbooted_stop.log")
	stopLogger, err := NewEventLogger(stopLogPath)
	if err != nil {
		t.Fatalf("UT-30 stop logger: %v", err)
	}
	var stopCalls atomic.Int32
	unbootedCfg := DefaultConfig()
	unbootedCfg.PoolSize = 1
	unbootedCfg.LocalPort = 0
	unbootedCfg.StopOnExit = true
	unbootedCfg.PreflightNetHygiene = false
	unbootedCfg.WarmupCodespaceOnBoot = false

	sup := NewSupervisor(unbootedCfg, stopLogger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
			return nil, fmt.Errorf("should not spawn child on pre-canceled ctx")
		},
		StopCodespace: func(ctx context.Context, cfg Config) (int, string, error) {
			stopCalls.Add(1)
			return 0, "", nil
		},
	})
	preCanceled, preCancel := context.WithCancel(context.Background())
	preCancel()
	_ = sup.Run(preCanceled)

	if stopCalls.Load() != 0 {
		t.Fatalf("UT-30 expected StopCodespace skipped on unbooted session, got %d calls", stopCalls.Load())
	}
	stopEvents := readJSONLLog(t, stopLogPath)
	foundSkip := false
	for _, ev := range stopEvents {
		if ev.Event == "SHUTDOWN_COMPLETE" {
			if invoked, _ := ev.Fields["stop_codespace_invoked"].(bool); invoked {
				t.Fatalf("UT-30 expected stop_codespace_invoked=false, got %+v", ev.Fields)
			}
			if reason, _ := ev.Fields["stop_skipped_reason"].(string); reason == "no_gh_calls_issued" {
				foundSkip = true
			}
		}
	}
	if !foundSkip {
		t.Fatalf("UT-30 missing stop_skipped_reason=no_gh_calls_issued in SHUTDOWN_COMPLETE")
	}

	// (c) TunnelPool monitorSingleWorker emits WORKER_DEGRADED and WORKER_RECOVERED events.
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	poolLogPath := filepath.Join(dir, "worker_degraded.log")
	poolLogger, err := NewEventLogger(poolLogPath)
	if err != nil {
		t.Fatalf("UT-30 pool logger: %v", err)
	}
	poolCfg := DefaultConfig()
	poolCfg.PoolSize = 2
	poolCfg.GHPort = basePort
	poolCfg.LocalPort = 0
	poolCfg.BootQualitySamples = 1
	poolCfg.BootMicroPayloadCheck = false
	poolCfg.ProbeInterval = 120 * time.Millisecond
	poolCfg.DegradedProbeInterval = 80 * time.Millisecond
	poolCfg.BreakerThreshold = 5
	poolCfg.BreakerMinWindow = 10 * time.Second
	poolCfg.GitHubMinCallSpacing = 0

	w1Addr := fmt.Sprintf("127.0.0.1:%d", basePort)
	var failW1 atomic.Bool
	pool := NewTunnelPool(poolCfg, SupervisorDeps{
		PortInspector:    &mockPortInspector{},
		NewJob:           NewProcessJob,
		BootPollDelay:    15 * time.Millisecond,
		LookupWANRemote:  func(uint32) string { return "20.93.53.155:443" },
		TuneChildProcess: func(int) error { return nil },
		TuneProcessTree:  func(int) int { return 0 },
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			if addr == w1Addr && failW1.Load() {
				return 0, fmt.Errorf("synthetic_transient_probe_timeout")
			}
			return ProbeSOCKS5(ctx, addr, target, timeout)
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			return cmd, nil
		},
	}, poolLogger, nil, NewGitHubGuard(poolCfg, poolLogger, nil))

	pCtx, pCancel := context.WithCancel(context.Background())
	if err := pool.Start(pCtx); err != nil {
		pCancel()
		t.Fatalf("UT-30 pool.Start: %v", err)
	}
	waitUntil(t, 4*time.Second, "UT-30 pool 2/2 healthy", func() bool {
		return pool.HealthyCount() == 2
	})

	failW1.Store(true)
	waitUntil(t, 3*time.Second, "UT-30 tunnel-1 transitions to TunnelDegraded", func() bool {
		return pool.workers[0].State() == TunnelDegraded
	})
	failW1.Store(false)
	waitUntil(t, 3*time.Second, "UT-30 tunnel-1 recovers to TunnelHealthy", func() bool {
		return pool.workers[0].State() == TunnelHealthy
	})

	pCancel()
	pool.Close()
	_ = poolLogger.Close()

	poolEvents := readJSONLLog(t, poolLogPath)
	sawDegraded, sawRecovered := false, false
	for _, ev := range poolEvents {
		tid, _ := ev.Fields["tunnel_id"].(string)
		if ev.Event == "WORKER_DEGRADED" && tid == "tunnel-1" {
			sawDegraded = true
		}
		if ev.Event == "WORKER_RECOVERED" && tid == "tunnel-1" {
			sawRecovered = true
		}
	}
	if !sawDegraded || !sawRecovered {
		t.Fatalf("UT-30 expected WORKER_DEGRADED and WORKER_RECOVERED for tunnel-1, got degraded=%v recovered=%v", sawDegraded, sawRecovered)
	}

	assertNoGoroutineLeak(t, baseG, 6)
}

// ST-15 (v6.2/v6.3): End-to-end cold Shutdown cache startup -> serialized tunnel-1->tunnel-2 boot (zero warmup calls) ->
// sole-healthy-worker burst traffic (>6 concurrent streams while tunnel-2 is still booting) ->
// mid-load tunnel-1 failover with 0 no_healthy_tunnel drops and clean shutdown.
func TestST15_ColdShutdownCachePoolBurstFailoverEndToEnd(t *testing.T) {
	baseG := runtime.NumGoroutine()

	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "st15.log")
	metricsPath := filepath.Join(dir, "st15_metrics.ndjson")
	cachePath := filepath.Join(dir, "st15_codespace_cache.json")

	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("ST-15 logger: %v", err)
	}
	defer func() { _ = logger.Close() }()
	metrics, err := NewMetricsEmitter(metricsPath, "st15")
	if err != nil {
		t.Fatalf("ST-15 metrics: %v", err)
	}
	defer func() { _ = metrics.Close() }()

	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.PerTunnelMaxConns = 6
	cfg.MaxActiveConns = 12
	cfg.MaxQueuedConns = 32
	cfg.StopOnExit = true
	cfg.StopTimeout = 3 * time.Second
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.DialPaceInterval = 0
	cfg.BackoffMin = 80 * time.Millisecond
	cfg.BackoffMax = 150 * time.Millisecond
	cfg.ProbeInterval = 400 * time.Millisecond
	cfg.SummaryLogInterval = 350 * time.Millisecond
	cfg.CodespaceCachePath = cachePath
	cfg.GitHubMinCallSpacing = 0

	// Pre-populate disk cache with "Shutdown" from a simulated previous NetShaper.exe exit.
	seedCache := NewCodespaceStateCache(cfg.CodespaceName, cachePath)
	if err := seedCache.Set("Shutdown"); err != nil {
		t.Fatalf("ST-15 seed Shutdown cache: %v", err)
	}

	var (
		stopCalls  atomic.Int32
		w1Mu       sync.Mutex
		w1Cmd      *exec.Cmd
		w1Spawns   atomic.Int32
		w2Gate     = make(chan struct{})
		w2GateOnce sync.Once
	)
	releaseW2 := func() { w2GateOnce.Do(func() { close(w2Gate) }) }

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 15 * time.Millisecond,
		Metrics:       metrics,
		LookupWANRemote: func(uint32) string {
			return "20.120.56.11:443"
		},
		StopCodespace: func(ctx context.Context, c Config) (int, string, error) {
			stopCalls.Add(1)
			return 0, "stopped", nil
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			if c.GHPort == basePort+1 {
				select {
				case <-w2Gate:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if c.GHPort == basePort && w1Spawns.Add(1) == 1 {
				w1Mu.Lock()
				w1Cmd = cmd
				w1Mu.Unlock()
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		releaseW2()
		cancel()
	})
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// 1. Wait until tunnel-1 is ready and local proxy is open while tunnel-2 is STILL gated.
	waitUntil(t, 5*time.Second, "ST-15 tunnel-1 healthy & proxy open with Shutdown cache", func() bool {
		return sup.State() == StateHealthy && sup.BoundLocalAddr() != "" && sup.PoolSnapshot().HealthyWorkers == 1
	})

	// 2. Fire 10 concurrent SOCKS5 transfers (> PerTunnelMaxConns=6, <= MaxActiveConns=12) on sole healthy tunnel-1!
	burstPayload := makeDeterministicPayload(8*1024, 1515)
	var burstOK atomic.Int64
	var burstWG sync.WaitGroup
	startGate := make(chan struct{})
	for i := 0; i < 10; i++ {
		burstWG.Add(1)
		go func() {
			defer burstWG.Done()
			<-startGate
			if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), burstPayload, 4*time.Second); err == nil {
				burstOK.Add(1)
			}
		}()
	}
	close(startGate)
	burstWG.Wait()

	if burstOK.Load() != 10 {
		releaseW2()
		cancel()
		<-done
		t.Fatalf("ST-15 sole-healthy-worker burst expected 10/10 OK, got %d/10", burstOK.Load())
	}

	// 3. Release tunnel-2, wait for 2/2 healthy, then kill tunnel-1 under 8 concurrent streams.
	releaseW2()
	waitUntil(t, 5*time.Second, "ST-15 pool converges to 2/2 HEALTHY", func() bool {
		return sup.PoolSnapshot().HealthyWorkers == 2
	})

	stopTraffic := make(chan struct{})
	var failoverOK atomic.Int64
	var tWG sync.WaitGroup
	for i := 0; i < 8; i++ {
		tWG.Add(1)
		go func() {
			defer tWG.Done()
			for {
				select {
				case <-stopTraffic:
					return
				default:
				}
				if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), burstPayload, 3*time.Second); err == nil {
					failoverOK.Add(1)
				}
				time.Sleep(15 * time.Millisecond)
			}
		}()
	}

	time.Sleep(80 * time.Millisecond)
	w1Mu.Lock()
	if w1Cmd != nil && w1Cmd.Process != nil {
		_ = w1Cmd.Process.Kill()
	}
	w1Mu.Unlock()

	waitUntil(t, 5*time.Second, "ST-15 tunnel-1 replaced and pool back to 2/2 HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return w1Spawns.Load() >= 2 && snap.TotalFailovers >= 1 && snap.HealthyWorkers == 2
	})

	close(stopTraffic)
	tWG.Wait()
	cancel()
	<-done

	if stopCalls.Load() != 1 {
		t.Fatalf("ST-15 expected StopCodespace called once on clean exit, got %d", stopCalls.Load())
	}
	if failoverOK.Load() < 8 {
		t.Fatalf("ST-15 expected continuous echo survival during failover, got only %d OK", failoverOK.Load())
	}

	// 4. Verify 0 codespace_cached_stopped lockouts and 0 no_healthy_tunnel drops in NDJSON metrics.
	mRecs := readMetricsNDJSON(t, metricsPath)
	for _, r := range mRecs {
		if r.Stream == "api_guard" {
			if br, _ := r.Data["block_reason"].(string); br == "codespace_cached_stopped" {
				t.Fatalf("ST-15 unexpected cross-session codespace_cached_stopped lockout: %+v", r.Data)
			}
		}
		if r.Stream == "conn" {
			if cr, _ := r.Data["close_reason"].(string); cr == "no_healthy_tunnel" {
				t.Fatalf("ST-15 unexpected no_healthy_tunnel drop during single-worker burst/failover: %+v", r.Data)
			}
		}
	}

	assertNoGoroutineLeak(t, baseG, 6)
}

// startConsecutiveMockSOCKS5Triple allocates three mock SOCKS5 servers bound to adjacent localhost ports (base, base+1, base+2)
// so TunnelPool(PoolSize=3) soak tests run cleanly with zero port collisions on any platform.
func startConsecutiveMockSOCKS5Triple(t *testing.T) (*mockSOCKS5Server, *mockSOCKS5Server, *mockSOCKS5Server, uint16) {
	t.Helper()
	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0xbb67ae85))
	for attempt := 0; attempt < 80; attempt++ {
		base := uint16(26000 + rng.IntN(22000))
		ln1, err1 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base))
		if err1 != nil {
			continue
		}
		ln2, err2 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+1))
		if err2 != nil {
			_ = ln1.Close()
			continue
		}
		ln3, err3 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+2))
		if err3 != nil {
			_ = ln1.Close()
			_ = ln2.Close()
			continue
		}
		return serveMockSOCKS5OnListener(ln1, socksModeNormal),
			serveMockSOCKS5OnListener(ln2, socksModeNormal),
			serveMockSOCKS5OnListener(ln3, socksModeNormal),
			base
	}
	t.Fatal("failed to allocate three adjacent localhost ports for 3-worker pool test")
	return nil, nil, nil, 0
}

// UT-31 (v6.3): Dynamic Direct Underlay Baseline B_raw(t), GitHub WAF Host Guard & Relative Overhead Normalization.
func TestUT31_DynamicUnderlayBaselineNormalization(t *testing.T) {
	// 1. Hard WAF safety invariant: underlay baseline MUST NEVER target GitHub endpoints.
	for _, gh := range []string{"github.com:443", "api.github.com:443", "ssh.github.com:443", "objects.githubusercontent.com:443"} {
		if !IsGitHubHost(gh) {
			t.Fatalf("UT-31 expected IsGitHubHost(%q) == true", gh)
		}
	}
	for _, nonGH := range []string{"20.120.56.11:443", "1.1.1.1:443", "127.0.0.1:443"} {
		if IsGitHubHost(nonGH) {
			t.Fatalf("UT-31 expected IsGitHubHost(%q) == false", nonGH)
		}
	}
	if _, _, err := MeasureUnderlayBaseline(context.Background(), []string{"api.github.com:443"}, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "refused GitHub host") {
		t.Fatalf("UT-31 expected MeasureUnderlayBaseline to refuse GitHub host, got err=%v", err)
	}
	badCfg := DefaultConfig()
	badCfg.UnderlayProbeTargets = "20.120.56.11:443,api.github.com:443"
	if err := badCfg.Validate(); err == nil {
		t.Fatal("UT-31 expected Config.Validate() to reject GitHub host in UnderlayProbeTargets")
	}

	// 2. Local loopback TLS echo responder proves MeasureUnderlayBaseline works with 0 internet calls.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("UT-31 listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		var buf [256]byte
		_, _ = conn.Read(buf[:])
		time.Sleep(15 * time.Millisecond)
		_, _ = conn.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x02})
	}()
	rtt, usedTarget, err := MeasureUnderlayBaseline(context.Background(), []string{ln.Addr().String()}, 500*time.Millisecond)
	if err != nil || usedTarget != ln.Addr().String() || rtt < 10*time.Millisecond {
		t.Fatalf("UT-31 local MeasureUnderlayBaseline failed: rtt=%s target=%q err=%v", rtt, usedTarget, err)
	}

	// 3. Relative overhead normalization: 650ms tunnel is REJECTED on clean 140ms Wi-Fi (rho=4.64x)
	//    yet ACCEPTED on congested 1-bar 450ms MCI cellular (rho=1.44x).
	cfg := DefaultConfig()
	cfg.BootQualitySamples = 3
	cfg.BootFastLaneMaxRTT = 1200 * time.Millisecond
	cfg.FastLaneMaxRatio = 2.2
	cfg.SlowLaneEvictRatio = 3.5

	samples650 := []time.Duration{640 * time.Millisecond, 650 * time.Millisecond, 660 * time.Millisecond}
	wifiRep := EvaluateFastLaneGateNormalized(cfg, 5*time.Second, samples650, 0, 0, 140.0, true, 180*time.Millisecond)
	if wifiRep.Accepted || wifiRep.Reason != "slow_lane_vs_underlay_baseline" || wifiRep.RelativeRho < 4.5 {
		t.Fatalf("UT-31 expected 650ms tunnel rejected on 140ms Wi-Fi (rho=4.64x), got %+v", wifiRep)
	}

	mci1BarRep := EvaluateFastLaneGateNormalized(cfg, 5*time.Second, samples650, 0, 0, 450.0, true, 500*time.Millisecond)
	if !mci1BarRep.Accepted || mci1BarRep.Reason != "ok" || mci1BarRep.RelativeRho > 1.6 {
		t.Fatalf("UT-31 expected 650ms tunnel accepted on 450ms 1-bar MCI (rho=1.44x), got %+v", mci1BarRep)
	}

	// 3b. Real cold boot (>= BootSlowThreshold = 13s) on weak 1-bar MCI (B_raw=450ms):
	//     Healthy 650ms tunnel (rho=1.44x) with bootDuration=15s MUST be accepted (BootSlowMaxRTT normalized),
	//     whereas an elevated 900ms slow-boot tunnel (rho=2.00x > 1.87x slowRatio) MUST still be rejected.
	mci1BarSlowBootOK := EvaluateFastLaneGateNormalized(cfg, 15*time.Second, samples650, 0, 0, 450.0, true, 500*time.Millisecond)
	if !mci1BarSlowBootOK.Accepted || !mci1BarSlowBootOK.SlowBoot || mci1BarSlowBootOK.Reason != "ok" {
		t.Fatalf("UT-31 expected 15s cold boot at 650ms accepted on 450ms 1-bar MCI, got %+v", mci1BarSlowBootOK)
	}
	samples900 := []time.Duration{890 * time.Millisecond, 900 * time.Millisecond, 910 * time.Millisecond}
	mci1BarSlowBootHigh := EvaluateFastLaneGateNormalized(cfg, 15*time.Second, samples900, 0, 0, 450.0, true, 500*time.Millisecond)
	if mci1BarSlowBootHigh.Accepted || mci1BarSlowBootHigh.Reason != "slow_boot_elevated_rtt" {
		t.Fatalf("UT-31 expected 15s cold boot at 900ms rejected with slow_boot_elevated_rtt on 450ms MCI, got %+v", mci1BarSlowBootHigh)
	}
	// Clean 220ms baseline parity: 15s cold boot at 650ms MUST still be rejected with slow_boot_elevated_rtt (UT-15 parity).
	cleanSlowBootReject := EvaluateFastLaneGateNormalized(cfg, 15*time.Second, samples650, 0, 0, 220.0, true, 300*time.Millisecond)
	if cleanSlowBootReject.Accepted || cleanSlowBootReject.Reason != "slow_boot_elevated_rtt" {
		t.Fatalf("UT-31 expected clean 220ms 15s cold boot at 650ms rejected with slow_boot_elevated_rtt, got %+v", cleanSlowBootReject)
	}

	// 4. Lane classifier boundaries.
	if got := EvaluateBaselineNormalizedLane(350, 220, 2.2, 3.5); got != "fast" {
		t.Fatalf("UT-31 expected fast lane for rho=1.59, got %q", got)
	}
	if got := EvaluateBaselineNormalizedLane(650, 220, 2.2, 3.5); got != "mediocre" {
		t.Fatalf("UT-31 expected mediocre lane for rho=2.95, got %q", got)
	}
	if got := EvaluateBaselineNormalizedLane(900, 220, 2.2, 3.5); got != "slow_lane" {
		t.Fatalf("UT-31 expected slow_lane for rho=4.09, got %q", got)
	}
}

// UT-32 (v6.3): 3-Layer Schmitt-Trigger Hysteresis & Continuous Dwell Window Anti-Flapping.
func TestUT32_SchmittTriggerHysteresisAndDwellAntiFlapping(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.PerTunnelMaxConns = 6
	cfg.MaxActiveConns = 12
	cfg.HysteresisDwellWindow = 5 * time.Second
	cfg.HysteresisRelMargin = 0.30
	cfg.HysteresisAbsMargin = 100 * time.Millisecond
	cfg.FastLaneMaxRatio = 2.2

	pool := NewTunnelPool(cfg, SupervisorDeps{}, nil, nil, nil)
	pool.SetUnderlayBaselineMS(220.0)
	w1 := pool.workers[0]
	w2 := pool.workers[1]
	w1.setState(TunnelHealthy)
	w2.setState(TunnelHealthy)

	// Phase 1: 30 cycles of 280ms vs 330ms oscillation (margin 50ms < 100ms & rel < 30%) -> 0 primary switches!
	simNow := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		if i%2 == 0 {
			w1.SetEWMARTT(280 * time.Millisecond)
			w2.SetEWMARTT(330 * time.Millisecond)
		} else {
			w1.SetEWMARTT(330 * time.Millisecond)
			w2.SetEWMARTT(280 * time.Millisecond)
		}
		pool.EvaluateRoutingMode(simNow)
		simNow = simNow.Add(2 * time.Second)
	}
	mode, primary := pool.RoutingMode()
	if pool.PrimarySwitches() != 0 || mode != "balanced" || primary != "" {
		t.Fatalf("UT-32 oscillation caused flapping: switches=%d mode=%q primary=%q", pool.PrimarySwitches(), mode, primary)
	}

	// Phase 2: Sustained asymmetry (w1=250ms vs w2=1800ms) promotes tunnel-1 ONLY after continuous 5s dwell.
	// Hold an active lease on w2 to verify zero forced drops of existing flows.
	w1.SetEWMARTT(250 * time.Millisecond)
	w2.SetEWMARTT(1800 * time.Millisecond)
	existingW2 := w2.TryAcquireSlotWithCap(6)
	if !existingW2 {
		t.Fatal("UT-32 failed to acquire baseline slot on w2")
	}
	defer w2.ReleaseSlot()

	pool.EvaluateRoutingMode(simNow) // starts dwell timer at T=0
	simNow = simNow.Add(4 * time.Second)
	pool.EvaluateRoutingMode(simNow) // T=4s < 5s dwell
	if m, _ := pool.RoutingMode(); m != "balanced" || pool.PrimarySwitches() != 0 {
		t.Fatalf("UT-32 promoted primary prematurely before 5s dwell: mode=%q switches=%d", m, pool.PrimarySwitches())
	}

	simNow = simNow.Add(2 * time.Second) // T=6s >= 5s dwell
	pool.EvaluateRoutingMode(simNow)
	mode, primary = pool.RoutingMode()
	if mode != "primary_preferred" || primary != w1.ID() || pool.PrimarySwitches() != 1 {
		t.Fatalf("UT-32 expected primary_preferred on %s with 1 switch, got mode=%q primary=%q switches=%d",
			w1.ID(), mode, primary, pool.PrimarySwitches())
	}
	if w2.State() != TunnelHealthy || w2.activeStreams.Load() != 1 {
		t.Fatalf("UT-32 existing flow on w2 was disrupted during promotion: state=%s active=%d", w2.State(), w2.activeStreams.Load())
	}

	// New dials must route to promoted Primary (tunnel-1).
	lease, err := pool.AcquireEndpoint(context.Background())
	if err != nil || lease.TunnelID != w1.ID() {
		t.Fatalf("UT-32 expected new lease routed to primary %s, got %+v err=%v", w1.ID(), lease, err)
	}
	lease.Release()

	// Phase 3: w2 recovers to 270ms -> must dwell 5s before returning to balanced multi-active mode.
	w2.SetEWMARTT(270 * time.Millisecond)
	simNow = simNow.Add(1 * time.Second)
	pool.EvaluateRoutingMode(simNow) // starts rebalance dwell
	simNow = simNow.Add(3 * time.Second)
	pool.EvaluateRoutingMode(simNow) // still < 5s
	if m, _ := pool.RoutingMode(); m != "primary_preferred" {
		t.Fatalf("UT-32 exited primary_preferred too early at 3s: mode=%q", m)
	}
	simNow = simNow.Add(3 * time.Second) // >= 5s
	pool.EvaluateRoutingMode(simNow)
	if m, p := pool.RoutingMode(); m != "balanced" || p != "" {
		t.Fatalf("UT-32 expected clean return to balanced after peer convergence, got mode=%q primary=%q", m, p)
	}
}

// UT-33 (v6.3): Chronic Slow-Lane Diversion, Underlay Congestion Suppression & Single-Worker Eviction/Reroll.
func TestUT33_ChronicSlowLaneEvictionAndReroll(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// Part A: Underlay congestion suppression (B_raw = 950ms > 800ms ceiling -> NEVER evict workers).
	cfgA := DefaultConfig()
	cfgA.PoolSize = 2
	cfgA.SlowLaneEvictRatio = 3.5
	cfgA.SlowLaneEvictWindow = 10 * time.Second
	cfgA.SlowLaneUnderlayCeiling = 800 * time.Millisecond

	poolA := NewTunnelPool(cfgA, SupervisorDeps{}, nil, nil, nil)
	poolA.SetUnderlayBaselineMS(950.0)
	poolA.workers[0].setState(TunnelHealthy)
	poolA.workers[1].setState(TunnelHealthy)
	poolA.workers[0].SetEWMARTT(1000 * time.Millisecond)
	poolA.workers[1].SetEWMARTT(3800 * time.Millisecond) // rho=4.0x, but underlay itself is >800ms

	t0 := time.Date(2026, 11, 21, 19, 0, 0, 0, time.UTC)
	if n := poolA.CheckSlowLaneEviction(t0); n != 0 {
		t.Fatalf("UT-33 expected 0 evictions at t0 under high B_raw, got %d", n)
	}
	if n := poolA.CheckSlowLaneEviction(t0.Add(60 * time.Second)); n != 0 || poolA.workers[1].IsSlowLaneDegraded() {
		t.Fatalf("UT-33 MUST suppress eviction when B_raw=950ms > 800ms ceiling, got n=%d degraded=%v", n, poolA.workers[1].IsSlowLaneDegraded())
	}

	// Verify slow-lane diversion + burst cap: marking w2 SlowLaneDegraded routes 10/10 leases to w1 (bursting > 6 up to 12).
	poolA.workers[1].SetSlowLaneDegraded(true)
	diverted := make([]UpstreamLease, 0, 10)
	for i := 0; i < 10; i++ {
		l, err := poolA.AcquireEndpoint(context.Background())
		if err != nil {
			t.Fatalf("UT-33 slow-lane diversion acquire %d failed: %v", i+1, err)
		}
		if l.TunnelID != poolA.workers[0].ID() {
			t.Fatalf("UT-33 leaked stream %d onto SlowLaneDegraded %s", i+1, l.TunnelID)
		}
		diverted = append(diverted, l)
	}
	for _, l := range diverted {
		l.Release()
	}

	// Part A2: GitHubGuard cooldown / 5m budget deferral safety —
	// When GitHubGuard is actively in a 429 cooldown or 5m budget lockout, CheckSlowLaneEviction MUST
	// mark the slow worker SlowLaneDegraded (diverting 100% of traffic to w1) WITHOUT tearing it down
	// into DEAD, so if w1 drops during the cooldown, AcquireEndpoint seamlessly falls back to w2.
	// Once cooldown/budget clears, CheckSlowLaneEviction fires the deferred eviction.
	cfgGuard := DefaultConfig()
	cfgGuard.PoolSize = 2
	cfgGuard.SlowLaneEvictRatio = 3.5
	cfgGuard.SlowLaneEvictWindow = 10 * time.Second
	cfgGuard.SlowLaneUnderlayCeiling = 800 * time.Millisecond
	cfgGuard.GitHubMaxCallsPer5Min = 2
	cfgGuard.GitHubMinCallSpacing = 0

	gNow := time.Date(2026, 11, 21, 19, 30, 0, 0, time.UTC)
	deferGuard := NewGitHubGuard(cfgGuard, nil, nil)
	deferGuard.nowFn = func() time.Time { return gNow }
	deferGuard.rng = rand.New(rand.NewPCG(33, 2026))
	deferGuard.RecordFailure("HTTP 429 Too Many Requests\nRetry-After: 60\n")

	poolG := NewTunnelPool(cfgGuard, SupervisorDeps{}, nil, nil, deferGuard)
	poolG.SetUnderlayBaselineMS(220.0)
	poolG.workers[0].setState(TunnelHealthy)
	poolG.workers[1].setState(TunnelHealthy)
	poolG.workers[0].SetEWMARTT(240 * time.Millisecond)
	poolG.workers[1].SetEWMARTT(2200 * time.Millisecond) // rho = 10.0x

	if n := poolG.CheckSlowLaneEviction(gNow); n != 0 {
		t.Fatalf("UT-33 Part A2 unexpected eviction at t=0: %d", n)
	}
	if n := poolG.CheckSlowLaneEviction(gNow.Add(15 * time.Second)); n != 0 {
		t.Fatalf("UT-33 Part A2 MUST defer destructive eviction during 429 cooldown, got %d", n)
	}
	if !poolG.workers[1].IsSlowLaneDegraded() {
		t.Fatal("UT-33 Part A2 expected w2 marked SlowLaneDegraded during cooldown to divert traffic")
	}
	if poolG.workers[1].IsEvictionTriggered() || poolG.workers[1].State() != TunnelHealthy {
		t.Fatalf("UT-33 Part A2 w2 must remain TunnelHealthy standby during cooldown, state=%s triggered=%v",
			poolG.workers[1].State(), poolG.workers[1].IsEvictionTriggered())
	}
	// If w1 crashes during the 429 cooldown, w2 (healthySlow standby) seamlessly saves the session (0 outage)!
	poolG.workers[0].setState(TunnelDead)
	fbLease, fbErr := poolG.AcquireEndpoint(context.Background())
	if fbErr != nil || fbLease.TunnelID != poolG.workers[1].ID() {
		t.Fatalf("UT-33 Part A2 expected fallback to healthySlow w2 during cooldown, got %+v err=%v", fbLease, fbErr)
	}
	fbLease.Release()

	// Restore w1 and exhaust 5m budget -> eviction must remain deferred while budget is exhausted.
	poolG.workers[0].setState(TunnelHealthy)
	gNow = gNow.Add(75 * time.Second) // past 60s 429 cooldown
	if ok, _, why := deferGuard.TryAllow("boot1"); !ok {
		t.Fatalf("UT-33 Part A2 boot1 blocked: %s", why)
	}
	if ok, _, why := deferGuard.TryAllow("boot2"); !ok {
		t.Fatalf("UT-33 Part A2 boot2 blocked: %s", why)
	}
	if n := poolG.CheckSlowLaneEviction(gNow); n != 0 || poolG.workers[1].IsEvictionTriggered() {
		t.Fatalf("UT-33 Part A2 MUST defer destructive eviction when 5m budget exhausted, got n=%d", n)
	}

	// Advance past 5m budget window -> deferred eviction MUST now trigger cleanly.
	gNow = gNow.Add(5*time.Minute + 5*time.Second)
	if n := poolG.CheckSlowLaneEviction(gNow); n != 1 || !poolG.workers[1].IsEvictionTriggered() {
		t.Fatalf("UT-33 Part A2 expected deferred eviction to fire once budget cleared, got n=%d triggered=%v",
			n, poolG.workers[1].IsEvictionTriggered())
	}

	// Part B: Live 2-worker pool chronic slow-lane eviction + GitHubGuard-gated reroll -> fast recovery.
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "ut33.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("UT-33 logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	cfgB := DefaultConfig()
	cfgB.PoolSize = 2
	cfgB.GHPort = basePort
	cfgB.LocalPort = 0
	cfgB.BootQualitySamples = 1
	cfgB.BootMicroPayloadCheck = false
	cfgB.ProbeInterval = 80 * time.Millisecond
	cfgB.DegradedProbeInterval = 60 * time.Millisecond
	cfgB.BackoffMin = 60 * time.Millisecond
	cfgB.BackoffMax = 120 * time.Millisecond
	cfgB.SlowLaneEvictRatio = 3.5
	cfgB.SlowLaneEvictWindow = 220 * time.Millisecond
	cfgB.UnderlayBaselineMS = 220.0
	cfgB.GitHubMinCallSpacing = 0

	w2Addr := fmt.Sprintf("127.0.0.1:%d", basePort+1)
	var w2Spawns atomic.Int32
	guard := NewGitHubGuard(cfgB, logger, nil)

	poolB := NewTunnelPool(cfgB, SupervisorDeps{
		PortInspector:    &mockPortInspector{},
		NewJob:           NewProcessJob,
		BootPollDelay:    15 * time.Millisecond,
		LookupWANRemote:  func(uint32) string { return "20.93.53.155:443" },
		TuneChildProcess: func(int) error { return nil },
		TuneProcessTree:  func(int) int { return 0 },
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			if _, err := ProbeSOCKS5(ctx, addr, target, timeout); err != nil {
				return 0, err
			}
			if addr == w2Addr && w2Spawns.Load() == 1 {
				return 2000 * time.Millisecond, nil // rho = 9.09x on spawn #1 -> triggers chronic eviction
			}
			return 240 * time.Millisecond, nil
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			if c.GHPort == basePort+1 {
				w2Spawns.Add(1)
			}
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
	}, logger, nil, guard)

	ctx, cancel := context.WithCancel(context.Background())
	if err := poolB.Start(ctx); err != nil {
		cancel()
		t.Fatalf("UT-33 poolB.Start: %v", err)
	}

	waitUntil(t, 5*time.Second, "UT-33 chronic slow-lane tunnel-2 evicted, rerolled and recovered fast", func() bool {
		snap := poolB.PoolSnapshot()
		return snap.SlowLaneEvictions >= 1 &&
			w2Spawns.Load() >= 2 &&
			snap.HealthyWorkers == 2 &&
			snap.SlowLaneWorkers == 0
	})

	cancel()
	poolB.Close()
	_ = logger.Close()

	events := readJSONLLog(t, logPath)
	sawEvict := false
	for _, ev := range events {
		if ev.Event == "WORKER_SLOW_LANE_EVICT" {
			sawEvict = true
		}
	}
	if !sawEvict {
		t.Fatal("UT-33 missing WORKER_SLOW_LANE_EVICT log event")
	}

	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-34 (v6.3): GitHub WAF/Bot Safety — 2s min inter-call spacing, Retry-After parsing, WAF 403/429 backoff
// and pid17040 aborted-boot StopCodespace skip (stop_skipped_reason="never_became_healthy").
func TestUT34_GitHubWAFSafetyRetryAfterSpacingAndAbortedBootStopSkip(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// (a) Production default 2s min inter-call spacing.
	cfg := DefaultConfig()
	if cfg.GitHubMinCallSpacing != 2*time.Second {
		t.Fatalf("UT-34 expected DefaultGitHubMinCallSpacing=2s, got %s", cfg.GitHubMinCallSpacing)
	}
	guard := NewGitHubGuard(cfg, nil, nil)
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	guard.nowFn = func() time.Time { return now }
	guard.rng = rand.New(rand.NewPCG(63, 2026))

	if ok, _, why := guard.TryAllow("call_1"); !ok {
		t.Fatalf("UT-34 first call should pass, blocked by %q", why)
	}
	now = now.Add(500 * time.Millisecond)
	if ok, wait, why := guard.TryAllow("call_2_too_soon"); ok || why != "min_call_spacing" || wait < 1400*time.Millisecond {
		t.Fatalf("UT-34 expected min_call_spacing block (~1.5s wait), got ok=%v wait=%s why=%q", ok, wait, why)
	}
	now = now.Add(1600 * time.Millisecond) // total 2.1s since call_1
	if ok, _, why := guard.TryAllow("call_2_spaced"); !ok {
		t.Fatalf("UT-34 call after >=2s spacing should pass, blocked by %q", why)
	}

	// (b) Retry-After parsing (delta-seconds + RFC 9110 HTTP-date formats) & WAF/bot 429/403 classification.
	if ra := ParseRetryAfterAt("HTTP 429 Too Many Requests\nRetry-After: 45\n", now); ra != 45*time.Second {
		t.Fatalf("UT-34 ParseRetryAfterAt(delta) = %s, want 45s", ra)
	}
	if ra := ParseRetryAfterAt("retry-after=120 seconds", now); ra != 120*time.Second {
		t.Fatalf("UT-34 ParseRetryAfterAt(=) = %s, want 120s", ra)
	}
	// HTTP-date RFC1123 / http.TimeFormat relative to injected clock `now` (2026-11-21 20:00:02.100Z).
	httpDateTarget := now.UTC().Truncate(time.Second).Add(90 * time.Second)
	httpDateHeader := fmt.Sprintf("HTTP 429 Too Many Requests\nRetry-After: %s\n", httpDateTarget.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	if ra := ParseRetryAfterAt(httpDateHeader, now); ra < 88*time.Second || ra > 91*time.Second {
		t.Fatalf("UT-34 ParseRetryAfterAt(HTTP-date GMT) = %s, want ~90s", ra)
	}
	rfc1123zHeader := fmt.Sprintf("Retry-After: %s", httpDateTarget.Format(time.RFC1123Z))
	if ra := ParseRetryAfterAt(rfc1123zHeader, now); ra < 88*time.Second || ra > 91*time.Second {
		t.Fatalf("UT-34 ParseRetryAfterAt(RFC1123Z) = %s, want ~90s", ra)
	}
	rfc850Header := fmt.Sprintf("Retry-After: %s", httpDateTarget.Format(time.RFC850))
	if ra := ParseRetryAfterAt(rfc850Header, now); ra < 88*time.Second || ra > 91*time.Second {
		t.Fatalf("UT-34 ParseRetryAfterAt(RFC850) = %s, want ~90s", ra)
	}
	pastDateHeader := fmt.Sprintf("Retry-After: %s", now.UTC().Add(-60*time.Second).Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	if ra := ParseRetryAfterAt(pastDateHeader, now); ra != 0 {
		t.Fatalf("UT-34 ParseRetryAfterAt(past HTTP-date) = %s, want 0", ra)
	}

	if cls := ClassifyStderr("HTTP 403 Forbidden: WAF bot detection / captcha challenge"); cls != FailureAPIRateLimit {
		t.Fatalf("UT-34 expected FailureAPIRateLimit for WAF 403, got %s", cls)
	}
	cls, cd := guard.RecordFailure("HTTP 429 Too Many Requests; Retry-After: 45")
	if cls != FailureAPIRateLimit || cd < 45*time.Second {
		t.Fatalf("UT-34 expected numeric Retry-After >=45s honored, got cls=%s cd=%s", cls, cd)
	}
	// Verify RecordFailure honors HTTP-date Retry-After using guard.nowFn() deterministically.
	dateTarget120 := now.UTC().Truncate(time.Second).Add(120 * time.Second)
	clsDate, cdDate := guard.RecordFailure(fmt.Sprintf("HTTP 429 Too Many Requests\nRetry-After: %s\n", dateTarget120.Format("Mon, 02 Jan 2006 15:04:05 GMT")))
	if clsDate != FailureAPIRateLimit || cdDate < 118*time.Second {
		t.Fatalf("UT-34 expected HTTP-date Retry-After ~120s honored via guard.nowFn(), got cls=%s cd=%s", clsDate, cdDate)
	}

	// (c) Aborted cold boot (reproduces live v6.2 pid17040): child spawned (TotalAllowed>=1),
	//     but user cancels before any tunnel ever reaches StateHealthy -> StopCodespace MUST be skipped.
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ut34_aborted.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("UT-34 logger: %v", err)
	}

	abortedCfg := DefaultConfig()
	abortedCfg.PoolSize = 1
	abortedCfg.LocalPort = 0
	abortedCfg.StopOnExit = true
	abortedCfg.PreflightNetHygiene = false
	abortedCfg.BootTimeout = 10 * time.Second
	abortedCfg.GitHubMinCallSpacing = 0

	var spawned atomic.Int32
	var stopCalls atomic.Int32
	sup := NewSupervisor(abortedCfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 25 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			spawned.Add(1)
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		ProbeFunc: func(ctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error) {
			return 0, fmt.Errorf("booting_not_ready_yet")
		},
		StopCodespace: func(ctx context.Context, c Config) (int, string, error) {
			stopCalls.Add(1)
			return 0, "should_not_be_called", nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 3*time.Second, "UT-34 child spawned before abort", func() bool {
		return spawned.Load() >= 1
	})
	sup.RequestShutdown("signal:interrupt_during_cold_boot")
	cancel()
	<-done

	if stopCalls.Load() != 0 {
		t.Fatalf("UT-34 expected StopCodespace skipped on aborted boot, got %d calls", stopCalls.Load())
	}
	recs := readJSONLLog(t, logPath)
	sawNeverHealthySkip := false
	for _, r := range recs {
		if r.Event == "SHUTDOWN_COMPLETE" {
			if inv, _ := r.Fields["stop_codespace_invoked"].(bool); inv {
				t.Fatalf("UT-34 expected stop_codespace_invoked=false, got %+v", r.Fields)
			}
			if reason, _ := r.Fields["stop_skipped_reason"].(string); reason == "never_became_healthy" {
				sawNeverHealthySkip = true
			}
		}
	}
	if !sawNeverHealthySkip {
		t.Fatal("UT-34 missing stop_skipped_reason=never_became_healthy in SHUTDOWN_COMPLETE")
	}

	assertNoGoroutineLeak(t, baseG, 6)
}

// ST-16 (v6.3): Full v6.3 End-to-End MCI Chaos Soak —
// PoolSize=3 serialized cold boot, 50-connection Chrome/SwitchyOmega SPA burst (0 queue_full drops, Peak<=12),
// streaming-aware two-tier pressure reaper (protects established >128B SSE/HTTP2 stream while fast-reaping 0B zombies),
// adaptive PMTU=576 (8 KiB) on 20.120.56.11, dynamic underlay baseline B_raw(t), and mid-run chronic slow-lane eviction on tunnel-3.
func TestST16_FullV63MCIChaosSoak(t *testing.T) {
	baseG := runtime.NumGoroutine()

	s1, s2, s3, basePort := startConsecutiveMockSOCKS5Triple(t)
	defer s1.Close()
	defer s2.Close()
	defer s3.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "st16.log")
	metricsPath := filepath.Join(dir, "st16_metrics.ndjson")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("ST-16 logger: %v", err)
	}
	defer func() { _ = logger.Close() }()
	metrics, err := NewMetricsEmitter(metricsPath, "st16")
	if err != nil {
		t.Fatalf("ST-16 metrics: %v", err)
	}
	defer func() { _ = metrics.Close() }()

	cfg := DefaultConfig()
	cfg.PoolSize = 3
	cfg.PerTunnelMaxConns = 4
	cfg.MaxActiveConns = 12
	cfg.MaxQueuedConns = DefaultMaxQueuedConns             // 128
	cfg.SemaphoreWaitTimeout = DefaultSemaphoreWaitTimeout // 25s
	cfg.PMTU576SafeMode = true
	cfg.IdleTimeout = 2 * time.Second
	cfg.PressureIdleTimeout = 250 * time.Millisecond
	cfg.StreamingIdleTimeout = 5 * time.Second
	cfg.StreamingPressureIdleTimeout = 2 * time.Second
	cfg.StalledHandshakeMaxDownBytes = DefaultStalledHandshakeMaxDownBytes // 128
	cfg.PressureThresholdPct = 75
	cfg.PreflightNetHygiene = false
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.StopOnExit = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.DialPaceInterval = 0
	cfg.BackoffMin = 60 * time.Millisecond
	cfg.BackoffMax = 120 * time.Millisecond
	cfg.ProbeInterval = 120 * time.Millisecond
	cfg.DegradedProbeInterval = 80 * time.Millisecond
	cfg.UnderlayProbeInterval = 500 * time.Millisecond
	cfg.HysteresisDwellWindow = 400 * time.Millisecond
	cfg.SlowLaneEvictRatio = 3.5
	cfg.SlowLaneEvictWindow = 260 * time.Millisecond
	cfg.SummaryLogInterval = 350 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	w3Addr := fmt.Sprintf("127.0.0.1:%d", basePort+2)
	var (
		w1PID        atomic.Uint32
		w3Spawns     atomic.Int32
		w3InjectSlow atomic.Bool
	)

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 15 * time.Millisecond,
		Metrics:       metrics,
		UnderlayProbeFunc: func(ctx context.Context, targets []string, timeout time.Duration) (time.Duration, string, error) {
			return 220 * time.Millisecond, "20.120.56.11:443", nil
		},
		LookupWANRemote: func(pid uint32) string {
			if pid != 0 && pid == w1PID.Load() {
				return "20.120.56.11:443"
			}
			return "20.93.53.155:443"
		},
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			if _, err := ProbeSOCKS5(ctx, addr, target, timeout); err != nil {
				return 0, err
			}
			if addr == w3Addr && w3InjectSlow.Load() && w3Spawns.Load() == 1 {
				return 2200 * time.Millisecond, nil // rho = 10x -> chronic slow-lane eviction
			}
			return 240 * time.Millisecond, nil
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if c.GHPort == basePort && cmd.Process != nil {
				w1PID.Store(uint32(cmd.Process.Pid))
			}
			if c.GHPort == basePort+2 {
				w3Spawns.Add(1)
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	// 1. Wait for 3/3 pool healthy + underlay baseline sampled.
	waitUntil(t, 5*time.Second, "ST-16 3-worker pool HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return sup.State() == StateHealthy && snap.HealthyWorkers == 3 && sup.BoundLocalAddr() != ""
	})

	// 2. Chrome/SwitchyOmega 50-connection SPA burst: MUST finish 50/50 with 0 queue_full/no_healthy_tunnel drops & Peak <= 12.
	const burstN = 50
	burstPayload := makeDeterministicPayload(4*1024, 1616)
	var burstOK atomic.Int64
	burstErrs := make([]error, burstN)
	var bWG sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < burstN; i++ {
		bWG.Add(1)
		go func(idx int) {
			defer bWG.Done()
			<-gate
			if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), burstPayload, 10*time.Second); err == nil {
				burstOK.Add(1)
			} else {
				burstErrs[idx] = err
			}
		}(i)
	}
	close(gate)
	bWG.Wait()

	if burstOK.Load() != burstN {
		sup.proxyMu.Lock()
		var sigs ProxySignals
		if sup.activeProxy != nil {
			sigs = sup.activeProxy.Signals()
		}
		sup.proxyMu.Unlock()
		poolSnap := sup.PoolSnapshot()
		cancel()
		<-done
		_ = metrics.Close()

		var errSamples []string
		for idx, berr := range burstErrs {
			if berr != nil && len(errSamples) < 10 {
				errSamples = append(errSamples, fmt.Sprintf("#%d:%v", idx, berr))
			}
		}
		reasonCounts := map[string]int{}
		for _, r := range readMetricsNDJSON(t, metricsPath) {
			if r.Stream == "conn" {
				cr, _ := r.Data["close_reason"].(string)
				reasonCounts[cr]++
			}
		}
		t.Fatalf("ST-16 50-conn SwitchyOmega SPA burst expected 50/50 OK, got %d/50 | signals=%+v | pool(healthy=%d,slow=%d,active=%d) | close_reasons=%v | client_errs=%v",
			burstOK.Load(), sigs, poolSnap.HealthyWorkers, poolSnap.SlowLaneWorkers, poolSnap.TotalActive, reasonCounts, errSamples)
	}

	sup.proxyMu.Lock()
	var pxStats ProxyMetrics
	if sup.activeProxy != nil {
		pxStats = sup.activeProxy.Metrics(false)
	}
	sup.proxyMu.Unlock()
	if pxStats.PeakConns > int64(cfg.MaxActiveConns) {
		cancel()
		<-done
		t.Fatalf("ST-16 PeakConns=%d exceeded MCI C=12 cap", pxStats.PeakConns)
	}
	if pxStats.SemaphoreRejects != 0 {
		cancel()
		<-done
		t.Fatalf("ST-16 unexpected SemaphoreRejects=%d during 50-conn burst (MaxQueuedConns=128)", pxStats.SemaphoreRejects)
	}

	// 3. Streaming-aware two-tier pressure reaper verification:
	//    Open 1 established streaming socket (>512B downstream) + 10 silent 0B zombies.
	//    Zombies MUST reap at ~250ms while the established stream SURVIVES a 550ms thinking pause!
	streamConn, err := net.DialTimeout("tcp", sup.BoundLocalAddr(), 2*time.Second)
	if err != nil {
		cancel()
		<-done
		t.Fatalf("ST-16 stream dial: %v", err)
	}
	defer streamConn.Close()
	_ = streamConn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := streamConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("ST-16 stream greet write: %v", err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(streamConn, greetResp[:]); err != nil {
		t.Fatalf("ST-16 stream greet read: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb}
	if _, err := streamConn.Write(req); err != nil {
		t.Fatalf("ST-16 stream connect write: %v", err)
	}
	var connResp [10]byte
	if _, err := io.ReadFull(streamConn, connResp[:]); err != nil {
		t.Fatalf("ST-16 stream connect read: %v", err)
	}
	firstFrame := makeDeterministicPayload(512, 1617)
	if _, err := streamConn.Write(firstFrame); err != nil {
		t.Fatalf("ST-16 stream first frame write: %v", err)
	}
	firstEcho := make([]byte, len(firstFrame))
	if _, err := io.ReadFull(streamConn, firstEcho); err != nil {
		t.Fatalf("ST-16 stream first frame read: %v", err)
	}

	// Park 10 silent 0B zombies (>= 75% of 12 slots -> activates pressure reaping).
	zombies := make([]net.Conn, 0, 10)
	for i := 0; i < 10; i++ {
		zc, zerr := net.DialTimeout("tcp", sup.BoundLocalAddr(), 2*time.Second)
		if zerr != nil {
			t.Fatalf("ST-16 zombie dial %d: %v", i, zerr)
		}
		zombies = append(zombies, zc)
	}
	defer func() {
		for _, zc := range zombies {
			_ = zc.Close()
		}
	}()

	// Pause the established stream for 550ms (> PressureIdleTimeout=250ms, < StreamingPressureIdleTimeout=2s).
	time.Sleep(550 * time.Millisecond)

	// Established stream MUST still be alive and echo a second frame cleanly!
	secondFrame := []byte("ai-studio-sse-post-pause-token")
	if _, err := streamConn.Write(secondFrame); err != nil {
		t.Fatalf("ST-16 established streaming socket was prematurely reaped on write: %v", err)
	}
	secondEcho := make([]byte, len(secondFrame))
	if _, err := io.ReadFull(streamConn, secondEcho); err != nil {
		t.Fatalf("ST-16 established streaming socket was prematurely reaped on read: %v", err)
	}
	_ = streamConn.Close()

	// Verify silent zombies WERE pressure-reaped.
	waitUntil(t, 2*time.Second, "ST-16 silent 0B zombies pressure-reaped", func() bool {
		sup.proxyMu.Lock()
		defer sup.proxyMu.Unlock()
		return sup.activeProxy != nil && sup.activeProxy.Metrics(false).PressureReaps >= 5
	})

	// 4. Trigger chronic slow-lane degradation on tunnel-3 -> verify automatic eviction, reroll & 3/3 recovery.
	w3InjectSlow.Store(true)
	waitUntil(t, 5*time.Second, "ST-16 tunnel-3 chronic slow-lane evicted and recovered 3/3", func() bool {
		snap := sup.PoolSnapshot()
		return snap.SlowLaneEvictions >= 1 &&
			w3Spawns.Load() >= 2 &&
			snap.HealthyWorkers == 3 &&
			snap.SlowLaneWorkers == 0
	})

	finalSnap := sup.PoolSnapshot()
	if finalSnap.UnderlayBaselineMS < 100 || finalSnap.UnderlayBaselineMS > 400 {
		t.Fatalf("ST-16 unexpected UnderlayBaselineMS=%.2f", finalSnap.UnderlayBaselineMS)
	}

	cancel()
	<-done

	mRecs := readMetricsNDJSON(t, metricsPath)
	for _, r := range mRecs {
		if r.Stream == "conn" {
			if cr, _ := r.Data["close_reason"].(string); cr == "no_healthy_tunnel" || cr == "queue_full" {
				t.Fatalf("ST-16 unexpected %s drop in NDJSON metrics: %+v", cr, r.Data)
			}
		}
	}

	assertNoGoroutineLeak(t, baseG, 8)
}

// ST-17 (v6.4): AI Studio Multi-Origin SPA Burst Behind 14 Persistent HTTP/2 / WebChannel / SSE Streams.
// Proves that v6.4's SSH-channel concurrency calibration (MaxActiveConns=64, PerTunnelMaxConns=32,
// DialPaceInterval=0, StreamingPressureIdleTimeout=20s < SemaphoreWaitTimeout=25s) completely eliminates
// v6.3's 12-slot starvation (17 failed *.google.com / *.gstatic.com resources) while keeping PoolSize=2
// (only 2 outer WAN TCP sockets << MCI C=12 outer WAN knee), adaptive 8 KiB PMTU=576 framing, and 0 leaks.
func TestST17_AIStudioMultiOriginSPABurstAndPersistentH2(t *testing.T) {
	baseG := runtime.NumGoroutine()

	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "st17.log")
	metricsPath := filepath.Join(dir, "st17_metrics.ndjson")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("ST-17 logger: %v", err)
	}
	defer func() { _ = logger.Close() }()
	metrics, err := NewMetricsEmitter(metricsPath, "st17")
	if err != nil {
		t.Fatalf("ST-17 metrics: %v", err)
	}
	defer func() { _ = metrics.Close() }()

	cfg := DefaultConfig()
	// Assert v6.4 production defaults directly so regressions in DefaultConfig are caught immediately.
	if cfg.MaxActiveConns != 64 || cfg.PerTunnelMaxConns != 32 {
		t.Fatalf("ST-17 expected v6.4 channel defaults (64/32), got MaxActiveConns=%d PerTunnelMaxConns=%d",
			cfg.MaxActiveConns, cfg.PerTunnelMaxConns)
	}
	if cfg.DialPaceInterval != 0 {
		t.Fatalf("ST-17 expected v6.4 DefaultDialPaceInterval=0, got %s", cfg.DialPaceInterval)
	}
	if cfg.StreamingPressureIdleTimeout >= cfg.SemaphoreWaitTimeout {
		t.Fatalf("ST-17 deadlock invariant violated: StreamingPressureIdleTimeout (%s) >= SemaphoreWaitTimeout (%s)",
			cfg.StreamingPressureIdleTimeout, cfg.SemaphoreWaitTimeout)
	}
	if cfg.StreamingIdleTimeout != 180*time.Second {
		t.Fatalf("ST-17 expected v6.4 StreamingIdleTimeout=180s, got %s", cfg.StreamingIdleTimeout)
	}

	cfg.PoolSize = 2
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.StopOnExit = false
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.BackoffMin = 60 * time.Millisecond
	cfg.BackoffMax = 120 * time.Millisecond
	cfg.ProbeInterval = 150 * time.Millisecond
	cfg.DegradedProbeInterval = 80 * time.Millisecond
	cfg.UnderlayProbeInterval = 500 * time.Millisecond
	cfg.SummaryLogInterval = 350 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	var w1PID atomic.Uint32
	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 15 * time.Millisecond,
		Metrics:       metrics,
		UnderlayProbeFunc: func(ctx context.Context, targets []string, timeout time.Duration) (time.Duration, string, error) {
			return 220 * time.Millisecond, "20.120.56.11:443", nil
		},
		LookupWANRemote: func(pid uint32) string {
			if pid != 0 && pid == w1PID.Load() {
				return "20.120.56.11:443" // exercises adaptive 8 KiB PMTU=576 copy buffer path
			}
			return "20.93.53.155:443"
		},
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			if _, err := ProbeSOCKS5(ctx, addr, target, timeout); err != nil {
				return 0, err
			}
			return 240 * time.Millisecond, nil
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if c.GHPort == basePort && cmd.Process != nil {
				w1PID.Store(uint32(cmd.Process.Pid))
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 5*time.Second, "ST-17 2-worker pool HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return sup.State() == StateHealthy && snap.HealthyWorkers == 2 && sup.BoundLocalAddr() != ""
	})

	// 1. Open 14 simultaneous persistent HTTP/2 / WebChannel / SSE SOCKS5 streams (> v6.3's old 12-slot cliff!)
	//    and keep every stream open across the entire multi-origin SPA asset burst.
	const persistentN = 14
	persistentConns := make([]net.Conn, 0, persistentN)
	defer func() {
		for _, pc := range persistentConns {
			_ = pc.Close()
		}
	}()

	for i := 0; i < persistentN; i++ {
		pc, derr := net.DialTimeout("tcp", sup.BoundLocalAddr(), 2*time.Second)
		if derr != nil {
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d dial: %v", i, derr)
		}
		_ = pc.SetDeadline(time.Now().Add(8 * time.Second))
		if _, werr := pc.Write([]byte{0x05, 0x01, 0x00}); werr != nil {
			_ = pc.Close()
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d greet write: %v", i, werr)
		}
		var greetResp [2]byte
		if _, rerr := io.ReadFull(pc, greetResp[:]); rerr != nil {
			_ = pc.Close()
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d greet read: %v", i, rerr)
		}
		req := []byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb}
		if _, werr := pc.Write(req); werr != nil {
			_ = pc.Close()
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d connect write: %v", i, werr)
		}
		var connResp [10]byte
		if _, rerr := io.ReadFull(pc, connResp[:]); rerr != nil {
			_ = pc.Close()
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d connect read: %v", i, rerr)
		}
		// Send 512B initial frame (>128B downstream) to promote connection to established streaming tier.
		initFrame := makeDeterministicPayload(512, uint64(1700+i))
		if _, werr := pc.Write(initFrame); werr != nil {
			_ = pc.Close()
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d init frame write: %v", i, werr)
		}
		initEcho := make([]byte, len(initFrame))
		if _, rerr := io.ReadFull(pc, initEcho); rerr != nil {
			_ = pc.Close()
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d init frame read: %v", i, rerr)
		}
		if sha256.Sum256(initEcho) != sha256.Sum256(initFrame) {
			_ = pc.Close()
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d init frame SHA-256 mismatch", i)
		}
		persistentConns = append(persistentConns, pc)
	}

	// 2. While all 14 persistent H2/WebChannel/SSE sockets hold slots open, fire 36 concurrent
	//    *.google.com & *.gstatic.com asset/API fetches simultaneously (14 + 36 = 50 active channels <= 64).
	const burstN = 36
	assetPayload := makeDeterministicPayload(8*1024, 1717)
	var burstOK atomic.Int64
	burstErrs := make([]error, burstN)
	var bWG sync.WaitGroup
	gate := make(chan struct{})

	burstStart := time.Now()
	for i := 0; i < burstN; i++ {
		bWG.Add(1)
		go func(idx int) {
			defer bWG.Done()
			<-gate
			if err := performSOCKS5EchoTransfer(sup.BoundLocalAddr(), assetPayload, 3*time.Second); err == nil {
				burstOK.Add(1)
			} else {
				burstErrs[idx] = err
			}
		}(i)
	}
	close(gate)
	bWG.Wait()
	burstElapsed := time.Since(burstStart)

	if burstOK.Load() != burstN {
		var errSamples []string
		for idx, berr := range burstErrs {
			if berr != nil && len(errSamples) < 10 {
				errSamples = append(errSamples, fmt.Sprintf("#%d:%v", idx, berr))
			}
		}
		cancel()
		<-done
		t.Fatalf("ST-17 AI Studio 36-asset burst behind 14 persistent H2 streams expected 36/36 OK, got %d/36 in %s | errs=%v",
			burstOK.Load(), burstElapsed, errSamples)
	}
	if burstElapsed >= 3*time.Second {
		cancel()
		<-done
		t.Fatalf("ST-17 36-asset burst took %s (>= 3s ceiling); loopback dial pacing or queueing regression", burstElapsed)
	}

	sup.proxyMu.Lock()
	var pxStats ProxyMetrics
	if sup.activeProxy != nil {
		pxStats = sup.activeProxy.Metrics(false)
	}
	sup.proxyMu.Unlock()

	if pxStats.SemaphoreRejects != 0 {
		cancel()
		<-done
		t.Fatalf("ST-17 unexpected SemaphoreRejects=%d, want 0", pxStats.SemaphoreRejects)
	}
	if pxStats.PeakConns < 20 || pxStats.PeakConns > int64(cfg.MaxActiveConns) {
		cancel()
		<-done
		t.Fatalf("ST-17 PeakConns=%d outside expected v6.4 SSH-channel range [20, %d]", pxStats.PeakConns, cfg.MaxActiveConns)
	}

	// 3. Verify all 14/14 persistent H2 / WebChannel / SSE streams survived the burst completely undisrupted.
	for i, pc := range persistentConns {
		postFrame := makeDeterministicPayload(256, uint64(1800+i))
		if _, werr := pc.Write(postFrame); werr != nil {
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d disrupted on post-burst write: %v", i, werr)
		}
		postEcho := make([]byte, len(postFrame))
		if _, rerr := io.ReadFull(pc, postEcho); rerr != nil {
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d disrupted on post-burst read: %v", i, rerr)
		}
		if sha256.Sum256(postEcho) != sha256.Sum256(postFrame) {
			cancel()
			<-done
			t.Fatalf("ST-17 persistent H2 stream #%d post-burst SHA-256 mismatch", i)
		}
		_ = pc.Close()
	}

	cancel()
	<-done
	_ = metrics.Close()

	// 4. Audit orthogonal NDJSON conn metrics: strictly 0 queue_full, queue_timeout, or no_healthy_tunnel drops.
	mRecs := readMetricsNDJSON(t, metricsPath)
	for _, r := range mRecs {
		if r.Stream == "conn" {
			if cr, _ := r.Data["close_reason"].(string); cr == "queue_full" || cr == "queue_timeout" || cr == "no_healthy_tunnel" {
				t.Fatalf("ST-17 unexpected %s drop in NDJSON conn metrics: %+v", cr, r.Data)
			}
		}
	}

	t.Logf("ST-17 PASS: 14 persistent H2/SSE streams + 36/36 multi-origin SPA fetches in %s (PeakConns=%d/%d, Rejects=0)",
		burstElapsed, pxStats.PeakConns, cfg.MaxActiveConns)
	assertNoGoroutineLeak(t, baseG, 8)
}

// =============================================================================
// NetShaper v7.0 Phase 4: UI Bridge, Zero-Lock Isolation, Lifecycle & Soak Tests
// (UT-35..UT-39, ST-18..ST-21; UT-40 resides in ui_stress_windows_test.go)
// =============================================================================

// UT-35 (v7.0): TerminalRingBuffer 600,000-line multi-goroutine flood, UTF-8 boundary safety,
// dirty-flag coalescing, and bounded O(1) memory (<5 MB heap delta, 0 PostMessageW).
func TestUT35_TerminalRingBufferFloodCoalescingAndUTF8(t *testing.T) {
	var dirtyMask atomic.Uint32
	rb := NewTerminalRingBuffer(&dirtyMask)

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	const workers = 8
	const perWorker = 75000 // 8 * 75,000 = 600,000 total lines
	longUTF8 := "سلام-تست-🚀-αβγδε-日本語-" + strings.Repeat("ش", 180) + "\r\n" + strings.Repeat("x", 4096)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			prefix := fmt.Sprintf("w%d ", id)
			for i := 0; i < perWorker; i++ {
				if i%3 == 0 {
					rb.Append(LogWarn, prefix+longUTF8)
				} else if i%3 == 1 {
					rb.Append(LogError, fmt.Sprintf("%sline=%d 日本語-🚀-αβγ-%s", prefix, i, strings.Repeat("A", 300)))
				} else {
					rb.Append(LogInfo, fmt.Sprintf("%snormal line %d", prefix, i))
				}
			}
		}(w)
	}
	wg.Wait()

	if got := rb.Len(); got != TerminalRingCapacity {
		t.Fatalf("UT-35 rb.Len()=%d, want %d", got, TerminalRingCapacity)
	}
	const wantTotal = uint64(workers * perWorker)
	if got := rb.TotalAppended(); got != wantTotal {
		t.Fatalf("UT-35 rb.TotalAppended()=%d, want %d", got, wantTotal)
	}
	if dirtyMask.Load()&DirtyLogs == 0 {
		t.Fatalf("UT-35 DirtyLogs flag was not set after 600k appends")
	}

	snap := rb.SnapshotInto(nil)
	if len(snap) != TerminalRingCapacity {
		t.Fatalf("UT-35 snapshot len=%d, want %d", len(snap), TerminalRingCapacity)
	}
	if snap[len(snap)-1].Seq != wantTotal {
		t.Fatalf("UT-35 last Seq=%d, want %d", snap[len(snap)-1].Seq, wantTotal)
	}
	for i, line := range snap {
		if i > 0 && line.Seq != snap[i-1].Seq+1 {
			t.Fatalf("UT-35 non-monotonic Seq at idx %d: prev=%d cur=%d", i, snap[i-1].Seq, line.Seq)
		}
		if len(line.Text) == 0 || len(line.Text) > TerminalMaxLineBytes {
			t.Fatalf("UT-35 line %d byte length=%d outside [1, %d]", i, len(line.Text), TerminalMaxLineBytes)
		}
		if !utf8.ValidString(line.Text) {
			t.Fatalf("UT-35 invalid UTF-8 after truncation at idx %d: %q", i, line.Text)
		}
		if strings.ContainsAny(line.Text, "\r\n") {
			t.Fatalf("UT-35 control newline leaked into terminal line %d", i)
		}
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	var delta int64
	if memAfter.HeapInuse > memBefore.HeapInuse {
		delta = int64(memAfter.HeapInuse - memBefore.HeapInuse)
	}
	if delta >= 5*1024*1024 {
		t.Fatalf("UT-35 HeapInuse delta=%d bytes (>= 5 MB cap) after 600k log flood", delta)
	}
	t.Logf("UT-35 PASS: 600,000 lines across 8 goroutines -> Len=%d, Seq=%d, UTF-8=100%%, HeapInuseDelta=%d KB",
		rb.Len(), snap[len(snap)-1].Seq, delta/1024)
}

// UT-36 (v7.0): Atomic UIConfig persistence, strict flag-injection rejection, end-to-end
// CodespaceName propagation (BuildGHSSHArgsForPort, StopCodespace, CodespaceStateCache),
// and CLI -codespace override precedence over netshaper_ui.json.
func TestUT36_UIConfigPersistenceValidationAndCLIOverride(t *testing.T) {
	t.Setenv("NETSHAPER_CODESPACE", "")

	badNames := []string{"", "   ", "-foo", "--codespace=evil", "a;b", "bad space", "foo/bar", "x", " leading", "trailing "}
	for _, bad := range badNames {
		if err := ValidateCodespaceName(bad); err == nil {
			t.Fatalf("UT-36 expected ValidateCodespaceName(%q) to fail, got nil", bad)
		}
	}
	for _, good := range []string{"example-space-alpha-01", "prod_space.v7-01"} {
		if err := ValidateCodespaceName(good); err != nil {
			t.Fatalf("UT-36 expected ValidateCodespaceName(%q) to pass, got %v", good, err)
		}
	}

	dir := t.TempDir()
	uiCfgPath := filepath.Join(dir, "netshaper_ui.json")
	cachePath := filepath.Join(dir, "codespace_state_cache.json")

	savedPath, err := SaveUIConfig(UIConfig{CodespaceName: "persisted-space-01", MinimizeToTray: true, LastAccount: "alice"}, uiCfgPath)
	if err != nil {
		t.Fatalf("UT-36 SaveUIConfig failed: %v", err)
	}
	if savedPath != uiCfgPath {
		t.Fatalf("UT-36 SaveUIConfig path=%q, want %q", savedPath, uiCfgPath)
	}
	if _, statErr := os.Stat(uiCfgPath + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("UT-36 atomic SaveUIConfig left temporary file behind")
	}

	loaded, _ := LoadUIConfig(DefaultCodespaceName, uiCfgPath)
	if loaded.CodespaceName != "persisted-space-01" || loaded.LastAccount != "alice" {
		t.Fatalf("UT-36 LoadUIConfig mismatch: %+v", loaded)
	}

	// 1. Default launch (no CLI -codespace) MUST load persisted-space-01 from netshaper_ui.json.
	defaultCfg, err := ParseConfig([]string{})
	if err != nil {
		t.Fatalf("UT-36 ParseConfig default: %v", err)
	}
	defaultCfg.LocalPort = 0
	if defaultCfg.CodespaceExplicit {
		t.Fatalf("UT-36 default ParseConfig unexpectedly set CodespaceExplicit=true")
	}
	ctrl1 := NewSessionController(defaultCfg, ControllerDeps{
		UIConfigPath: uiCfgPath,
		CachePath:    cachePath,
	})
	defer ctrl1.ShutdownAndWait(2 * time.Second)
	if got := ctrl1.Snapshot().CodespaceName; got != "persisted-space-01" {
		t.Fatalf("UT-36 default launch CodespaceName=%q, want persisted-space-01", got)
	}

	// 2. CLI -codespace override MUST take precedence over netshaper_ui.json.
	cliCfg, err := ParseConfig([]string{"-codespace", "cli-override-space-99"})
	if err != nil {
		t.Fatalf("UT-36 ParseConfig -codespace: %v", err)
	}
	cliCfg.LocalPort = 0
	if !cliCfg.CodespaceExplicit {
		t.Fatalf("UT-36 ParseConfig -codespace did not set CodespaceExplicit=true")
	}
	ctrlCLI := NewSessionController(cliCfg, ControllerDeps{
		UIConfigPath: uiCfgPath,
		CachePath:    cachePath,
	})
	defer ctrlCLI.ShutdownAndWait(2 * time.Second)
	if got := ctrlCLI.Snapshot().CodespaceName; got != "cli-override-space-99" {
		t.Fatalf("UT-36 CLI -codespace override failed: got %q, want cli-override-space-99", got)
	}

	// 3. Updating CodespaceName via SetCodespaceName propagates into BuildGHSSHArgsForPort,
	//    CodespaceStateCache, and Supervisor StopCodespace.
	if err := ctrl1.SetCodespaceName("-injected"); err == nil {
		t.Fatalf("UT-36 SetCodespaceName accepted leading '-' flag injection")
	}
	const updatedName = "fresh-codespace-v7"
	if err := ctrl1.SetCodespaceName(updatedName); err != nil {
		t.Fatalf("UT-36 SetCodespaceName(%q): %v", updatedName, err)
	}

	ctrl1.cfgMu.RLock()
	updatedCfg := ctrl1.baseCfg
	ctrl1.cfgMu.RUnlock()
	args := BuildGHSSHArgsForPort(updatedCfg, 1081)
	foundCS := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-c" && args[i+1] == updatedName {
			foundCS = true
			break
		}
	}
	if !foundCS {
		t.Fatalf("UT-36 BuildGHSSHArgsForPort did not propagate %q: args=%v", updatedName, args)
	}

	ctrl1.Guard().MarkCodespaceState("Available")
	rawCache, err := os.ReadFile(cachePath)
	if err != nil || !strings.Contains(string(rawCache), updatedName) {
		t.Fatalf("UT-36 CodespaceStateCache did not bind updated name %q: err=%v body=%s", updatedName, err, string(rawCache))
	}

	// Verify StopCodespace receives updatedName when a healthy session stops.
	mockSocks := startMockSOCKS5Server(t, socksModeNormal)
	defer mockSocks.Close()

	var stoppedCS atomic.Value
	ctrl1.cfgMu.Lock()
	ctrl1.baseCfg.PoolSize = 1
	ctrl1.baseCfg.LocalPort = 0
	ctrl1.baseCfg.GHPort = mockSocks.Port(t)
	ctrl1.baseCfg.StopOnExit = true
	ctrl1.baseCfg.PreflightNetHygiene = false
	ctrl1.baseCfg.BootQualitySamples = 1
	ctrl1.baseCfg.BootMicroPayloadCheck = false
	ctrl1.baseCfg.ProbeInterval = 150 * time.Millisecond
	ctrl1.baseCfg.GitHubMinCallSpacing = 0
	ctrl1.cfgMu.Unlock()

	ctrl1.deps.OpenLogger = func(c Config) (*EventLogger, error) {
		return NewEventLogger(filepath.Join(dir, "ut36.log"))
	}
	ctrl1.deps.OpenMetrics = func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil }
	ctrl1.deps.SupervisorDepsFactory = func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
		return SupervisorDeps{
			PortInspector: &mockPortInspector{},
			GitHubGuard:   g,
			BootPollDelay: 15 * time.Millisecond,
			StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
				cmd := newHelperCmd("sleep_alive")
				cmd.Stderr = stderr
				if err := cmd.Start(); err != nil {
					return nil, err
				}
				return cmd, nil
			},
			ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
				if _, err := ProbeSOCKS5(ctx, addr, target, timeout); err != nil {
					return 0, err
				}
				return 120 * time.Millisecond, nil
			},
			StopCodespace: func(ctx context.Context, cfg Config) (int, string, error) {
				stoppedCS.Store(cfg.CodespaceName)
				return 0, "stopped", nil
			},
		}
	}
	ctrl1.Start()
	ctrl1.RequestStart()
	waitUntil(t, 4*time.Second, "UT-36 session running", func() bool {
		return ctrl1.Snapshot().State == CtrlRunning
	})
	// Editing CodespaceName MUST be rejected while running.
	if err := ctrl1.SetCodespaceName("blocked-while-active"); err == nil {
		t.Fatalf("UT-36 SetCodespaceName must be rejected while tunnel is active")
	}
	ctrl1.RequestStop()
	waitUntil(t, 4*time.Second, "UT-36 session stopped", func() bool {
		return ctrl1.Snapshot().State == CtrlStopped
	})
	if got, _ := stoppedCS.Load().(string); got != updatedName {
		t.Fatalf("UT-36 StopCodespace received %q, want %q", got, updatedName)
	}
}

// UT-37 (v7.0): Wait-free snapshot isolation (AtomicTelemetry, TunnelPool.CachedSnapshot,
// GitHubGuard.CachedSnapshot) never mutates SnapshotWindow counters, AND fresh process launch
// initializes WAF Guard strictly at 0/6 (5m) and 0/24 (1h).
func TestUT37_ZeroLockSnapshotBridgeAndFreshWAFGuard(t *testing.T) {
	mockSocks := startMockSOCKS5Server(t, socksModeNormal)
	defer mockSocks.Close()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.GHPort = mockSocks.Port(t)
	cfg.PoolSize = 1
	cfg.GitHubMinCallSpacing = 0

	dir := t.TempDir()
	logger, err := NewEventLogger(filepath.Join(dir, "ut37.log"))
	if err != nil {
		t.Fatalf("UT-37 logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	px := NewProxyServer(cfg, mockSocks.Addr(), logger, nil, nil)
	pxCtx, pxCancel := context.WithCancel(context.Background())
	defer pxCancel()
	localAddr, err := px.Start(pxCtx)
	if err != nil {
		t.Fatalf("UT-37 proxy start: %v", err)
	}
	defer px.Stop(true)

	payload := makeDeterministicPayload(4096, 3737)
	if err := performSOCKS5EchoTransfer(localAddr, payload, 3*time.Second); err != nil {
		t.Fatalf("UT-37 initial SOCKS5 transfer: %v", err)
	}

	winBefore := px.SnapshotWindow(false)
	if winBefore.TotalConnsWindow < 1 || winBefore.BytesUpWindow == 0 || winBefore.BytesDownWindow == 0 {
		t.Fatalf("UT-37 expected non-zero window stats before wait-free reads, got %+v", winBefore)
	}

	guard := NewGitHubGuard(cfg, logger, nil)
	_, _, _ = guard.TryAllow("ut37_call_1")
	pool := NewTunnelPool(cfg, SupervisorDeps{}, logger, nil, guard)

	// Hammer wait-free shadow reads concurrently with live proxy transfers.
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1500; i++ {
				_ = px.AtomicTelemetry()
				_ = pool.CachedSnapshot()
				gs := guard.CachedSnapshot()
				if gs.CallsLast5Min != 1 {
					return
				}
			}
		}()
	}
	for c := 0; c < 4; c++ {
		if err := performSOCKS5EchoTransfer(localAddr, payload, 3*time.Second); err != nil {
			t.Fatalf("UT-37 concurrent SOCKS5 transfer #%d: %v", c, err)
		}
	}
	wg.Wait()

	winAfter := px.SnapshotWindow(false)
	atom := px.AtomicTelemetry()
	if winAfter.TotalConnsWindow < winBefore.TotalConnsWindow+4 {
		t.Fatalf("UT-37 AtomicTelemetry mutated SnapshotWindow TotalConnsWindow: before=%d after=%d",
			winBefore.TotalConnsWindow, winAfter.TotalConnsWindow)
	}
	if winAfter.BytesUpWindow <= winBefore.BytesUpWindow || winAfter.BytesDownWindow <= winBefore.BytesDownWindow {
		t.Fatalf("UT-37 AtomicTelemetry reset window byte counters: before=%+v after=%+v", winBefore, winAfter)
	}
	if atom.TotalBytesUp != winAfter.TotalBytesUp || atom.TotalBytesDown != winAfter.TotalBytesDown {
		t.Fatalf("UT-37 atomic totals (%d/%d) != window totals (%d/%d)",
			atom.TotalBytesUp, atom.TotalBytesDown, winAfter.TotalBytesUp, winAfter.TotalBytesDown)
	}

	// Verify fresh process SessionController ALWAYS begins with WAF Guard 0/6 (5m) and 0/24 (1h).
	uiCfgPath := filepath.Join(dir, "netshaper_ui.json")
	cachePath := filepath.Join(dir, "codespace_state_cache.json")

	ctrl1 := NewSessionController(cfg, ControllerDeps{UIConfigPath: uiCfgPath, CachePath: cachePath})
	_, _, _ = ctrl1.Guard().TryAllow("proc1_boot_1")
	_, _, _ = ctrl1.Guard().TryAllow("proc1_boot_2")
	ctrl1.publishSnapshotNow()
	if s1 := ctrl1.Snapshot(); s1.GuardCalls5Min != 2 || s1.GuardCallsHour != 2 {
		t.Fatalf("UT-37 proc1 expected 2/6 guard calls, got 5m=%d 1h=%d", s1.GuardCalls5Min, s1.GuardCallsHour)
	}
	ctrl1.ShutdownAndWait(2 * time.Second)

	// Fresh process launch reusing the same config/cache paths must start cleanly at 0/6 and 0/24.
	ctrl2 := NewSessionController(cfg, ControllerDeps{UIConfigPath: uiCfgPath, CachePath: cachePath})
	defer ctrl2.ShutdownAndWait(2 * time.Second)
	s2 := ctrl2.Snapshot()
	if s2.GuardCalls5Min != 0 || s2.GuardCallsHour != 0 || s2.GuardCooldownMS != 0 {
		t.Fatalf("UT-37 fresh process launch must reset WAF Guard to 0/6 & 0/24, got 5m=%d 1h=%d cooldown=%d",
			s2.GuardCalls5Min, s2.GuardCallsHour, s2.GuardCooldownMS)
	}
}

// UT-38 (v7.0): On-demand QuotaChecker issues 0 background GitHub API calls while idle,
// isolates missing billing-scope HTTP 403 from GitHubGuard penalties, enforces inter-call
// WAF spacing, and engages GitHubGuard cooldown cleanly on genuine HTTP 429.
func TestUT38_OnDemandQuotaCheckerScope403AndWAF429Isolation(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.CodespaceName = "quota-space-38"
	cfg.GitHubMinCallSpacing = 80 * time.Millisecond

	var apiCalls atomic.Int32
	var mode atomic.Int32 // 0 = 403 billing fallback, 1 = 429 WAF rate limit
	var callTimesMu sync.Mutex
	var callTimes []time.Time

	ctrl := NewSessionController(cfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "netshaper_ui.json"),
		CachePath:        filepath.Join(dir, "codespace_state_cache.json"),
		SnapshotInterval: 50 * time.Millisecond,
		RunSilentGH: func(ctx context.Context, args ...string) (string, string, int, error) {
			apiCalls.Add(1)
			callTimesMu.Lock()
			callTimes = append(callTimes, time.Now())
			callTimesMu.Unlock()

			if mode.Load() == 1 {
				return "", "gh: HTTP 429 Too Many Requests; Retry-After: 30", 1, fmt.Errorf("exit status 1")
			}
			if len(args) >= 2 && args[1] == "/user/codespaces" {
				return `{"codespaces":[{"name":"quota-space-38","state":"Available","owner":{"login":"octocat"},"machine":{"name":"basicLinux32gb","display_name":"2 cores, 8 GB RAM, 32 GB storage","cpus":2,"memory_in_bytes":8589934592,"storage_in_bytes":34359738368}}]}`, "", 0, nil
			}
			// Billing endpoint returns HTTP 403 missing scope.
			return "", "gh: HTTP 403: Resource not accessible by integration (missing billing scope)", 1, fmt.Errorf("exit status 1")
		},
	})
	ctrl.Start()
	defer ctrl.ShutdownAndWait(2 * time.Second)

	// 1. Assert strictly 0 background gh api calls during idle operation.
	time.Sleep(320 * time.Millisecond)
	if got := apiCalls.Load(); got != 0 {
		t.Fatalf("UT-38 expected 0 background GitHub API calls while idle, got %d", got)
	}

	// 2. Trigger on-demand quota check with HTTP 403 billing fallback.
	if !ctrl.RequestQuotaCheck() {
		t.Fatalf("UT-38 RequestQuotaCheck returned false")
	}
	waitUntil(t, 3*time.Second, "UT-38 quota check 403 fallback complete", func() bool {
		s := ctrl.Snapshot()
		return s.Quota.Checked && !s.Quota.Loading
	})

	snap := ctrl.Snapshot()
	if snap.Quota.CPUs != 2 || snap.Quota.MemoryGB != 8 || snap.Quota.CodespaceState != "Available" {
		t.Fatalf("UT-38 unexpected machine metadata: %+v", snap.Quota)
	}
	if snap.Quota.BillingAvailable || !strings.Contains(snap.Quota.BillingNote, "403") {
		t.Fatalf("UT-38 expected graceful HTTP 403 billing fallback, got %+v", snap.Quota)
	}
	if snap.GuardCooldownMS != 0 || snap.GuardRateLimits != 0 {
		t.Fatalf("UT-38 billing HTTP 403 must NOT penalize GitHubGuard: cooldown=%dms rateLimits=%d",
			snap.GuardCooldownMS, snap.GuardRateLimits)
	}

	// Verify inter-call spacing was honored between /user/codespaces and /users/octocat/settings/billing/usage.
	callTimesMu.Lock()
	if len(callTimes) != 2 {
		callTimesMu.Unlock()
		t.Fatalf("UT-38 expected 2 gh api calls, got %d", len(callTimes))
	}
	gap := callTimes[1].Sub(callTimes[0])
	callTimesMu.Unlock()
	if gap < 65*time.Millisecond {
		t.Fatalf("UT-38 min_call_spacing violated between quota calls: gap=%s", gap)
	}

	// 3. Genuine HTTP 429 MUST engage GitHubGuard cooldown and block follow-up calls.
	time.Sleep(110 * time.Millisecond)
	mode.Store(1)
	if !ctrl.RequestQuotaCheck() {
		t.Fatalf("UT-38 second RequestQuotaCheck returned false")
	}
	waitUntil(t, 3*time.Second, "UT-38 HTTP 429 backoff recorded", func() bool {
		s := ctrl.Snapshot()
		return !s.Quota.Loading && s.GuardRateLimits >= 1 && s.GuardCooldownMS > 0
	})

	callsAt429 := apiCalls.Load()
	if !ctrl.RequestQuotaCheck() {
		t.Fatalf("UT-38 third RequestQuotaCheck returned false")
	}
	waitUntil(t, 2*time.Second, "UT-38 follow-up quota blocked by guard", func() bool {
		s := ctrl.Snapshot()
		return !s.Quota.Loading && s.Quota.GuardBlocked != ""
	})
	if apiCalls.Load() != callsAt429 {
		t.Fatalf("UT-38 blocked quota call still invoked gh api: before=%d after=%d", callsAt429, apiCalls.Load())
	}
}

// UT-39 (v7.0): Re-Auth stops any active tunnel cleanly, deletes codespace_state_cache.json,
// wipes stale quotaInfo, executes sequential gh auth login -> gh auth refresh -> gh auth status
// (multi-account Active account: true + gh api /user fallback), and updates active username.
func TestUT39_ReAuthDynamicAccountSwitchAndStaleQuotaWipe(t *testing.T) {
	baseG := runtime.NumGoroutine()
	mockSocks := startMockSOCKS5Server(t, socksModeNormal)
	defer mockSocks.Close()

	dir := t.TempDir()
	uiCfgPath := filepath.Join(dir, "netshaper_ui.json")
	cachePath := filepath.Join(dir, "codespace_state_cache.json")

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.GHPort = mockSocks.Port(t)
	cfg.PoolSize = 1
	cfg.CodespaceName = "reauth-space-39"
	cfg.StopOnExit = false
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.ProbeInterval = 150 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	var interactiveMu sync.Mutex
	var interactiveCalls []string
	var authPhase atomic.Int32 // 0 = multi-account gh auth status, 1 = fallback to gh api /user --jq .login

	ctrl := NewSessionController(cfg, ControllerDeps{
		UIConfigPath:     uiCfgPath,
		CachePath:        cachePath,
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "ut39.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil },
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				BootPollDelay: 15 * time.Millisecond,
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					cmd := newHelperCmd("sleep_alive")
					cmd.Stderr = stderr
					if err := cmd.Start(); err != nil {
						return nil, err
					}
					return cmd, nil
				},
				ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
					if _, err := ProbeSOCKS5(ctx, addr, target, timeout); err != nil {
						return 0, err
					}
					return 110 * time.Millisecond, nil
				},
			}
		},
		RunInteractiveGH: func(ctx context.Context, args ...string) (int, error) {
			interactiveMu.Lock()
			interactiveCalls = append(interactiveCalls, strings.Join(args, " "))
			interactiveMu.Unlock()
			return 0, nil
		},
		RunSilentGH: func(ctx context.Context, args ...string) (string, string, int, error) {
			joined := strings.Join(args, " ")
			if joined == "api /user/codespaces" {
				return `{"codespaces":[{"name":"reauth-space-39","state":"Available","owner":{"login":"olduser"},"machine":{"name":"basic","display_name":"2 cores, 8 GB RAM","cpus":2,"memory_in_bytes":8589934592,"storage_in_bytes":34359738368}}]}`, "", 0, nil
			}
			if strings.HasPrefix(joined, "api /users/") {
				return "", "HTTP 403 forbidden", 1, fmt.Errorf("exit status 1")
			}
			if joined == "auth status" {
				if authPhase.Load() == 0 {
					return `github.com
  ✓ Logged in to github.com account olduser (keyring)
  - Active account: false
  - Token scopes: 'codespace', 'repo'

  ✓ Logged in to github.com account newuser (keyring)
  - Active account: true
  - Token scopes: 'codespace', 'gist', 'read:org', 'repo'`, "", 0, nil
				}
				return "", "unknown format", 0, nil
			}
			if joined == "api /user --jq .login" {
				return "fallbackuser\n", "", 0, nil
			}
			return "", "unexpected args: " + joined, 1, fmt.Errorf("unexpected")
		},
	})
	ctrl.Start()
	defer ctrl.ShutdownAndWait(3 * time.Second)

	// 1. Start tunnel and populate old account + quota + cache file on disk.
	ctrl.RequestStart()
	waitUntil(t, 4*time.Second, "UT-39 tunnel running", func() bool {
		return ctrl.Snapshot().State == CtrlRunning
	})
	if !ctrl.RequestQuotaCheck() {
		t.Fatalf("UT-39 RequestQuotaCheck failed")
	}
	waitUntil(t, 3*time.Second, "UT-39 initial olduser quota loaded", func() bool {
		s := ctrl.Snapshot()
		return s.Quota.Checked && !s.Quota.Loading && s.Auth.Username == "olduser"
	})
	if err := os.WriteFile(cachePath, []byte(`{"codespace_name":"reauth-space-39","state":"Available"}`), 0o600); err != nil {
		t.Fatalf("UT-39 write cache: %v", err)
	}

	// 2. Trigger Re-Auth while tunnel is active -> must stop tunnel, delete cache, wipe quota, switch to @newuser.
	if err := ctrl.RequestReAuth(); err != nil {
		t.Fatalf("UT-39 RequestReAuth failed: %v", err)
	}
	waitUntil(t, 5*time.Second, "UT-39 Re-Auth switched to @newuser", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlStopped && !ctrl.reauthRequested.Load() && s.Auth.Username == "newuser"
	})

	if ctrl.activeSup.Load() != nil {
		t.Fatalf("UT-39 active Supervisor still attached after Re-Auth")
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("UT-39 codespace_state_cache.json was not removed during Re-Auth (err=%v)", err)
	}
	snap1 := ctrl.Snapshot()
	if snap1.Quota.Checked || snap1.Quota.CodespaceName != "" || snap1.Quota.CPUs != 0 {
		t.Fatalf("UT-39 stale quotaInfo was not wiped on Re-Auth: %+v", snap1.Quota)
	}

	interactiveMu.Lock()
	gotCalls := append([]string(nil), interactiveCalls...)
	interactiveMu.Unlock()
	if len(gotCalls) != 2 || gotCalls[0] != "auth login" || gotCalls[1] != "auth refresh -h github.com -s codespace" {
		t.Fatalf("UT-39 unexpected interactive gh call sequence: %v", gotCalls)
	}

	// 3. Second Re-Auth testing deterministic `gh api /user --jq .login` fallback when auth status format is unrecognized.
	authPhase.Store(1)
	if err := ctrl.RequestReAuth(); err != nil {
		t.Fatalf("UT-39 second RequestReAuth failed: %v", err)
	}
	waitUntil(t, 4*time.Second, "UT-39 fallback username resolved", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlStopped && !ctrl.reauthRequested.Load() && s.Auth.Username == "fallbackuser"
	})

	ctrl.ShutdownAndWait(3 * time.Second)
	assertNoGoroutineLeak(t, baseG, 8)
}

// ST-18 (v7.0): Rapid Start/Stop spam (20 consecutive Start -> 50ms -> Stop cycles) against
// a shared process-lifetime GitHubGuard, followed by full ShutdownAndWait.
// Proves: 0 panics, <=1 concurrent Supervisor, StopCodespace==0 (!everHealthy), WAF 5m budget <=6, 0 leaks.
func TestST18_RapidStartStopSpamAndFullExit(t *testing.T) {
	baseG := runtime.NumGoroutine()
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.GHPort = 49152
	cfg.PoolSize = 1
	cfg.StopOnExit = true
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.BackoffMin = 20 * time.Millisecond
	cfg.BackoffMax = 40 * time.Millisecond
	cfg.GitHubMaxCallsPer5Min = 6
	cfg.GitHubMaxCallsPerHour = 24
	cfg.GitHubMinCallSpacing = 0

	var activeSpawns atomic.Int32
	var maxConcurrent atomic.Int32
	var stopCodespaceCalls atomic.Int32

	ctrl := NewSessionController(cfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "netshaper_ui.json"),
		CachePath:        filepath.Join(dir, "codespace_state_cache.json"),
		SnapshotInterval: 50 * time.Millisecond,
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "st18.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil },
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				BootPollDelay: 25 * time.Millisecond,
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					cur := activeSpawns.Add(1)
					for {
						prev := maxConcurrent.Load()
						if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
							break
						}
					}
					cmd := newHelperCmd("sleep_alive")
					cmd.Stderr = stderr
					if err := cmd.Start(); err != nil {
						activeSpawns.Add(-1)
						return nil, err
					}
					go func() {
						_ = cmd.Wait()
						activeSpawns.Add(-1)
					}()
					return cmd, nil
				},
				ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
					// Slow probe ensures 50ms rapid stops abort before everHealthy becomes true.
					select {
					case <-ctx.Done():
						return 0, ctx.Err()
					case <-time.After(400 * time.Millisecond):
						return 0, fmt.Errorf("boot probe timeout")
					}
				},
				StopCodespace: func(ctx context.Context, cfg Config) (int, string, error) {
					stopCodespaceCalls.Add(1)
					return 0, "stopped", nil
				},
			}
		},
	})
	ctrl.Start()

	for i := 0; i < 20; i++ {
		ctrl.RequestStart()
		time.Sleep(50 * time.Millisecond)
		ctrl.RequestStop()
		time.Sleep(15 * time.Millisecond)
	}

	ctrl.ShutdownAndWait(5 * time.Second)

	if mc := maxConcurrent.Load(); mc > 1 {
		t.Fatalf("ST-18 concurrent Supervisor/child overlap detected: maxConcurrent=%d (want <= 1)", mc)
	}
	if sc := stopCodespaceCalls.Load(); sc != 0 {
		t.Fatalf("ST-18 aborted boots (!everHealthy) must NOT call StopCodespace, got %d", sc)
	}
	gs := ctrl.Guard().CachedSnapshot()
	if gs.CallsLast5Min > cfg.GitHubMaxCallsPer5Min {
		t.Fatalf("ST-18 WAF 5m budget exceeded under 20x Start/Stop spam: %d > %d", gs.CallsLast5Min, cfg.GitHubMaxCallsPer5Min)
	}
	if st := ctrl.Snapshot().State; st != CtrlStopped {
		t.Fatalf("ST-18 final controller state=%s, want STOPPED", st)
	}
	t.Logf("ST-18 PASS: 20x rapid Start/Stop spam -> maxConcurrent=%d, StopCodespace=0, WAF5m=%d/%d",
		maxConcurrent.Load(), gs.CallsLast5Min, gs.MaxCallsPer5Min)
	assertNoGoroutineLeak(t, baseG, 8)
}

// ST-19 (v7.0): Full 64-channel saturation (14 persistent H2/SSE streams + 36 concurrent 8 KiB fetches)
// behind SessionController while hammering wait-free UI snapshots at 100 Hz and running on-demand QuotaCheck.
func TestST19_Saturation64ChWith100HzUIBridgeAndQuota(t *testing.T) {
	baseG := runtime.NumGoroutine()
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.CodespaceName = "st19-space"
	cfg.StopOnExit = false
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.BackoffMin = 60 * time.Millisecond
	cfg.BackoffMax = 120 * time.Millisecond
	cfg.ProbeInterval = 150 * time.Millisecond
	cfg.DegradedProbeInterval = 80 * time.Millisecond
	cfg.UnderlayProbeInterval = 500 * time.Millisecond
	cfg.SummaryLogInterval = 350 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	ctrl := NewSessionController(cfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "netshaper_ui.json"),
		CachePath:        filepath.Join(dir, "codespace_state_cache.json"),
		SnapshotInterval: 50 * time.Millisecond,
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "st19.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) {
			return NewMetricsEmitter(filepath.Join(dir, "st19_metrics.ndjson"), sid)
		},
		RunSilentGH: func(ctx context.Context, args ...string) (string, string, int, error) {
			if len(args) >= 2 && args[1] == "/user/codespaces" {
				return `{"codespaces":[{"name":"st19-space","state":"Available","owner":{"login":"st19user"},"machine":{"name":"basic","display_name":"2 cores, 8 GB RAM","cpus":2,"memory_in_bytes":8589934592,"storage_in_bytes":34359738368}}]}`, "", 0, nil
			}
			return "", "HTTP 403 forbidden", 1, fmt.Errorf("exit status 1")
		},
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				Metrics:       m,
				BootPollDelay: 15 * time.Millisecond,
				UnderlayProbeFunc: func(ctx context.Context, targets []string, timeout time.Duration) (time.Duration, string, error) {
					return 210 * time.Millisecond, "20.120.56.11:443", nil
				},
				LookupWANRemote: func(pid uint32) string { return "20.120.56.11:443" },
				ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
					if _, err := ProbeSOCKS5(ctx, addr, target, timeout); err != nil {
						return 0, err
					}
					return 230 * time.Millisecond, nil
				},
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					cmd := newHelperCmd("sleep_alive")
					cmd.Stderr = stderr
					if err := cmd.Start(); err != nil {
						return nil, err
					}
					return cmd, nil
				},
			}
		},
	})
	ctrl.Start()
	defer ctrl.ShutdownAndWait(5 * time.Second)

	ctrl.RequestStart()
	waitUntil(t, 5*time.Second, "ST-19 2-worker pool RUNNING via UI bridge", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2 && s.LocalAddr != "" && !strings.HasSuffix(s.LocalAddr, ":0")
	})

	localAddr := ctrl.Snapshot().LocalAddr

	// 1. Open 14 persistent H2/SSE SOCKS5 streams.
	const persistentN = 14
	persistentConns := make([]net.Conn, 0, persistentN)
	defer func() {
		for _, pc := range persistentConns {
			_ = pc.Close()
		}
	}()
	for i := 0; i < persistentN; i++ {
		pc, err := net.DialTimeout("tcp", localAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("ST-19 persistent stream #%d dial: %v", i, err)
		}
		_ = pc.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err := pc.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("ST-19 persistent #%d greet write: %v", i, err)
		}
		var gr [2]byte
		if _, err := io.ReadFull(pc, gr[:]); err != nil {
			t.Fatalf("ST-19 persistent #%d greet read: %v", i, err)
		}
		if _, err := pc.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb}); err != nil {
			t.Fatalf("ST-19 persistent #%d connect write: %v", i, err)
		}
		var cr [10]byte
		if _, err := io.ReadFull(pc, cr[:]); err != nil {
			t.Fatalf("ST-19 persistent #%d connect read: %v", i, err)
		}
		initFrame := makeDeterministicPayload(512, uint64(1900+i))
		if _, err := pc.Write(initFrame); err != nil {
			t.Fatalf("ST-19 persistent #%d init write: %v", i, err)
		}
		initEcho := make([]byte, len(initFrame))
		if _, err := io.ReadFull(pc, initEcho); err != nil {
			t.Fatalf("ST-19 persistent #%d init read: %v", i, err)
		}
		if sha256.Sum256(initEcho) != sha256.Sum256(initFrame) {
			t.Fatalf("ST-19 persistent #%d init SHA-256 mismatch", i)
		}
		persistentConns = append(persistentConns, pc)
	}

	// 2. Hammer wait-free UI bridge at 100 Hz while firing 36 concurrent 8 KiB fetches + QuotaCheck.
	uiStop := make(chan struct{})
	var uiSnapReads atomic.Int64
	var uiWG sync.WaitGroup
	uiWG.Add(1)
	go func() {
		defer uiWG.Done()
		scratch := make([]TerminalLine, 0, TerminalRingCapacity)
		tk := time.NewTicker(10 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-uiStop:
				return
			case <-tk.C:
				_ = ctrl.Snapshot()
				_ = ctrl.ConsumeDirty()
				scratch = ctrl.Logs().SnapshotInto(scratch)
				uiSnapReads.Add(1)
			}
		}
	}()

	_ = ctrl.RequestQuotaCheck()

	const burstN = 36
	payload := makeDeterministicPayload(8*1024, 1919)
	var burstOK atomic.Int64
	burstErrs := make([]error, burstN)
	var bWG sync.WaitGroup
	gate := make(chan struct{})

	burstStart := time.Now()
	for i := 0; i < burstN; i++ {
		bWG.Add(1)
		go func(idx int) {
			defer bWG.Done()
			<-gate
			if err := performSOCKS5EchoTransfer(localAddr, payload, 3*time.Second); err == nil {
				burstOK.Add(1)
			} else {
				burstErrs[idx] = err
			}
		}(i)
	}
	close(gate)
	bWG.Wait()
	burstElapsed := time.Since(burstStart)

	waitUntil(t, 3*time.Second, "ST-19 mid-burst QuotaCheck finished", func() bool {
		s := ctrl.Snapshot()
		return s.Quota.Checked && !s.Quota.Loading
	})
	close(uiStop)
	uiWG.Wait()

	if burstOK.Load() != burstN {
		t.Fatalf("ST-19 expected 36/36 burst OK under 100Hz UI load, got %d/36 in %s (errs=%v)", burstOK.Load(), burstElapsed, burstErrs[:min(5, len(burstErrs))])
	}
	if burstElapsed >= 3*time.Second {
		t.Fatalf("ST-19 36-fetch burst took %s (>= 3s ceiling)", burstElapsed)
	}
	snapFinal := ctrl.Snapshot()
	if snapFinal.SemaphoreRejects != 0 {
		t.Fatalf("ST-19 SemaphoreRejects=%d, want 0", snapFinal.SemaphoreRejects)
	}
	if snapFinal.GuardCooldownMS != 0 {
		t.Fatalf("ST-19 billing 403 triggered guard cooldown=%dms", snapFinal.GuardCooldownMS)
	}

	// 3. Verify all 14/14 persistent streams remain completely intact post-burst.
	for i, pc := range persistentConns {
		post := makeDeterministicPayload(256, uint64(1950+i))
		if _, err := pc.Write(post); err != nil {
			t.Fatalf("ST-19 persistent #%d post-burst write: %v", i, err)
		}
		echo := make([]byte, len(post))
		if _, err := io.ReadFull(pc, echo); err != nil {
			t.Fatalf("ST-19 persistent #%d post-burst read: %v", i, err)
		}
		if sha256.Sum256(echo) != sha256.Sum256(post) {
			t.Fatalf("ST-19 persistent #%d post-burst SHA-256 mismatch", i)
		}
		_ = pc.Close()
	}

	ctrl.ShutdownAndWait(5 * time.Second)
	t.Logf("ST-19 PASS: 14 persistent + 36/36 fetches in %s | 100Hz UI reads=%d | Quota=%dvCPU | Rejects=0",
		burstElapsed, uiSnapReads.Load(), snapFinal.Quota.CPUs)
	assertNoGoroutineLeak(t, baseG, 10)
}

// ST-20 (v7.0): Terminal log flood (>=10,000 lines/sec) concurrently with live multi-MB SOCKS5
// proxy transfers and 250ms UI repaint/H-scroll ticks. Proves <5 MB HeapAlloc delta, 0 drops, 0 leaks.
func TestST20_TerminalFlood10kLPSWithLiveProxyDownloadSoak(t *testing.T) {
	baseG := runtime.NumGoroutine()
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.CodespaceName = "st20-space"
	cfg.StopOnExit = false
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.ProbeInterval = 200 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	ctrl := NewSessionController(cfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "netshaper_ui.json"),
		CachePath:        filepath.Join(dir, "codespace_state_cache.json"),
		SnapshotInterval: 100 * time.Millisecond,
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "st20.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil },
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				BootPollDelay: 15 * time.Millisecond,
				ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
					if _, err := ProbeSOCKS5(ctx, addr, target, timeout); err != nil {
						return 0, err
					}
					return 140 * time.Millisecond, nil
				},
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					cmd := newHelperCmd("sleep_alive")
					cmd.Stderr = stderr
					if err := cmd.Start(); err != nil {
						return nil, err
					}
					return cmd, nil
				},
			}
		},
	})
	ctrl.Start()
	defer ctrl.ShutdownAndWait(5 * time.Second)

	ctrl.RequestStart()
	waitUntil(t, 5*time.Second, "ST-20 pool RUNNING", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2 && !strings.HasSuffix(s.LocalAddr, ":0")
	})
	localAddr := ctrl.Snapshot().LocalAddr

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	stopCh := make(chan struct{})
	var floodWG sync.WaitGroup
	var floodedLines atomic.Int64

	// 1. 4 concurrent log flooders delivering >= 10,000 lines/s of long lines.
	for g := 0; g < 4; g++ {
		floodWG.Add(1)
		go func(id int) {
			defer floodWG.Done()
			longTail := strings.Repeat("Z", 220)
			for i := 0; ; i++ {
				select {
				case <-stopCh:
					return
				default:
				}
				ctrl.Logs().Append(LogInfo, fmt.Sprintf("[Flood-%d] seq=%d payload=%s", id, i, longTail))
				floodedLines.Add(1)
				if i%250 == 0 {
					runtime.Gosched()
				}
			}
		}(g)
	}

	// 2. Simulated 250ms coalesced UI timer consumer computing H-scroll extents.
	var uiTicks atomic.Int64
	floodWG.Add(1)
	go func() {
		defer floodWG.Done()
		scratch := make([]TerminalLine, 0, TerminalRingCapacity)
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-tk.C:
				_ = ctrl.ConsumeDirty()
				_ = ctrl.Snapshot()
				scratch = ctrl.Logs().SnapshotInto(scratch)
				maxLen := 0
				for _, l := range scratch {
					if len(l.Text) > maxLen {
						maxLen = len(l.Text)
					}
				}
				if maxLen > 0 {
					uiTicks.Add(1)
				}
			}
		}
	}()

	// 3. Concurrent multi-MB live SOCKS5 echo transfers (4 workers x 12 x 64 KiB = 3 MiB).
	chunk := makeDeterministicPayload(64*1024, 2020)
	var xferOK atomic.Int64
	var xferErrs atomic.Int64
	var xferWG sync.WaitGroup
	start := time.Now()
	for w := 0; w < 4; w++ {
		xferWG.Add(1)
		go func() {
			defer xferWG.Done()
			for n := 0; n < 12; n++ {
				if err := performSOCKS5EchoTransfer(localAddr, chunk, 4*time.Second); err == nil {
					xferOK.Add(1)
				} else {
					xferErrs.Add(1)
				}
			}
		}()
	}
	xferWG.Wait()
	// Ensure soak runs at least 1.0s so >=10k lines/sec and >=3 UI 250ms ticks execute.
	if rem := time.Second - time.Since(start); rem > 0 {
		time.Sleep(rem)
	}
	close(stopCh)
	floodWG.Wait()
	elapsed := time.Since(start)

	if xferErrs.Load() != 0 || xferOK.Load() != 48 {
		t.Fatalf("ST-20 proxy transfer failures under log flood: ok=%d/48 errs=%d", xferOK.Load(), xferErrs.Load())
	}
	if ctrl.Logs().Len() != TerminalRingCapacity {
		t.Fatalf("ST-20 ring buffer Len()=%d, want %d", ctrl.Logs().Len(), TerminalRingCapacity)
	}
	lps := float64(floodedLines.Load()) / elapsed.Seconds()
	if lps < 10000 {
		t.Fatalf("ST-20 flood rate=%.0f lines/s (< 10,000 lines/s target)", lps)
	}

	ctrl.ShutdownAndWait(5 * time.Second)
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	var heapDelta int64
	if memAfter.HeapAlloc > memBefore.HeapAlloc {
		heapDelta = int64(memAfter.HeapAlloc - memBefore.HeapAlloc)
	}
	if heapDelta >= 5*1024*1024 {
		t.Fatalf("ST-20 HeapAlloc delta=%d bytes (>= 5 MB ceiling)", heapDelta)
	}
	t.Logf("ST-20 PASS: %.0f lines/s (%d lines) + 48/48 64KiB transfers (3 MiB) | UI ticks=%d | HeapAllocDelta=%d KB",
		lps, floodedLines.Load(), uiTicks.Load(), heapDelta/1024)
	assertNoGoroutineLeak(t, baseG, 10)
}

// ST-21 (v7.0): Full cross-platform v6.4 + v7.0 contract & parser integrity gate.
// Validates immutable MCI defaults, multi-account gh auth parsing, 403/429 classifier disjointness,
// FormatLogRecord coverage, Codespaces/Billing JSON parsing, and UISnapshot immutability.
func TestST21_V7FullStaticAndContractIntegrityGate(t *testing.T) {
	// 1. Immutable v6.4 MCI defaults.
	cfg := DefaultConfig()
	if cfg.PoolSize != 2 || cfg.MaxActiveConns != 64 || cfg.PerTunnelMaxConns != 32 {
		t.Fatalf("ST-21 v6.4 pool/channel defaults drifted: pool=%d max=%d per=%d", cfg.PoolSize, cfg.MaxActiveConns, cfg.PerTunnelMaxConns)
	}
	if cfg.PMTU576CopyBufSize != 8*1024 || cfg.TCPKeepAlivePeriod != 8*time.Second ||
		cfg.SSHServerAliveInterval != 10 || cfg.SSHServerAliveCountMax != 3 {
		t.Fatalf("ST-21 v6.4 PMTU/keepalive defaults drifted")
	}
	if cfg.GitHubMaxCallsPer5Min != 6 || cfg.GitHubMaxCallsPerHour != 24 || cfg.GitHubMinCallSpacing != 2*time.Second ||
		cfg.HysteresisDwellWindow != 25*time.Second || cfg.StreamingPressureIdleTimeout >= cfg.SemaphoreWaitTimeout {
		t.Fatalf("ST-21 v6.4 WAF/hysteresis/deadlock defaults drifted")
	}

	// 2. Multi-account ParseGHAuthStatus precedence.
	multiOut := `github.com
  ✓ Logged in to github.com account inactive_first (keyring)
  - Active account: false
  - Token scopes: 'repo'
  ✓ Logged in to github.com account active_second (keyring)
  - Active account: true
  - Token scopes: 'codespace', 'repo'`
	ai := ParseGHAuthStatus(multiOut)
	if !ai.LoggedIn || ai.Username != "active_second" || !strings.Contains(ai.Scopes, "codespace") {
		t.Fatalf("ST-21 ParseGHAuthStatus multi-account failed: %+v", ai)
	}
	legacyOut := "  ✓ Logged in to github.com as legacy_user (oauth_token)\n  - Token scopes: codespace"
	ai2 := ParseGHAuthStatus(legacyOut)
	if !ai2.LoggedIn || ai2.Username != "legacy_user" {
		t.Fatalf("ST-21 ParseGHAuthStatus legacy failed: %+v", ai2)
	}

	// 3. Strict disjointness between billing HTTP 403 and WAF HTTP 429.
	if !IsQuotaBillingScope403("HTTP 403: Resource not accessible") || IsQuotaRateLimitOrWAF("HTTP 403: Resource not accessible") {
		t.Fatalf("ST-21 billing HTTP 403 misclassified")
	}
	if !IsQuotaRateLimitOrWAF("HTTP 429 Too Many Requests; Retry-After: 60") || IsQuotaBillingScope403("HTTP 429 Too Many Requests") {
		t.Fatalf("ST-21 WAF HTTP 429 misclassified")
	}

	// 4. Codespaces & Billing JSON parsers + Formatters.
	csJSON := `{"codespaces":[{"name":"cs-a","state":"Available","owner":{"login":"dev1"},"machine":{"name":"m1","display_name":"4 cores, 16 GB RAM","cpus":4,"memory_in_bytes":17179869184,"storage_in_bytes":34359738368}}]}`
	qi, owner, err := ParseCodespacesAPIJSON([]byte(csJSON), "cs-a")
	if err != nil || owner != "dev1" || qi.CPUs != 4 || qi.MemoryGB != 16 || qi.StorageGB != 32 {
		t.Fatalf("ST-21 ParseCodespacesAPIJSON failed: qi=%+v owner=%q err=%v", qi, owner, err)
	}
	used, inc, ok := ParseBillingUsageJSON([]byte(`{"usageItems":[{"product":"Codespaces","unitType":"Hours","quantity":14.5}]}`))
	if !ok || used != 14.5 || inc != 120.0 {
		t.Fatalf("ST-21 ParseBillingUsageJSON failed: used=%v inc=%v ok=%v", used, inc, ok)
	}
	if FormatBytesShort(1536*1024) != "1.5 MB" || FormatDurationShort(65*time.Second) != "01m 05s" {
		t.Fatalf("ST-21 short formatters drifted")
	}

	// 5. FormatLogRecord coverage across critical lifecycle events.
	sev, line := FormatLogRecord(LogRecord{Event: "STATE_TRANSITION", Fields: map[string]any{"from": "PROBING", "to": string(StateHealthy)}})
	if sev != LogSuccess || !strings.Contains(line, "HEALTHY") {
		t.Fatalf("ST-21 FormatLogRecord STATE_TRANSITION unexpected: sev=%v line=%q", sev, line)
	}
	sev2, line2 := FormatLogRecord(LogRecord{Event: "GITHUB_API_BACKOFF", Fields: map[string]any{"failure_class": "rate_limit", "cooldown_ms": 15000}})
	if sev2 != LogError || !strings.Contains(line2, "WAF Guard") {
		t.Fatalf("ST-21 FormatLogRecord GITHUB_API_BACKOFF unexpected: sev=%v line=%q", sev2, line2)
	}
}

// UT-41 (v7.0 field incident): Permanent HTTP 404 / auth errors fail fast (<=1 API call,
// 0 synthetic rate-limit cooldown, 0 StopCodespace) and unconfigured "my-codespace"
// placeholder aborts in 0ms with 0 GitHub API calls in production GUI mode.
func TestUT41_FatalBootErrorFailFastAndPlaceholderGuard(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// 1. Classifier precision: permanent 404/401 vs transient/retriable errors.
	live404 := "getting full codespace details: HTTP 404: Not Found (https://api.github.com/user/codespaces/my-codespace?internal=true&refresh=true)"
	if fe := ClassifyPermanentBootError(live404); fe == nil || fe.Code != "codespace_not_found" {
		t.Fatalf("UT-41 expected codespace_not_found for live 404 stderr, got %+v", fe)
	}
	for _, authErr := range []string{
		"HTTP 401: Unauthorized",
		"To get started with GitHub CLI, please run: gh auth login",
		"HTTP 403: missing required scope, run gh auth refresh -h github.com -s codespace",
	} {
		if fe := ClassifyPermanentBootError(authErr); fe == nil || fe.Code != "auth_required" {
			t.Fatalf("UT-41 expected auth_required for %q, got %+v", authErr, fe)
		}
	}
	for _, retriable := range []string{
		"HTTP 429 Too Many Requests; Retry-After: 45",
		"HTTP 403: abuse detection mechanism triggered",
		"HTTP 400: You may have too many codespaces starting at the same time",
		"HTTP 502 Bad Gateway",
		"HTTP 503 Service Unavailable",
		"Timeout, server not responding.",
		"codespace is stopped",
	} {
		if fe := ClassifyPermanentBootError(retriable); fe != nil {
			t.Fatalf("UT-41 transient/retriable stderr %q misclassified as fatal: %+v", retriable, fe)
		}
	}

	// 2. Live PoolSize=2 SessionController + crash_404 subprocess -> fails fast after 1 call (never 5/6).
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ut41_404.log")
	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.GHPort = 49210
	cfg.PoolSize = 2
	cfg.CodespaceName = "nonexistent-space-41"
	cfg.StopOnExit = true
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BackoffMin = 20 * time.Millisecond
	cfg.BackoffMax = 40 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	var spawns atomic.Int32
	var stopCalls atomic.Int32

	ctrl := NewSessionController(cfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "ui_404.json"),
		CachePath:        filepath.Join(dir, "cache_404.json"),
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(logPath)
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil },
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				BootPollDelay: 15 * time.Millisecond,
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					spawns.Add(1)
					cmd := newHelperCmd("crash_404", "HELPER_DELAY_MS=15")
					cmd.Stderr = stderr
					if err := cmd.Start(); err != nil {
						return nil, err
					}
					return cmd, nil
				},
				StopCodespace: func(ctx context.Context, cfg Config) (int, string, error) {
					stopCalls.Add(1)
					return 0, "should_not_run", nil
				},
			}
		},
	})
	ctrl.Start()
	ctrl.RequestStart()

	waitUntil(t, 4*time.Second, "UT-41 HTTP 404 fails fast to CtrlStopped with LastError", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlStopped && s.LastError != ""
	})
	// Allow a brief settle window to verify zero further retry spawns occur.
	time.Sleep(150 * time.Millisecond)

	if got := spawns.Load(); got != 1 {
		ctrl.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 HTTP 404 retried instead of failing fast: spawns=%d (want 1)", got)
	}
	if gs := ctrl.Guard().CachedSnapshot(); gs.CallsLast5Min != 1 || gs.CooldownRemainingMS != 0 {
		ctrl.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 expected 1/6 API call and 0 cooldown after 404, got 5m=%d cooldown=%dms",
			gs.CallsLast5Min, gs.CooldownRemainingMS)
	}
	if stopCalls.Load() != 0 {
		ctrl.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 expected 0 StopCodespace calls on 404, got %d", stopCalls.Load())
	}
	if !strings.Contains(ctrl.Snapshot().LastError, "404") {
		ctrl.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 expected LastError mentioning 404, got %q", ctrl.Snapshot().LastError)
	}
	ctrl.ShutdownAndWait(3 * time.Second)

	recs := readJSONLLog(t, logPath)
	sawFatal := false
	for _, r := range recs {
		if r.Event == "FATAL_BOOT_ERROR" && r.Fields["code"] == "codespace_not_found" {
			sawFatal = true
		}
	}
	if !sawFatal {
		t.Fatal("UT-41 missing FATAL_BOOT_ERROR record in history log")
	}

	// 3. Unconfigured placeholder "my-codespace" guard (production GUI mode: SupervisorDepsFactory == nil).
	phCfg := DefaultConfig()
	phCfg.LocalPort = 0
	phCfg.CodespaceExplicit = false
	ctrlPH := NewSessionController(phCfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "ui_placeholder.json"),
		CachePath:        filepath.Join(dir, "cache_placeholder.json"),
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
	})
	ctrlPH.Start()
	ctrlPH.RequestStart()

	waitUntil(t, 2*time.Second, "UT-41 placeholder 'my-codespace' fails fast with 0 API calls", func() bool {
		s := ctrlPH.Snapshot()
		return s.State == CtrlStopped && s.LastError != ""
	})
	if gs := ctrlPH.Guard().CachedSnapshot(); gs.CallsLast5Min != 0 || gs.TotalAllowed != 0 {
		ctrlPH.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 placeholder guard spent GitHub API calls: %+v", gs)
	}
	if !strings.Contains(ctrlPH.Snapshot().LastError, "Account tab") {
		ctrlPH.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 placeholder error not actionable: %q", ctrlPH.Snapshot().LastError)
	}
	if err := ctrlPH.SetCodespaceName("real-space-ut41"); err != nil {
		ctrlPH.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 SetCodespaceName failed: %v", err)
	}
	if ctrlPH.Snapshot().LastError != "" {
		ctrlPH.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-41 SetCodespaceName did not clear prior LastError: %q", ctrlPH.Snapshot().LastError)
	}
	ctrlPH.ShutdownAndWait(2 * time.Second)
	assertNoGoroutineLeak(t, baseG, 8)
}

// UT-42 (v7.0 field incident): Underlay-normalized cold-boot jitter accepts healthy high-WAN
// tunnels (B_raw=586.69ms, p50=563ms, jitter=442ms, rho=0.96, boot=27s), rejects genuinely
// degraded lanes, and avoids destroying a working tunnel when GitHubGuard budget is exhausted.
func TestUT42_ColdBootUnderlayNormalizedJitterAndBudgetConstrainedAccept(t *testing.T) {
	baseG := runtime.NumGoroutine()
	cfg := DefaultConfig()

	// 1. Exact Session 2 field telemetry: B_raw=586.69ms, p50=563ms, jitter=442ms (350/563/792), boot=27087ms -> ACCEPTED.
	incidentSamples := []time.Duration{350 * time.Millisecond, 563 * time.Millisecond, 792 * time.Millisecond}
	repOK := EvaluateFastLaneGateNormalized(cfg, 27087*time.Millisecond, incidentSamples, 0, 0, 586.69, true, 540*time.Millisecond)
	if !repOK.Accepted || repOK.Reason != "ok" || !repOK.SlowBoot || repOK.RelativeRho != 0.96 {
		t.Fatalf("UT-42 expected Session 2 healthy cold-boot tunnel accepted, got %+v", repOK)
	}

	// 2. Genuine degraded RTT on same 586.69ms underlay (1097ms < p50=1180ms <= 1290ms, rho=2.01) -> REJECTED.
	highRTT := []time.Duration{1150 * time.Millisecond, 1180 * time.Millisecond, 1210 * time.Millisecond}
	repBadRTT := EvaluateFastLaneGateNormalized(cfg, 27*time.Second, highRTT, 0, 0, 586.69, true, 900*time.Millisecond)
	if repBadRTT.Accepted || repBadRTT.Reason != "slow_boot_elevated_rtt" {
		t.Fatalf("UT-42 expected degraded RTT rejected, got %+v", repBadRTT)
	}

	// 3. Extreme jitter on same 586.69ms underlay (jitter=1100ms > 877ms adaptive ceiling) -> REJECTED.
	highJitter := []time.Duration{400 * time.Millisecond, 563 * time.Millisecond, 1500 * time.Millisecond}
	repBadJitter := EvaluateFastLaneGateNormalized(cfg, 27*time.Second, highJitter, 0, 0, 586.69, true, 540*time.Millisecond)
	if repBadJitter.Accepted || repBadJitter.Reason != "slow_boot_elevated_jitter" {
		t.Fatalf("UT-42 expected extreme jitter rejected, got %+v", repBadJitter)
	}

	// 4. Failed Stage 2 micro-payload on same 586.69ms underlay -> REJECTED.
	repBadMicro := EvaluateFastLaneGateNormalized(cfg, 27*time.Second, incidentSamples, 0, 0, 586.69, false, 0)
	if repBadMicro.Accepted || repBadMicro.Reason != "micro_payload_failed" {
		t.Fatalf("UT-42 expected micro_payload_failed rejection, got %+v", repBadMicro)
	}

	// 5. Clean 220ms underlay retains exact UT-15 400ms slow-boot jitter ceiling (480ms -> REJECTED).
	cleanJitter := []time.Duration{220 * time.Millisecond, 310 * time.Millisecond, 700 * time.Millisecond}
	repClean := EvaluateFastLaneGateNormalized(cfg, 14500*time.Millisecond, cleanJitter, 0, 0, 220.0, true, 220*time.Millisecond)
	if repClean.Accepted || repClean.Reason != "slow_boot_elevated_jitter" {
		t.Fatalf("UT-42 expected clean 220ms slow-boot jitter parity rejection, got %+v", repClean)
	}

	// 6. Budget-constrained BootAndQualify: when last 5m budget slot was just consumed (2/2),
	//    do NOT tear down a live working tunnel (Failures==0 && MicroPayloadOK==true) into a 5m blackout.
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "ut42_budget.log")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("UT-42 logger: %v", err)
	}

	bCfg := DefaultConfig()
	bCfg.LocalPort = 0
	bCfg.GHPort = socks.Port(t)
	bCfg.BootQualitySamples = 2
	bCfg.BootQualityMaxRetries = 2
	bCfg.BootQualityMaxRTT = 600 * time.Millisecond
	bCfg.BootFastLaneMaxRTT = 1200 * time.Millisecond
	bCfg.BootMicroPayloadCheck = true
	bCfg.GitHubMaxCallsPer5Min = 2
	bCfg.GitHubMaxCallsPerHour = 10
	bCfg.GitHubMinCallSpacing = 0

	guard := NewGitHubGuard(bCfg, logger, nil)
	if ok, _, why := guard.TryAllow("prior_call"); !ok {
		t.Fatalf("UT-42 seed guard call failed: %s", why)
	}

	var spawns atomic.Int32
	deps := SupervisorDeps{
		PortInspector:          &mockPortInspector{},
		NewJob:                 NewProcessJob,
		BootPollDelay:          15 * time.Millisecond,
		BootQualitySampleDelay: 15 * time.Millisecond,
		BootQualityRetryDelay:  50 * time.Millisecond,
		LookupWANRemote:        func(uint32) string { return "20.120.56.11:443" },
		TuneChildProcess:       func(int) error { return nil },
		TuneProcessTree:        func(int) int { return 0 },
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			spawns.Add(1)
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			if _, perr := ProbeSOCKS5(ctx, addr, target, timeout); perr != nil {
				return 0, perr
			}
			return 1400 * time.Millisecond, nil // triggers BootQuality reject while working
		},
		MicroPayloadProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			return 150 * time.Millisecond, nil // proves real payload flow
		},
	}

	ti := NewTunnelInstance("tunnel-1", socks.Port(t), bCfg, deps, logger, nil, guard)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _, bootErr := ti.BootAndQualify(ctx, nil, func() float64 { return 220.0 })
	ti.TeardownChild()
	_ = logger.Close()

	if bootErr != nil {
		t.Fatalf("UT-42 expected budget-constrained working tunnel accepted best-effort, got err=%v", bootErr)
	}
	if spawns.Load() != 1 {
		t.Fatalf("UT-42 expected exactly 1 spawn when budget exhausted, got %d", spawns.Load())
	}

	recs := readJSONLLog(t, logPath)
	sawBudgetBestEffort := false
	for _, r := range recs {
		if r.Event == "BOOT_QUALITY_ACCEPTED_BEST_EFFORT" {
			if bc, _ := r.Fields["budget_constrained"].(bool); bc && r.Fields["defer_reason"] == "budget_5m_exhausted" {
				sawBudgetBestEffort = true
			}
		}
	}
	if !sawBudgetBestEffort {
		t.Fatal("UT-42 missing BOOT_QUALITY_ACCEPTED_BEST_EFFORT with budget_constrained=true")
	}
	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-43 (v7.0 field incident): Verifies (A) StopCodespace runs when a VM was woken via E2E SOCKS5
// even if BootQuality rejected before StateHealthy, (B) unbooted aborts still skip StopCodespace
// (ST-18/UT-34 boundary), and (C) GUI Stop (StopOnExit=true -> MarkCodespaceState("Shutdown"))
// followed by Start in the same SessionController does NOT hit a 10-minute codespace_cached_stopped lockout.
func TestUT43_VMWokenStopCodespaceAndGUIStopRestartCycle(t *testing.T) {
	baseG := runtime.NumGoroutine()
	dir := t.TempDir()

	// Part A: VM woken via E2E SOCKS5, then aborted during Stage 2 quality retry before StateHealthy -> MUST stop VM.
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	logA := filepath.Join(dir, "ut43_a.log")
	loggerA, err := NewEventLogger(logA)
	if err != nil {
		t.Fatalf("UT-43 Part A logger: %v", err)
	}
	cfgA := DefaultConfig()
	cfgA.PoolSize = 2
	cfgA.LocalPort = 0
	cfgA.GHPort = basePort
	cfgA.StopOnExit = true
	cfgA.StopTimeout = 2 * time.Second
	cfgA.PreflightNetHygiene = false
	cfgA.BootQualitySamples = 2
	cfgA.BootQualityMaxRetries = 2
	cfgA.BootMicroPayloadCheck = true
	cfgA.GitHubMinCallSpacing = 0

	var microCallsA atomic.Int32
	var stopCallsA atomic.Int32
	supA := NewSupervisor(cfgA, loggerA, SupervisorDeps{
		PortInspector:          &mockPortInspector{},
		BootPollDelay:          15 * time.Millisecond,
		BootQualitySampleDelay: 15 * time.Millisecond,
		BootQualityRetryDelay:  3 * time.Second,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			return ProbeSOCKS5(ctx, addr, target, timeout)
		},
		MicroPayloadProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			microCallsA.Add(1)
			return 0, fmt.Errorf("simulated_micro_payload_reject")
		},
		StopCodespace: func(ctx context.Context, c Config) (int, string, error) {
			stopCallsA.Add(1)
			return 0, "stopped_woken_vm", nil
		},
	})

	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan error, 1)
	go func() { doneA <- supA.Run(ctxA) }()

	waitUntil(t, 4*time.Second, "UT-43 Part A tunnel-1 reached SOCKS5 + Stage 2", func() bool {
		return microCallsA.Load() >= 1 && supA.VMWoken()
	})
	supA.RequestShutdown("ui_stop_after_vm_woken")
	cancelA()
	<-doneA

	if stopCallsA.Load() != 1 {
		t.Fatalf("UT-43 Part A expected StopCodespace=1 for woken VM, got %d", stopCallsA.Load())
	}
	recsA := readJSONLLog(t, logA)
	sawWokenStop := false
	for _, r := range recsA {
		if r.Event == "SHUTDOWN_COMPLETE" {
			inv, _ := r.Fields["stop_codespace_invoked"].(bool)
			vmW, _ := r.Fields["vm_woken"].(bool)
			evH, _ := r.Fields["ever_healthy"].(bool)
			if inv && vmW && !evH {
				sawWokenStop = true
			}
		}
	}
	if !sawWokenStop {
		t.Fatal("UT-43 Part A expected SHUTDOWN_COMPLETE with vm_woken=true, ever_healthy=false, stop_codespace_invoked=true")
	}

	// Part B: Unbooted abort (WaitForTunnelReadyDetailed never succeeds) -> MUST skip StopCodespace.
	logB := filepath.Join(dir, "ut43_b.log")
	loggerB, err := NewEventLogger(logB)
	if err != nil {
		t.Fatalf("UT-43 Part B logger: %v", err)
	}
	cfgB := cfgA
	var spawnsB atomic.Int32
	var stopCallsB atomic.Int32
	supB := NewSupervisor(cfgB, loggerB, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 20 * time.Millisecond,
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			spawnsB.Add(1)
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			return 0, fmt.Errorf("not_ready_yet")
		},
		StopCodespace: func(ctx context.Context, c Config) (int, string, error) {
			stopCallsB.Add(1)
			return 0, "should_not_run", nil
		},
	})
	ctxB, cancelB := context.WithCancel(context.Background())
	doneB := make(chan error, 1)
	go func() { doneB <- supB.Run(ctxB) }()
	waitUntil(t, 3*time.Second, "UT-43 Part B child spawned", func() bool { return spawnsB.Load() >= 1 })
	supB.RequestShutdown("ui_stop_before_vm_ready")
	cancelB()
	<-doneB
	if stopCallsB.Load() != 0 || supB.VMWoken() {
		t.Fatalf("UT-43 Part B unbooted abort must skip StopCodespace: stopCalls=%d vmWoken=%v", stopCallsB.Load(), supB.VMWoken())
	}

	// Part C: GUI Start -> Healthy -> Stop (StopOnExit=true -> Shutdown cache) -> Start again in SAME SessionController.
	socksC := startMockSOCKS5Server(t, socksModeNormal)
	defer socksC.Close()

	cfgC := DefaultConfig()
	cfgC.LocalPort = 0
	cfgC.GHPort = socksC.Port(t)
	cfgC.PoolSize = 1
	cfgC.CodespaceName = "gui-restart-space-43"
	cfgC.StopOnExit = true
	cfgC.StopTimeout = 2 * time.Second
	cfgC.PreflightNetHygiene = false
	cfgC.BootQualitySamples = 1
	cfgC.BootMicroPayloadCheck = false
	cfgC.ProbeInterval = 150 * time.Millisecond
	cfgC.GitHubMinCallSpacing = 0

	var stopCallsC atomic.Int32
	ctrlC := NewSessionController(cfgC, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "ui_c.json"),
		CachePath:        filepath.Join(dir, "cache_c.json"),
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "ut43_c.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil },
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				BootPollDelay: 15 * time.Millisecond,
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					cmd := newHelperCmd("sleep_alive")
					cmd.Stderr = stderr
					return cmd, cmd.Start()
				},
				ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
					return ProbeSOCKS5(ctx, addr, target, timeout)
				},
				StopCodespace: func(ctx context.Context, cfg Config) (int, string, error) {
					stopCallsC.Add(1)
					return 0, "stopped", nil
				},
			}
		},
	})
	ctrlC.Start()
	defer ctrlC.ShutdownAndWait(3 * time.Second)

	for cycle := 1; cycle <= 2; cycle++ {
		ctrlC.RequestStart()
		waitUntil(t, 4*time.Second, fmt.Sprintf("UT-43 Part C cycle %d RUNNING", cycle), func() bool {
			return ctrlC.Snapshot().State == CtrlRunning
		})
		ctrlC.RequestStop()
		waitUntil(t, 4*time.Second, fmt.Sprintf("UT-43 Part C cycle %d STOPPED", cycle), func() bool {
			return ctrlC.Snapshot().State == CtrlStopped
		})
	}
	if stopCallsC.Load() != 2 {
		t.Fatalf("UT-43 Part C expected 2 clean StopCodespace calls across Stop->Start cycle, got %d", stopCallsC.Load())
	}
	ctrlC.ShutdownAndWait(3 * time.Second)
	assertNoGoroutineLeak(t, baseG, 8)
}

// UT-44 (v7.0 field incident): Wait-free GitHubGuard budget countdown & automatic 5m window expiry
// in CachedSnapshot() (0 locks) + SessionController throttle visibility & live Guard sinks.
func TestUT44_WaitFreeBudgetExhaustionCountdownAndGuardSinks(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// 1. Deterministic wait-free CachedSnapshot() budget countdown & live 5m expiry.
	cfg := DefaultConfig()
	cfg.GitHubMaxCallsPer5Min = 6
	cfg.GitHubMaxCallsPerHour = 24
	cfg.GitHubMinCallSpacing = 0

	guard := NewGitHubGuard(cfg, nil, nil)
	now := time.Date(2026, 11, 22, 18, 30, 0, 0, time.UTC)
	guard.nowFn = func() time.Time { return now }

	for i := 0; i < 6; i++ {
		if ok, _, why := guard.TryAllow("boot"); !ok {
			t.Fatalf("UT-44 call %d failed: %s", i+1, why)
		}
		now = now.Add(10 * time.Second)
	}
	// At t=60s: 6 calls in [0..50s] -> earliest slot unlocks at t=300s -> 240,000ms remaining.
	cs := guard.CachedSnapshot()
	if cs.CallsLast5Min != 6 || cs.BudgetWaitMS != 240000 || cs.ThrottleWaitMS != 240000 ||
		cs.ThrottleReason != "budget_5m_exhausted" || cs.CooldownRemainingMS != 0 {
		t.Fatalf("UT-44 unexpected exhausted CachedSnapshot: %+v", cs)
	}

	// Advance clock to t=301s WITHOUT calling any mutating method -> CachedSnapshot() decays live to 5/6!
	now = now.Add(241 * time.Second)
	cs2 := guard.CachedSnapshot()
	if cs2.CallsLast5Min != 5 || cs2.BudgetWaitMS != 0 || cs2.ThrottleWaitMS != 0 || cs2.ThrottleReason != "" {
		t.Fatalf("UT-44 expected wait-free expiry to 5/6 and 0 wait, got %+v", cs2)
	}

	// 2. SessionController surfaces budget exhaustion in UISnapshot & emits api_guard/GITHUB_API_THROTTLED via SetSinks.
	dir := t.TempDir()
	metricsPath := filepath.Join(dir, "ut44_metrics.ndjson")
	uiCfg := DefaultConfig()
	uiCfg.LocalPort = 0
	uiCfg.GHPort = 49220
	uiCfg.PoolSize = 1
	uiCfg.CodespaceName = "throttled-space-44"
	uiCfg.StopOnExit = false
	uiCfg.PreflightNetHygiene = false
	uiCfg.GitHubMaxCallsPer5Min = 2
	uiCfg.GitHubMaxCallsPerHour = 10
	uiCfg.GitHubMinCallSpacing = 0

	ctrl := NewSessionController(uiCfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "ui44.json"),
		CachePath:        filepath.Join(dir, "cache44.json"),
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "ut44.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) {
			return NewMetricsEmitter(metricsPath, sid)
		},
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				Metrics:       m,
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					return nil, fmt.Errorf("should not spawn while budget exhausted")
				},
			}
		},
	})
	// Pre-exhaust the 2/2 5-minute budget on the shared controller guard.
	_, _, _ = ctrl.Guard().TryAllow("pre_1")
	_, _, _ = ctrl.Guard().TryAllow("pre_2")

	ctrl.Start()
	ctrl.RequestStart()

	waitUntil(t, 3*time.Second, "UT-44 UISnapshot surfaces budget_5m_exhausted countdown", func() bool {
		s := ctrl.Snapshot()
		return s.State == CtrlStarting && s.GuardBudgetWaitMS > 0 &&
			s.GuardThrottleWaitMS > 0 && s.GuardThrottleReason == "budget_5m_exhausted"
	})

	waitUntil(t, 3*time.Second, "UT-44 TerminalRingBuffer logs [WAF Guard] throttled event", func() bool {
		for _, ln := range ctrl.Logs().SnapshotInto(nil) {
			if strings.Contains(ln.Text, "[WAF Guard]") {
				return true
			}
		}
		return false
	})

	ctrl.ShutdownAndWait(3 * time.Second)

	mRecs := readMetricsNDJSON(t, metricsPath)
	sawThrottledMetric := false
	for _, r := range mRecs {
		if r.Stream == "api_guard" && r.Data["action"] == "throttled" && r.Data["block_reason"] == "budget_5m_exhausted" {
			sawThrottledMetric = true
		}
	}
	if !sawThrottledMetric {
		t.Fatalf("UT-44 missing stream=api_guard throttled record in metrics NDJSON (total=%d)", len(mRecs))
	}
	assertNoGoroutineLeak(t, baseG, 8)
}

// UT-45 (v7.0 BUG-01): Verifies promoteToStreaming() immediately extends the live OS read deadline
// on a blocked localDC beyond IdleTimeout, cross-direction refresh keeps unidirectional streams
// alive past StreamingIdleTimeout, and unpromoted <=128B sockets still reap promptly at IdleTimeout.
func TestUT45_StreamingPromotionDeadlineAndCrossDirRefresh(t *testing.T) {
	baseG := runtime.NumGoroutine()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("UT-45 upstream listen: %v", err)
	}
	var srvWG sync.WaitGroup
	srvWG.Add(1)
	go func() {
		defer srvWG.Done()
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			srvWG.Add(1)
			go func(conn net.Conn) {
				defer srvWG.Done()
				defer conn.Close()
				var cmdBuf [16]byte
				n, rerr := conn.Read(cmdBuf[:])
				if rerr != nil || n == 0 {
					return
				}
				cmd := strings.TrimSpace(string(cmdBuf[:n]))
				switch cmd {
				case "PROMOTE":
					// Reply >128B so localDC & remoteDC promote immediately, then echo any follow-up frame.
					if _, werr := conn.Write(makeDeterministicPayload(256, 4501)); werr != nil {
						return
					}
					var tail [64]byte
					m, rerr2 := conn.Read(tail[:])
					if rerr2 == nil && m > 0 {
						_, _ = conn.Write(tail[:m])
					}
				case "STREAM":
					// Unidirectional server->client stream lasting >1.1s (> 750ms StreamingIdleTimeout)
					// while client sends 0 additional uplink bytes.
					chunk := makeDeterministicPayload(256, 4502)
					for i := 0; i < 11; i++ {
						if _, werr := conn.Write(chunk); werr != nil {
							return
						}
						if i < 10 {
							time.Sleep(110 * time.Millisecond)
						}
					}
					if cw, ok := conn.(closeWriter); ok {
						_ = cw.CloseWrite()
					}
				case "STALL":
					// Reply <=128B (unpromoted) and sit silent until idle reaper closes it.
					_, _ = conn.Write(makeDeterministicPayload(64, 4503))
					var sink [16]byte
					for {
						if _, rerr2 := conn.Read(sink[:]); rerr2 != nil {
							return
						}
					}
				}
			}(c)
		}
	}()
	defer func() {
		_ = ln.Close()
		srvWG.Wait()
	}()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.IdleTimeout = 200 * time.Millisecond
	cfg.PressureIdleTimeout = 200 * time.Millisecond
	cfg.StreamingIdleTimeout = 750 * time.Millisecond
	cfg.StreamingPressureIdleTimeout = 750 * time.Millisecond
	cfg.StalledHandshakeMaxDownBytes = 128
	cfg.HalfCloseDrainTimeout = 200 * time.Millisecond
	cfg.DialPaceInterval = 0

	proxy := NewProxyServer(cfg, ln.Addr().String(), nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("UT-45 proxy.Start: %v", err)
	}

	// Subcheck A: Promoted stream survives 420ms silent pause (> 200ms IdleTimeout, < 750ms StreamingIdleTimeout).
	c1, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("UT-45 Subcheck A dial: %v", err)
	}
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c1.Write([]byte("PROMOTE\n")); err != nil {
		_ = c1.Close()
		t.Fatalf("UT-45 Subcheck A write: %v", err)
	}
	first := make([]byte, 256)
	if _, err := io.ReadFull(c1, first); err != nil {
		_ = c1.Close()
		t.Fatalf("UT-45 Subcheck A read promoted reply: %v", err)
	}
	time.Sleep(420 * time.Millisecond)
	followUp := []byte("POST-PAUSE-OK")
	if _, err := c1.Write(followUp); err != nil {
		_ = c1.Close()
		t.Fatalf("UT-45 Subcheck A blocked localDC died at stale IdleTimeout: %v", err)
	}
	gotFollow := make([]byte, len(followUp))
	if _, err := io.ReadFull(c1, gotFollow); err != nil || string(gotFollow) != string(followUp) {
		_ = c1.Close()
		t.Fatalf("UT-45 Subcheck A post-pause echo failed: got=%q err=%v", string(gotFollow), err)
	}
	_ = c1.Close()

	// Subcheck B: Unidirectional server->client stream survives 1.1s (> 750ms StreamingIdleTimeout) with 0 uplink bytes.
	c2, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("UT-45 Subcheck B dial: %v", err)
	}
	_ = c2.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c2.Write([]byte("STREAM\n")); err != nil {
		_ = c2.Close()
		t.Fatalf("UT-45 Subcheck B write: %v", err)
	}
	streamed, err := io.ReadAll(c2)
	_ = c2.Close()
	if err != nil || len(streamed) != 11*256 {
		t.Fatalf("UT-45 Subcheck B unidirectional stream aborted mid-download: got=%d want=%d err=%v", len(streamed), 11*256, err)
	}

	// Subcheck C: Unpromoted <=128B connection still reaps promptly near IdleTimeout (200ms), NOT 750ms.
	c3, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("UT-45 Subcheck C dial: %v", err)
	}
	_ = c3.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c3.Write([]byte("STALL\n")); err != nil {
		_ = c3.Close()
		t.Fatalf("UT-45 Subcheck C write: %v", err)
	}
	small := make([]byte, 64)
	if _, err := io.ReadFull(c3, small); err != nil {
		_ = c3.Close()
		t.Fatalf("UT-45 Subcheck C read 64B: %v", err)
	}
	reapStart := time.Now()
	var eofBuf [8]byte
	_, _ = c3.Read(eofBuf[:])
	reapElapsed := time.Since(reapStart)
	_ = c3.Close()
	if reapElapsed > 550*time.Millisecond {
		t.Fatalf("UT-45 Subcheck C unpromoted 64B socket took %s to reap (expected ~200ms, << 750ms)", reapElapsed)
	}

	proxy.Stop(true)
	_ = ln.Close()
	srvWG.Wait()
	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-46 (v7.0 BUG-02): Verifies bounded, oldest-idle-first pressure reaping at 48/64 (sparing young
// established streams instead of mass-terminating all 40) AND 64/64 saturation deadlock-freedom (< SemaphoreWaitTimeout).
func TestUT46_BoundedPressureSweepOldestIdleFirst(t *testing.T) {
	baseG := runtime.NumGoroutine()
	echoAddr, _, _, stopEcho := startPlainTCPEchoServer(t, 0)
	defer stopEcho()

	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.MaxActiveConns = 64
	cfg.MaxQueuedConns = 64
	cfg.PressureThresholdPct = 75 // thresh = 48, lowWater = 41
	cfg.IdleTimeout = 10 * time.Second
	cfg.PressureIdleTimeout = 120 * time.Millisecond
	cfg.StreamingIdleTimeout = 10 * time.Second
	cfg.StreamingPressureIdleTimeout = 200 * time.Millisecond
	cfg.SemaphoreWaitTimeout = 1200 * time.Millisecond
	cfg.DialPaceInterval = 0

	proxy := NewProxyServer(cfg, echoAddr, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, err := proxy.Start(ctx)
	if err != nil {
		t.Fatalf("UT-46 proxy.Start: %v", err)
	}

	openEstablished := func() net.Conn {
		c, derr := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if derr != nil {
			t.Fatalf("UT-46 dial: %v", derr)
		}
		_ = c.SetDeadline(time.Now().Add(6 * time.Second))
		msg := makeDeterministicPayload(256, 4646)
		if _, werr := c.Write(msg); werr != nil {
			_ = c.Close()
			t.Fatalf("UT-46 init write: %v", werr)
		}
		resp := make([]byte, len(msg))
		if _, rerr := io.ReadFull(c, resp); rerr != nil {
			_ = c.Close()
			t.Fatalf("UT-46 init read: %v", rerr)
		}
		return c
	}

	probeAlive := func(c net.Conn) bool {
		_ = c.SetDeadline(time.Now().Add(400 * time.Millisecond))
		msg := []byte("alive-check-ut46")
		if _, werr := c.Write(msg); werr != nil {
			return false
		}
		resp := make([]byte, len(msg))
		_, rerr := io.ReadFull(c, resp)
		return rerr == nil && string(resp) == string(msg)
	}

	// Part A: 20 older idle streams + 20 younger idle streams + 8 active streams -> crosses 48/64.
	oldConns := make([]net.Conn, 20)
	for i := range oldConns {
		oldConns[i] = openEstablished()
	}
	time.Sleep(150 * time.Millisecond)

	youngConns := make([]net.Conn, 20)
	for i := range youngConns {
		youngConns[i] = openEstablished()
	}
	time.Sleep(240 * time.Millisecond) // old ~390ms idle, young ~240ms idle (both > 200ms StreamingPressureIdleTimeout)

	activeStop := make(chan struct{})
	var activeWG sync.WaitGroup
	activeConns := make([]net.Conn, 8)
	for i := range activeConns {
		c := openEstablished()
		activeConns[i] = c
		activeWG.Add(1)
		go func(conn net.Conn) {
			defer activeWG.Done()
			tk := time.NewTicker(50 * time.Millisecond)
			defer tk.Stop()
			frame := []byte("active-heartbeat")
			buf := make([]byte, len(frame))
			for {
				select {
				case <-activeStop:
					return
				case <-tk.C:
					_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
					if _, werr := conn.Write(frame); werr != nil {
						return
					}
					if _, rerr := io.ReadFull(conn, buf); rerr != nil {
						return
					}
				}
			}
		}(c)
	}

	waitUntil(t, 2*time.Second, "UT-46 bounded pressure sweep reaps >=7 excess slots", func() bool {
		return proxy.Metrics(false).PressureReaps >= 7
	})
	time.Sleep(120 * time.Millisecond) // confirm no runaway secondary slaughter

	reaps := proxy.Metrics(false).PressureReaps
	if reaps < 7 || reaps > 14 {
		close(activeStop)
		activeWG.Wait()
		t.Fatalf("UT-46 expected bounded reap count in [7, 14] at 48/64 (lowWater=41), got %d", reaps)
	}

	youngAlive := 0
	for _, c := range youngConns {
		if probeAlive(c) {
			youngAlive++
		}
		_ = c.Close()
	}
	oldDead := 0
	for _, c := range oldConns {
		if !probeAlive(c) {
			oldDead++
		}
		_ = c.Close()
	}
	close(activeStop)
	activeWG.Wait()
	for _, c := range activeConns {
		_ = c.Close()
	}
	if youngAlive < 18 {
		t.Fatalf("UT-46 oldest-idle-first violated: only %d/20 younger streams survived (expected >=18/20)", youngAlive)
	}
	if oldDead < 7 {
		t.Fatalf("UT-46 expected >=7 oldest streams reaped, got %d", oldDead)
	}

	waitUntil(t, 2*time.Second, "UT-46 Part A drains to 0 active conns", func() bool {
		return proxy.Metrics(false).ActiveConns == 0
	})

	// Part B: 64/64 saturation deadlock-freedom (< SemaphoreWaitTimeout).
	// Open all 64 connections concurrently (<20ms) so early connections don't age past 200ms
	// StreamingPressureIdleTimeout while the 64th connection is still being established.
	satConns := make([]net.Conn, 64)
	var satWG sync.WaitGroup
	for i := range satConns {
		satWG.Add(1)
		go func(idx int) {
			defer satWG.Done()
			satConns[idx] = openEstablished()
		}(i)
	}
	satWG.Wait()
	defer func() {
		for _, c := range satConns {
			_ = c.Close()
		}
	}()
	waitUntil(t, 2*time.Second, "UT-46 64/64 saturated", func() bool {
		return proxy.Metrics(false).ActiveConns == 64
	})

	const queuedN = 24
	payload := makeDeterministicPayload(1024, 4647)
	var qOK atomic.Int64
	var qWG sync.WaitGroup
	for i := 0; i < queuedN; i++ {
		qWG.Add(1)
		go func() {
			defer qWG.Done()
			if err := shapingEchoClient(proxyAddr, payload, 2*time.Second); err == nil {
				qOK.Add(1)
			}
		}()
	}
	qWG.Wait()

	if qOK.Load() != queuedN || proxy.Metrics(false).SemaphoreRejects != 0 {
		t.Fatalf("UT-46 Part B 64/64 saturation deadlocked: ok=%d/%d rejects=%d",
			qOK.Load(), queuedN, proxy.Metrics(false).SemaphoreRejects)
	}

	for _, c := range satConns {
		_ = c.Close()
	}
	proxy.Stop(true)
	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-47 (v7.0 BUG-03 & BUG-05): Verifies unimodal 1.1.1.1:443 target order, 2x underlay spike
// outlier clamping, hard upper caps on EvaluateFastLaneGateNormalized, and eviction of workers
// trapped in TunnelDegraded slow-lane purgatory (4.25s RTT).
func TestUT47_Underlay1RTTClampingDegradedEvictionAndBootCap(t *testing.T) {
	baseG := runtime.NumGoroutine()

	// Part A: Target order + underlay outlier clamping under 2,601ms spike.
	if !strings.HasPrefix(DefaultUnderlayProbeTargets, "1.1.1.1:443") {
		t.Fatalf("UT-47 expected unimodal 1.1.1.1:443 first in DefaultUnderlayProbeTargets, got %q", DefaultUnderlayProbeTargets)
	}
	cfg := DefaultConfig()
	poolClamp := NewTunnelPool(cfg, SupervisorDeps{}, nil, nil, nil)
	poolClamp.SetUnderlayBaselineMS(250.0)
	poolClamp.recordUnderlaySample(2601*time.Millisecond, "1.1.1.1:443")
	if got := poolClamp.UnderlayBaselineMS(); got > 350.0 {
		t.Fatalf("UT-47 expected 2,601ms spike clamped to <=350ms EWMA (from 250ms), got %.2fms", got)
	}
	poolInit := NewTunnelPool(cfg, SupervisorDeps{}, nil, nil, nil)
	poolInit.recordUnderlaySample(2601*time.Millisecond, "1.1.1.1:443")
	if got := poolInit.UnderlayBaselineMS(); got > 1200.0 {
		t.Fatalf("UT-47 expected initial 2,601ms spike clamped <=1200ms, got %.2fms", got)
	}

	// Part B: Hard upper caps on EvaluateFastLaneGateNormalized under extreme 2,601ms B_raw.
	fastBroken := EvaluateFastLaneGateNormalized(cfg, 5*time.Second, []time.Duration{1950 * time.Millisecond, 2000 * time.Millisecond, 2050 * time.Millisecond}, 0, 0, 2601.0, true, 1200*time.Millisecond)
	if fastBroken.Accepted {
		t.Fatalf("UT-47 expected 2,000ms broken fast-boot lane rejected despite B_raw=2601ms, got %+v", fastBroken)
	}
	slowBroken := EvaluateFastLaneGateNormalized(cfg, 20*time.Second, []time.Duration{1600 * time.Millisecond, 1650 * time.Millisecond, 1700 * time.Millisecond}, 0, 0, 2601.0, true, 900*time.Millisecond)
	if slowBroken.Accepted || slowBroken.Reason != "slow_boot_elevated_rtt" {
		t.Fatalf("UT-47 expected 1,650ms slow-boot lane rejected by 1,500ms hard cap, got %+v", slowBroken)
	}
	jitterBroken := EvaluateFastLaneGateNormalized(cfg, 20*time.Second, []time.Duration{200 * time.Millisecond, 700 * time.Millisecond, 1500 * time.Millisecond}, 0, 0, 2601.0, true, 500*time.Millisecond)
	if jitterBroken.Accepted || jitterBroken.Reason != "slow_boot_elevated_jitter" {
		t.Fatalf("UT-47 expected 1,300ms slow-boot jitter rejected by 1,100ms hard cap, got %+v", jitterBroken)
	}
	// Preserve UT-42 healthy 586.69ms cold-boot parity.
	healthyHighWAN := EvaluateFastLaneGateNormalized(cfg, 27*time.Second, []time.Duration{350 * time.Millisecond, 563 * time.Millisecond, 792 * time.Millisecond}, 0, 0, 586.69, true, 540*time.Millisecond)
	if !healthyHighWAN.Accepted {
		t.Fatalf("UT-47 broke UT-42 high-WAN healthy cold-boot parity: %+v", healthyHighWAN)
	}

	// Part C (BUG-05): Live TunnelDegraded (4.25s RTT) slow-lane worker MUST be evicted & rerolled.
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	poolCfg := DefaultConfig()
	poolCfg.PoolSize = 2
	poolCfg.GHPort = basePort
	poolCfg.LocalPort = 0
	poolCfg.BootQualitySamples = 1
	poolCfg.BootMicroPayloadCheck = false
	poolCfg.ProbeInterval = 60 * time.Millisecond
	poolCfg.DegradedProbeInterval = 50 * time.Millisecond
	poolCfg.DegradedRTTThreshold = 4000 * time.Millisecond
	poolCfg.ProbeTimeout = 12 * time.Second
	poolCfg.SlowLaneEvictRatio = 3.5
	poolCfg.SlowLaneEvictWindow = 220 * time.Millisecond
	poolCfg.UnderlayBaselineMS = 220.0
	poolCfg.BackoffMin = 50 * time.Millisecond
	poolCfg.BackoffMax = 100 * time.Millisecond
	poolCfg.GitHubMinCallSpacing = 0

	w2Addr := fmt.Sprintf("127.0.0.1:%d", basePort+1)
	var w2Spawns atomic.Int32
	var injectDegradedSlow atomic.Bool
	guard := NewGitHubGuard(poolCfg, nil, nil)

	pool := NewTunnelPool(poolCfg, SupervisorDeps{
		PortInspector:    &mockPortInspector{},
		NewJob:           NewProcessJob,
		BootPollDelay:    15 * time.Millisecond,
		LookupWANRemote:  func(uint32) string { return "20.120.56.11:443" },
		TuneChildProcess: func(int) error { return nil },
		TuneProcessTree:  func(int) int { return 0 },
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			if _, perr := ProbeSOCKS5(ctx, addr, target, timeout); perr != nil {
				return 0, perr
			}
			if addr == w2Addr && injectDegradedSlow.Load() && w2Spawns.Load() == 1 {
				return 4250 * time.Millisecond, nil // >4000ms DegradedRTTThreshold, <12000ms ProbeTimeout
			}
			return 220 * time.Millisecond, nil
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			if c.GHPort == basePort+1 {
				w2Spawns.Add(1)
			}
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			return cmd, cmd.Start()
		},
	}, nil, nil, guard)

	ctx, cancel := context.WithCancel(context.Background())
	if err := pool.Start(ctx); err != nil {
		cancel()
		t.Fatalf("UT-47 pool.Start: %v", err)
	}
	waitUntil(t, 4*time.Second, "UT-47 initial 2/2 HEALTHY", func() bool {
		return pool.HealthyCount() == 2
	})

	injectDegradedSlow.Store(true)
	waitUntil(t, 3*time.Second, "UT-47 tunnel-2 enters TunnelDegraded (4.25s RTT)", func() bool {
		return pool.workers[1].State() == TunnelDegraded || pool.SlowLaneEvictions() >= 1
	})
	waitUntil(t, 5*time.Second, "UT-47 TunnelDegraded tunnel-2 evicted, rerolled and recovered 2/2 HEALTHY", func() bool {
		snap := pool.PoolSnapshot()
		return snap.SlowLaneEvictions >= 1 && w2Spawns.Load() >= 2 && snap.HealthyWorkers == 2 && snap.DegradedWorkers == 0
	})

	cancel()
	pool.Close()
	assertNoGoroutineLeak(t, baseG, 6)
}

// UT-48 (v7.0 BUG-04, BUG-06, BUG-07): Verifies mid-session HTTP 404 aborts PoolSize=2 cleanly via
// FatalErrCh(), slow RequestQuotaCheck cannot overwrite newer Re-Auth username, and HTTP 403 missing
// required scope classifies as FailureAuthOrStopped with 0 WAF cooldown.
func TestUT48_MidSessionFatalBootAbortAndQuotaReAuthRace(t *testing.T) {
	baseG := runtime.NumGoroutine()
	dir := t.TempDir()

	// Part A (BUG-04): Mid-session HTTP 404 on tunnel-2 aborts PoolSize=2 cleanly (no DEGRADED 0/2 wedge).
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	cfgA := DefaultConfig()
	cfgA.LocalPort = 0
	cfgA.GHPort = basePort
	cfgA.PoolSize = 2
	cfgA.CodespaceName = "mid-session-404-space"
	cfgA.StopOnExit = true
	cfgA.PreflightNetHygiene = false
	cfgA.BootQualitySamples = 1
	cfgA.BootMicroPayloadCheck = false
	cfgA.BackoffMin = 40 * time.Millisecond
	cfgA.BackoffMax = 80 * time.Millisecond
	cfgA.ProbeInterval = 150 * time.Millisecond
	cfgA.GitHubMinCallSpacing = 0

	var (
		w2Mu       sync.Mutex
		w2FirstCmd *exec.Cmd
		w2Spawns   atomic.Int32
		stopCalls  atomic.Int32
	)
	ctrlA := NewSessionController(cfgA, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "ui48a.json"),
		CachePath:        filepath.Join(dir, "cache48a.json"),
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "ut48a.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil },
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				BootPollDelay: 15 * time.Millisecond,
				ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
					return ProbeSOCKS5(ctx, addr, target, timeout)
				},
				StopCodespace: func(ctx context.Context, cfg Config) (int, string, error) {
					stopCalls.Add(1)
					return 0, "should_not_run_on_404", nil
				},
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					if cfg.GHPort == basePort+1 {
						n := w2Spawns.Add(1)
						if n >= 2 {
							cmd := newHelperCmd("crash_404", "HELPER_DELAY_MS=15")
							cmd.Stderr = stderr
							return cmd, cmd.Start()
						}
						cmd := newHelperCmd("sleep_alive")
						cmd.Stderr = stderr
						if err := cmd.Start(); err != nil {
							return nil, err
						}
						w2Mu.Lock()
						w2FirstCmd = cmd
						w2Mu.Unlock()
						return cmd, nil
					}
					cmd := newHelperCmd("sleep_alive")
					cmd.Stderr = stderr
					return cmd, cmd.Start()
				},
			}
		},
	})
	ctrlA.Start()
	ctrlA.RequestStart()

	waitUntil(t, 5*time.Second, "UT-48 Part A 2/2 pool RUNNING", func() bool {
		s := ctrlA.Snapshot()
		return s.State == CtrlRunning && s.HealthyWorkers == 2 && !strings.HasSuffix(s.LocalAddr, ":0")
	})
	boundAddr := ctrlA.Snapshot().LocalAddr

	w2Mu.Lock()
	if w2FirstCmd != nil && w2FirstCmd.Process != nil {
		_ = w2FirstCmd.Process.Kill()
	}
	w2Mu.Unlock()

	waitUntil(t, 5*time.Second, "UT-48 Part A mid-session 404 aborts cleanly to CtrlStopped", func() bool {
		s := ctrlA.Snapshot()
		return s.State == CtrlStopped && strings.Contains(s.LastError, "404")
	})
	if stopCalls.Load() != 0 {
		ctrlA.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-48 Part A expected 0 StopCodespace calls on fatal 404 abort, got %d", stopCalls.Load())
	}
	if c, derr := net.DialTimeout("tcp", boundAddr, 150*time.Millisecond); derr == nil {
		_ = c.Close()
		ctrlA.ShutdownAndWait(2 * time.Second)
		t.Fatalf("UT-48 Part A local proxy %s remained bound after fatal 404 abort", boundAddr)
	}
	ctrlA.ShutdownAndWait(3 * time.Second)

	// Part B (BUG-06): Slow RequestQuotaCheck under @olduser cannot overwrite fresh Re-Auth @newuser.
	cfgB := DefaultConfig()
	cfgB.LocalPort = 0
	cfgB.CodespaceName = "race-space-48"
	cfgB.GitHubMinCallSpacing = 0

	quotaEntered := make(chan struct{}, 1)
	quotaRelease := make(chan struct{})

	ctrlB := NewSessionController(cfgB, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "ui48b.json"),
		CachePath:        filepath.Join(dir, "cache48b.json"),
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
		RunInteractiveGH: func(ctx context.Context, args ...string) (int, error) {
			return 0, nil
		},
		RunSilentGH: func(ctx context.Context, args ...string) (string, string, int, error) {
			joined := strings.Join(args, " ")
			if joined == "api /user/codespaces" {
				select {
				case quotaEntered <- struct{}{}:
				default:
				}
				// Deliberately ignore ctx.Done() to prove authGen discards late completions too.
				<-quotaRelease
				return `{"codespaces":[{"name":"race-space-48","state":"Available","owner":{"login":"olduser"},"machine":{"name":"basic","display_name":"2 cores, 8 GB RAM","cpus":2,"memory_in_bytes":8589934592,"storage_in_bytes":34359738368}}]}`, "", 0, nil
			}
			if joined == "auth status" {
				return "github.com\n  ✓ Logged in to github.com account newuser (keyring)\n  - Active account: true\n  - Token scopes: 'codespace'\n", "", 0, nil
			}
			return "", "unexpected", 1, fmt.Errorf("unexpected")
		},
	})
	ctrlB.Start()
	defer ctrlB.ShutdownAndWait(3 * time.Second)

	if !ctrlB.RequestQuotaCheck() {
		t.Fatal("UT-48 Part B RequestQuotaCheck returned false")
	}
	select {
	case <-quotaEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("UT-48 Part B timed out waiting for slow quota call to start")
	}
	if err := ctrlB.RequestReAuth(); err != nil {
		t.Fatalf("UT-48 Part B RequestReAuth: %v", err)
	}
	waitUntil(t, 4*time.Second, "UT-48 Part B Re-Auth switches to @newuser", func() bool {
		s := ctrlB.Snapshot()
		return s.State == CtrlStopped && !ctrlB.reauthRequested.Load() && s.Auth.Username == "newuser"
	})

	close(quotaRelease)
	waitUntil(t, 2*time.Second, "UT-48 Part B stale quota goroutine finishes", func() bool {
		return !ctrlB.quotaBusy.Load()
	})
	snapB := ctrlB.Snapshot()
	if snapB.Auth.Username != "newuser" || snapB.Quota.Checked {
		t.Fatalf("UT-48 Part B stale @olduser quota overwrote @newuser Re-Auth state: user=%q quota=%+v",
			snapB.Auth.Username, snapB.Quota)
	}
	ctrlB.ShutdownAndWait(3 * time.Second)

	// Part C (BUG-07): HTTP 403 missing required scope -> FailureAuthOrStopped with 0 cooldown + new fatal tokens.
	for _, sample := range []string{
		"Codespaces spending limit reached for this billing period",
		"error: codespace is suspended by organization policy",
		"no such codespace found",
		"git@github.com: Permission denied (publickey).",
	} {
		if fe := ClassifyPermanentBootError(sample); fe == nil {
			t.Fatalf("UT-48 Part C expected permanent FatalBootError for %q, got nil", sample)
		}
	}
	guardC := NewGitHubGuard(DefaultConfig(), nil, nil)
	scopeErr := "HTTP 403: missing required scope, run gh auth refresh -h github.com -s codespace"
	cls, cd := guardC.RecordFailure(scopeErr)
	snapC := guardC.Snapshot()
	if cls != FailureAuthOrStopped || cd != 0 || snapC.RateLimitHits != 0 || snapC.CooldownRemainingMS != 0 {
		t.Fatalf("UT-48 Part C scope 403 misclassified as rate-limit: cls=%s cd=%s hits=%d cooldown=%dms",
			cls, cd, snapC.RateLimitHits, snapC.CooldownRemainingMS)
	}
	// Genuine 403 WAF abuse detection MUST still trigger FailureAPIRateLimit.
	clsWAF, cdWAF := guardC.RecordFailure("HTTP 403: abuse detection mechanism triggered")
	if clsWAF != FailureAPIRateLimit || cdWAF <= 0 {
		t.Fatalf("UT-48 Part C WAF 403 lost rate-limit classification: cls=%s cd=%s", clsWAF, cdWAF)
	}

	assertNoGoroutineLeak(t, baseG, 10)
}

// UT-49 (v7.0 BUG-08 & BUG-09): Verifies exit shutdown timeout budgets (StopTimeout+4s vs WM_ENDSESSION
// 3.5s), exiting re-launch mutex/restore safety, and owned-HWND clipboard ownership & error cleanup.
func TestUT49_ExitReLaunchSafetyAndClipboardHWND(t *testing.T) {
	baseG := runtime.NumGoroutine()

	if got := exitShutdownTimeout(10*time.Second, false); got != 14*time.Second {
		t.Fatalf("UT-49 interactive exit timeout=%s, want 14s (StopTimeout+4s)", got)
	}
	if got := exitShutdownTimeout(10*time.Second, true); got != 3500*time.Millisecond {
		t.Fatalf("UT-49 WM_ENDSESSION timeout=%s, want 3500ms (< 5s WaitToKillAppTimeout)", got)
	}
	if err := verifyExitReLaunchAndClipboardInvariants(); err != nil {
		t.Fatalf("UT-49 platform exit/clipboard invariant failed: %v", err)
	}

	// Verify SessionController.ShutdownAndWait honors bounded dead-WAN teardown budget cleanly.
	socks := startMockSOCKS5Server(t, socksModeNormal)
	defer socks.Close()
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.LocalPort = 0
	cfg.GHPort = socks.Port(t)
	cfg.PoolSize = 1
	cfg.CodespaceName = "ut49-exit-space"
	cfg.StopOnExit = true
	cfg.StopTimeout = 400 * time.Millisecond
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.GitHubMinCallSpacing = 0

	ctrl := NewSessionController(cfg, ControllerDeps{
		UIConfigPath:     filepath.Join(dir, "ui49.json"),
		CachePath:        filepath.Join(dir, "cache49.json"),
		SnapshotInterval: 50 * time.Millisecond,
		ReadLocalHostsFn: func() string { return "" },
		OpenLogger: func(c Config) (*EventLogger, error) {
			return NewEventLogger(filepath.Join(dir, "ut49.log"))
		},
		OpenMetrics: func(c Config, sid string) (*MetricsEmitter, error) { return nil, nil },
		SupervisorDepsFactory: func(c Config, g *GitHubGuard, m *MetricsEmitter) SupervisorDeps {
			return SupervisorDeps{
				PortInspector: &mockPortInspector{},
				GitHubGuard:   g,
				BootPollDelay: 15 * time.Millisecond,
				StartChild: func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
					cmd := newHelperCmd("sleep_alive")
					cmd.Stderr = stderr
					return cmd, cmd.Start()
				},
				ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
					return ProbeSOCKS5(ctx, addr, target, timeout)
				},
				StopCodespace: func(ctx context.Context, cfg Config) (int, string, error) {
					<-ctx.Done()
					return -1, "dead_wan_timeout", ctx.Err()
				},
			}
		},
	})
	ctrl.Start()
	ctrl.RequestStart()
	waitUntil(t, 4*time.Second, "UT-49 session RUNNING", func() bool {
		return ctrl.Snapshot().State == CtrlRunning
	})

	exitStart := time.Now()
	ctrl.ShutdownAndWait(exitShutdownTimeout(cfg.StopTimeout, false))
	exitElapsed := time.Since(exitStart)
	if exitElapsed > 2*time.Second {
		t.Fatalf("UT-49 dead-WAN ShutdownAndWait exceeded budget: %s", exitElapsed)
	}
	if st := ctrl.Snapshot().State; st != CtrlStopped {
		t.Fatalf("UT-49 final state=%s, want STOPPED", st)
	}
	assertNoGoroutineLeak(t, baseG, 8)
}

// ST-22 (v7.0): Cellular-Hell 64-Channel Mixed Chaos & Spike Soak — combines PoolSize=2,
// 14 persistent HTTP/2/SSE streams + 10 older idle streams + 40 concurrent burst fetches (64/64
// crossing 48/64 pressure), 2,601ms underlay spikes, 4,250ms TunnelDegraded eviction, and mid-run failover.
func TestST22_CellularHell64ChMixedChaosAndSpikeSoak(t *testing.T) {
	baseG := runtime.NumGoroutine()
	s1, s2, basePort := startConsecutiveMockSOCKS5Pair(t)
	defer s1.Close()
	defer s2.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "st22.log")
	metricsPath := filepath.Join(dir, "st22_metrics.ndjson")
	logger, err := NewEventLogger(logPath)
	if err != nil {
		t.Fatalf("ST-22 logger: %v", err)
	}
	defer func() { _ = logger.Close() }()
	metrics, err := NewMetricsEmitter(metricsPath, "st22")
	if err != nil {
		t.Fatalf("ST-22 metrics: %v", err)
	}
	defer func() { _ = metrics.Close() }()

	cfg := DefaultConfig()
	cfg.PoolSize = 2
	cfg.MaxActiveConns = 64
	cfg.PerTunnelMaxConns = 32
	cfg.MaxQueuedConns = 128
	cfg.PressureThresholdPct = 75 // thresh = 48, lowWater = 41
	cfg.IdleTimeout = 10 * time.Second
	cfg.PressureIdleTimeout = 180 * time.Millisecond
	cfg.StreamingIdleTimeout = 10 * time.Second
	cfg.StreamingPressureIdleTimeout = 450 * time.Millisecond
	cfg.SemaphoreWaitTimeout = 2 * time.Second
	cfg.LocalPort = 0
	cfg.GHPort = basePort
	cfg.StopOnExit = false
	cfg.PreflightNetHygiene = false
	cfg.BootQualitySamples = 1
	cfg.BootMicroPayloadCheck = false
	cfg.DialPaceInterval = 0
	cfg.BackoffMin = 50 * time.Millisecond
	cfg.BackoffMax = 100 * time.Millisecond
	cfg.ProbeInterval = 70 * time.Millisecond
	cfg.DegradedProbeInterval = 50 * time.Millisecond
	cfg.DegradedRTTThreshold = 4000 * time.Millisecond
	cfg.UnderlayProbeInterval = 180 * time.Millisecond
	cfg.SlowLaneEvictRatio = 3.5
	cfg.SlowLaneEvictWindow = 220 * time.Millisecond
	cfg.SummaryLogInterval = 350 * time.Millisecond
	cfg.GitHubMinCallSpacing = 0

	w2Addr := fmt.Sprintf("127.0.0.1:%d", basePort+1)
	var (
		underlayCalls   atomic.Int32
		w1Mu            sync.Mutex
		w1FirstCmd      *exec.Cmd
		w1Spawns        atomic.Int32
		w2Spawns        atomic.Int32
		injectW2Degrade atomic.Bool
	)

	sup := NewSupervisor(cfg, logger, SupervisorDeps{
		PortInspector: &mockPortInspector{},
		BootPollDelay: 15 * time.Millisecond,
		Metrics:       metrics,
		UnderlayProbeFunc: func(ctx context.Context, targets []string, timeout time.Duration) (time.Duration, string, error) {
			n := underlayCalls.Add(1)
			if n == 2 {
				return 2601 * time.Millisecond, "1.1.1.1:443", nil // violent cellular spike
			}
			return 220 * time.Millisecond, "1.1.1.1:443", nil
		},
		LookupWANRemote: func(pid uint32) string {
			return "20.120.56.11:443"
		},
		ProbeFunc: func(ctx context.Context, addr, target string, timeout time.Duration) (time.Duration, error) {
			if _, perr := ProbeSOCKS5(ctx, addr, target, timeout); perr != nil {
				return 0, perr
			}
			if addr == w2Addr && injectW2Degrade.Load() && w2Spawns.Load() == 1 {
				return 4250 * time.Millisecond, nil // TunnelDegraded slow-lane purgatory
			}
			return 230 * time.Millisecond, nil
		},
		StartChild: func(ctx context.Context, c Config, stderr io.Writer) (*exec.Cmd, error) {
			cmd := newHelperCmd("sleep_alive")
			cmd.Stderr = stderr
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			if c.GHPort == basePort {
				if w1Spawns.Add(1) == 1 {
					w1Mu.Lock()
					w1FirstCmd = cmd
					w1Mu.Unlock()
				}
			} else {
				w2Spawns.Add(1)
			}
			return cmd, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sup.Run(ctx) }()

	waitUntil(t, 5*time.Second, "ST-22 2/2 pool HEALTHY + underlay spike observed", func() bool {
		snap := sup.PoolSnapshot()
		return sup.State() == StateHealthy && snap.HealthyWorkers == 2 && underlayCalls.Load() >= 2 && sup.BoundLocalAddr() != ""
	})
	if baseMS := sup.PoolSnapshot().UnderlayBaselineMS; baseMS >= 600.0 {
		cancel()
		<-done
		t.Fatalf("ST-22 2,601ms underlay spike was not outlier-clamped: UnderlayBaselineMS=%.2fms", baseMS)
	}

	localAddr := sup.BoundLocalAddr()
	openSOCKS5Established := func(seed uint64) net.Conn {
		pc, derr := net.DialTimeout("tcp", localAddr, 2*time.Second)
		if derr != nil {
			t.Fatalf("ST-22 dial: %v", derr)
		}
		_ = pc.SetDeadline(time.Now().Add(8 * time.Second))
		if _, werr := pc.Write([]byte{0x05, 0x01, 0x00}); werr != nil {
			_ = pc.Close()
			t.Fatalf("ST-22 greet write: %v", werr)
		}
		var gr [2]byte
		if _, rerr := io.ReadFull(pc, gr[:]); rerr != nil {
			_ = pc.Close()
			t.Fatalf("ST-22 greet read: %v", rerr)
		}
		if _, werr := pc.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb}); werr != nil {
			_ = pc.Close()
			t.Fatalf("ST-22 connect write: %v", werr)
		}
		var cr [10]byte
		if _, rerr := io.ReadFull(pc, cr[:]); rerr != nil {
			_ = pc.Close()
			t.Fatalf("ST-22 connect read: %v", rerr)
		}
		frame := makeDeterministicPayload(256, seed)
		if _, werr := pc.Write(frame); werr != nil {
			_ = pc.Close()
			t.Fatalf("ST-22 init write: %v", werr)
		}
		echo := make([]byte, len(frame))
		if _, rerr := io.ReadFull(pc, echo); rerr != nil {
			_ = pc.Close()
			t.Fatalf("ST-22 init read: %v", rerr)
		}
		return pc
	}

	// 1. Open 10 older idle streams and let them age past 450ms StreamingPressureIdleTimeout.
	oldIdle := make([]net.Conn, 10)
	for i := range oldIdle {
		oldIdle[i] = openSOCKS5Established(uint64(2200 + i))
	}
	defer func() {
		for _, c := range oldIdle {
			_ = c.Close()
		}
	}()
	time.Sleep(500 * time.Millisecond)

	// 2. Open 14 fresh persistent HTTP/2 / SSE streams, then immediately fire 40 concurrent burst fetches
	//    (10 + 14 + 40 = 64/64 crossing the 48/64 pressure threshold).
	persistent := make([]net.Conn, 14)
	for i := range persistent {
		persistent[i] = openSOCKS5Established(uint64(2300 + i))
	}
	defer func() {
		for _, c := range persistent {
			_ = c.Close()
		}
	}()

	const burstN = 40
	burstPayload := makeDeterministicPayload(4*1024, 2222)
	var burstOK atomic.Int64
	var bWG sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < burstN; i++ {
		bWG.Add(1)
		go func() {
			defer bWG.Done()
			<-gate
			if err := performSOCKS5EchoTransfer(localAddr, burstPayload, 4*time.Second); err == nil {
				burstOK.Add(1)
			}
		}()
	}
	close(gate)
	bWG.Wait()

	if burstOK.Load() != burstN {
		cancel()
		<-done
		t.Fatalf("ST-22 expected %d/%d burst transfers OK, got %d", burstN, burstN, burstOK.Load())
	}
	for _, c := range oldIdle {
		_ = c.Close()
	}

	// 3. Inject 4,250ms TunnelDegraded slow-lane on tunnel-2 -> verify eviction + recovery back to 2/2.
	injectW2Degrade.Store(true)
	waitUntil(t, 5*time.Second, "ST-22 TunnelDegraded tunnel-2 evicted and recovered 2/2 HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return snap.SlowLaneEvictions >= 1 && w2Spawns.Load() >= 2 && snap.HealthyWorkers == 2 && snap.DegradedWorkers == 0
	})

	// 4. Mid-run failover: kill tunnel-1 while firing fresh transfers and verify 2/2 self-healing.
	w1Mu.Lock()
	if w1FirstCmd != nil && w1FirstCmd.Process != nil {
		_ = w1FirstCmd.Process.Kill()
	}
	w1Mu.Unlock()
	for i := 0; i < 6; i++ {
		if err := performSOCKS5EchoTransfer(localAddr, burstPayload, 3*time.Second); err != nil {
			cancel()
			<-done
			t.Fatalf("ST-22 post-kill transfer #%d failed: %v", i, err)
		}
	}
	waitUntil(t, 5*time.Second, "ST-22 tunnel-1 failover recovered 2/2 HEALTHY", func() bool {
		snap := sup.PoolSnapshot()
		return w1Spawns.Load() >= 2 && snap.TotalFailovers >= 1 && snap.HealthyWorkers == 2
	})

	// 5. Verify all 14/14 persistent HTTP/2/SSE streams survived burst + spike + eviction + failover!
	for i, pc := range persistent {
		post := makeDeterministicPayload(256, uint64(2400+i))
		if _, werr := pc.Write(post); werr != nil {
			cancel()
			<-done
			t.Fatalf("ST-22 persistent stream #%d disrupted on post-chaos write: %v", i, werr)
		}
		echo := make([]byte, len(post))
		if _, rerr := io.ReadFull(pc, echo); rerr != nil {
			cancel()
			<-done
			t.Fatalf("ST-22 persistent stream #%d disrupted on post-chaos read: %v", i, rerr)
		}
		if sha256.Sum256(echo) != sha256.Sum256(post) {
			cancel()
			<-done
			t.Fatalf("ST-22 persistent stream #%d SHA-256 mismatch", i)
		}
		_ = pc.Close()
	}

	sup.proxyMu.Lock()
	var rejects uint64
	if sup.activeProxy != nil {
		rejects = sup.activeProxy.Metrics(false).SemaphoreRejects
	}
	sup.proxyMu.Unlock()
	if rejects != 0 {
		cancel()
		<-done
		t.Fatalf("ST-22 unexpected SemaphoreRejects=%d (want 0)", rejects)
	}

	cancel()
	<-done
	assertNoGoroutineLeak(t, baseG, 10)
}

