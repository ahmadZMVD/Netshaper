package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxConsecutiveProbeSkips bounds data-plane-aware probe skipping: at most ONE consecutive probe may
	// be skipped under active traffic, so a real E2E SOCKS5 RTT measurement runs at least every 2*ProbeInterval.
	maxConsecutiveProbeSkips = 1
	// probeStressSpikeThreshold is the combined drain_timeouts+abrupt_errors delta between two probe-timer
	// evaluations that counts as a stress spike and forbids skipping the E2E probe.
	probeStressSpikeThreshold = 5
)

// probeSkipDecision reports whether the data-plane-aware probe skip is allowed and, if not, why.
func probeSkipDecision(cur, prev ProxySignals, consecutiveSkips int) (allowSkip bool, forceReason string) {
	if consecutiveSkips >= maxConsecutiveProbeSkips {
		return false, "max_consecutive_skips"
	}
	if cur.MaxConns > 0 && cur.ActiveConns >= int64(cur.MaxConns) {
		return false, "proxy_saturated"
	}
	if cur.QueuedConns > 0 {
		return false, "proxy_queueing"
	}
	if cur.SemaphoreRejects > prev.SemaphoreRejects {
		return false, "semaphore_rejects_increased"
	}
	var spike uint64
	if cur.DrainTimeouts >= prev.DrainTimeouts {
		spike += cur.DrainTimeouts - prev.DrainTimeouts
	}
	if cur.AbruptErrors >= prev.AbruptErrors {
		spike += cur.AbruptErrors - prev.AbruptErrors
	}
	if spike >= probeStressSpikeThreshold {
		return false, "drain_or_abrupt_spike"
	}
	return true, ""
}

// SupervisorState enumerates the deterministic NetShaper v6.3 FSM states.
type SupervisorState string

const (
	StateInit          SupervisorState = "INIT"
	StatePortCleanup   SupervisorState = "PORT_CLEANUP"
	StateStartingGH    SupervisorState = "STARTING_GH"
	StateProbingSOCKS5 SupervisorState = "PROBING_SOCKS5_E2E"
	StateHealthy       SupervisorState = "HEALTHY"
	StateDegraded      SupervisorState = "DEGRADED"
	StateReconnecting  SupervisorState = "RECONNECTING"
	StateShutdown      SupervisorState = "SHUTDOWN"
)

type boundedBuffer struct {
	mu  sync.Mutex
	max int
	buf bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.max <= 0 {
		b.max = 4096
	}
	rem := b.max - b.buf.Len()
	if rem > 0 {
		if len(p) <= rem {
			_, _ = b.buf.Write(p)
		} else {
			_, _ = b.buf.Write(p[:rem])
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(b.buf.String())
}

// BuildGHSSHArgsForPort constructs the hardened gh codespace ssh argument vector for a specific worker port.
func BuildGHSSHArgsForPort(cfg Config, port uint16) []string {
	ghHost := strings.TrimSpace(cfg.GHHost)
	if ghHost == "" {
		ghHost = "127.0.0.1"
	}
	connectTimeout := cfg.SSHConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = DefaultSSHConnectTimeout
	}
	aliveInterval := cfg.SSHServerAliveInterval
	if aliveInterval <= 0 {
		aliveInterval = DefaultSSHAliveInterval
	}
	aliveCountMax := cfg.SSHServerAliveCountMax
	if aliveCountMax <= 0 {
		aliveCountMax = DefaultSSHAliveCountMax
	}
	return []string{
		"codespace", "ssh",
		"-c", cfg.CodespaceName,
		"--",
		"-D", fmt.Sprintf("%s:%d", ghHost, port),
		"-N",
		"-o", "AddressFamily=inet",
		"-o", "Compression=no",
		"-o", "Ciphers=aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeout),
		"-o", "LogLevel=ERROR",
		"-o", fmt.Sprintf("ServerAliveInterval=%d", aliveInterval),
		"-o", fmt.Sprintf("ServerAliveCountMax=%d", aliveCountMax),
	}
}

// BuildGHSSHArgs constructs the hardened gh codespace ssh argument vector for cfg.GHPort.
func BuildGHSSHArgs(cfg Config) []string {
	return BuildGHSSHArgsForPort(cfg, cfg.GHPort)
}

// ComputeBackoff returns decorrelated jittered exponential backoff bounded in [minD, maxD].
func ComputeBackoff(attempt int, minD, maxD time.Duration, rng *rand.Rand) time.Duration {
	if minD <= 0 {
		minD = 2 * time.Second
	}
	if maxD < minD {
		maxD = minD
	}
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 10 {
		shift = 10
	}
	base := float64(minD) * math.Pow(2, float64(shift))
	if base > float64(maxD) {
		base = float64(maxD)
	}
	var u float64
	if rng != nil {
		u = rng.Float64()
	} else {
		u = rand.Float64()
	}
	jittered := base * (0.8 + 0.4*u)
	if jittered < float64(minD) {
		jittered = float64(minD)
	}
	if jittered > float64(maxD) {
		jittered = float64(maxD)
	}
	return time.Duration(jittered)
}

// WatchStdinForQuit reads 1-byte commands from r and triggers onQuit on 'q'/'Q'.
func WatchStdinForQuit(r io.Reader, onQuit func()) {
	if r == nil {
		return
	}
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if err != nil {
			return
		}
		if n > 0 && (b[0] == 'q' || b[0] == 'Q') {
			if onQuit != nil {
				onQuit()
			}
			return
		}
	}
}

// SupervisorDeps allows injecting mocks for deterministic unit and chaos tests.
type SupervisorDeps struct {
	PortInspector          PortInspector
	NewJob                 func() (ProcessJob, error)
	StartChild             func(ctx context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error)
	StopCodespace          func(ctx context.Context, cfg Config) (int, string, error)
	ProbeFunc              func(ctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error)
	MicroPayloadProbeFunc  func(ctx context.Context, ghAddr, target string, timeout time.Duration) (time.Duration, error)
	UnderlayProbeFunc      func(ctx context.Context, targets []string, timeout time.Duration) (time.Duration, string, error)
	LookupWANRemote        func(pid uint32) string
	StderrEcho             io.Writer
	BootPollDelay          time.Duration
	BootQualitySampleDelay time.Duration
	BootQualityRetryDelay  time.Duration
	OnStateChange          func(from, to SupervisorState)
	DisableEcoQoSF         func() error
	TuneChildProcess       func(pid int) error
	TuneProcessTree        func(rootPID int) int
	Metrics                *MetricsEmitter
	GitHubGuard            *GitHubGuard
}

// Supervisor manages the complete NetShaper lifecycle across all 5 core modules:
// Module 1 (GitHubGuard WAF/Bot Safety), Module 2 (Adaptive Baseline-Normalized TunnelPool + Hysteresis),
// Module 3 (Streaming-Aware Multiplexed ProxyServer), Module 4 (Read-Only NetHygiene Preflight),
// and Module 5 (Orthogonal NDJSON MetricsEmitter).
type Supervisor struct {
	cfg     Config
	deps    SupervisorDeps
	logger  *EventLogger
	metrics *MetricsEmitter
	guard   *GitHubGuard

	stateMu        sync.RWMutex
	state          SupervisorState
	stateShadow    atomic.Pointer[SupervisorState]
	sessionStart   time.Time
	reconnectCount atomic.Int64
	everHealthy    atomic.Bool
	vmWoken        atomic.Bool
	fatalBootAbort atomic.Bool

	childMu        sync.Mutex
	activeJob      ProcessJob
	activeCmd      *exec.Cmd
	activeRing     *StderrRingBuffer
	waitDoneCh     chan struct{}
	activeChildPID atomic.Int64

	poolMu        sync.Mutex
	activePool    *TunnelPool
	activePoolPtr atomic.Pointer[TunnelPool]

	proxyMu        sync.Mutex
	activeProxy    *ProxyServer
	boundAddr      string
	activeProxyPtr atomic.Pointer[ProxyServer]
	boundAddrPtr   atomic.Pointer[string]

	closedBytesUp   atomic.Uint64
	closedBytesDown atomic.Uint64

	shutdownMu     sync.Mutex
	shutdownReason string
	shutdownOnce   sync.Once
	cancelMain     context.CancelFunc

	rttMu              sync.Mutex
	rttSamples         []float64
	probeOKWindow      atomic.Uint64
	probeFailWindow    atomic.Uint64
	probeSkippedActive atomic.Uint64
	probeForcedWindow  atomic.Uint64
}

// NewSupervisor initializes a Supervisor with production defaults for any unset dependency.
func NewSupervisor(cfg Config, logger *EventLogger, deps SupervisorDeps) *Supervisor {
	if deps.PortInspector == nil {
		deps.PortInspector = NewPlatformPortInspector()
	}
	if deps.NewJob == nil {
		deps.NewJob = NewProcessJob
	}
	startChildProvided := deps.StartChild != nil
	if deps.StartChild == nil {
		deps.StartChild = defaultStartGHChild
	}
	if deps.StopCodespace == nil {
		deps.StopCodespace = defaultStopCodespace
	}
	if deps.ProbeFunc == nil {
		deps.ProbeFunc = ProbeSOCKS5
	}
	if deps.MicroPayloadProbeFunc == nil {
		deps.MicroPayloadProbeFunc = ProbeSOCKS5MicroPayload
	}
	// Only enable real external direct underlay probes in production (when StartChild is not mocked).
	// Unit/chaos tests inject StartChild (and optionally UnderlayProbeFunc) and must never dial the internet.
	if deps.UnderlayProbeFunc == nil && !startChildProvided {
		deps.UnderlayProbeFunc = MeasureUnderlayBaseline
	}
	if deps.LookupWANRemote == nil {
		deps.LookupWANRemote = LookupProcessWANRemote
	}
	if deps.BootPollDelay <= 0 {
		deps.BootPollDelay = 500 * time.Millisecond
	}
	if deps.BootQualitySampleDelay <= 0 {
		deps.BootQualitySampleDelay = 120 * time.Millisecond
	}
	if deps.BootQualityRetryDelay <= 0 {
		deps.BootQualityRetryDelay = 1500 * time.Millisecond
	}
	if deps.DisableEcoQoSF == nil {
		deps.DisableEcoQoSF = DisableEcoQoS
	}
	if deps.TuneChildProcess == nil {
		deps.TuneChildProcess = TuneChildProcessQoS
	}
	if deps.TuneProcessTree == nil {
		deps.TuneProcessTree = TuneProcessTreeQoS
	}
	guard := deps.GitHubGuard
	if guard == nil {
		guard = NewGitHubGuard(cfg, logger, deps.Metrics)
	}

	sup := &Supervisor{
		cfg:          cfg,
		deps:         deps,
		logger:       logger,
		metrics:      deps.Metrics,
		guard:        guard,
		state:        StateInit,
		sessionStart: time.Now(),
	}
	initState := StateInit
	sup.stateShadow.Store(&initState)
	return sup
}

func defaultStartGHChild(_ context.Context, cfg Config, stderr io.Writer) (*exec.Cmd, error) {
	cmd := exec.Command("gh", BuildGHSSHArgs(cfg)...)
	ConfigureChildCmd(cmd)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func defaultStopCodespace(ctx context.Context, cfg Config) (int, string, error) {
	cmd := exec.CommandContext(ctx, "gh", "codespace", "stop", "-c", cfg.CodespaceName)
	ConfigureChildCmd(cmd)
	configureHiddenCmd(cmd)

	outBuf := &boundedBuffer{max: 2048}
	cmd.Stdout = outBuf
	cmd.Stderr = outBuf

	job, jobErr := NewProcessJob()
	if err := cmd.Start(); err != nil {
		if jobErr == nil && job != nil {
			_ = job.Close()
		}
		return -1, outBuf.String(), err
	}
	if jobErr == nil && job != nil {
		_ = job.Assign(cmd.Process.Pid)
		defer job.Close()
	}

	err := cmd.Wait()
	output := outBuf.String()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), output, err
		}
		return -1, output, err
	}
	return 0, output, nil
}

// State returns the current FSM state safely.
func (s *Supervisor) State() SupervisorState {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}

// BoundLocalAddr returns the active listening address of the local proxy.
func (s *Supervisor) BoundLocalAddr() string {
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	return s.boundAddr
}

// ReconnectCount returns total mid-session reconnect cycles initiated.
func (s *Supervisor) ReconnectCount() int64 {
	return s.reconnectCount.Load()
}

// GuardSnapshot returns the live GitHub API budget & anti-bot guard metrics.
func (s *Supervisor) GuardSnapshot() GitHubGuardSnapshot {
	return s.guard.Snapshot()
}

// PoolSnapshot returns multi-tunnel pool health when running with PoolSize > 1.
func (s *Supervisor) PoolSnapshot() PoolSnapshot {
	s.poolMu.Lock()
	p := s.activePool
	s.poolMu.Unlock()
	if p == nil {
		return PoolSnapshot{PoolSize: 1}
	}
	return p.PoolSnapshot()
}

// AtomicState returns the latest published SupervisorState with 0 mutex acquisitions.
func (s *Supervisor) AtomicState() SupervisorState {
	if s == nil {
		return StateShutdown
	}
	if ptr := s.stateShadow.Load(); ptr != nil {
		return *ptr
	}
	return StateInit
}

// AtomicBoundLocalAddr returns the bound proxy address with 0 mutex acquisitions.
func (s *Supervisor) AtomicBoundLocalAddr() string {
	if s == nil {
		return ""
	}
	if ptr := s.boundAddrPtr.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

// AtomicProxyTelemetry returns wait-free data-plane counters with 0 mutex acquisitions.
func (s *Supervisor) AtomicProxyTelemetry() ProxyAtomicSnapshot {
	if s == nil {
		return ProxyAtomicSnapshot{}
	}
	if p := s.activeProxyPtr.Load(); p != nil {
		return p.AtomicTelemetry()
	}
	return ProxyAtomicSnapshot{}
}

// AtomicPoolSnapshot returns the wait-free cached pool snapshot with 0 mutex acquisitions.
func (s *Supervisor) AtomicPoolSnapshot() PoolSnapshot {
	if s == nil {
		return PoolSnapshot{}
	}
	if p := s.activePoolPtr.Load(); p != nil {
		return p.CachedSnapshot()
	}
	return PoolSnapshot{PoolSize: s.cfg.PoolSize}
}

// AtomicGuardSnapshot returns the wait-free cached GitHubGuard snapshot with 0 mutex acquisitions.
func (s *Supervisor) AtomicGuardSnapshot() GitHubGuardSnapshot {
	if s == nil || s.guard == nil {
		return GitHubGuardSnapshot{}
	}
	return s.guard.CachedSnapshot()
}

// EverHealthy reports whether at least one tunnel reached StateHealthy during this run.
func (s *Supervisor) EverHealthy() bool {
	if s == nil {
		return false
	}
	return s.everHealthy.Load()
}

// VMWoken reports whether at least one tunnel completed an E2E SOCKS5 handshake with the Codespace VM.
func (s *Supervisor) VMWoken() bool {
	if s == nil {
		return false
	}
	return s.vmWoken.Load()
}

// SessionStartTime returns when this Supervisor instance was created.
func (s *Supervisor) SessionStartTime() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.sessionStart
}

// LastStderrTail returns trailing captured stderr from the active or most recent child process.
func (s *Supervisor) LastStderrTail(maxBytes int) string {
	s.childMu.Lock()
	ring := s.activeRing
	s.childMu.Unlock()
	if ring == nil {
		return ""
	}
	return ring.Tail(maxBytes)
}

func (s *Supervisor) setState(next SupervisorState) {
	s.stateMu.Lock()
	prev := s.state
	if prev == next {
		s.stateMu.Unlock()
		return
	}
	s.state = next
	stCopy := next
	s.stateShadow.Store(&stCopy)
	if next == StateHealthy {
		s.everHealthy.Store(true)
	}
	s.stateMu.Unlock()

	if s.logger != nil {
		s.logger.Log("STATE_TRANSITION", map[string]any{
			"from": string(prev),
			"to":   string(next),
		})
	}
	if s.deps.OnStateChange != nil {
		s.deps.OnStateChange(prev, next)
	}
}

// RequestShutdown triggers an idempotent, ordered shutdown from signal or stdin handlers.
func (s *Supervisor) RequestShutdown(reason string) {
	s.shutdownMu.Lock()
	if s.shutdownReason == "" {
		s.shutdownReason = reason
	}
	cancel := s.cancelMain
	s.shutdownMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// Run executes the deterministic NetShaper v6.4 state machine until ctx cancels or RequestShutdown is called.
func (s *Supervisor) Run(parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)
	s.shutdownMu.Lock()
	s.cancelMain = cancel
	alreadyRequested := s.shutdownReason != ""
	s.shutdownMu.Unlock()
	if alreadyRequested {
		cancel()
	}
	defer cancel()

	// --- INIT ---
	s.setState(StateInit)
	selfEcoQoSOK := true
	if err := s.deps.DisableEcoQoSF(); err != nil {
		selfEcoQoSOK = false
		if s.logger != nil {
			s.logger.Log("POWER_HYGIENE", map[string]any{
				"ecoqos_disabled": false,
				"warning":         err.Error(),
			})
		}
	}

	// Module 4: Read-only host network hygiene diagnostic preflight (NEVER mutates OS settings).
	if s.cfg.PreflightNetHygiene {
		_ = RunNetHygienePreflight(ctx, s.logger, s.metrics)
	}

	if s.logger != nil {
		s.logger.Log("SESSION_START", map[string]any{
			"version":                           "v6.4",
			"pid":                               os.Getpid(),
			"codespace":                         s.cfg.CodespaceName,
			"local_port":                        s.cfg.LocalPort,
			"gh_port":                           s.cfg.GHPort,
			"pool_size":                         s.cfg.PoolSize,
			"per_tunnel_max_conns":              s.cfg.PerTunnelMaxConns,
			"max_conns":                         s.cfg.MaxActiveConns,
			"max_queued_conns":                  s.cfg.MaxQueuedConns,
			"copy_buffer_bytes":                 s.cfg.CopyBufferSize,
			"semaphore_wait_ms":                 s.cfg.SemaphoreWaitTimeout.Milliseconds(),
			"dial_pace_interval_ms":             s.cfg.DialPaceInterval.Milliseconds(),
			"tcp_keepalive_ms":                  s.cfg.TCPKeepAlivePeriod.Milliseconds(),
			"idle_timeout_ms":                   s.cfg.IdleTimeout.Milliseconds(),
			"pressure_idle_timeout_ms":          s.cfg.PressureIdleTimeout.Milliseconds(),
			"streaming_idle_timeout_ms":         s.cfg.StreamingIdleTimeout.Milliseconds(),
			"streaming_pressure_idle_timeout_ms": s.cfg.StreamingPressureIdleTimeout.Milliseconds(),
			"stalled_handshake_max_down_bytes":  s.cfg.StalledHandshakeMaxDownBytes,
			"pressure_threshold_pct":            s.cfg.PressureThresholdPct,
			"half_close_drain_ms":               s.cfg.HalfCloseDrainTimeout.Milliseconds(),
			"ssh_connect_timeout_s":             s.cfg.SSHConnectTimeout,
			"stop_on_exit":                      s.cfg.StopOnExit,
			"go_version":                        runtime.Version(),
			"self_ecoqos_disabled":              selfEcoQoSOK,
			"probe_interval_ms":                 s.cfg.ProbeInterval.Milliseconds(),
			"degraded_probe_interval_ms":        s.cfg.DegradedProbeInterval.Milliseconds(),
			"probe_timeout_ms":                  s.cfg.ProbeTimeout.Milliseconds(),
			"degraded_rtt_threshold_ms":         s.cfg.DegradedRTTThreshold.Milliseconds(),
			"breaker_threshold":                 s.cfg.BreakerThreshold,
			"breaker_min_window_ms":             s.cfg.BreakerMinWindow.Milliseconds(),
			"loopback_refused_threshold":        s.cfg.LoopbackRefusedThreshold,
			"ssh_alive_interval_s":              s.cfg.SSHServerAliveInterval,
			"ssh_alive_count_max":               s.cfg.SSHServerAliveCountMax,
			"boot_quality_samples":              s.cfg.BootQualitySamples,
			"boot_quality_max_retries":          s.cfg.BootQualityMaxRetries,
			"boot_quality_max_rtt_ms":           s.cfg.BootQualityMaxRTT.Milliseconds(),
			"boot_quality_max_jitter_ms":        s.cfg.BootQualityMaxJitter.Milliseconds(),
			"boot_fast_lane_max_rtt_ms":         s.cfg.BootFastLaneMaxRTT.Milliseconds(),
			"boot_slow_threshold_ms":            s.cfg.BootSlowThreshold.Milliseconds(),
			"boot_slow_max_rtt_ms":              s.cfg.BootSlowMaxRTT.Milliseconds(),
			"boot_slow_max_jitter_ms":           s.cfg.BootSlowMaxJitter.Milliseconds(),
			"underlay_probe_interval_ms":        s.cfg.UnderlayProbeInterval.Milliseconds(),
			"underlay_probe_targets":            s.cfg.UnderlayProbeTargets,
			"hysteresis_dwell_ms":               s.cfg.HysteresisDwellWindow.Milliseconds(),
			"hysteresis_rel_margin":             s.cfg.HysteresisRelMargin,
			"hysteresis_abs_margin_ms":          s.cfg.HysteresisAbsMargin.Milliseconds(),
			"fast_lane_max_ratio":               s.cfg.FastLaneMaxRatio,
			"slow_lane_evict_ratio":             s.cfg.SlowLaneEvictRatio,
			"slow_lane_evict_window_ms":         s.cfg.SlowLaneEvictWindow.Milliseconds(),
			"slow_lane_underlay_ceiling_ms":     s.cfg.SlowLaneUnderlayCeiling.Milliseconds(),
			"gh_max_calls_5m":                   s.cfg.GitHubMaxCallsPer5Min,
			"gh_max_calls_hour":                 s.cfg.GitHubMaxCallsPerHour,
			"gh_min_call_spacing_ms":            s.cfg.GitHubMinCallSpacing.Milliseconds(),
		})
	}

	// --- PORT_CLEANUP (initial across LocalPort + all upstream PoolPorts, NEVER 10808) ---
	s.setState(StatePortCleanup)
	cleanPorts := append([]uint16{s.cfg.LocalPort}, s.cfg.PoolPorts()...)
	_, _ = CleanTargetPorts(
		s.deps.PortInspector,
		cleanPorts,
		uint32(os.Getpid()),
		DefaultCleanupAllowedImages,
		s.logger,
	)

	// Multi-tunnel pool mode (v6.3 production default: PoolSize >= 2, recommended 2..3).
	if s.cfg.PoolSize > 1 {
		return s.runMultiTunnelPool(ctx)
	}

	// Single-tunnel deterministic mode (PoolSize == 1, full v5 parity + v6.3 GitHubGuard/StreamingReaper/Metrics).
	return s.runSingleTunnelLoop(ctx)
}

func (s *Supervisor) runMultiTunnelPool(ctx context.Context) error {
	s.setState(StateStartingGH)
	pool := NewTunnelPool(s.cfg, s.deps, s.logger, s.metrics, s.guard)
	pool.SetOnVMWoken(func() {
		s.vmWoken.Store(true)
	})
	s.poolMu.Lock()
	s.activePool = pool
	s.activePoolPtr.Store(pool)
	s.poolMu.Unlock()

	s.setState(StateProbingSOCKS5)
	if err := pool.Start(ctx); err != nil {
		var fatalErr *FatalBootError
		if errors.As(err, &fatalErr) {
			s.fatalBootAbort.Store(true)
		}
		if pool.HasWokenVM() {
			s.vmWoken.Store(true)
		}
		pool.Close()
		s.executeOrderedShutdown()
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	proxy := NewPooledProxyServer(s.cfg, pool, s.logger, s.metrics)
	boundAddr, listenErr := proxy.Start(ctx)
	if listenErr != nil {
		if s.logger != nil {
			s.logger.Log("LISTEN_BIND_ERROR", map[string]any{
				"local_addr": s.cfg.LocalAddr(),
				"error":      listenErr.Error(),
			})
		}
		pool.Close()
		s.executeOrderedShutdown()
		return listenErr
	}

	s.proxyMu.Lock()
	s.activeProxy = proxy
	s.boundAddr = boundAddr
	s.activeProxyPtr.Store(proxy)
	baCopy := boundAddr
	s.boundAddrPtr.Store(&baCopy)
	s.proxyMu.Unlock()

	snap := pool.PoolSnapshot()
	if s.logger != nil {
		s.logger.Log("BOOT_READY", map[string]any{
			"mode":                 "multi_tunnel_pool",
			"pool_size":            snap.PoolSize,
			"healthy_workers":      snap.HealthyWorkers,
			"underlay_baseline_ms": snap.UnderlayBaselineMS,
			"routing_mode":         snap.RoutingMode,
			"primary_tunnel_id":    snap.PrimaryTunnelID,
			"local_addr":           boundAddr,
			"workers":              snap.Workers,
		})
	}

	s.setState(StateHealthy)

	summaryInterval := s.cfg.SummaryLogInterval
	if summaryInterval <= 0 {
		summaryInterval = DefaultSummaryLogInterval
	}
	summaryTicker := time.NewTicker(summaryInterval)
	defer summaryTicker.Stop()

	healthTicker := time.NewTicker(250 * time.Millisecond)
	defer healthTicker.Stop()
	summaryWindowStart := time.Now()

	for {
		select {
		case <-ctx.Done():
			s.stopActiveProxy(true)
			pool.Close()
			s.executeOrderedShutdown()
			return nil
		case fatalErr := <-pool.FatalErrCh():
			s.fatalBootAbort.Store(true)
			s.stopActiveProxy(true)
			pool.Close()
			s.executeOrderedShutdown()
			return fatalErr
		case <-healthTicker.C:
			hc := pool.HealthyCount()
			if hc > 0 {
				if s.State() != StateHealthy {
					s.setState(StateHealthy)
				}
			} else {
				if s.State() != StateDegraded {
					s.setState(StateDegraded)
				}
			}
		case <-summaryTicker.C:
			now := time.Now()
			elapsed := now.Sub(summaryWindowStart)
			summaryWindowStart = now
			s.emitPoolSummary(proxy, pool, elapsed)
		}
	}
}

func (s *Supervisor) runSingleTunnelLoop(ctx context.Context) error {
	attempt := 0
	qualityRetries := 0
	var outageStart time.Time

	for {
		if ctx.Err() != nil {
			s.executeOrderedShutdown()
			return nil
		}

		// Module 1: Enforce GitHub API budget, min inter-call spacing & 429/403 anti-bot cooldown before spawning gh.
		if err := s.guard.Allow(ctx, "single_tunnel_boot"); err != nil {
			s.executeOrderedShutdown()
			return nil
		}

		// --- STARTING_GH ---
		s.setState(StateStartingGH)
		bootStart := time.Now()
		childExitCh, startErr := s.spawnChild(ctx)
		if startErr != nil {
			s.guard.RecordFailure(startErr.Error())
			if s.logger != nil {
				s.logger.Log("CHILD_START_ERROR", map[string]any{
					"error":   startErr.Error(),
					"attempt": attempt + 1,
				})
			}
			if outageStart.IsZero() {
				outageStart = time.Now()
			}
			attempt++
			if !s.enterReconnectBackoff(ctx, attempt) {
				s.executeOrderedShutdown()
				return nil
			}
			continue
		}

		// --- PROBING_SOCKS5_E2E ---
		s.setState(StateProbingSOCKS5)
		bootMetrics, earlyExit, probeErr := WaitForTunnelReadyDetailed(
			ctx,
			childExitCh,
			s.cfg.GHAddr(),
			s.cfg.ProbeTarget,
			s.cfg.BootTimeout,
			s.cfg.ProbeTimeout,
			s.deps.BootPollDelay,
			s.deps.ProbeFunc,
		)
		if probeErr != nil {
			tail := s.LastStderrTail(2048)
			if earlyExit != nil && earlyExit.StderrTail != "" {
				tail = earlyExit.StderrTail
			}
			s.teardownChild()
			if ctx.Err() != nil {
				s.executeOrderedShutdown()
				return nil
			}
			s.guard.RecordFailure(tail)
			if earlyExit != nil && s.logger != nil {
				s.logger.Log("CHILD_EXIT", map[string]any{
					"phase":       "boot",
					"exit_code":   earlyExit.ExitCode,
					"uptime_ms":   earlyExit.Uptime.Milliseconds(),
					"stderr_tail": earlyExit.StderrTail,
				})
			} else if s.logger != nil {
				s.logger.Log("BOOT_TIMEOUT", map[string]any{
					"error":       probeErr.Error(),
					"stderr_tail": tail,
				})
			}
			if fatalErr := ClassifyPermanentBootError(tail); fatalErr != nil {
				if s.logger != nil {
					s.logger.Log("FATAL_BOOT_ERROR", map[string]any{
						"code":        fatalErr.Code,
						"message":     fatalErr.Message,
						"stderr_tail": tail,
					})
				}
				s.fatalBootAbort.Store(true)
				s.executeOrderedShutdown()
				return fatalErr
			}
			if outageStart.IsZero() {
				outageStart = time.Now()
			}
			attempt++
			if !s.enterReconnectBackoff(ctx, attempt) {
				s.executeOrderedShutdown()
				return nil
			}
			continue
		}

		s.vmWoken.Store(true)
		ghPID := uint32(s.activeChildPID.Load())
		tunedTreeCount := s.deps.TuneProcessTree(int(ghPID))

		// --- PRE-TRAFFIC BOOT QUALITY GATE (before :1080 ever opens!) ---
		qReport, qEarlyExit, qErr := s.qualifyBootTunnel(ctx, childExitCh, bootStart, bootMetrics)
		if qErr != nil {
			s.teardownChild()
			if ctx.Err() != nil {
				s.executeOrderedShutdown()
				return nil
			}
			if qEarlyExit != nil {
				s.guard.RecordFailure(qEarlyExit.StderrTail)
				if s.logger != nil {
					s.logger.Log("CHILD_EXIT", map[string]any{
						"phase":       "boot_qualify",
						"exit_code":   qEarlyExit.ExitCode,
						"uptime_ms":   qEarlyExit.Uptime.Milliseconds(),
						"stderr_tail": qEarlyExit.StderrTail,
					})
				}
				if fatalErr := ClassifyPermanentBootError(qEarlyExit.StderrTail); fatalErr != nil {
					if s.logger != nil {
						s.logger.Log("FATAL_BOOT_ERROR", map[string]any{
							"code":        fatalErr.Code,
							"message":     fatalErr.Message,
							"stderr_tail": qEarlyExit.StderrTail,
						})
					}
					s.fatalBootAbort.Store(true)
					s.executeOrderedShutdown()
					return fatalErr
				}
			}
			if outageStart.IsZero() {
				outageStart = time.Now()
			}
			attempt++
			if !s.enterReconnectBackoff(ctx, attempt) {
				s.executeOrderedShutdown()
				return nil
			}
			continue
		}

		ghWAN := s.deps.LookupWANRemote(ghPID)
		if !qReport.Accepted {
			if qualityRetries < s.cfg.BootQualityMaxRetries {
				qualityRetries++
				if s.logger != nil {
					s.logger.Log("BOOT_QUALITY_REJECT", map[string]any{
						"reason":                  qReport.Reason,
						"boot_duration_ms":        qReport.BootDurMS,
						"boot_phase_port_open_ms": bootMetrics.SpawnToPortOpen.Milliseconds(),
						"boot_phase_socks5_ms":    bootMetrics.PortOpenToSOCKS5.Milliseconds(),
						"p50_ms":                  qReport.P50MS,
						"min_ms":                  qReport.MinMS,
						"max_ms":                  qReport.MaxMS,
						"jitter_ms":               qReport.JitterMS,
						"samples":                 qReport.Samples,
						"failures":                qReport.Failures,
						"slow_boot":               qReport.SlowBoot,
						"quality_retry":           qualityRetries,
						"max_retries":             s.cfg.BootQualityMaxRetries,
						"gh_pid":                  ghPID,
						"gh_wan_remote":           ghWAN,
					})
				}
				s.teardownChild()
				_, _ = CleanTargetPorts(
					s.deps.PortInspector,
					[]uint16{s.cfg.GHPort},
					uint32(os.Getpid()),
					DefaultCleanupAllowedImages,
					s.logger,
				)
				retryTimer := time.NewTimer(s.deps.BootQualityRetryDelay)
				select {
				case <-ctx.Done():
					retryTimer.Stop()
					s.executeOrderedShutdown()
					return nil
				case <-retryTimer.C:
				}
				continue
			}

			if s.logger != nil {
				s.logger.Log("BOOT_QUALITY_ACCEPTED_BEST_EFFORT", map[string]any{
					"reason":           qReport.Reason,
					"boot_duration_ms": qReport.BootDurMS,
					"p50_ms":           qReport.P50MS,
					"jitter_ms":        qReport.JitterMS,
					"quality_retries":  qualityRetries,
					"gh_pid":           ghPID,
					"gh_wan_remote":    ghWAN,
				})
			}
		}

		s.guard.RecordSuccess()

		dialFailCh := make(chan error, 32)
		dialOKCh := make(chan struct{}, 32)

		proxy := NewProxyServer(
			s.cfg,
			s.cfg.GHAddr(),
			s.logger,
			func(err error) {
				select {
				case dialFailCh <- err:
				default:
				}
			},
			func() {
				select {
				case dialOKCh <- struct{}{}:
				default:
				}
			},
		)
		proxy.SetMetrics(s.metrics)
		pmtu576Active := s.cfg.PMTU576SafeMode && IsPMTU576RelayIP(ghWAN)
		proxy.SetSinglePMTU576Safe(pmtu576Active)

		boundAddr, listenErr := proxy.Start(ctx)
		if listenErr != nil {
			s.teardownChild()
			if s.logger != nil {
				s.logger.Log("LISTEN_BIND_ERROR", map[string]any{
					"local_addr": s.cfg.LocalAddr(),
					"error":      listenErr.Error(),
				})
			}
			if outageStart.IsZero() {
				outageStart = time.Now()
			}
			attempt++
			if !s.enterReconnectBackoff(ctx, attempt) {
				s.executeOrderedShutdown()
				return nil
			}
			continue
		}

		s.proxyMu.Lock()
		s.activeProxy = proxy
		s.boundAddr = boundAddr
		s.activeProxyPtr.Store(proxy)
		baCopy := boundAddr
		s.boundAddrPtr.Store(&baCopy)
		s.proxyMu.Unlock()

		s.recordRTTSample(bootMetrics.InitialRTT)
		if s.logger != nil {
			s.logger.Log("BOOT_READY", map[string]any{
				"boot_duration_ms":        time.Since(bootStart).Milliseconds(),
				"boot_phase_port_open_ms": bootMetrics.SpawnToPortOpen.Milliseconds(),
				"boot_phase_socks5_ms":    bootMetrics.PortOpenToSOCKS5.Milliseconds(),
				"boot_probe_attempts":     bootMetrics.Attempts,
				"socks5_probe_rtt_ms":     bootMetrics.InitialRTT.Milliseconds(),
				"boot_quality_p50_ms":     qReport.P50MS,
				"boot_quality_jitter_ms":  qReport.JitterMS,
				"boot_quality_samples":    qReport.Samples,
				"boot_quality_retries":    qualityRetries,
				"boot_quality_reason":     qReport.Reason,
				"child_ecoqos_tuned":      tunedTreeCount,
				"local_addr":              boundAddr,
				"gh_pid":                  ghPID,
				"gh_wan_remote":           ghWAN,
				"pmtu576_safe_active":     pmtu576Active,
			})
		}
		qualityRetries = 0

		if attempt > 0 && !outageStart.IsZero() {
			if s.logger != nil {
				s.logger.Log("RECONNECT_COMPLETE", map[string]any{
					"attempt":         attempt,
					"total_outage_ms": time.Since(outageStart).Milliseconds(),
				})
			}
			attempt = 0
			outageStart = time.Time{}
		}

		// --- HEALTHY <-> DEGRADED ---
		s.setState(StateHealthy)
		shouldReconnect := s.superviseHealthySession(ctx, proxy, childExitCh, dialFailCh, dialOKCh)

		s.stopActiveProxy(true)
		s.teardownChild()

		if !shouldReconnect || ctx.Err() != nil {
			s.executeOrderedShutdown()
			return nil
		}

		outageStart = time.Now()
		attempt++
		s.reconnectCount.Add(1)
		if !s.enterReconnectBackoff(ctx, attempt) {
			s.executeOrderedShutdown()
			return nil
		}
	}
}

func (s *Supervisor) qualifyBootTunnel(
	ctx context.Context,
	childExitCh <-chan ChildExitResult,
	bootStart time.Time,
	bootMetrics BootProbeMetrics,
) (BootQualityReport, *ChildExitResult, error) {
	rtts := []time.Duration{bootMetrics.InitialRTT}
	if s.cfg.BootQualitySamples <= 1 {
		return EvaluateBootQuality(s.cfg, time.Since(bootStart), rtts, 0), nil, nil
	}

	qualCtx, cancelQual := context.WithCancel(ctx)
	exitCaptured := make(chan ChildExitResult, 1)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		if childExitCh == nil {
			<-qualCtx.Done()
			return
		}
		select {
		case res := <-childExitCh:
			exitCaptured <- res
			cancelQual()
		case <-qualCtx.Done():
		}
	}()
	defer func() {
		cancelQual()
		<-watcherDone
	}()

	failures := 0
	delay := s.deps.BootQualitySampleDelay
	for i := 1; i < s.cfg.BootQualitySamples; i++ {
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case res := <-exitCaptured:
				t.Stop()
				return BootQualityReport{}, &res, ErrChildExitedDuringBoot
			case <-qualCtx.Done():
				t.Stop()
				select {
				case res := <-exitCaptured:
					return BootQualityReport{}, &res, ErrChildExitedDuringBoot
				default:
				}
				return BootQualityReport{}, nil, qualCtx.Err()
			case <-t.C:
			}
		}

		rtt, err := s.deps.ProbeFunc(qualCtx, s.cfg.GHAddr(), s.cfg.ProbeTarget, s.cfg.ProbeTimeout)
		select {
		case res := <-exitCaptured:
			return BootQualityReport{}, &res, ErrChildExitedDuringBoot
		default:
		}
		if ctx.Err() != nil {
			return BootQualityReport{}, nil, ctx.Err()
		}
		if err != nil {
			failures++
			break
		}
		rtts = append(rtts, rtt)
		s.recordRTTSample(rtt)
	}

	// Compute bootDuration AFTER all qualification probes so slow probes are counted against BootSlowThreshold.
	bootDuration := time.Since(bootStart)
	return EvaluateBootQuality(s.cfg, bootDuration, rtts, failures), nil, nil
}

func (s *Supervisor) spawnChild(ctx context.Context) (<-chan ChildExitResult, error) {
	job, err := s.deps.NewJob()
	if err != nil {
		return nil, fmt.Errorf("create process job: %w", err)
	}
	ring := NewStderrRingBuffer(DefaultStderrRingCap, s.deps.StderrEcho)

	startTime := time.Now()
	cmd, err := s.deps.StartChild(ctx, s.cfg, ring)
	if err != nil {
		_ = job.Close()
		return nil, err
	}

	childPID := int64(0)
	if cmd.Process != nil {
		childPID = int64(cmd.Process.Pid)
		if assignErr := job.Assign(cmd.Process.Pid); assignErr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			_ = job.Close()
			return nil, fmt.Errorf("assign child pid %d to job: %w", cmd.Process.Pid, assignErr)
		}
		_ = s.deps.TuneChildProcess(cmd.Process.Pid)
	}

	exitCh := make(chan ChildExitResult, 1)
	waitDone := make(chan struct{})

	s.childMu.Lock()
	s.activeJob = job
	s.activeCmd = cmd
	s.activeRing = ring
	s.waitDoneCh = waitDone
	s.childMu.Unlock()
	s.activeChildPID.Store(childPID)

	go func() {
		defer close(waitDone)
		waitErr := cmd.Wait()
		code := 0
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				code = -1
			}
		}
		exitCh <- ChildExitResult{
			ExitCode:   code,
			Err:        waitErr,
			StderrTail: ring.Tail(2048),
			Uptime:     time.Since(startTime),
		}
	}()

	return exitCh, nil
}

func (s *Supervisor) teardownChild() {
	s.childMu.Lock()
	job := s.activeJob
	cmd := s.activeCmd
	waitDone := s.waitDoneCh
	s.activeJob = nil
	s.activeCmd = nil
	s.waitDoneCh = nil
	s.childMu.Unlock()
	s.activeChildPID.Store(0)

	if job != nil {
		_ = job.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if waitDone != nil {
		select {
		case <-waitDone:
		case <-time.After(2 * time.Second):
		}
	}
}

func (s *Supervisor) stopActiveProxy(forceClose bool) {
	s.proxyMu.Lock()
	p := s.activeProxy
	s.activeProxy = nil
	s.boundAddr = ""
	s.activeProxyPtr.Store(nil)
	s.boundAddrPtr.Store(nil)
	s.proxyMu.Unlock()

	if p != nil {
		p.Stop(forceClose)
		up, down := p.TotalBytes()
		s.closedBytesUp.Add(up)
		s.closedBytesDown.Add(down)
	}
}

type asyncProbeResult struct {
	rtt time.Duration
	err error
}

func (s *Supervisor) superviseHealthySession(
	ctx context.Context,
	proxy *ProxyServer,
	childExitCh <-chan ChildExitResult,
	dialFailCh <-chan error,
	dialOKCh <-chan struct{},
) bool {
	probeInterval := s.cfg.ProbeInterval
	if probeInterval <= 0 {
		probeInterval = DefaultProbeInterval
	}
	degradedInterval := s.cfg.DegradedProbeInterval
	if degradedInterval <= 0 {
		degradedInterval = probeInterval / 3
		if degradedInterval < 100*time.Millisecond {
			degradedInterval = 100 * time.Millisecond
		}
		if degradedInterval > DefaultDegradedProbeInterval {
			degradedInterval = DefaultDegradedProbeInterval
		}
	}
	if probeInterval < degradedInterval {
		degradedInterval = probeInterval
	}

	loopbackRefusedThreshold := s.cfg.LoopbackRefusedThreshold
	if loopbackRefusedThreshold < 1 {
		loopbackRefusedThreshold = DefaultLoopbackRefusedThreshold
	}

	probeTimer := time.NewTimer(probeInterval)
	defer probeTimer.Stop()

	summaryInterval := s.cfg.SummaryLogInterval
	if summaryInterval <= 0 {
		summaryInterval = DefaultSummaryLogInterval
	}
	summaryTicker := time.NewTicker(summaryInterval)
	defer summaryTicker.Stop()
	summaryWindowStart := time.Now()
	healthySince := time.Now()
	s.probeOKWindow.Store(0)
	s.probeFailWindow.Store(0)
	s.probeSkippedActive.Store(0)
	s.probeForcedWindow.Store(0)

	consecLoopbackDialFails := 0
	consecLoopbackRefused := 0
	consecProbeFailures := 0
	lastLoggedFailureStreak := 0
	var firstFailureAt time.Time
	var degradedSince time.Time
	var lastDialErr string
	var lastProbeErr string

	consecProbeSkips := 0
	prevSignals := proxy.Signals()

	probeResCh := make(chan asyncProbeResult, 1)
	probeInFlight := false
	var probeCancel context.CancelFunc
	var probeWG sync.WaitGroup

	cancelInFlightProbe := func() {
		if probeCancel != nil {
			probeCancel()
			probeCancel = nil
		}
	}
	defer func() {
		cancelInFlightProbe()
		probeWG.Wait()
	}()

	resetTimer := func(d time.Duration) {
		if !probeTimer.Stop() {
			select {
			case <-probeTimer.C:
			default:
			}
		}
		probeTimer.Reset(d)
	}

	startAsyncProbe := func() {
		if probeInFlight {
			return
		}
		probeInFlight = true
		pctx, pcancel := context.WithCancel(ctx)
		probeCancel = pcancel
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			rtt, err := s.deps.ProbeFunc(pctx, s.cfg.GHAddr(), s.cfg.ProbeTarget, s.cfg.ProbeTimeout)
			select {
			case probeResCh <- asyncProbeResult{rtt: rtt, err: err}:
			case <-pctx.Done():
			}
		}()
	}

	secondsSinceLastBytes := func(now time.Time) float64 {
		lastMoved := proxy.LastBytesMovedAt()
		if !lastMoved.IsZero() {
			return round2(now.Sub(lastMoved).Seconds())
		}
		return round2(now.Sub(healthySince).Seconds())
	}

	for {
		select {
		case <-ctx.Done():
			return false
		case exitRes := <-childExitCh:
			cancelInFlightProbe()
			s.guard.RecordFailure(exitRes.StderrTail)
			if s.logger != nil {
				s.logger.Log("CHILD_EXIT", map[string]any{
					"phase":       "active",
					"exit_code":   exitRes.ExitCode,
					"uptime_ms":   exitRes.Uptime.Milliseconds(),
					"stderr_tail": exitRes.StderrTail,
				})
			}
			return true
		default:
		}

		select {
		case <-ctx.Done():
			return false

		case exitRes := <-childExitCh:
			cancelInFlightProbe()
			s.guard.RecordFailure(exitRes.StderrTail)
			if s.logger != nil {
				s.logger.Log("CHILD_EXIT", map[string]any{
					"phase":       "active",
					"exit_code":   exitRes.ExitCode,
					"uptime_ms":   exitRes.Uptime.Milliseconds(),
					"stderr_tail": exitRes.StderrTail,
				})
			}
			return true

		case <-dialOKCh:
			consecLoopbackDialFails = 0
			consecLoopbackRefused = 0

		case derr := <-dialFailCh:
			consecLoopbackDialFails++
			lastDialErr = derr.Error()

			if isConnRefused(derr) {
				consecLoopbackRefused++
				if consecLoopbackRefused >= loopbackRefusedThreshold {
					cancelInFlightProbe()
					now := time.Now()
					if s.logger != nil {
						s.logger.Log("ZOMBIE_BREAKER_TRIP", map[string]any{
							"reason":                   "loopback_conn_refused",
							"consecutive_failures":     consecLoopbackRefused,
							"seconds_since_last_bytes": secondsSinceLastBytes(now),
							"last_dial_err":            lastDialErr,
							"last_probe_err":           lastProbeErr,
						})
					}
					return true
				}
			} else {
				consecLoopbackRefused = 0
			}

			if !probeInFlight {
				startAsyncProbe()
			}

		case <-probeTimer.C:
			if probeInFlight {
				continue
			}
			lastMoved := proxy.LastBytesMovedAt()
			curSignals := proxy.Signals()
			if s.State() == StateHealthy && !lastMoved.IsZero() && time.Since(lastMoved) < probeInterval {
				allowSkip, forceReason := probeSkipDecision(curSignals, prevSignals, consecProbeSkips)
				prevSignals = curSignals
				if allowSkip {
					consecProbeSkips++
					s.probeSkippedActive.Add(1)
					resetTimer(probeInterval)
					continue
				}
				s.probeForcedWindow.Add(1)
				if s.logger != nil {
					s.logger.Log("PROBE_FORCED", map[string]any{
						"reason":                  forceReason,
						"consecutive_skips":       consecProbeSkips,
						"active_conns":            curSignals.ActiveConns,
						"max_conns":               curSignals.MaxConns,
						"queued_conns":            curSignals.QueuedConns,
						"semaphore_rejects_total": curSignals.SemaphoreRejects,
						"drain_timeouts_total":    curSignals.DrainTimeouts,
						"abrupt_errors_total":     curSignals.AbruptErrors,
					})
				}
			}
			prevSignals = curSignals
			consecProbeSkips = 0
			startAsyncProbe()

		case res := <-probeResCh:
			probeInFlight = false
			if probeCancel != nil {
				probeCancel()
				probeCancel = nil
			}
			if ctx.Err() != nil {
				return false
			}

			now := time.Now()
			if res.err != nil {
				s.probeFailWindow.Add(1)
				consecProbeFailures++
				lastProbeErr = res.err.Error()
				if firstFailureAt.IsZero() {
					firstFailureAt = now
				}

				if isConnRefused(res.err) {
					consecLoopbackRefused++
					if consecLoopbackRefused >= loopbackRefusedThreshold {
						if s.logger != nil {
							s.logger.Log("ZOMBIE_BREAKER_TRIP", map[string]any{
								"reason":                   "loopback_conn_refused",
								"consecutive_failures":     consecLoopbackRefused,
								"seconds_since_last_bytes": secondsSinceLastBytes(now),
								"last_dial_err":            lastDialErr,
								"last_probe_err":           lastProbeErr,
							})
						}
						return true
					}
					if s.State() == StateHealthy {
						degradedSince = now
					}
					s.setState(StateDegraded)
					resetTimer(150 * time.Millisecond)
					continue
				}

				lastMoved := proxy.LastBytesMovedAt()
				failureWindow := now.Sub(firstFailureAt)
				minWindow := s.cfg.BreakerMinWindow

				freshnessWindow := minWindow
				if freshnessWindow <= 0 {
					freshnessWindow = s.cfg.ProbeTimeout
				}
				wanProgressRecent := !lastMoved.IsZero() && now.Sub(lastMoved) < freshnessWindow

				if consecProbeFailures >= s.cfg.BreakerThreshold && failureWindow >= minWindow && !wanProgressRecent {
					if s.logger != nil {
						s.logger.Log("ZOMBIE_BREAKER_TRIP", map[string]any{
							"reason":                   "sustained_e2e_blackhole",
							"consecutive_failures":     consecProbeFailures,
							"failure_window_ms":        failureWindow.Milliseconds(),
							"seconds_since_last_bytes": secondsSinceLastBytes(now),
							"last_dial_err":            lastDialErr,
							"last_probe_err":           lastProbeErr,
						})
					}
					return true
				}

				wasHealthy := s.State() == StateHealthy
				if wasHealthy {
					degradedSince = now
				}
				s.setState(StateDegraded)

				if wasHealthy || consecProbeFailures > lastLoggedFailureStreak {
					lastLoggedFailureStreak = consecProbeFailures
					if s.logger != nil {
						fields := map[string]any{
							"reason":                   "e2e_probe_failed",
							"consecutive_failures":     consecProbeFailures,
							"failure_window_ms":        failureWindow.Milliseconds(),
							"seconds_since_last_bytes": secondsSinceLastBytes(now),
							"last_probe_err":           lastProbeErr,
						}
						if consecProbeFailures >= s.cfg.BreakerThreshold && wanProgressRecent {
							fields["vetoed_by_wan_traffic"] = true
						}
						s.logger.Log("DEGRADED_TRIP", fields)
					}
				}
				resetTimer(degradedInterval)
				continue
			}

			s.probeOKWindow.Add(1)
			s.recordRTTSample(res.rtt)
			consecProbeFailures = 0
			lastLoggedFailureStreak = 0
			firstFailureAt = time.Time{}
			lastProbeErr = ""

			if s.cfg.DegradedRTTThreshold > 0 && res.rtt > s.cfg.DegradedRTTThreshold {
				wasHealthy := s.State() == StateHealthy
				if wasHealthy {
					degradedSince = now
				}
				s.setState(StateDegraded)
				if wasHealthy && s.logger != nil {
					s.logger.Log("DEGRADED_TRIP", map[string]any{
						"reason":               "high_rtt_bufferbloat",
						"probe_rtt_ms":         res.rtt.Milliseconds(),
						"threshold_ms":         s.cfg.DegradedRTTThreshold.Milliseconds(),
						"consecutive_failures": 0,
					})
				}
				resetTimer(degradedInterval)
				continue
			}

			if s.State() == StateDegraded {
				var degDurMS int64
				if !degradedSince.IsZero() {
					degDurMS = now.Sub(degradedSince).Milliseconds()
				}
				s.setState(StateHealthy)
				if s.logger != nil {
					s.logger.Log("RECOVERY_FROM_DEGRADED", map[string]any{
						"degraded_duration_ms":  degDurMS,
						"recovery_probe_rtt_ms": res.rtt.Milliseconds(),
					})
				}
				degradedSince = time.Time{}
			} else {
				s.setState(StateHealthy)
			}
			resetTimer(probeInterval)

		case <-summaryTicker.C:
			now := time.Now()
			elapsed := now.Sub(summaryWindowStart)
			summaryWindowStart = now
			s.emitProbeSummary(proxy, elapsed)
		}
	}
}

func (s *Supervisor) enterReconnectBackoff(ctx context.Context, attempt int) bool {
	s.setState(StateReconnecting)
	backoff := ComputeBackoff(attempt, s.cfg.BackoffMin, s.cfg.BackoffMax, nil)
	if s.logger != nil {
		s.logger.Log("RECONNECT_SCHEDULED", map[string]any{
			"attempt":    attempt,
			"backoff_ms": backoff.Milliseconds(),
		})
	}

	timer := time.NewTimer(backoff)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
	}

	_, _ = CleanTargetPorts(
		s.deps.PortInspector,
		[]uint16{s.cfg.GHPort},
		uint32(os.Getpid()),
		DefaultCleanupAllowedImages,
		s.logger,
	)
	return ctx.Err() == nil
}

func (s *Supervisor) executeOrderedShutdown() {
	s.shutdownOnce.Do(func() {
		s.setState(StateShutdown)

		// 1. Close :1080 listener synchronously.
		s.stopActiveProxy(true)

		// 2. Tear down multi-tunnel pool or single child JobObject.
		s.poolMu.Lock()
		pool := s.activePool
		s.activePool = nil
		s.activePoolPtr.Store(nil)
		s.poolMu.Unlock()
		if pool != nil {
			if pool.HasWokenVM() {
				s.vmWoken.Store(true)
			}
			pool.Close()
		}
		s.teardownChild()

		// 3. Exact-port cleanup across LocalPort + all upstream pool ports, excluding self PID.
		cleanPorts := append([]uint16{s.cfg.LocalPort}, s.cfg.PoolPorts()...)
		_, _ = CleanTargetPorts(
			s.deps.PortInspector,
			cleanPorts,
			uint32(os.Getpid()),
			DefaultCleanupAllowedImages,
			s.logger,
		)

		// 4. Bounded 'gh codespace stop' ONLY on program exit and ONLY if:
		//    (a) this session issued at least one GitHub CLI call (TotalAllowed > 0), AND
		//    (b) at least one tunnel reached StateHealthy OR completed E2E SOCKS5 against the VM (vmWoken == true).
		//    Prevents billing leaks when a VM was woken before quality-gate abort, while still skipping unbooted aborts.
		guardSnap := s.guard.Snapshot()
		stopInvoked := false
		stopExitCode := 0
		var stopDurMS int64
		var stopErrStr string
		var stopOutput string
		var stopSkippedReason string

		if s.cfg.StopOnExit {
			if s.guard != nil && guardSnap.TotalAllowed == 0 {
				stopSkippedReason = "no_gh_calls_issued"
			} else if !s.everHealthy.Load() && !s.vmWoken.Load() {
				stopSkippedReason = "never_became_healthy"
			} else if s.fatalBootAbort.Load() {
				stopSkippedReason = "fatal_boot_error"
			} else {
				stopInvoked = true
				stopStart := time.Now()
				stopCtx, cancelStop := context.WithTimeout(context.Background(), s.cfg.StopTimeout)
				code, out, err := s.deps.StopCodespace(stopCtx, s.cfg)
				cancelStop()
				stopExitCode = code
				stopOutput = out
				stopDurMS = time.Since(stopStart).Milliseconds()
				if err != nil {
					stopErrStr = err.Error()
				} else if code == 0 && s.guard != nil {
					s.guard.MarkCodespaceState("Shutdown")
				}
			}
		}

		s.shutdownMu.Lock()
		reason := s.shutdownReason
		if reason == "" {
			reason = "context_canceled"
		}
		s.shutdownMu.Unlock()

		guardSnap = s.guard.Snapshot()
		if s.logger != nil {
			fields := map[string]any{
				"reason":                 reason,
				"stop_codespace_invoked": stopInvoked,
				"stop_exit_code":         stopExitCode,
				"stop_duration_ms":       stopDurMS,
				"stop_output":            stopOutput,
				"total_bytes_up":         s.closedBytesUp.Load(),
				"total_bytes_down":       s.closedBytesDown.Load(),
				"total_reconnects":       s.reconnectCount.Load(),
				"session_uptime_ms":      time.Since(s.sessionStart).Milliseconds(),
				"gh_api_calls_allowed":   guardSnap.TotalAllowed,
				"gh_api_throttled":       guardSnap.TotalThrottled,
				"gh_api_rate_limit_hits": guardSnap.RateLimitHits,
				"ever_healthy":           s.everHealthy.Load(),
				"vm_woken":               s.vmWoken.Load(),
			}
			if stopErrStr != "" {
				fields["stop_error"] = stopErrStr
			}
			if stopSkippedReason != "" {
				fields["stop_skipped_reason"] = stopSkippedReason
			}
			s.logger.Log("SHUTDOWN_COMPLETE", fields)
			_ = s.logger.Close()
		}
		if s.metrics != nil {
			_ = s.metrics.Close()
		}
	})
}

func (s *Supervisor) recordRTTSample(d time.Duration) {
	s.rttMu.Lock()
	defer s.rttMu.Unlock()
	if len(s.rttSamples) >= 256 {
		s.rttSamples = s.rttSamples[1:]
	}
	s.rttSamples = append(s.rttSamples, float64(d.Milliseconds()))
}

func (s *Supervisor) emitPoolSummary(proxy *ProxyServer, pool *TunnelPool, windowElapsed time.Duration) {
	if proxy == nil || pool == nil {
		return
	}
	stats := proxy.SnapshotWindow(true)
	poolSnap := pool.PoolSnapshot()
	guardSnap := s.guard.Snapshot()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	heapAllocMB := round2(float64(mem.HeapAlloc) / (1024.0 * 1024.0))

	elapsedSec := windowElapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 1.0
	}
	upKbps := round2((float64(stats.BytesUpWindow) * 8.0) / (elapsedSec * 1000.0))
	downKbps := round2((float64(stats.BytesDownWindow) * 8.0) / (elapsedSec * 1000.0))

	payload := map[string]any{
		"mode":                  "multi_tunnel_pool",
		"state":                 string(s.State()),
		"pool_size":             poolSnap.PoolSize,
		"healthy_workers":       poolSnap.HealthyWorkers,
		"degraded_workers":      poolSnap.DegradedWorkers,
		"slow_lane_workers":     poolSnap.SlowLaneWorkers,
		"total_failovers":       poolSnap.TotalFailovers,
		"slow_lane_evictions":   poolSnap.SlowLaneEvictions,
		"primary_switches":      poolSnap.PrimarySwitches,
		"routing_mode":          poolSnap.RoutingMode,
		"primary_tunnel_id":     poolSnap.PrimaryTunnelID,
		"underlay_baseline_ms":  poolSnap.UnderlayBaselineMS,
		"underlay_target":       poolSnap.UnderlayTarget,
		"aggregate_p50_ms":      poolSnap.AggregateP50MS,
		"workers":               poolSnap.Workers,
		"active_conns":          stats.ActiveConns,
		"peak_conns_window":     stats.PeakConns,
		"queued_conns":          stats.QueuedConns,
		"queue_wait_p50_ms":     round2(stats.QueueWaitP50MS),
		"queue_wait_p95_ms":     round2(stats.QueueWaitP95MS),
		"semaphore_rejects":     stats.SemaphoreRejects,
		"pressure_reaps":        stats.PressureReaps,
		"idle_reaps":            stats.IdleReaps,
		"drain_timeouts":        stats.DrainTimeouts,
		"abrupt_errors":         stats.AbruptErrors,
		"throughput_up_kbps":    upKbps,
		"throughput_down_kbps":  downKbps,
		"bytes_up_window":       stats.BytesUpWindow,
		"bytes_down_window":     stats.BytesDownWindow,
		"gh_api_calls_last_5m":  guardSnap.CallsLast5Min,
		"gh_api_calls_last_hr":  guardSnap.CallsLastHour,
		"gh_api_rate_limits":    guardSnap.RateLimitHits,
		"goroutines":            runtime.NumGoroutine(),
		"heap_alloc_mb":         heapAllocMB,
	}

	if s.logger != nil {
		s.logger.Log("POOL_SUMMARY", payload)
	}
	if s.metrics != nil {
		s.metrics.Emit("pool", payload)
	}
}

func (s *Supervisor) emitProbeSummary(proxy *ProxyServer, windowElapsed time.Duration) {
	if s.logger == nil || proxy == nil {
		return
	}
	stats := proxy.SnapshotWindow(true)

	s.rttMu.Lock()
	samples := append([]float64(nil), s.rttSamples...)
	s.rttSamples = s.rttSamples[:0]
	s.rttMu.Unlock()

	rttMin, rttP50, rttP95, rttMax := computeRTTStats(samples)
	probeOK := s.probeOKWindow.Swap(0)
	probeFail := s.probeFailWindow.Swap(0)
	probeSkipped := s.probeSkippedActive.Swap(0)
	probeForced := s.probeForcedWindow.Swap(0)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	heapAllocMB := round2(float64(mem.HeapAlloc) / (1024.0 * 1024.0))

	elapsedSec := windowElapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 1.0
	}
	upKbps := round2((float64(stats.BytesUpWindow) * 8.0) / (elapsedSec * 1000.0))
	downKbps := round2((float64(stats.BytesDownWindow) * 8.0) / (elapsedSec * 1000.0))

	ghWAN := s.deps.LookupWANRemote(uint32(s.activeChildPID.Load()))
	guardSnap := s.guard.Snapshot()

	s.logger.Log("PROBE_SUMMARY", map[string]any{
		"active_conns":                 stats.ActiveConns,
		"peak_conns_window":            stats.PeakConns,
		"semaphore_rejects":            stats.SemaphoreRejects,
		"queued_conns":                 stats.QueuedConns,
		"queue_wait_p50_ms":            round2(stats.QueueWaitP50MS),
		"queue_wait_p95_ms":            round2(stats.QueueWaitP95MS),
		"dial_paced":                   stats.DialPaced,
		"max_conns":                    s.cfg.MaxActiveConns,
		"goroutines":                   runtime.NumGoroutine(),
		"heap_alloc_mb":                heapAllocMB,
		"gc_count":                     mem.NumGC,
		"dropped_logs":                 s.logger.DroppedCount(),
		"bytes_up_window":              stats.BytesUpWindow,
		"bytes_down_window":            stats.BytesDownWindow,
		"throughput_up_kbps":           upKbps,
		"throughput_down_kbps":         downKbps,
		"total_conns_window":           stats.TotalConnsWindow,
		"dial_ok":                      stats.DialOK,
		"dial_fail":                    stats.DialFail,
		"dial_rtt_p50_ms":              round2(stats.DialRTTP50MS),
		"dial_rtt_p95_ms":              round2(stats.DialRTTP95MS),
		"half_close_clean":             stats.HalfCloseClean,
		"drain_timeouts":               stats.DrainTimeouts,
		"idle_reaps":                   stats.IdleReaps,
		"pressure_reaps":               stats.PressureReaps,
		"abrupt_errors":                stats.AbruptErrors,
		"state":                        string(s.State()),
		"probe_ok_window":              probeOK,
		"probe_fail_window":            probeFail,
		"probe_skipped_active_traffic": probeSkipped,
		"probe_forced_window":          probeForced,
		"probe_rtt_min_ms":             rttMin,
		"probe_rtt_p50_ms":             rttP50,
		"probe_rtt_p95_ms":             rttP95,
		"probe_rtt_max_ms":             rttMax,
		"gh_wan_remote":                ghWAN,
		"gh_api_calls_last_5m":         guardSnap.CallsLast5Min,
		"gh_api_calls_last_hr":         guardSnap.CallsLastHour,
	})
}

func computeRTTStats(samples []float64) (minV, p50, p95, maxV float64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	sort.Float64s(samples)
	idx50 := int(math.Ceil(0.50*float64(len(samples)))) - 1
	idx95 := int(math.Ceil(0.95*float64(len(samples)))) - 1
	if idx50 < 0 {
		idx50 = 0
	}
	if idx95 < 0 {
		idx95 = 0
	}
	return samples[0], samples[idx50], samples[idx95], samples[len(samples)-1]
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

// activeProxyLastMoved returns the verified-WAN-progress timestamp of the currently active proxy.
func (s *Supervisor) activeProxyLastMoved() time.Time {
	s.proxyMu.Lock()
	p := s.activeProxy
	s.proxyMu.Unlock()
	if p == nil {
		return time.Time{}
	}
	return p.LastBytesMovedAt()
}
