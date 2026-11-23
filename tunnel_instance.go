package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// TunnelState enumerates the lifecycle states of an individual upstream tunnel worker in the v6 pool.
type TunnelState string

const (
	TunnelStarting TunnelState = "STARTING"
	TunnelHealthy  TunnelState = "HEALTHY"
	TunnelDegraded TunnelState = "DEGRADED"
	TunnelDraining TunnelState = "DRAINING"
	TunnelDead     TunnelState = "DEAD"
)

// TunnelSnapshot summarizes per-worker health, EWMA latency/jitter, baseline-normalized rho, active streams, and WAN endpoint.
type TunnelSnapshot struct {
	ID               string      `json:"id"`
	Port             uint16      `json:"port"`
	Addr             string      `json:"addr"`
	State            TunnelState `json:"state"`
	SlowLaneDegraded bool        `json:"slow_lane_degraded"`
	PID              int64       `json:"pid"`
	WANRemote        string      `json:"wan_remote"`
	PMTU576Active    bool        `json:"pmtu576_active"`
	ActiveStreams    int64       `json:"active_streams"`
	MaxStreams       int         `json:"max_streams"`
	EWMARTTMS        float64     `json:"ewma_rtt_ms"`
	EWMAJitterMS     float64     `json:"ewma_jitter_ms"`
	RelativeRho      float64     `json:"relative_rho"`
	StreamErrorRate  float64     `json:"stream_error_rate"`
	TotalRouted      uint64      `json:"total_routed"`
	DialFailures     uint64      `json:"dial_failures"`
	BootRetries      int         `json:"boot_retries"`
	Restarts         int64       `json:"restarts"`
	LastBootMS       int64       `json:"last_boot_ms"`
}

// TunnelInstance owns one `gh codespace ssh -D 127.0.0.1:<port>` worker with independent JobObject,
// EcoQoS/priority tuning, per-tunnel concurrency semaphore, EWMA RTT/jitter + live stream outcome tracking,
// chronic slow-lane eviction signaling, and graceful drain.
type TunnelInstance struct {
	id   string
	port uint16
	addr string
	cfg  Config
	deps SupervisorDeps

	logger  *EventLogger
	metrics *MetricsEmitter
	guard   *GitHubGuard

	maxStreams       int
	activeStreams    atomic.Int64
	totalRouted      atomic.Uint64
	dialFailures     atomic.Uint64
	restarts         atomic.Int64
	lastWANBytes     atomic.Int64 // UnixNano
	ewmaRTTBits      atomic.Uint64
	ewmaJitterBits   atomic.Uint64
	lastRTTBits      atomic.Uint64
	streamErrRateBit  atomic.Uint64
	slowLaneDegraded  atomic.Bool
	evictionTriggered atomic.Bool
	evictDeferLogged  atomic.Bool
	vmReached         atomic.Bool

	stateMu       sync.RWMutex
	state         TunnelState
	lastBootMS    int64
	bootRetries   int
	wanRemote     string
	pmtu576Active bool
	slowLaneSince time.Time
	onVMReached   func()

	evictCh chan string

	childMu    sync.Mutex
	job        ProcessJob
	cmd        *exec.Cmd
	ring       *StderrRingBuffer
	waitDoneCh chan struct{}
	pid        atomic.Int64
}

// NewTunnelInstance creates a dedicated upstream tunnel worker bound to cfg.GHHost:port.
func NewTunnelInstance(
	id string,
	port uint16,
	cfg Config,
	deps SupervisorDeps,
	logger *EventLogger,
	metrics *MetricsEmitter,
	guard *GitHubGuard,
) *TunnelInstance {
	capPer := cfg.PerTunnelMaxConns
	if capPer < 1 {
		capPer = DefaultPerTunnelMaxConns
	}
	ti := &TunnelInstance{
		id:         id,
		port:       port,
		addr:       cfg.GHAddrForPort(port),
		cfg:        cfg,
		deps:       deps,
		logger:     logger,
		metrics:    metrics,
		guard:      guard,
		maxStreams: capPer,
		state:      TunnelStarting,
		evictCh:    make(chan string, 1),
	}
	ti.ewmaRTTBits.Store(math.Float64bits(350.0))
	ti.ewmaJitterBits.Store(math.Float64bits(0.0))
	ti.lastRTTBits.Store(math.Float64bits(0.0))
	ti.streamErrRateBit.Store(math.Float64bits(0.0))
	return ti
}

func (t *TunnelInstance) ID() string   { return t.id }
func (t *TunnelInstance) Port() uint16 { return t.port }
func (t *TunnelInstance) Addr() string { return t.addr }

// SetOnVMReached registers an optional callback fired once a real E2E SOCKS5 handshake succeeds
// through this worker (proving the Codespace VM has woken to Available).
func (t *TunnelInstance) SetOnVMReached(fn func()) {
	t.stateMu.Lock()
	t.onVMReached = fn
	t.stateMu.Unlock()
}

// HasReachedVM reports whether this worker has proven the Codespace VM reachable via SOCKS5.
func (t *TunnelInstance) HasReachedVM() bool {
	return t.vmReached.Load()
}

func (t *TunnelInstance) State() TunnelState {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.state
}

// IsSlowLaneDegraded reports whether this worker has been flagged as trapped in a chronic slow 5-tuple lane.
func (t *TunnelInstance) IsSlowLaneDegraded() bool {
	return t.slowLaneDegraded.Load()
}

// SetSlowLaneDegraded marks or clears the chronic slow-lane degradation flag on this worker.
func (t *TunnelInstance) SetSlowLaneDegraded(degraded bool) {
	prev := t.slowLaneDegraded.Swap(degraded)
	if prev != degraded && t.metrics != nil {
		t.metrics.Emit("tunnel", map[string]any{
			"tunnel_id":          t.id,
			"port":               t.port,
			"event":              "slow_lane_flag_change",
			"slow_lane_degraded": degraded,
		})
	}
}

// IsEvictionTriggered reports whether a destructive slow-lane DrainAndClose reroll has already been signaled.
func (t *TunnelInstance) IsEvictionTriggered() bool {
	return t.evictionTriggered.Load()
}

// MarkEvictionTriggered atomically claims the single destructive eviction signal for this slow-lane episode.
func (t *TunnelInstance) MarkEvictionTriggered() bool {
	return t.evictionTriggered.CompareAndSwap(false, true)
}

// MarkEvictDeferLogged returns true once per slow-lane deferral episode so deferred logs don't spam.
func (t *TunnelInstance) MarkEvictDeferLogged() bool {
	return t.evictDeferLogged.CompareAndSwap(false, true)
}

// ResetEvictionState clears pending eviction/deferral markers after recovery or worker restart.
func (t *TunnelInstance) ResetEvictionState() {
	t.evictionTriggered.Store(false)
	t.evictDeferLogged.Store(false)
}

// TriggerEviction signals this worker's monitor loop to drain active streams and reroll via GitHubGuard.
func (t *TunnelInstance) TriggerEviction(reason string) bool {
	select {
	case t.evictCh <- reason:
		return true
	default:
		return false
	}
}

func (t *TunnelInstance) drainEvictSignal() {
	for {
		select {
		case <-t.evictCh:
		default:
			return
		}
	}
}

// PMTU576Active reports whether this worker's WAN endpoint resolved to a known PMTU=576 relay VIP
// (20.120.56.11) with PMTU576SafeMode enabled, triggering adaptive 8 KiB copy buffer step-down.
func (t *TunnelInstance) PMTU576Active() bool {
	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	return t.pmtu576Active
}

// SetWANRemote updates the observed WAN remote endpoint and recalculates PMTU576Active.
func (t *TunnelInstance) SetWANRemote(wan string) {
	active := t.cfg.PMTU576SafeMode && IsPMTU576RelayIP(wan)
	t.stateMu.Lock()
	t.wanRemote = wan
	t.pmtu576Active = active
	t.stateMu.Unlock()
}

func (t *TunnelInstance) setState(next TunnelState) {
	t.stateMu.Lock()
	prev := t.state
	t.state = next
	if next == TunnelStarting || next == TunnelDead {
		t.slowLaneSince = time.Time{}
	}
	t.stateMu.Unlock()
	if next == TunnelStarting || next == TunnelDead {
		t.slowLaneDegraded.Store(false)
		t.ResetEvictionState()
	}
	if prev != next && t.metrics != nil {
		t.metrics.Emit("tunnel", map[string]any{
			"tunnel_id": t.id,
			"port":      t.port,
			"event":     "state_change",
			"from":      string(prev),
			"to":        string(next),
		})
	}
}

// EWMARTTMS returns the smoothed EWMA RTT in milliseconds for weighted routing decisions.
func (t *TunnelInstance) EWMARTTMS() float64 {
	return math.Float64frombits(t.ewmaRTTBits.Load())
}

// EWMAJitterMS returns the smoothed EWMA jitter (consecutive RTT delta) in milliseconds.
func (t *TunnelInstance) EWMAJitterMS() float64 {
	return math.Float64frombits(t.ewmaJitterBits.Load())
}

// StreamErrorRate returns the exponentially smoothed live per-stream error rate in [0, 1].
func (t *TunnelInstance) StreamErrorRate() float64 {
	return math.Float64frombits(t.streamErrRateBit.Load())
}

// Rho computes this worker's baseline-normalized relative overhead EWMA_RTT / max(baselineMS, 50ms).
func (t *TunnelInstance) Rho(baselineMS float64) float64 {
	return ComputeRelativeOverhead(t.EWMARTTMS(), baselineMS)
}

// RecordRTT updates the EWMA RTT estimator (alpha=0.25) and EWMA jitter estimator (alpha=0.25).
func (t *TunnelInstance) RecordRTT(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	if ms <= 0 {
		ms = 1.0
	}
	prevSample := math.Float64frombits(t.lastRTTBits.Swap(math.Float64bits(ms)))
	if prevSample > 0 {
		delta := math.Abs(ms - prevSample)
		for {
			oldJBits := t.ewmaJitterBits.Load()
			oldJ := math.Float64frombits(oldJBits)
			nextJ := 0.75*oldJ + 0.25*delta
			if t.ewmaJitterBits.CompareAndSwap(oldJBits, math.Float64bits(nextJ)) {
				break
			}
		}
	}
	for {
		oldBits := t.ewmaRTTBits.Load()
		oldVal := math.Float64frombits(oldBits)
		nextVal := 0.75*oldVal + 0.25*ms
		if oldVal <= 0 {
			nextVal = ms
		}
		if t.ewmaRTTBits.CompareAndSwap(oldBits, math.Float64bits(nextVal)) {
			break
		}
	}
}

// SetEWMARTT directly initializes the EWMA RTT (used after fresh boot qualification or deterministic tests).
func (t *TunnelInstance) SetEWMARTT(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	if ms <= 0 {
		ms = 1.0
	}
	t.ewmaRTTBits.Store(math.Float64bits(ms))
	t.lastRTTBits.Store(math.Float64bits(ms))
}

// RecordStreamSuccess updates the live per-stream error rate downward without waiting for the 25s probe tick.
func (t *TunnelInstance) RecordStreamSuccess() {
	for {
		oldBits := t.streamErrRateBit.Load()
		oldVal := math.Float64frombits(oldBits)
		nextVal := 0.85 * oldVal
		if nextVal < 0.0001 {
			nextVal = 0.0
		}
		if t.streamErrRateBit.CompareAndSwap(oldBits, math.Float64bits(nextVal)) {
			break
		}
	}
}

// RecordStreamError updates the live per-stream error rate upward immediately on dial/stream failure.
func (t *TunnelInstance) RecordStreamError() {
	for {
		oldBits := t.streamErrRateBit.Load()
		oldVal := math.Float64frombits(oldBits)
		nextVal := 0.85*oldVal + 0.15
		if nextVal > 1.0 {
			nextVal = 1.0
		}
		if t.streamErrRateBit.CompareAndSwap(oldBits, math.Float64bits(nextVal)) {
			break
		}
	}
}

// RecordWANBytes records verified downstream WAN activity on this tunnel worker.
func (t *TunnelInstance) RecordWANBytes(n uint64) {
	if n > 0 {
		t.lastWANBytes.Store(time.Now().UnixNano())
	}
}

// LastWANBytesAt returns the most recent verified WAN progress timestamp on this worker.
func (t *TunnelInstance) LastWANBytesAt() time.Time {
	ns := t.lastWANBytes.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// TryAcquireSlot non-blockingly claims one per-tunnel stream slot up to nominal PerTunnelMaxConns.
func (t *TunnelInstance) TryAcquireSlot() bool {
	return t.TryAcquireSlotWithCap(t.maxStreams)
}

// TryAcquireSlotWithCap non-blockingly claims one stream slot if activeStreams < capLimit.
// Used by TunnelPool.AcquireEndpoint to allow surviving healthy worker(s) to burst up to MaxActiveConns
// during peer startup/degradation/slow-lane-eviction without artificial no_healthy_tunnel drops.
func (t *TunnelInstance) TryAcquireSlotWithCap(capLimit int) bool {
	if capLimit < 1 {
		return false
	}
	for {
		cur := t.activeStreams.Load()
		if cur >= int64(capLimit) {
			return false
		}
		if t.activeStreams.CompareAndSwap(cur, cur+1) {
			t.totalRouted.Add(1)
			return true
		}
	}
}

// ReleaseSlot frees one per-tunnel stream slot.
func (t *TunnelInstance) ReleaseSlot() {
	for {
		cur := t.activeStreams.Load()
		if cur <= 0 {
			return
		}
		if t.activeStreams.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

// QualityScore returns the load-independent baseline-normalized lane quality score (lower is better),
// combining relative overhead rho_i, normalized jitter, and live per-stream error rate.
func (t *TunnelInstance) QualityScore(baselineMS float64) float64 {
	denom := baselineMS
	if denom < 50.0 {
		denom = 50.0
	}
	rho := t.Rho(denom)
	jitterRatio := t.EWMAJitterMS() / denom
	errRate := t.StreamErrorRate()
	score := rho + 0.5*jitterRatio + 2.0*errRate
	if t.IsSlowLaneDegraded() {
		score *= 4.0
	}
	if t.State() == TunnelDegraded {
		score *= 4.0
	}
	return score
}

// RoutingScore computes the Power-of-Two-Choices weighted cost: (active + 1) * (ewmaRTT + 50ms) * penalty.
func (t *TunnelInstance) RoutingScore() float64 {
	active := float64(t.activeStreams.Load())
	if active < 0 {
		active = 0
	}
	rtt := t.EWMARTTMS()
	if rtt < 1.0 {
		rtt = 1.0
	}
	errPenalty := 1.0 + 2.0*t.StreamErrorRate()
	penalty := errPenalty
	if t.State() == TunnelDegraded || t.IsSlowLaneDegraded() {
		penalty *= 4.0
	}
	return (active + 1.0) * (rtt + 50.0) * penalty
}

// NormalizedRoutingScore computes the v6.3 baseline-normalized load-aware routing cost.
func (t *TunnelInstance) NormalizedRoutingScore(baselineMS float64) float64 {
	active := float64(t.activeStreams.Load())
	if active < 0 {
		active = 0
	}
	return (active + 1.0) * t.QualityScore(baselineMS)
}

// LastStderrTail returns the trailing stderr captured from this worker's gh/ssh child.
func (t *TunnelInstance) LastStderrTail(maxBytes int) string {
	t.childMu.Lock()
	ring := t.ring
	t.childMu.Unlock()
	if ring == nil {
		return ""
	}
	return ring.Tail(maxBytes)
}

// Snapshot returns a point-in-time telemetry view of this worker.
func (t *TunnelInstance) Snapshot() TunnelSnapshot {
	return t.SnapshotWithBaseline(t.cfg.UnderlayBaselineMS)
}

// SnapshotWithBaseline returns a point-in-time telemetry view including baseline-normalized rho.
func (t *TunnelInstance) SnapshotWithBaseline(baselineMS float64) TunnelSnapshot {
	t.stateMu.RLock()
	st := t.state
	lb := t.lastBootMS
	br := t.bootRetries
	wan := t.wanRemote
	pmtu576 := t.pmtu576Active
	t.stateMu.RUnlock()
	return TunnelSnapshot{
		ID:               t.id,
		Port:             t.port,
		Addr:             t.addr,
		State:            st,
		SlowLaneDegraded: t.slowLaneDegraded.Load(),
		PID:              t.pid.Load(),
		WANRemote:        wan,
		PMTU576Active:    pmtu576,
		ActiveStreams:    t.activeStreams.Load(),
		MaxStreams:       t.maxStreams,
		EWMARTTMS:        round2(t.EWMARTTMS()),
		EWMAJitterMS:     round2(t.EWMAJitterMS()),
		RelativeRho:      round2(t.Rho(baselineMS)),
		StreamErrorRate:  round2(t.StreamErrorRate()),
		TotalRouted:      t.totalRouted.Load(),
		DialFailures:     t.dialFailures.Load(),
		BootRetries:      br,
		Restarts:         t.restarts.Load(),
		LastBootMS:       lb,
	}
}

// BootAndQualify boots this worker's gh codespace ssh child (respecting GitHubGuard),
// tunes EcoQoS/priority across its full process tree, and passes it through the Two-Stage
// 5-Tuple Fast-Lane Boot Gate before marking it TunnelHealthy.
func (t *TunnelInstance) BootAndQualify(
	ctx context.Context,
	peerMedianFn func(excludeID string) float64,
	underlayBaselineFn func() float64,
) (<-chan ChildExitResult, BootQualityReport, BootProbeMetrics, error) {
	t.setState(TunnelStarting)
	t.drainEvictSignal()
	workerCfg := t.cfg
	workerCfg.GHPort = t.port

	qualityRetries := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, BootQualityReport{}, BootProbeMetrics{}, err
		}
		if t.guard != nil {
			if err := t.guard.Allow(ctx, "tunnel_boot:"+t.id); err != nil {
				return nil, BootQualityReport{}, BootProbeMetrics{}, err
			}
		}

		bootStart := time.Now()
		exitCh, err := t.spawnChild(ctx, workerCfg)
		if err != nil {
			if t.guard != nil {
				t.guard.RecordFailure(err.Error())
			}
			return nil, BootQualityReport{}, BootProbeMetrics{}, err
		}

		bootMetrics, earlyExit, probeErr := WaitForTunnelReadyDetailed(
			ctx,
			exitCh,
			t.addr,
			workerCfg.ProbeTarget,
			workerCfg.BootTimeout,
			workerCfg.ProbeTimeout,
			t.deps.BootPollDelay,
			t.deps.ProbeFunc,
		)
		if probeErr != nil {
			tail := t.LastStderrTail(2048)
			if earlyExit != nil && earlyExit.StderrTail != "" {
				tail = earlyExit.StderrTail
			}
			t.TeardownChild()
			if t.guard != nil && ctx.Err() == nil {
				t.guard.RecordFailure(tail)
			}
			if earlyExit != nil && t.logger != nil {
				t.logger.Log("WORKER_BOOT_EXIT", map[string]any{
					"tunnel_id":   t.id,
					"port":        t.port,
					"exit_code":   earlyExit.ExitCode,
					"stderr_tail": tail,
				})
			}
			if fatalErr := ClassifyPermanentBootError(tail); fatalErr != nil && ctx.Err() == nil {
				if t.logger != nil {
					t.logger.Log("FATAL_BOOT_ERROR", map[string]any{
						"tunnel_id":   t.id,
						"port":        t.port,
						"code":        fatalErr.Code,
						"message":     fatalErr.Message,
						"stderr_tail": tail,
					})
				}
				return nil, BootQualityReport{}, BootProbeMetrics{}, fatalErr
			}
			return nil, BootQualityReport{}, BootProbeMetrics{}, probeErr
		}

		t.vmReached.Store(true)
		t.stateMu.RLock()
		vmCB := t.onVMReached
		t.stateMu.RUnlock()
		if vmCB != nil {
			vmCB()
		}

		ghPID := uint32(t.pid.Load())
		_ = t.deps.TuneProcessTree(int(ghPID))

		// Stage 1 + Stage 2 Fast-Lane Qualification.
		rtts := []time.Duration{bootMetrics.InitialRTT}
		failures := 0
		if workerCfg.BootQualitySamples > 1 {
			for i := 1; i < workerCfg.BootQualitySamples; i++ {
				if d := t.deps.BootQualitySampleDelay; d > 0 {
					tm := time.NewTimer(d)
					select {
					case <-ctx.Done():
						tm.Stop()
						t.TeardownChild()
						return nil, BootQualityReport{}, BootProbeMetrics{}, ctx.Err()
					case res := <-exitCh:
						tm.Stop()
						t.TeardownChild()
						if t.guard != nil {
							t.guard.RecordFailure(res.StderrTail)
						}
						if fatalErr := ClassifyPermanentBootError(res.StderrTail); fatalErr != nil && ctx.Err() == nil {
							if t.logger != nil {
								t.logger.Log("FATAL_BOOT_ERROR", map[string]any{
									"tunnel_id":   t.id,
									"port":        t.port,
									"code":        fatalErr.Code,
									"message":     fatalErr.Message,
									"stderr_tail": res.StderrTail,
								})
							}
							return nil, BootQualityReport{}, BootProbeMetrics{}, fatalErr
						}
						return nil, BootQualityReport{}, BootProbeMetrics{}, ErrChildExitedDuringBoot
					case <-tm.C:
					}
				}
				rtt, qErr := t.deps.ProbeFunc(ctx, t.addr, workerCfg.ProbeTarget, workerCfg.ProbeTimeout)
				if qErr != nil {
					failures++
					break
				}
				rtts = append(rtts, rtt)
			}
		}

		// Stage 2: Micro-payload bidirectional probe (when enabled and Stage 1 had no probe failures).
		microOK := true
		var microRTT time.Duration
		if workerCfg.BootMicroPayloadCheck && failures == 0 && workerCfg.BootQualitySamples > 1 {
			mpFn := t.deps.MicroPayloadProbeFunc
			if mpFn == nil {
				mpFn = ProbeSOCKS5MicroPayload
			}
			var mpErr error
			microRTT, mpErr = mpFn(ctx, t.addr, workerCfg.ProbeTarget, workerCfg.ProbeTimeout)
			if mpErr != nil {
				microOK = false
			}
		}

		// Compute bootDuration AFTER Stage 1+2 qualification probes (fixes v5 pid14300 timing bug).
		bootDuration := time.Since(bootStart)

		var peerMedian float64
		if peerMedianFn != nil {
			peerMedian = peerMedianFn(t.id)
		}
		var underlayRaw float64
		if underlayBaselineFn != nil {
			underlayRaw = underlayBaselineFn()
		}
		qRep := EvaluateFastLaneGateNormalized(workerCfg, bootDuration, rtts, failures, peerMedian, underlayRaw, microOK, microRTT)
		wan := t.deps.LookupWANRemote(ghPID)
		pmtu576 := workerCfg.PMTU576SafeMode && IsPMTU576RelayIP(wan)

		canRetry := true
		deferReason := ""
		if !qRep.Accepted && t.guard != nil {
			if ok, why := t.guard.CanAllowNonConsuming(); !ok && why != "min_call_spacing" {
				canRetry = false
				deferReason = why
			}
		}

		// Never tear down a live working tunnel (Failures==0 && MicroPayloadOK) when GitHubGuard
		// has no remaining API budget or is in cooldown to boot a replacement.
		if !qRep.Accepted && qualityRetries < workerCfg.BootQualityMaxRetries && (canRetry || qRep.Failures > 0 || !qRep.MicroPayloadOK) {
			qualityRetries++
			if t.logger != nil {
				t.logger.Log("BOOT_QUALITY_REJECT", map[string]any{
					"tunnel_id":        t.id,
					"port":             t.port,
					"reason":           qRep.Reason,
					"boot_duration_ms": qRep.BootDurMS,
					"p50_ms":           qRep.P50MS,
					"jitter_ms":        qRep.JitterMS,
					"peer_median_ms":   qRep.PeerMedianMS,
					"underlay_raw_ms":  qRep.UnderlayRawMS,
					"relative_rho":     qRep.RelativeRho,
					"micro_payload_ok": qRep.MicroPayloadOK,
					"quality_retry":    qualityRetries,
					"max_retries":      workerCfg.BootQualityMaxRetries,
					"gh_wan_remote":    wan,
				})
			}
			t.TeardownChild()
			_, _ = CleanTargetPorts(t.deps.PortInspector, []uint16{t.port}, 0, DefaultCleanupAllowedImages, t.logger)
			retryTimer := time.NewTimer(t.deps.BootQualityRetryDelay)
			select {
			case <-ctx.Done():
				retryTimer.Stop()
				return nil, BootQualityReport{}, BootProbeMetrics{}, ctx.Err()
			case <-retryTimer.C:
			}
			continue
		}

		if !qRep.Accepted && t.logger != nil {
			fields := map[string]any{
				"tunnel_id":       t.id,
				"port":            t.port,
				"reason":          qRep.Reason,
				"p50_ms":          qRep.P50MS,
				"underlay_raw_ms": qRep.UnderlayRawMS,
				"relative_rho":    qRep.RelativeRho,
				"quality_retries": qualityRetries,
				"gh_wan_remote":   wan,
			}
			if !canRetry {
				fields["budget_constrained"] = true
				fields["defer_reason"] = deferReason
			}
			t.logger.Log("BOOT_QUALITY_ACCEPTED_BEST_EFFORT", fields)
		}

		if t.guard != nil {
			t.guard.RecordSuccess()
		}
		if qRep.P50MS > 0 {
			t.SetEWMARTT(time.Duration(qRep.P50MS) * time.Millisecond)
		} else if bootMetrics.InitialRTT > 0 {
			t.SetEWMARTT(bootMetrics.InitialRTT)
		}
		t.streamErrRateBit.Store(math.Float64bits(0.0))
		t.ewmaJitterBits.Store(math.Float64bits(float64(qRep.JitterMS)))
		t.slowLaneDegraded.Store(false)

		t.stateMu.Lock()
		t.lastBootMS = bootDuration.Milliseconds()
		t.bootRetries = qualityRetries
		t.wanRemote = wan
		t.pmtu576Active = pmtu576
		t.slowLaneSince = time.Time{}
		t.stateMu.Unlock()
		t.setState(TunnelHealthy)

		if t.metrics != nil {
			t.metrics.Emit("tunnel", map[string]any{
				"tunnel_id":        t.id,
				"port":             t.port,
				"event":            "boot_ready",
				"boot_ms":          bootDuration.Milliseconds(),
				"p50_ms":           qRep.P50MS,
				"jitter_ms":        qRep.JitterMS,
				"underlay_raw_ms":  qRep.UnderlayRawMS,
				"relative_rho":     qRep.RelativeRho,
				"micro_payload_ok": qRep.MicroPayloadOK,
				"quality_retries":  qualityRetries,
				"wan_remote":       wan,
				"pmtu576_active":   pmtu576,
			})
		}
		return exitCh, qRep, bootMetrics, nil
	}
}

func (t *TunnelInstance) spawnChild(ctx context.Context, workerCfg Config) (<-chan ChildExitResult, error) {
	job, err := t.deps.NewJob()
	if err != nil {
		return nil, fmt.Errorf("tunnel %s create job: %w", t.id, err)
	}
	ring := NewStderrRingBuffer(DefaultStderrRingCap, t.deps.StderrEcho)
	startTime := time.Now()
	cmd, err := t.deps.StartChild(ctx, workerCfg, ring)
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
			return nil, fmt.Errorf("tunnel %s assign pid %d to job: %w", t.id, cmd.Process.Pid, assignErr)
		}
		_ = t.deps.TuneChildProcess(cmd.Process.Pid)
	}

	exitCh := make(chan ChildExitResult, 1)
	waitDone := make(chan struct{})

	t.childMu.Lock()
	t.job = job
	t.cmd = cmd
	t.ring = ring
	t.waitDoneCh = waitDone
	t.childMu.Unlock()
	t.pid.Store(childPID)

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

// DrainAndClose transitions this worker out of rotation, waits briefly for active streams to drain
// (up to drainTimeout), and then atomically tears down its JobObject + child process tree.
func (t *TunnelInstance) DrainAndClose(drainTimeout time.Duration) {
	t.setState(TunnelDraining)
	if drainTimeout > 0 {
		deadline := time.Now().Add(drainTimeout)
		for t.activeStreams.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(15 * time.Millisecond)
		}
	}
	t.TeardownChild()
	t.setState(TunnelDead)
}

// TeardownChild atomically closes the worker's JobObject and ensures child exit completes.
func (t *TunnelInstance) TeardownChild() {
	t.childMu.Lock()
	job := t.job
	cmd := t.cmd
	waitDone := t.waitDoneCh
	t.job = nil
	t.cmd = nil
	t.waitDoneCh = nil
	t.childMu.Unlock()
	t.pid.Store(0)

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
