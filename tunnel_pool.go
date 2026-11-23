package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamLease represents a single routed stream slot leased from the TunnelPool (or single endpoint).
type UpstreamLease struct {
	TunnelID    string
	Addr        string
	PMTU576Safe bool
	release     func()
}

// Release frees the per-tunnel slot when the relayed client connection closes.
func (l UpstreamLease) Release() {
	if l.release != nil {
		l.release()
	}
}

// UpstreamSelector decouples ProxyServer from single-tunnel vs multi-tunnel pool routing.
type UpstreamSelector interface {
	AcquireEndpoint(ctx context.Context) (UpstreamLease, error)
	NotifyDialFailure(tunnelID string, err error)
	NotifyDialSuccess(tunnelID string, rtt time.Duration)
	NotifyWANBytes(tunnelID string, n uint64)
}

// PoolSnapshot summarizes aggregate TunnelPool health, dynamic underlay baseline, hysteresis routing mode,
// chronic slow-lane evictions, and per-worker telemetry.
type PoolSnapshot struct {
	PoolSize           int              `json:"pool_size"`
	HealthyWorkers     int              `json:"healthy_workers"`
	DegradedWorkers    int              `json:"degraded_workers"`
	SlowLaneWorkers    int              `json:"slow_lane_workers"`
	TotalActive        int64            `json:"total_active"`
	TotalFailovers     int64            `json:"total_failovers"`
	SlowLaneEvictions  int64            `json:"slow_lane_evictions"`
	PrimarySwitches    int64            `json:"primary_switches"`
	RoutingMode        string           `json:"routing_mode"`
	PrimaryTunnelID    string           `json:"primary_tunnel_id"`
	UnderlayBaselineMS float64          `json:"underlay_baseline_ms"`
	UnderlayTarget     string           `json:"underlay_target"`
	Workers            []TunnelSnapshot `json:"workers"`
	AggregateP50MS     float64          `json:"aggregate_p50_ms"`
}

// TunnelPool orchestrates 1..4 (recommended 2..3) parallel TunnelInstance workers with:
//   - Always-serialized tunnel-1 -> TunnelHealthy -> tunnel-2..N cold-start (zero 'gh codespace start' calls).
//   - Dynamic direct underlay baseline B_raw(t) measurement (never touching GitHub API).
//   - 3-layer Schmitt-trigger hysteresis & continuous dwell window (25s default) for anti-flapping routing.
//   - Chronic slow-lane diversion & single-worker eviction strictly gated by GitHubGuard.
type TunnelPool struct {
	cfg     Config
	deps    SupervisorDeps
	logger  *EventLogger
	metrics *MetricsEmitter
	guard   *GitHubGuard

	mu                sync.RWMutex
	workers           []*TunnelInstance
	workerByID        map[string]*TunnelInstance
	dialFailChs       map[string]chan error
	totalFailovers    atomic.Int64
	slowLaneEvictions atomic.Int64
	primarySwitches   atomic.Int64

	underlayMu       sync.RWMutex
	underlayRawMS    float64
	underlayTarget   string
	underlaySampled  bool
	underlayProbeRun atomic.Uint64

	hystMu          sync.RWMutex
	routingMode     string // "balanced", "primary_preferred", "single_primary", "degraded"
	primaryTunnelID string
	challengerID    string
	challengerSince time.Time
	rebalanceSince  time.Time

	fatalErrCh chan error
	vmWoken    atomic.Bool
	onVMWoken  atomic.Pointer[func()]

	cancel        context.CancelFunc
	wg            sync.WaitGroup
	started       atomic.Bool
	closed        atomic.Bool
	publishedSnap atomic.Pointer[PoolSnapshot]
}

// NewTunnelPool allocates PoolSize independent TunnelInstance workers on GHPort..GHPort+PoolSize-1.
func NewTunnelPool(
	cfg Config,
	deps SupervisorDeps,
	logger *EventLogger,
	metrics *MetricsEmitter,
	guard *GitHubGuard,
) *TunnelPool {
	ports := cfg.PoolPorts()
	workers := make([]*TunnelInstance, 0, len(ports))
	byID := make(map[string]*TunnelInstance, len(ports))
	failChs := make(map[string]chan error, len(ports))
	for i, port := range ports {
		id := fmt.Sprintf("tunnel-%d", i+1)
		w := NewTunnelInstance(id, port, cfg, deps, logger, metrics, guard)
		workers = append(workers, w)
		byID[id] = w
		failChs[id] = make(chan error, 16)
	}
	initBase := cfg.UnderlayBaselineMS
	if initBase <= 0 {
		initBase = DefaultUnderlayBaselineMS
	}
	pool := &TunnelPool{
		cfg:           cfg,
		deps:          deps,
		logger:        logger,
		metrics:       metrics,
		guard:         guard,
		workers:       workers,
		workerByID:    byID,
		dialFailChs:   failChs,
		underlayRawMS: initBase,
		routingMode:   "balanced",
		fatalErrCh:    make(chan error, 1),
	}
	for _, w := range workers {
		w.SetOnVMReached(pool.markVMWoken)
	}
	pool.publishSnapshot()
	return pool
}

// SetOnVMWoken registers an optional callback fired once any worker proves the Codespace VM reachable.
func (p *TunnelPool) SetOnVMWoken(fn func()) {
	if p == nil {
		return
	}
	if fn == nil {
		p.onVMWoken.Store(nil)
		return
	}
	p.onVMWoken.Store(&fn)
}

// HasWokenVM reports whether any pool worker has completed an E2E SOCKS5 handshake with the VM.
func (p *TunnelPool) HasWokenVM() bool {
	if p == nil {
		return false
	}
	return p.vmWoken.Load()
}

func (p *TunnelPool) markVMWoken() {
	if p == nil {
		return
	}
	p.vmWoken.Store(true)
	if cb := p.onVMWoken.Load(); cb != nil && *cb != nil {
		(*cb)()
	}
}

func (p *TunnelPool) reportFatalError(err error) {
	if p == nil || err == nil {
		return
	}
	select {
	case p.fatalErrCh <- err:
	default:
	}
}

// FatalErrCh returns a channel signaled when any worker encounters a permanent, non-retriable
// boot or runtime failure (e.g. HTTP 404 deleted codespace or HTTP 401 revoked token).
func (p *TunnelPool) FatalErrCh() <-chan error {
	if p == nil {
		return nil
	}
	return p.fatalErrCh
}

// UnderlayBaselineMS returns the current EWMA-smoothed direct underlay baseline B_raw(t) in milliseconds.
func (p *TunnelPool) UnderlayBaselineMS() float64 {
	p.underlayMu.RLock()
	v := p.underlayRawMS
	p.underlayMu.RUnlock()
	if v < 50.0 {
		return 50.0
	}
	return v
}

// SetUnderlayBaselineMS explicitly sets B_raw(t) (used by underlayBaselineLoop and deterministic unit tests).
func (p *TunnelPool) SetUnderlayBaselineMS(ms float64) {
	if ms < 50.0 {
		ms = 50.0
	}
	p.underlayMu.Lock()
	p.underlayRawMS = ms
	p.underlaySampled = true
	p.underlayMu.Unlock()
}

func (p *TunnelPool) recordUnderlaySample(d time.Duration, target string) {
	const (
		maxInitialUnderlayMS  = 1200.0
		maxUnderlaySpikeRatio = 2.0
	)
	ms := float64(d.Microseconds()) / 1000.0
	if ms < 10.0 {
		ms = 10.0
	}
	p.underlayMu.Lock()
	clampedMS := ms
	if !p.underlaySampled {
		if clampedMS > maxInitialUnderlayMS {
			clampedMS = maxInitialUnderlayMS
		}
		p.underlayRawMS = clampedMS
		p.underlaySampled = true
	} else {
		maxStep := math.Max(p.underlayRawMS, 50.0) * maxUnderlaySpikeRatio
		if clampedMS > maxStep {
			clampedMS = maxStep
		}
		p.underlayRawMS = 0.70*p.underlayRawMS + 0.30*clampedMS
	}
	p.underlayTarget = target
	cur := p.underlayRawMS
	p.underlayMu.Unlock()
	p.underlayProbeRun.Add(1)

	if p.metrics != nil {
		p.metrics.Emit("pool", map[string]any{
			"event":                "underlay_baseline",
			"sample_ms":            round2(ms),
			"clamped_sample_ms":    round2(clampedMS),
			"underlay_baseline_ms": round2(cur),
			"target":               target,
		})
	}
}

// RoutingMode returns the current Schmitt-trigger routing mode and primary tunnel ID.
func (p *TunnelPool) RoutingMode() (mode string, primaryID string) {
	p.hystMu.RLock()
	defer p.hystMu.RUnlock()
	return p.routingMode, p.primaryTunnelID
}

// PrimarySwitches returns the total number of sustained Schmitt-trigger primary promotions/switches.
func (p *TunnelPool) PrimarySwitches() int64 {
	return p.primarySwitches.Load()
}

// SlowLaneEvictions returns the total number of chronic slow-lane worker evictions triggered.
func (p *TunnelPool) SlowLaneEvictions() int64 {
	return p.slowLaneEvictions.Load()
}

// Start launches the direct underlay baseline probe loop, routing/eviction watchdog, and pool worker
// supervision loops, waiting until at least one worker is TunnelHealthy (or ctx cancels).
//
// v6.3 GitHub WAF & Cold-Start Safety:
//   - NEVER invokes nonexistent `gh codespace start`.
//   - When PoolSize > 1, ALWAYS boots tunnel-1 to TunnelHealthy BEFORE spawning tunnel-2..N so concurrent
//     `gh codespace ssh` invocations never collide on GitHub's `/start` VM lock (0 HTTP 400 races) and
//     peer workers inherit live tunnel-1 median RTT for fast-lane qualification.
func (p *TunnelPool) Start(ctx context.Context) error {
	if !p.started.CompareAndSwap(false, true) {
		return errors.New("tunnel pool already started")
	}
	poolCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	// Start direct underlay baseline loop + hysteresis/eviction evaluator (never touches GitHub API).
	p.wg.Add(1)
	go p.underlayAndHysteresisLoop(poolCtx)

	firstReady := make(chan struct{}, len(p.workers))
	needSerializedBoot := len(p.workers) > 1

	if needSerializedBoot {
		p.wg.Add(1)
		go p.superviseWorker(poolCtx, p.workers[0], firstReady)

		select {
		case <-firstReady:
		case fatalErr := <-p.fatalErrCh:
			p.Close()
			return fatalErr
		case <-ctx.Done():
			p.Close()
			return ctx.Err()
		}

		// tunnel-1 is now TunnelHealthy and has marked the Codespace VM "Available";
		// spawn peer workers safely without racing GitHub's single-start VM lock.
		for _, w := range p.workers[1:] {
			p.wg.Add(1)
			go p.superviseWorker(poolCtx, w, firstReady)
		}
		p.publishSnapshot()
		return nil
	}

	for _, w := range p.workers {
		p.wg.Add(1)
		go p.superviseWorker(poolCtx, w, firstReady)
	}

	select {
	case <-firstReady:
		p.publishSnapshot()
		return nil
	case fatalErr := <-p.fatalErrCh:
		p.Close()
		return fatalErr
	case <-ctx.Done():
		p.Close()
		return ctx.Err()
	}
}

func (p *TunnelPool) underlayAndHysteresisLoop(ctx context.Context) {
	defer p.wg.Done()

	underlayInterval := p.cfg.UnderlayProbeInterval
	if underlayInterval <= 0 {
		underlayInterval = DefaultUnderlayProbeInterval
	}
	underlayTimeout := p.cfg.UnderlayProbeTimeout
	if underlayTimeout <= 0 {
		underlayTimeout = DefaultUnderlayProbeTimeout
	}
	targets := p.cfg.ParsedUnderlayTargets()

	runUnderlay := func() {
		if p.deps.UnderlayProbeFunc == nil {
			return
		}
		pctx, pcancel := context.WithTimeout(ctx, underlayTimeout)
		rtt, usedTarget, err := p.deps.UnderlayProbeFunc(pctx, targets, underlayTimeout)
		pcancel()
		if err == nil && rtt > 0 {
			p.recordUnderlaySample(rtt, usedTarget)
		}
	}

	// Run one initial non-blocking baseline check if UnderlayProbeFunc is provided.
	if p.deps.UnderlayProbeFunc != nil {
		runUnderlay()
	}

	underlayTicker := time.NewTicker(underlayInterval)
	defer underlayTicker.Stop()

	evalInterval := 1 * time.Second
	if p.cfg.HysteresisDwellWindow > 0 && p.cfg.HysteresisDwellWindow/4 < evalInterval {
		evalInterval = p.cfg.HysteresisDwellWindow / 4
		if evalInterval < 25*time.Millisecond {
			evalInterval = 25 * time.Millisecond
		}
	}
	if p.cfg.SlowLaneEvictWindow > 0 && p.cfg.SlowLaneEvictWindow/4 < evalInterval {
		evalInterval = p.cfg.SlowLaneEvictWindow / 4
		if evalInterval < 25*time.Millisecond {
			evalInterval = 25 * time.Millisecond
		}
	}
	evalTicker := time.NewTicker(evalInterval)
	defer evalTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-underlayTicker.C:
			runUnderlay()
			p.publishSnapshot()
		case <-evalTicker.C:
			now := time.Now()
			p.CheckSlowLaneEviction(now)
			p.EvaluateRoutingMode(now)
			p.publishSnapshot()
		}
	}
}

// EvaluateRoutingMode executes Layer 1 (Fast Multi-Active TCP HoL Balance) and Layer 2
// (Schmitt-Trigger Hysteresis + Continuous Dwell Primary Promotion).
// Safe to invoke directly with simulated timestamps in deterministic unit tests.
func (p *TunnelPool) EvaluateRoutingMode(now time.Time) {
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	baselineMS := p.UnderlayBaselineMS()
	relMargin := p.cfg.HysteresisRelMargin
	if relMargin <= 0 {
		relMargin = DefaultHysteresisRelMargin
	}
	absMarginMS := float64(p.cfg.HysteresisAbsMargin.Milliseconds())
	if absMarginMS <= 0 {
		absMarginMS = float64(DefaultHysteresisAbsMargin.Milliseconds())
	}
	dwell := p.cfg.HysteresisDwellWindow
	if dwell <= 0 {
		dwell = DefaultHysteresisDwellWindow
	}
	fastRatio := p.cfg.FastLaneMaxRatio
	if fastRatio < 1.0 {
		fastRatio = DefaultFastLaneMaxRatio
	}

	var healthyFast []*TunnelInstance
	for _, w := range workers {
		if w.State() == TunnelHealthy && !w.IsSlowLaneDegraded() {
			healthyFast = append(healthyFast, w)
		}
	}

	p.hystMu.Lock()
	defer p.hystMu.Unlock()

	if len(healthyFast) == 0 {
		p.routingMode = "degraded"
		p.primaryTunnelID = ""
		p.challengerID = ""
		p.challengerSince = time.Time{}
		p.rebalanceSince = time.Time{}
		return
	}
	if len(healthyFast) == 1 {
		p.routingMode = "single_primary"
		p.primaryTunnelID = healthyFast[0].ID()
		p.challengerID = ""
		p.challengerSince = time.Time{}
		p.rebalanceSince = time.Time{}
		return
	}

	// Sort healthy non-slow-lane workers by load-independent QualityScore (lowest = best).
	sort.SliceStable(healthyFast, func(i, j int) bool {
		return healthyFast[i].QualityScore(baselineMS) < healthyFast[j].QualityScore(baselineMS)
	})
	best := healthyFast[0]
	worst := healthyFast[len(healthyFast)-1]

	// Determine the reference incumbent/peer for Schmitt-trigger comparison.
	var compareAgainst *TunnelInstance
	if p.routingMode == "primary_preferred" && p.primaryTunnelID != "" {
		for _, w := range healthyFast {
			if w.ID() == p.primaryTunnelID {
				compareAgainst = w
				break
			}
		}
	}

	// Case A: Already in primary_preferred and current primary is still healthy.
	if compareAgainst != nil {
		if best.ID() != compareAgainst.ID() {
			// Check if challenger beats current primary by BOTH >= relMargin AND >= absMarginMS.
			incScore := compareAgainst.QualityScore(baselineMS)
			bestScore := best.QualityScore(baselineMS)
			relGain := 0.0
			if incScore > 0 {
				relGain = (incScore - bestScore) / incScore
			}
			absGainMS := compareAgainst.EWMARTTMS() - best.EWMARTTMS()

			if relGain >= relMargin && absGainMS >= absMarginMS {
				p.rebalanceSince = time.Time{}
				if p.challengerID != best.ID() {
					p.challengerID = best.ID()
					p.challengerSince = now
				} else if now.Sub(p.challengerSince) >= dwell {
					prevPrimary := p.primaryTunnelID
					p.primaryTunnelID = best.ID()
					p.challengerID = ""
					p.challengerSince = time.Time{}
					p.primarySwitches.Add(1)
					p.logPrimarySwitchLocked(prevPrimary, best.ID(), "schmitt_challenger_dwell_met", baselineMS, relGain, absGainMS)
				}
				return
			}
			p.challengerID = ""
			p.challengerSince = time.Time{}
		}

		// Check Schmitt exit condition: if all healthy workers are fast (rho <= FastLaneMaxRatio) AND
		// the gap between primary and worst peer drops below half the entry margin for >= dwell, return to balanced!
		allFast := true
		for _, w := range healthyFast {
			if w.Rho(baselineMS) > fastRatio {
				allFast = false
				break
			}
		}
		worstScore := worst.QualityScore(baselineMS)
		bestScore := best.QualityScore(baselineMS)
		relGap := 0.0
		if worstScore > 0 {
			relGap = (worstScore - bestScore) / worstScore
		}
		absGapMS := math.Abs(worst.EWMARTTMS() - best.EWMARTTMS())

		if allFast && (relGap < relMargin*0.5 || absGapMS < absMarginMS*0.5) {
			if p.rebalanceSince.IsZero() {
				p.rebalanceSince = now
			} else if now.Sub(p.rebalanceSince) >= dwell {
				prevPrimary := p.primaryTunnelID
				p.routingMode = "balanced"
				p.primaryTunnelID = ""
				p.rebalanceSince = time.Time{}
				p.challengerID = ""
				p.challengerSince = time.Time{}
				p.logPrimarySwitchLocked(prevPrimary, "balanced", "fast_peers_converged", baselineMS, relGap, absGapMS)
			}
		} else {
			p.rebalanceSince = time.Time{}
		}
		return
	}

	// Case B: Currently balanced (or former primary left healthyFast). Check whether `best` clearly
	// dominates `worst` by BOTH >= relMargin (30%) AND >= absMarginMS (100ms) continuously for dwell.
	worstScore := worst.QualityScore(baselineMS)
	bestScore := best.QualityScore(baselineMS)
	relGain := 0.0
	if worstScore > 0 {
		relGain = (worstScore - bestScore) / worstScore
	}
	absGainMS := worst.EWMARTTMS() - best.EWMARTTMS()

	if relGain >= relMargin && absGainMS >= absMarginMS {
		if p.challengerID != best.ID() {
			p.challengerID = best.ID()
			p.challengerSince = now
		} else if now.Sub(p.challengerSince) >= dwell {
			prevPrimary := p.primaryTunnelID
			p.routingMode = "primary_preferred"
			p.primaryTunnelID = best.ID()
			p.challengerID = ""
			p.challengerSince = time.Time{}
			p.rebalanceSince = time.Time{}
			p.primarySwitches.Add(1)
			p.logPrimarySwitchLocked(prevPrimary, best.ID(), "schmitt_primary_promoted", baselineMS, relGain, absGainMS)
		}
	} else {
		p.routingMode = "balanced"
		p.primaryTunnelID = ""
		p.challengerID = ""
		p.challengerSince = time.Time{}
		p.rebalanceSince = time.Time{}
	}
}

func (p *TunnelPool) logPrimarySwitchLocked(fromID, toID, reason string, baselineMS, relGain, absGainMS float64) {
	if p.logger != nil {
		p.logger.Log("POOL_PRIMARY_SWITCH", map[string]any{
			"from":                 fromID,
			"to":                   toID,
			"routing_mode":         p.routingMode,
			"reason":               reason,
			"underlay_baseline_ms": round2(baselineMS),
			"rel_gain":             round2(relGain),
			"abs_gain_ms":          round2(absGainMS),
			"primary_switches":     p.primarySwitches.Load(),
		})
	}
	if p.metrics != nil {
		p.metrics.Emit("pool", map[string]any{
			"event":                "primary_switch",
			"from":                 fromID,
			"to":                   toID,
			"routing_mode":         p.routingMode,
			"reason":               reason,
			"underlay_baseline_ms": round2(baselineMS),
			"rel_gain":             round2(relGain),
			"abs_gain_ms":          round2(absGainMS),
		})
	}
}

// CheckSlowLaneEviction executes Layer 3: if a healthy worker stays trapped in a chronic slow lane
// (rho_i > SlowLaneEvictRatio sustained for >= SlowLaneEvictWindow) while direct underlay B_raw is healthy
// (<= SlowLaneUnderlayCeiling) AND at least one healthy non-slow-lane peer exists, it marks the worker
// SlowLaneDegraded (diverting 100% of new dials to healthy peers) and signals background drain + reroll.
func (p *TunnelPool) CheckSlowLaneEviction(now time.Time) int {
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	if len(workers) < 2 {
		return 0
	}

	baselineMS := p.UnderlayBaselineMS()
	underlayCeilingMS := float64(p.cfg.SlowLaneUnderlayCeiling.Milliseconds())
	if underlayCeilingMS <= 0 {
		underlayCeilingMS = float64(DefaultSlowLaneUnderlayCeiling.Milliseconds())
	}
	evictRatio := p.cfg.SlowLaneEvictRatio
	if evictRatio <= 1.0 {
		evictRatio = DefaultSlowLaneEvictRatio
	}
	evictWindow := p.cfg.SlowLaneEvictWindow
	if evictWindow <= 0 {
		evictWindow = DefaultSlowLaneEvictWindow
	}

	// If the direct underlay itself is congested (>800ms), NEVER blame or evict individual workers!
	if baselineMS > underlayCeilingMS {
		for _, w := range workers {
			w.stateMu.Lock()
			w.slowLaneSince = time.Time{}
			w.stateMu.Unlock()
			if w.IsSlowLaneDegraded() {
				w.SetSlowLaneDegraded(false)
			}
			w.ResetEvictionState()
		}
		return 0
	}

	// Count healthy peers that are NOT in a slow lane right now.
	healthyFastCount := 0
	for _, w := range workers {
		if w.State() == TunnelHealthy && !w.IsSlowLaneDegraded() && w.Rho(baselineMS) <= evictRatio {
			healthyFastCount++
		}
	}

	evicted := 0
	for _, w := range workers {
		st := w.State()
		if st != TunnelHealthy && st != TunnelDegraded {
			w.stateMu.Lock()
			w.slowLaneSince = time.Time{}
			w.stateMu.Unlock()
			continue
		}
		rho := w.Rho(baselineMS)
		if rho > evictRatio {
			w.stateMu.Lock()
			if w.slowLaneSince.IsZero() {
				w.slowLaneSince = now
			}
			elapsed := now.Sub(w.slowLaneSince)
			w.stateMu.Unlock()

			if elapsed >= evictWindow && healthyFastCount >= 1 {
				// Stage 1 (0 API calls): immediately mark SlowLaneDegraded to divert 100% of new traffic
				// to healthy fast peer(s), while keeping w alive in healthySlow standby if peer drops.
				w.SetSlowLaneDegraded(true)

				// Stage 2 (Destructive Reroll): ONLY tear down w into DEAD when GitHubGuard permits a
				// replacement boot right now, and evict at most 1 slow worker per pass to prevent concurrent
				// budget exhaustion or WAF burst spikes.
				if evicted == 0 && !w.IsEvictionTriggered() {
					if p.guard != nil {
						if canReroll, deferReason := p.guard.CanAllowNonConsuming(); !canReroll {
							if w.MarkEvictDeferLogged() {
								if p.logger != nil {
									p.logger.Log("WORKER_SLOW_LANE_EVICT_DEFERRED", map[string]any{
										"tunnel_id":            w.ID(),
										"port":                 w.Port(),
										"worker_state":         string(st),
										"defer_reason":         deferReason,
										"ewma_rtt_ms":          round2(w.EWMARTTMS()),
										"underlay_baseline_ms": round2(baselineMS),
										"relative_rho":         round2(rho),
										"healthy_fast_peers":   healthyFastCount,
									})
								}
								if p.metrics != nil {
									p.metrics.Emit("tunnel", map[string]any{
										"tunnel_id":    w.ID(),
										"port":         w.Port(),
										"event":        "slow_lane_evict_deferred",
										"defer_reason": deferReason,
										"relative_rho": round2(rho),
									})
								}
							}
							continue
						}
					}

					if w.MarkEvictionTriggered() {
						p.slowLaneEvictions.Add(1)
						evicted++
						if p.logger != nil {
							p.logger.Log("WORKER_SLOW_LANE_EVICT", map[string]any{
								"tunnel_id":            w.ID(),
								"port":                 w.Port(),
								"worker_state":         string(st),
								"ewma_rtt_ms":          round2(w.EWMARTTMS()),
								"underlay_baseline_ms": round2(baselineMS),
								"relative_rho":         round2(rho),
								"evict_ratio":          evictRatio,
								"slow_duration_ms":     elapsed.Milliseconds(),
								"healthy_fast_peers":   healthyFastCount,
							})
						}
						if p.metrics != nil {
							p.metrics.Emit("tunnel", map[string]any{
								"tunnel_id":            w.ID(),
								"port":                 w.Port(),
								"event":                "slow_lane_evict",
								"ewma_rtt_ms":          round2(w.EWMARTTMS()),
								"underlay_baseline_ms": round2(baselineMS),
								"relative_rho":         round2(rho),
							})
						}
						w.TriggerEviction("chronic_slow_lane")
					}
				}
			}
		} else {
			w.stateMu.Lock()
			w.slowLaneSince = time.Time{}
			w.stateMu.Unlock()
			if w.IsSlowLaneDegraded() {
				w.SetSlowLaneDegraded(false)
			}
			w.ResetEvictionState()
		}
	}
	return evicted
}

// PeerFastMedianMS returns the median EWMA RTT across healthy non-slow-lane peer workers excluding excludeID.
func (p *TunnelPool) PeerFastMedianMS(excludeID string) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var vals []float64
	for _, w := range p.workers {
		if w.ID() == excludeID {
			continue
		}
		if w.State() == TunnelHealthy && !w.IsSlowLaneDegraded() {
			if rtt := w.EWMARTTMS(); rtt > 0 {
				vals = append(vals, rtt)
			}
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	return vals[(len(vals)-1)/2]
}

// HealthyCount returns the number of workers currently in TunnelHealthy state.
func (p *TunnelPool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, w := range p.workers {
		if w.State() == TunnelHealthy {
			n++
		}
	}
	return n
}

// AcquireEndpoint implements v6.3/v6.4 hysteresis-aware, baseline-normalized weighted routing:
//   - Prefers TunnelHealthy workers that are NOT SlowLaneDegraded.
//   - In primary_preferred mode (promoted via 3-layer Schmitt-trigger dwell), prefers PrimaryTunnelID first.
//   - When >= 2 fast workers are balanced, distributes across <= PerTunnelMaxConns (default 32) to halve TCP HoL stall radius.
//   - When any peer is starting/draining/dead/degraded/SlowLaneDegraded, surviving healthy fast worker(s)
//     burst smoothly up to MaxActiveConns (default 64 SSH channels over 1 outer WAN TCP socket, zero no_healthy_tunnel cliff).
func (p *TunnelPool) AcquireEndpoint(ctx context.Context) (UpstreamLease, error) {
	if err := ctx.Err(); err != nil {
		return UpstreamLease{}, err
	}
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	var healthyFast []*TunnelInstance
	var healthySlow []*TunnelInstance
	var degraded []*TunnelInstance
	for _, w := range workers {
		switch w.State() {
		case TunnelHealthy:
			if w.IsSlowLaneDegraded() {
				healthySlow = append(healthySlow, w)
			} else {
				healthyFast = append(healthyFast, w)
			}
		case TunnelDegraded:
			degraded = append(degraded, w)
		}
	}

	candidates := healthyFast
	if len(candidates) == 0 {
		candidates = healthySlow
	}
	if len(candidates) == 0 {
		candidates = degraded
	}
	if len(candidates) == 0 {
		return UpstreamLease{}, errors.New("no healthy upstream tunnel workers available")
	}

	mode, primaryID := p.RoutingMode()

	order := make([]*TunnelInstance, len(candidates))
	copy(order, candidates)

	if mode == "primary_preferred" && primaryID != "" && len(order) >= 2 {
		// Place promoted Primary first, then order remaining candidates by RoutingScore.
		sort.SliceStable(order, func(i, j int) bool {
			if order[i].ID() == primaryID {
				return true
			}
			if order[j].ID() == primaryID {
				return false
			}
			return order[i].RoutingScore() < order[j].RoutingScore()
		})
	} else if len(order) > 2 {
		// Power-of-Two-Choices for >2 balanced fast workers using lossless permutation swaps
		// so every candidate worker stays in `order` exactly once (zero dropped workers on PoolSize>=3).
		i := rand.IntN(len(order))
		j := rand.IntN(len(order) - 1)
		if j >= i {
			j++
		}
		if order[j].RoutingScore() < order[i].RoutingScore() {
			i, j = j, i
		}
		order[0], order[i] = order[i], order[0]
		if j == 0 {
			j = i
		}
		order[1], order[j] = order[j], order[1]
		sort.SliceStable(order[2:], func(x, y int) bool {
			return order[2+x].RoutingScore() < order[2+y].RoutingScore()
		})
	} else {
		sort.SliceStable(order, func(i, j int) bool {
			return order[i].RoutingScore() < order[j].RoutingScore()
		})
	}

	perTunnelCap := p.cfg.PerTunnelMaxConns
	if perTunnelCap < 1 {
		perTunnelCap = DefaultPerTunnelMaxConns
	}

	// Pass 1: honor nominal PerTunnelMaxConns across candidate workers (halves TCP HoL blast radius).
	// tryAcquireFromOrder eliminates concurrent slot-turnover TOCTOU scan misses without spinning
	// when all workers are genuinely full (UT-22 / UT-29 return immediately).
	if lease, ok := tryAcquireFromOrder(order, perTunnelCap); ok {
		return lease, nil
	}

	// Pass 2 (Burst Cap): when any peer is starting/draining/dead/degraded/slow-lane-evicted
	// (len(healthyFast) < len(workers)), allow surviving fast worker(s) to absorb up to MaxActiveConns=12.
	if len(healthyFast) < len(workers) {
		globalCap := p.cfg.MaxActiveConns
		if globalCap < perTunnelCap {
			globalCap = perTunnelCap
		}
		burstCap := perTunnelCap
		if len(healthyFast) == 1 {
			burstCap = globalCap
		} else if len(healthyFast) >= 2 {
			burstCap = (globalCap + len(healthyFast) - 1) / len(healthyFast)
		} else if len(healthySlow) > 0 {
			burstCap = (globalCap + len(healthySlow) - 1) / len(healthySlow)
		} else if len(degraded) > 0 {
			burstCap = (globalCap + len(degraded) - 1) / len(degraded)
		}
		if burstCap < perTunnelCap {
			burstCap = perTunnelCap
		}
		if burstCap > globalCap {
			burstCap = globalCap
		}
		if burstCap > perTunnelCap {
			sort.SliceStable(order, func(i, j int) bool {
				ai := order[i].activeStreams.Load()
				aj := order[j].activeStreams.Load()
				if ai != aj {
					return ai < aj
				}
				return order[i].RoutingScore() < order[j].RoutingScore()
			})
			if lease, ok := tryAcquireFromOrder(order, burstCap); ok {
				return lease, nil
			}
		}
	}

	return UpstreamLease{}, errors.New("all healthy upstream tunnel workers at per-tunnel capacity")
}

// tryAcquireFromOrder scans `order` in preference order for a slot under capLimit.
// If the initial scan misses due to concurrent slot turnover (another goroutine released on an
// already-scanned worker while a third goroutine grabbed our tail worker), it performs up to 2
// immediate rescans sorted by activeStreams ascending ONLY when a free slot is currently observed.
func tryAcquireFromOrder(order []*TunnelInstance, capLimit int) (UpstreamLease, bool) {
	for _, w := range order {
		if w.TryAcquireSlotWithCap(capLimit) {
			return UpstreamLease{
				TunnelID:    w.ID(),
				Addr:        w.Addr(),
				PMTU576Safe: w.PMTU576Active(),
				release:     w.ReleaseSlot,
			}, true
		}
	}
	for retry := 0; retry < 6; retry++ {
		hasFree := false
		for _, w := range order {
			if w.activeStreams.Load() < int64(capLimit) {
				hasFree = true
				break
			}
		}
		if !hasFree {
			return UpstreamLease{}, false
		}
		sort.SliceStable(order, func(i, j int) bool {
			return order[i].activeStreams.Load() < order[j].activeStreams.Load()
		})
		for _, w := range order {
			if w.TryAcquireSlotWithCap(capLimit) {
				return UpstreamLease{
					TunnelID:    w.ID(),
					Addr:        w.Addr(),
					PMTU576Safe: w.PMTU576Active(),
					release:     w.ReleaseSlot,
				}, true
			}
		}
	}
	return UpstreamLease{}, false
}

// NotifyDialFailure feeds loopback dial failures directly to the owning worker's supervision loop
// and immediately updates its live stream error rate without waiting for the 25s probe cadence.
func (p *TunnelPool) NotifyDialFailure(tunnelID string, err error) {
	w := p.workerByID[tunnelID]
	if w == nil {
		return
	}
	w.dialFailures.Add(1)
	w.RecordStreamError()
	if ch, ok := p.dialFailChs[tunnelID]; ok {
		select {
		case ch <- err:
		default:
		}
	}
}

// NotifyDialSuccess updates the worker's live stream success indicator (decaying error rate).
func (p *TunnelPool) NotifyDialSuccess(tunnelID string, _ time.Duration) {
	if w := p.workerByID[tunnelID]; w != nil {
		w.RecordStreamSuccess()
	}
}

// NotifyWANBytes marks verified downstream WAN progress on the owning worker.
func (p *TunnelPool) NotifyWANBytes(tunnelID string, n uint64) {
	if w := p.workerByID[tunnelID]; w != nil {
		w.RecordWANBytes(n)
	}
}

// PoolSnapshot returns a complete, thread-safe snapshot of all pool workers, underlay baseline, and hysteresis state.
func (p *TunnelPool) PoolSnapshot() PoolSnapshot {
	p.mu.RLock()
	workers := p.workers
	p.mu.RUnlock()

	baselineMS := p.UnderlayBaselineMS()
	p.underlayMu.RLock()
	underlayTarget := p.underlayTarget
	p.underlayMu.RUnlock()
	mode, primaryID := p.RoutingMode()

	snaps := make([]TunnelSnapshot, 0, len(workers))
	healthy := 0
	degraded := 0
	slowLane := 0
	var totalActive int64
	var rtts []float64
	for _, w := range workers {
		s := w.SnapshotWithBaseline(baselineMS)
		snaps = append(snaps, s)
		totalActive += s.ActiveStreams
		if s.SlowLaneDegraded {
			slowLane++
		}
		switch s.State {
		case TunnelHealthy:
			healthy++
			if s.EWMARTTMS > 0 {
				rtts = append(rtts, s.EWMARTTMS)
			}
		case TunnelDegraded:
			degraded++
		}
	}
	_, p50, _, _ := computeRTTStats(rtts)
	return PoolSnapshot{
		PoolSize:           len(workers),
		HealthyWorkers:     healthy,
		DegradedWorkers:    degraded,
		SlowLaneWorkers:    slowLane,
		TotalActive:        totalActive,
		TotalFailovers:     p.totalFailovers.Load(),
		SlowLaneEvictions:  p.slowLaneEvictions.Load(),
		PrimarySwitches:    p.primarySwitches.Load(),
		RoutingMode:        mode,
		PrimaryTunnelID:    primaryID,
		UnderlayBaselineMS: round2(baselineMS),
		UnderlayTarget:     underlayTarget,
		Workers:            snaps,
		AggregateP50MS:     round2(p50),
	}
}

// publishSnapshot stores an immutable PoolSnapshot copy for wait-free UI observation.
func (p *TunnelPool) publishSnapshot() {
	if p == nil {
		return
	}
	snap := p.PoolSnapshot()
	p.publishedSnap.Store(&snap)
}

// CachedSnapshot returns the latest wait-free published PoolSnapshot with 0 mutex acquisitions.
func (p *TunnelPool) CachedSnapshot() PoolSnapshot {
	if p == nil {
		return PoolSnapshot{}
	}
	if ptr := p.publishedSnap.Load(); ptr != nil {
		return *ptr
	}
	return PoolSnapshot{PoolSize: p.cfg.PoolSize, RoutingMode: "starting"}
}

// Close shuts down every worker supervision loop and tears down all JobObjects cleanly.
func (p *TunnelPool) Close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	for _, w := range p.workers {
		w.TeardownChild()
	}
	p.publishSnapshot()
}

func (p *TunnelPool) superviseWorker(ctx context.Context, w *TunnelInstance, firstReady chan<- struct{}) {
	defer p.wg.Done()
	attempt := 0
	signaledReady := false
	failCh := p.dialFailChs[w.ID()]

	for {
		if ctx.Err() != nil {
			w.DrainAndClose(200 * time.Millisecond)
			return
		}

		exitCh, _, _, err := w.BootAndQualify(ctx, p.PeerFastMedianMS, p.UnderlayBaselineMS)
		if err != nil {
			var fatalErr *FatalBootError
			if errors.As(err, &fatalErr) {
				w.DrainAndClose(100 * time.Millisecond)
				p.reportFatalError(fatalErr)
				p.publishSnapshot()
				return
			}
			if ctx.Err() != nil {
				w.DrainAndClose(200 * time.Millisecond)
				return
			}
			attempt++
			backoff := ComputeBackoff(attempt, p.cfg.BackoffMin, p.cfg.BackoffMax, nil)
			tm := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				tm.Stop()
				return
			case <-tm.C:
			}
			_, _ = CleanTargetPorts(p.deps.PortInspector, []uint16{w.Port()}, uint32(os.Getpid()), DefaultCleanupAllowedImages, p.logger)
			continue
		}

		attempt = 0
		if !signaledReady {
			signaledReady = true
			select {
			case firstReady <- struct{}{}:
			default:
			}
		}
		p.publishSnapshot()

		// Supervise this individual worker until crash, breaker trip, chronic slow-lane eviction, or shutdown.
		reason := p.monitorSingleWorker(ctx, w, exitCh, failCh)
		if reason == "fatal_boot_error" {
			w.DrainAndClose(100 * time.Millisecond)
			p.publishSnapshot()
			return
		}
		if ctx.Err() != nil {
			w.DrainAndClose(200 * time.Millisecond)
			p.publishSnapshot()
			return
		}

		// Single-worker failure/eviction isolation: gracefully drain & replace ONLY this worker while peers carry traffic!
		w.restarts.Add(1)
		p.totalFailovers.Add(1)
		p.publishSnapshot()
		if p.logger != nil {
			p.logger.Log("POOL_WORKER_FAILOVER", map[string]any{
				"tunnel_id":       w.ID(),
				"port":            w.Port(),
				"reason":          reason,
				"healthy_peers":   p.HealthyCount(),
				"worker_restarts": w.restarts.Load(),
				"total_failovers": p.totalFailovers.Load(),
			})
		}
		drainTimeout := 300 * time.Millisecond
		if reason == "chronic_slow_lane" {
			drainTimeout = 1500 * time.Millisecond
		}
		w.DrainAndClose(drainTimeout)
		_, _ = CleanTargetPorts(p.deps.PortInspector, []uint16{w.Port()}, uint32(os.Getpid()), DefaultCleanupAllowedImages, p.logger)

		attempt++
		backoff := ComputeBackoff(attempt, p.cfg.BackoffMin, p.cfg.BackoffMax, nil)
		tm := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			tm.Stop()
			return
		case <-tm.C:
		}
	}
}

func (p *TunnelPool) monitorSingleWorker(
	ctx context.Context,
	w *TunnelInstance,
	exitCh <-chan ChildExitResult,
	failCh <-chan error,
) string {
	probeInterval := p.cfg.ProbeInterval
	if probeInterval <= 0 {
		probeInterval = DefaultProbeInterval
	}
	degradedInterval := p.cfg.DegradedProbeInterval
	if degradedInterval <= 0 || degradedInterval > probeInterval {
		degradedInterval = probeInterval
	}
	refusedThresh := p.cfg.LoopbackRefusedThreshold
	if refusedThresh < 1 {
		refusedThresh = DefaultLoopbackRefusedThreshold
	}

	probeTimer := time.NewTimer(probeInterval)
	defer probeTimer.Stop()

	consecRefused := 0
	consecProbeFails := 0
	var firstFailAt time.Time

	probeResCh := make(chan asyncProbeResult, 1)
	probeInFlight := false
	var probeCancel context.CancelFunc
	var probeWG sync.WaitGroup

	cancelProbe := func() {
		if probeCancel != nil {
			probeCancel()
			probeCancel = nil
		}
	}
	defer func() {
		cancelProbe()
		probeWG.Wait()
	}()

	startProbe := func() {
		if probeInFlight {
			return
		}
		probeInFlight = true
		pctx, pcancel := context.WithCancel(ctx)
		probeCancel = pcancel
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			rtt, err := p.deps.ProbeFunc(pctx, w.Addr(), p.cfg.ProbeTarget, p.cfg.ProbeTimeout)
			select {
			case probeResCh <- asyncProbeResult{rtt: rtt, err: err}:
			case <-pctx.Done():
			}
		}()
	}

	resetTimer := func(d time.Duration) {
		if !probeTimer.Stop() {
			select {
			case <-probeTimer.C:
			default:
			}
		}
		probeTimer.Reset(d)
	}

	for {
		select {
		case <-ctx.Done():
			return "shutdown"
		case evictReason := <-w.evictCh:
			cancelProbe()
			return evictReason
		case res := <-exitCh:
			cancelProbe()
			if p.guard != nil {
				p.guard.RecordFailure(res.StderrTail)
			}
			if p.logger != nil {
				p.logger.Log("WORKER_CHILD_EXIT", map[string]any{
					"tunnel_id":   w.ID(),
					"port":        w.Port(),
					"exit_code":   res.ExitCode,
					"uptime_ms":   res.Uptime.Milliseconds(),
					"stderr_tail": res.StderrTail,
				})
			}
			if fatalErr := ClassifyPermanentBootError(res.StderrTail); fatalErr != nil && ctx.Err() == nil {
				if p.logger != nil {
					p.logger.Log("FATAL_BOOT_ERROR", map[string]any{
						"tunnel_id":   w.ID(),
						"port":        w.Port(),
						"code":        fatalErr.Code,
						"message":     fatalErr.Message,
						"stderr_tail": res.StderrTail,
					})
				}
				p.reportFatalError(fatalErr)
				return "fatal_boot_error"
			}
			return "child_exit"
		case derr := <-failCh:
			if isConnRefused(derr) {
				consecRefused++
				if consecRefused >= refusedThresh {
					return "loopback_conn_refused"
				}
			} else {
				consecRefused = 0
			}
			startProbe()
		case <-probeTimer.C:
			startProbe()
		case res := <-probeResCh:
			probeInFlight = false
			cancelProbe()
			if ctx.Err() != nil {
				return "shutdown"
			}
			now := time.Now()
			if res.err != nil {
				consecProbeFails++
				if firstFailAt.IsZero() {
					firstFailAt = now
				}
				if isConnRefused(res.err) {
					consecRefused++
					if consecRefused >= refusedThresh {
						return "loopback_conn_refused"
					}
				}
				minWin := p.cfg.BreakerMinWindow
				freshWin := minWin
				if freshWin <= 0 {
					freshWin = p.cfg.ProbeTimeout
				}
				lastWAN := w.LastWANBytesAt()
				wanRecent := !lastWAN.IsZero() && now.Sub(lastWAN) < freshWin
				if consecProbeFails >= p.cfg.BreakerThreshold && now.Sub(firstFailAt) >= minWin && !wanRecent {
					return "sustained_e2e_blackhole"
				}
				prevState := w.State()
				w.setState(TunnelDegraded)
				if prevState != TunnelDegraded && p.logger != nil {
					p.logger.Log("WORKER_DEGRADED", map[string]any{
						"tunnel_id":            w.ID(),
						"port":                 w.Port(),
						"reason":               "e2e_probe_failed",
						"consecutive_failures": consecProbeFails,
						"error":                res.err.Error(),
					})
				}
				resetTimer(degradedInterval)
				continue
			}

			w.RecordRTT(res.rtt)
			consecProbeFails = 0
			consecRefused = 0
			firstFailAt = time.Time{}
			if p.cfg.DegradedRTTThreshold > 0 && res.rtt > p.cfg.DegradedRTTThreshold {
				prevState := w.State()
				w.setState(TunnelDegraded)
				if prevState != TunnelDegraded && p.logger != nil {
					p.logger.Log("WORKER_DEGRADED", map[string]any{
						"tunnel_id":    w.ID(),
						"port":         w.Port(),
						"reason":       "high_rtt_bufferbloat",
						"probe_rtt_ms": res.rtt.Milliseconds(),
						"threshold_ms": p.cfg.DegradedRTTThreshold.Milliseconds(),
					})
				}
				resetTimer(degradedInterval)
				continue
			}
			prevState := w.State()
			w.setState(TunnelHealthy)
			if prevState == TunnelDegraded && p.logger != nil {
				p.logger.Log("WORKER_RECOVERED", map[string]any{
					"tunnel_id":             w.ID(),
					"port":                  w.Port(),
					"recovery_probe_rtt_ms": res.rtt.Milliseconds(),
				})
			}
			resetTimer(probeInterval)
		}
	}
}
