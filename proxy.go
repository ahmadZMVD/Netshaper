package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	acceptBackoffMin        = 5 * time.Millisecond
	acceptBackoffMax        = 100 * time.Millisecond
	wanVerifiedMinDownBytes = 12 // 2B SOCKS5 greeting + 10B CONNECT reply proves real WAN/sshd bytes
)

type closeWriter interface {
	CloseWrite() error
}

// deadlineConn manages lock-free-fast-path sliding idle deadlines with idle/2 re-arm hysteresis,
// progress-resetting half-close drain watchdogs, v6.3 streaming-idle promotion for established
// SSE/WebChannel/HTTP2 streams (>128B down), and pressure-aware idle reaping.
type deadlineConn struct {
	net.Conn
	idleTimeout       time.Duration
	streamIdleTimeout time.Duration
	drainTimeout      time.Duration

	established    atomic.Bool
	draining       atomic.Bool
	pressureReaped atomic.Bool
	readUntilNS    atomic.Int64
	writeUntilNS   atomic.Int64
	readMu         sync.Mutex
	writeMu        sync.Mutex

	onReadBytes func(n int)
}

func (d *deadlineConn) baseIdleTimeout() time.Duration {
	if d.established.Load() && d.streamIdleTimeout > d.idleTimeout {
		return d.streamIdleTimeout
	}
	return d.idleTimeout
}

func (d *deadlineConn) activeTimeout() time.Duration {
	base := d.baseIdleTimeout()
	if d.draining.Load() && d.drainTimeout > 0 && d.drainTimeout < base {
		return d.drainTimeout
	}
	return base
}

func (d *deadlineConn) minRemainingNS(t time.Duration) int64 {
	if d.draining.Load() {
		return int64((t * 4) / 5)
	}
	return int64(t / 2)
}

// promoteToStreaming upgrades the connection from normal IdleTimeout to StreamingIdleTimeout
// and immediately extends the live OS socket read deadline so blocked Read() calls (e.g. localDC
// awaiting the next HTTP/2 or SSE client frame) are not prematurely reaped at the stale 60s deadline.
func (d *deadlineConn) promoteToStreaming() {
	if !d.established.CompareAndSwap(false, true) {
		return
	}
	if d.streamIdleTimeout <= d.idleTimeout || d.pressureReaped.Load() || d.draining.Load() {
		return
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	if d.pressureReaped.Load() || d.draining.Load() {
		return
	}
	target := time.Now().Add(d.streamIdleTimeout)
	if target.UnixNano() > d.readUntilNS.Load() {
		_ = d.Conn.SetReadDeadline(target)
		d.readUntilNS.Store(target.UnixNano())
	}
}

// refreshReadDeadline keeps an active unidirectional stream's opposite-direction blocked Read()
// alive via the existing t/2 hysteresis fast path (0 locks / 0 syscalls on hot reads) without
// overriding an active half-close drain watchdog or pressure reap.
func (d *deadlineConn) refreshReadDeadline(now time.Time) {
	if d == nil || d.pressureReaped.Load() || d.draining.Load() {
		return
	}
	d.armReadDeadline(now)
}

func (d *deadlineConn) armReadDeadline(now time.Time) {
	if d.pressureReaped.Load() {
		return
	}
	t := d.activeTimeout()
	if t <= 0 {
		return
	}
	nowNS := now.UnixNano()
	minRemNS := d.minRemainingNS(t)
	cur := d.readUntilNS.Load()
	if cur > nowNS+minRemNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}

	d.readMu.Lock()
	defer d.readMu.Unlock()
	if d.pressureReaped.Load() {
		return
	}
	t = d.activeTimeout()
	if t <= 0 {
		return
	}
	minRemNS = d.minRemainingNS(t)
	cur = d.readUntilNS.Load()
	if cur > nowNS+minRemNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}
	target := now.Add(t)
	_ = d.Conn.SetReadDeadline(target)
	d.readUntilNS.Store(target.UnixNano())
}

func (d *deadlineConn) armWriteDeadline(now time.Time) {
	if d.pressureReaped.Load() {
		return
	}
	t := d.activeTimeout()
	if t <= 0 {
		return
	}
	nowNS := now.UnixNano()
	hystNS := int64(t / 2)
	cur := d.writeUntilNS.Load()
	if cur > nowNS+hystNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.pressureReaped.Load() {
		return
	}
	t = d.activeTimeout()
	if t <= 0 {
		return
	}
	hystNS = int64(t / 2)
	cur = d.writeUntilNS.Load()
	if cur > nowNS+hystNS && cur <= nowNS+int64(t)+int64(time.Millisecond) {
		return
	}
	target := now.Add(t)
	_ = d.Conn.SetWriteDeadline(target)
	d.writeUntilNS.Store(target.UnixNano())
}

// shortenReadDeadline activates the progress-resetting half-close drain watchdog immediately.
func (d *deadlineConn) shortenReadDeadline() {
	d.draining.Store(true)
	t := d.drainTimeout
	base := d.baseIdleTimeout()
	if t <= 0 || t > base {
		t = base
	}
	if t <= 0 {
		return
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	target := time.Now().Add(t)
	cur := d.readUntilNS.Load()
	if cur == 0 || target.UnixNano() < cur {
		_ = d.Conn.SetReadDeadline(target)
		d.readUntilNS.Store(target.UnixNano())
	}
}

// triggerPressureReap immediately expires the socket read deadline so an idle slot hog
// yields its semaphore slot in milliseconds under load.
func (d *deadlineConn) triggerPressureReap() {
	if !d.pressureReaped.CompareAndSwap(false, true) {
		return
	}
	d.readMu.Lock()
	now := time.Now()
	_ = d.Conn.SetReadDeadline(now)
	d.readUntilNS.Store(now.UnixNano())
	d.readMu.Unlock()
}

func (d *deadlineConn) Read(p []byte) (int, error) {
	d.armReadDeadline(time.Now())
	n, err := d.Conn.Read(p)
	if n > 0 {
		if d.onReadBytes != nil {
			d.onReadBytes(n)
		}
		if d.draining.Load() {
			d.armReadDeadline(time.Now())
		}
	}
	return n, err
}

func (d *deadlineConn) Write(p []byte) (int, error) {
	d.armWriteDeadline(time.Now())
	return d.Conn.Write(p)
}

// activeRelay tracks a live bidirectional relay for v6.3 stalled-handshake vs established-stream pressure reaping.
type activeRelay struct {
	localDC        *deadlineConn
	remoteDC       *deadlineConn
	lastActivityNS atomic.Int64
	downBytes      atomic.Int64
	upBytes        atomic.Int64
	pressureReaped atomic.Bool
}

func (r *activeRelay) touch() {
	r.lastActivityNS.Store(time.Now().UnixNano())
}

func (r *activeRelay) touchAt(now time.Time) {
	r.lastActivityNS.Store(now.UnixNano())
}

func (r *activeRelay) idleFor(now time.Time) time.Duration {
	ns := r.lastActivityNS.Load()
	if ns == 0 {
		return 0
	}
	d := now.Sub(time.Unix(0, ns))
	if d < 0 {
		return 0
	}
	return d
}

// ProxyMetrics holds live data-plane counters for lightweight checks and unit tests.
type ProxyMetrics struct {
	ActiveConns      int64
	PeakConns        int64
	QueuedConns      int64
	SemaphoreRejects uint64
	PressureReaps    uint64
}

// ProxySignals is the cumulative (never window-reset) saturation/stress snapshot used by the supervisor
// to decide whether an E2E probe may be skipped.
type ProxySignals struct {
	ActiveConns      int64
	MaxConns         int
	QueuedConns      int64
	SemaphoreRejects uint64
	DrainTimeouts    uint64
	AbruptErrors     uint64
	PressureReaps    uint64
}

// ProxyWindowStats captures comprehensive zero-overhead window + cumulative telemetry.
type ProxyWindowStats struct {
	ActiveConns      int64
	PeakConns        int64
	QueuedConns      int64
	QueueWaitP50MS   float64
	QueueWaitP95MS   float64
	DialPaced        uint64
	SemaphoreRejects uint64
	BytesUpWindow    uint64
	BytesDownWindow  uint64
	TotalBytesUp     uint64
	TotalBytesDown   uint64
	TotalConnsWindow uint64
	DialOK           uint64
	DialFail         uint64
	DialRTTP50MS     float64
	DialRTTP95MS     float64
	HalfCloseClean   uint64
	DrainTimeouts    uint64
	IdleReaps        uint64
	PressureReaps    uint64
	AbruptErrors     uint64
}

// ProxyServer is NetShaper's upstream traffic shaper and multiplexed SOCKS5 relay:
//   - Configurable PMTU-safe copy buffer pool (16 KiB default, adaptive 8 KiB on 20.120.56.11 PMTU=576).
//   - Global concurrency semaphore (default 64 SSH channels across pool) + deep browser-burst queue (128).
//   - Serialized dial-launch pacer (dialLaunchMu across loopback DialContext when DialPaceInterval > 0)
//     eliminating Windows 11 scheduler-jitter SYN collision races when dial pacing is enabled.
//   - TCP_NODELAY + 8s TCPKeepAlive (< 15s CG-NAT drop) without touching SO_SNDBUF/SO_RCVBUF.
//   - Streaming-aware two-tier pressure reaper: stalled handshakes (<=128B down, e.g. 0B zombies & 2B/13B SOCKS5 stalls)
//     reap fast at PressureIdleTimeout (12s), while established SSE/WebChannel/HTTP2 streams (>128B down) survive
//     20s under pressure (< 25s SemaphoreWaitTimeout) and 180s idle.
type ProxyServer struct {
	cfg           Config
	upstreamAddr  string
	selector      UpstreamSelector
	logger        *EventLogger
	metrics       *MetricsEmitter
	onDialFailure func(error)
	onDialSuccess func()

	copyBufSize       int
	pmtu576BufSize    int
	copyBufPool       sync.Pool
	copyBufPool8K     sync.Pool
	singlePMTU576Safe atomic.Bool

	sem          chan struct{}
	activeConns  atomic.Int64
	peakConns    atomic.Int64
	queuedConns  atomic.Int64
	semRejects   atomic.Uint64
	lastSatLogNS atomic.Int64

	paceMu       sync.Mutex
	dialLaunchMu sync.Mutex // v6.3: serializes loopback DialContext when DialPaceInterval > 0 to eliminate Win11 preemption races
	nextDialAt   time.Time
	lastDialAt   time.Time

	dialPacedWindow    atomic.Uint64
	totalDrainTimeouts atomic.Uint64
	totalAbruptErrors  atomic.Uint64
	totalPressureReaps atomic.Uint64
	queueWaitMu        sync.Mutex
	queueWaitSamplesMS []float64

	// Verified WAN progress signal (updated ONLY after >= 12B received from remoteConn).
	lastBytesMovedNS atomic.Int64

	bytesUpWindow        atomic.Uint64
	bytesDownWindow      atomic.Uint64
	totalBytesUp         atomic.Uint64
	totalBytesDown       atomic.Uint64
	totalConnsWindow     atomic.Uint64
	dialOKWindow         atomic.Uint64
	dialFailWindow       atomic.Uint64
	halfCloseCleanWindow atomic.Uint64
	drainTimeoutsWindow  atomic.Uint64
	idleReapsWindow      atomic.Uint64
	pressureReapsWindow  atomic.Uint64
	abruptErrorsWindow   atomic.Uint64

	dialRTTMu      sync.Mutex
	dialRTTSamples []float64

	relaysMu sync.Mutex
	relays   map[*activeRelay]struct{}

	mu         sync.Mutex
	ln         net.Listener
	stopCancel context.CancelFunc
	closing    bool
	conns      map[net.Conn]struct{}
	acceptWG   sync.WaitGroup
	connWG     sync.WaitGroup
}

// NewProxyServer creates a single-upstream data plane forwarding LocalAddr -> upstreamAddr.
func NewProxyServer(
	cfg Config,
	upstreamAddr string,
	logger *EventLogger,
	onDialFailure func(error),
	onDialSuccess func(),
) *ProxyServer {
	if upstreamAddr == "" {
		upstreamAddr = cfg.GHAddr()
	}
	return newProxyServerInternal(cfg, upstreamAddr, nil, logger, nil, onDialFailure, onDialSuccess)
}

// NewPooledProxyServer creates a multi-tunnel pool-backed v6.3 data plane with orthogonal NDJSON metrics.
func NewPooledProxyServer(
	cfg Config,
	selector UpstreamSelector,
	logger *EventLogger,
	metrics *MetricsEmitter,
) *ProxyServer {
	return newProxyServerInternal(cfg, cfg.GHAddr(), selector, logger, metrics, nil, nil)
}

func newProxyServerInternal(
	cfg Config,
	upstreamAddr string,
	selector UpstreamSelector,
	logger *EventLogger,
	metrics *MetricsEmitter,
	onDialFailure func(error),
	onDialSuccess func(),
) *ProxyServer {
	bufSz := cfg.CopyBufferSize
	if bufSz < 4096 {
		bufSz = DefaultCopyBufferSize
	}
	pmtuSz := cfg.PMTU576CopyBufSize
	if pmtuSz < 4096 || pmtuSz > bufSz {
		pmtuSz = DefaultPMTU576CopyBufSize
		if pmtuSz > bufSz {
			pmtuSz = bufSz
		}
	}
	maxActive := cfg.MaxActiveConns
	if maxActive < 1 {
		maxActive = DefaultMaxActiveConns
	}
	p := &ProxyServer{
		cfg:            cfg,
		upstreamAddr:   upstreamAddr,
		selector:       selector,
		logger:         logger,
		metrics:        metrics,
		onDialFailure:  onDialFailure,
		onDialSuccess:  onDialSuccess,
		copyBufSize:    bufSz,
		pmtu576BufSize: pmtuSz,
		sem:            make(chan struct{}, maxActive),
		conns:          make(map[net.Conn]struct{}),
		relays:         make(map[*activeRelay]struct{}),
	}
	p.copyBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, bufSz)
			return &b
		},
	}
	p.copyBufPool8K = sync.Pool{
		New: func() any {
			b := make([]byte, pmtuSz)
			return &b
		},
	}
	return p
}

// SetMetrics attaches an orthogonal NDJSON MetricsEmitter to an existing ProxyServer.
func (p *ProxyServer) SetMetrics(m *MetricsEmitter) {
	p.metrics = m
}

// SetSinglePMTU576Safe enables or disables adaptive 8 KiB copy buffer step-down for single-tunnel mode.
func (p *ProxyServer) SetSinglePMTU576Safe(active bool) {
	p.singlePMTU576Safe.Store(active)
}

func (p *ProxyServer) effectiveCopyBufSize(usePMTU576 bool) int {
	if usePMTU576 && p.cfg.PMTU576SafeMode {
		return p.pmtu576BufSize
	}
	return p.copyBufSize
}

// Start binds the client-facing listener and starts both the accept loop and pressure-reaper loop.
func (p *ProxyServer) Start(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", p.cfg.LocalAddr())
	if err != nil {
		return "", err
	}
	srvCtx, stopCancel := context.WithCancel(ctx)
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		stopCancel()
		_ = ln.Close()
		return "", errors.New("proxy server already closed")
	}
	p.ln = ln
	p.stopCancel = stopCancel
	p.mu.Unlock()

	p.acceptWG.Add(2)
	go p.acceptLoop(srvCtx, ln)
	go p.pressureReapLoop(srvCtx)
	return ln.Addr().String(), nil
}

// effectivePressureIdleTimeout returns the active pressure idle limit clamped to <= IdleTimeout.
func (p *ProxyServer) effectivePressureIdleTimeout() time.Duration {
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	pi := p.cfg.PressureIdleTimeout
	if pi <= 0 || pi > idle {
		return idle
	}
	return pi
}

// effectiveStreamingIdleTimeout returns the protected idle timeout for established streams (>128B down).
func (p *ProxyServer) effectiveStreamingIdleTimeout() time.Duration {
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	st := p.cfg.StreamingIdleTimeout
	if st <= idle {
		return idle
	}
	// If a caller/test explicitly lowered IdleTimeout below DefaultIdleTimeout without modifying
	// StreamingIdleTimeout, respect the lowered IdleTimeout ceiling.
	if idle < DefaultIdleTimeout && st == DefaultStreamingIdleTimeout {
		return idle
	}
	return st
}

// effectiveStreamingPressureIdleTimeout returns the pressure idle timeout for established streams (>128B down).
func (p *ProxyServer) effectiveStreamingPressureIdleTimeout() time.Duration {
	pi := p.effectivePressureIdleTimeout()
	stIdle := p.effectiveStreamingIdleTimeout()
	sp := p.cfg.StreamingPressureIdleTimeout
	if sp <= pi {
		return pi
	}
	if sp > stIdle {
		return stIdle
	}
	return sp
}

// isUnderPressure returns true when active slot utilization >= PressureThresholdPct or waiters are queued.
func (p *ProxyServer) isUnderPressure() bool {
	if p.queuedConns.Load() > 0 {
		return true
	}
	maxC := p.cfg.MaxActiveConns
	if maxC <= 0 {
		return false
	}
	threshPct := p.cfg.PressureThresholdPct
	if threshPct <= 0 || threshPct > 100 {
		threshPct = DefaultPressureThresholdPct
	}
	thresh := (maxC*threshPct + 99) / 100
	if thresh < 1 {
		thresh = 1
	}
	return p.activeConns.Load() >= int64(thresh)
}

func (p *ProxyServer) pressureReapLoop(ctx context.Context) {
	defer p.acceptWG.Done()
	pi := p.effectivePressureIdleTimeout()
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	if pi >= idle {
		<-ctx.Done()
		return
	}

	tickInterval := pi / 4
	if tickInterval < 25*time.Millisecond {
		tickInterval = 25 * time.Millisecond
	}
	if tickInterval > 500*time.Millisecond {
		tickInterval = 500 * time.Millisecond
	}

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.sweepPressureIdleRelays()
		}
	}
}

type relayVictim struct {
	relay *activeRelay
	idle  time.Duration
}

// sweepPressureIdleRelays executes bounded, oldest-idle-first two-tier pressure reaping:
//   - Tier 1 (Stalled Handshakes / Zombies <= StalledHandshakeMaxDownBytes, e.g. 0B or 2B/13B SOCKS5 stalls):
//     reaped aggressively once idle >= PressureIdleTimeout (12s).
//   - Tier 2 (Established SSE/WebChannel/HTTP2 streams > StalledHandshakeMaxDownBytes):
//     reaped strictly oldest-idle-first ONLY up to the bounded slot deficit needed to return
//     below the low-water mark (65% of MaxActiveConns, e.g. 41/64) plus queued demand, preventing
//     mass-termination storms at 48/64 while guaranteeing deadlock-freedom at 64/64 saturation.
func (p *ProxyServer) sweepPressureIdleRelays() {
	if !p.isUnderPressure() {
		return
	}
	stalledLimit := p.effectivePressureIdleTimeout()
	streamLimit := p.effectiveStreamingPressureIdleTimeout()
	stalledMaxBytes := int64(p.cfg.StalledHandshakeMaxDownBytes)
	if stalledMaxBytes < 0 {
		stalledMaxBytes = 0
	}
	maxC := p.cfg.MaxActiveConns
	if maxC <= 0 {
		maxC = DefaultMaxActiveConns
	}
	threshPct := p.cfg.PressureThresholdPct
	if threshPct <= 0 || threshPct > 100 {
		threshPct = DefaultPressureThresholdPct
	}
	thresh := int64((maxC*threshPct + 99) / 100)
	if thresh < 1 {
		thresh = 1
	}
	lowPct := threshPct - 10
	if lowPct < 0 {
		lowPct = 0
	}
	lowWater := int64((maxC * lowPct) / 100)
	if lowWater >= thresh && thresh > 0 {
		lowWater = thresh - 1
	}
	now := time.Now()

	p.relaysMu.Lock()
	active := p.activeConns.Load()
	queued := p.queuedConns.Load()
	var inFlightReaping int64
	var stalledVictims []relayVictim
	var streamVictims []relayVictim
	for r := range p.relays {
		if r.pressureReaped.Load() {
			inFlightReaping++
			continue
		}
		idle := r.idleFor(now)
		if r.downBytes.Load() <= stalledMaxBytes {
			if idle >= stalledLimit {
				stalledVictims = append(stalledVictims, relayVictim{relay: r, idle: idle})
			}
		} else {
			if idle >= streamLimit {
				streamVictims = append(streamVictims, relayVictim{relay: r, idle: idle})
			}
		}
	}
	p.relaysMu.Unlock()

	if len(stalledVictims) > 1 {
		sort.Slice(stalledVictims, func(i, j int) bool {
			return stalledVictims[i].idle > stalledVictims[j].idle
		})
	}
	var reaped int64
	for _, v := range stalledVictims {
		if v.relay.pressureReaped.CompareAndSwap(false, true) {
			v.relay.localDC.triggerPressureReap()
			v.relay.remoteDC.triggerPressureReap()
			reaped++
		}
	}

	need := (active + queued - inFlightReaping) - lowWater
	streamBudget := need - reaped
	if streamBudget <= 0 || len(streamVictims) == 0 {
		return
	}
	if len(streamVictims) > 1 {
		sort.Slice(streamVictims, func(i, j int) bool {
			return streamVictims[i].idle > streamVictims[j].idle
		})
	}
	var reapedStreams int64
	for _, v := range streamVictims {
		if reapedStreams >= streamBudget {
			break
		}
		if v.relay.pressureReaped.CompareAndSwap(false, true) {
			v.relay.localDC.triggerPressureReap()
			v.relay.remoteDC.triggerPressureReap()
			reapedStreams++
		}
	}
}

// LastBytesMovedAt returns the timestamp of the most recent verified WAN downstream data transfer (>= 12B).
func (p *ProxyServer) LastBytesMovedAt() time.Time {
	ns := p.lastBytesMovedNS.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// TotalBytes returns cumulative upstream and downstream bytes relayed by this ProxyServer instance.
func (p *ProxyServer) TotalBytes() (up uint64, down uint64) {
	return p.totalBytesUp.Load(), p.totalBytesDown.Load()
}

// Metrics returns current and peak active connection metrics, resetting the window peak if resetPeak is true.
func (p *ProxyServer) Metrics(resetPeak bool) ProxyMetrics {
	active := p.activeConns.Load()
	var peak int64
	if resetPeak {
		peak = p.peakConns.Swap(active)
		if active > peak {
			peak = active
		}
	} else {
		peak = p.peakConns.Load()
	}
	return ProxyMetrics{
		ActiveConns:      active,
		PeakConns:        peak,
		QueuedConns:      p.queuedConns.Load(),
		SemaphoreRejects: p.semRejects.Load(),
		PressureReaps:    p.totalPressureReaps.Load(),
	}
}

// Signals returns cumulative saturation and stress counters (never reset by SnapshotWindow).
func (p *ProxyServer) Signals() ProxySignals {
	return ProxySignals{
		ActiveConns:      p.activeConns.Load(),
		MaxConns:         p.cfg.MaxActiveConns,
		QueuedConns:      p.queuedConns.Load(),
		SemaphoreRejects: p.semRejects.Load(),
		DrainTimeouts:    p.totalDrainTimeouts.Load(),
		AbruptErrors:     p.totalAbruptErrors.Load(),
		PressureReaps:    p.totalPressureReaps.Load(),
	}
}

// ProxyAtomicSnapshot holds wait-free read-only data-plane counters for decoupled UI snapshots.
type ProxyAtomicSnapshot struct {
	ActiveConns      int64
	PeakConns        int64
	QueuedConns      int64
	SemaphoreRejects uint64
	TotalBytesUp     uint64
	TotalBytesDown   uint64
	PressureReaps    uint64
}

// AtomicTelemetry returns a wait-free snapshot of live data-plane counters via pure atomic loads (0 mutexes).
func (p *ProxyServer) AtomicTelemetry() ProxyAtomicSnapshot {
	if p == nil {
		return ProxyAtomicSnapshot{}
	}
	return ProxyAtomicSnapshot{
		ActiveConns:      p.activeConns.Load(),
		PeakConns:        p.peakConns.Load(),
		QueuedConns:      p.queuedConns.Load(),
		SemaphoreRejects: p.semRejects.Load(),
		TotalBytesUp:     p.totalBytesUp.Load(),
		TotalBytesDown:   p.totalBytesDown.Load(),
		PressureReaps:    p.totalPressureReaps.Load(),
	}
}

// SnapshotWindow returns rich window metrics and atomically resets window counters when reset is true.
func (p *ProxyServer) SnapshotWindow(reset bool) ProxyWindowStats {
	m := p.Metrics(reset)

	var (
		bytesUp, bytesDown, totalConns, dialOK, dialFail uint64
		halfClose, drainTO, idleReap, pressureReap       uint64
		abrupt, dialPaced                                uint64
		dialSamples                                      []float64
		queueSamples                                     []float64
	)
	if reset {
		bytesUp = p.bytesUpWindow.Swap(0)
		bytesDown = p.bytesDownWindow.Swap(0)
		totalConns = p.totalConnsWindow.Swap(0)
		dialOK = p.dialOKWindow.Swap(0)
		dialFail = p.dialFailWindow.Swap(0)
		halfClose = p.halfCloseCleanWindow.Swap(0)
		drainTO = p.drainTimeoutsWindow.Swap(0)
		idleReap = p.idleReapsWindow.Swap(0)
		pressureReap = p.pressureReapsWindow.Swap(0)
		abrupt = p.abruptErrorsWindow.Swap(0)
		dialPaced = p.dialPacedWindow.Swap(0)

		p.dialRTTMu.Lock()
		dialSamples = append([]float64(nil), p.dialRTTSamples...)
		p.dialRTTSamples = p.dialRTTSamples[:0]
		p.dialRTTMu.Unlock()
	} else {
		bytesUp = p.bytesUpWindow.Load()
		bytesDown = p.bytesDownWindow.Load()
		totalConns = p.totalConnsWindow.Load()
		dialOK = p.dialOKWindow.Load()
		dialFail = p.dialFailWindow.Load()
		halfClose = p.halfCloseCleanWindow.Load()
		drainTO = p.drainTimeoutsWindow.Load()
		idleReap = p.idleReapsWindow.Load()
		pressureReap = p.pressureReapsWindow.Load()
		abrupt = p.abruptErrorsWindow.Load()
		dialPaced = p.dialPacedWindow.Load()

		p.dialRTTMu.Lock()
		dialSamples = append([]float64(nil), p.dialRTTSamples...)
		p.dialRTTMu.Unlock()
	}

	p.queueWaitMu.Lock()
	queueSamples = append([]float64(nil), p.queueWaitSamplesMS...)
	if reset {
		p.queueWaitSamplesMS = p.queueWaitSamplesMS[:0]
	}
	p.queueWaitMu.Unlock()

	_, dialP50, dialP95, _ := computeRTTStats(dialSamples)
	_, queueP50, queueP95, _ := computeRTTStats(queueSamples)
	return ProxyWindowStats{
		ActiveConns:      m.ActiveConns,
		PeakConns:        m.PeakConns,
		QueuedConns:      m.QueuedConns,
		QueueWaitP50MS:   queueP50,
		QueueWaitP95MS:   queueP95,
		DialPaced:        dialPaced,
		SemaphoreRejects: m.SemaphoreRejects,
		BytesUpWindow:    bytesUp,
		BytesDownWindow:  bytesDown,
		TotalBytesUp:     p.totalBytesUp.Load(),
		TotalBytesDown:   p.totalBytesDown.Load(),
		TotalConnsWindow: totalConns,
		DialOK:           dialOK,
		DialFail:         dialFail,
		DialRTTP50MS:     dialP50,
		DialRTTP95MS:     dialP95,
		HalfCloseClean:   halfClose,
		DrainTimeouts:    drainTO,
		IdleReaps:        idleReap,
		PressureReaps:    pressureReap,
		AbruptErrors:     abrupt,
	}
}

func (p *ProxyServer) recordQueueWait(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	p.queueWaitMu.Lock()
	defer p.queueWaitMu.Unlock()
	if len(p.queueWaitSamplesMS) >= 256 {
		p.queueWaitSamplesMS = p.queueWaitSamplesMS[1:]
	}
	p.queueWaitSamplesMS = append(p.queueWaitSamplesMS, ms)
}

func (p *ProxyServer) recordDialRTT(d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	p.dialRTTMu.Lock()
	defer p.dialRTTMu.Unlock()
	if len(p.dialRTTSamples) >= 256 {
		p.dialRTTSamples = p.dialRTTSamples[1:]
	}
	p.dialRTTSamples = append(p.dialRTTSamples, ms)
}

// Stop closes the listener synchronously, cancels in-flight dials/semaphore waits when forceCloseActive
// is true, waits for accept/pressure loops to exit, and drains active handlers in <300ms.
func (p *ProxyServer) Stop(forceCloseActive bool) {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		p.acceptWG.Wait()
		p.connWG.Wait()
		return
	}
	p.closing = true
	ln := p.ln
	p.ln = nil
	stopCancel := p.stopCancel
	p.stopCancel = nil
	var toClose []net.Conn
	if forceCloseActive {
		toClose = make([]net.Conn, 0, len(p.conns))
		for c := range p.conns {
			toClose = append(toClose, c)
		}
	}
	p.mu.Unlock()

	if forceCloseActive && stopCancel != nil {
		stopCancel()
	}

	if ln != nil {
		_ = ln.Close()
	}
	if !forceCloseActive && stopCancel != nil {
		stopCancel()
	}
	p.acceptWG.Wait()

	if forceCloseActive {
		for _, c := range toClose {
			_ = c.Close()
		}
		p.mu.Lock()
		for c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
	}

	p.connWG.Wait()
}

func (p *ProxyServer) acceptLoop(ctx context.Context, ln net.Listener) {
	defer p.acceptWG.Done()
	backoff := acceptBackoffMin

	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			isClosing := p.closing
			p.mu.Unlock()
			if isClosing || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > acceptBackoffMax {
				backoff = acceptBackoffMax
			}
			continue
		}
		backoff = acceptBackoffMin

		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		p.connWG.Add(1)
		p.mu.Unlock()

		go p.handleClient(ctx, conn)
	}
}

func (p *ProxyServer) trackConn(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *ProxyServer) untrackConn(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// acquireSemaphore claims a global upstream slot. When saturated, enforces MaxQueuedConns
// and triggers immediate pressure reaping of idle zombies before queueing up to SemaphoreWaitTimeout.
func (p *ProxyServer) acquireSemaphore(ctx context.Context) (ok bool, waited time.Duration, reason string) {
	select {
	case p.sem <- struct{}{}:
		return true, 0, ""
	default:
	}

	wait := p.cfg.SemaphoreWaitTimeout
	if wait <= 0 {
		return false, 0, "queue_disabled"
	}

	if maxQ := p.cfg.MaxQueuedConns; maxQ > 0 {
		curQ := p.queuedConns.Add(1)
		if curQ > int64(maxQ) {
			p.queuedConns.Add(-1)
			return false, 0, "queue_full"
		}
	} else {
		p.queuedConns.Add(1)
	}
	defer p.queuedConns.Add(-1)

	// Immediately wake the pressure reaper if any stalled handshake sockets have already exceeded PressureIdleTimeout.
	p.sweepPressureIdleRelays()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	queuedAt := time.Now()

	select {
	case p.sem <- struct{}{}:
		w := time.Since(queuedAt)
		p.recordQueueWait(w)
		return true, w, ""
	case <-timer.C:
		return false, time.Since(queuedAt), "queue_timeout"
	case <-ctx.Done():
		return false, time.Since(queuedAt), "shutdown"
	}
}

// paceDial reserves the caller's FIFO dial slot when DialPaceInterval > 0.
// Used together with pacedDialUpstream (which holds dialLaunchMu across loopback DialContext)
// so Windows 11 goroutine preemption can NEVER collapse two consecutive dials onto Accept() < DialPaceInterval apart.
func (p *ProxyServer) paceDial(ctx context.Context) (bool, time.Duration) {
	interval := p.cfg.DialPaceInterval
	if interval <= 0 {
		return ctx.Err() == nil, 0
	}

	paceStart := time.Now()
	p.paceMu.Lock()
	now := time.Now()
	slot := p.nextDialAt
	if slot.Before(now) {
		slot = now
	}
	p.nextDialAt = slot.Add(interval)
	p.paceMu.Unlock()

	if d := time.Until(slot); d > 0 {
		p.dialPacedWindow.Add(1)
		timer := time.NewTimer(d)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return false, time.Since(paceStart)
		}
		timer.Stop()
	}
	return ctx.Err() == nil, time.Since(paceStart)
}

// pacedDialUpstream executes the loopback upstream dial with strict inter-dial spacing when DialPaceInterval > 0.
// Holding dialLaunchMu across the sub-millisecond loopback DialContext AND stamping lastDialAt AFTER DialContext
// returns eliminates the v6.2 Windows 11 scheduler-preemption gap that caused 552us Accept() collisions in UT-17/ST-12.
func (p *ProxyServer) pacedDialUpstream(ctx context.Context, targetAddr string) (net.Conn, time.Duration, time.Duration, error) {
	interval := p.cfg.DialPaceInterval
	if interval <= 0 {
		dialStart := time.Now()
		dialCtx, cancelDial := context.WithTimeout(ctx, p.cfg.DialTimeout)
		dialer := &net.Dialer{Timeout: p.cfg.DialTimeout}
		conn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
		cancelDial()
		return conn, 0, time.Since(dialStart), err
	}

	paceStart := time.Now()
	paceOK, _ := p.paceDial(ctx)
	if !paceOK {
		return nil, time.Since(paceStart), 0, ctx.Err()
	}

	p.dialLaunchMu.Lock()
	defer p.dialLaunchMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, time.Since(paceStart), 0, err
	}

	if !p.lastDialAt.IsZero() {
		if wait := p.lastDialAt.Add(interval).Sub(time.Now()); wait > 0 {
			p.dialPacedWindow.Add(1)
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, time.Since(paceStart), 0, ctx.Err()
			}
			timer.Stop()
		}
	}

	paceDur := time.Since(paceStart)
	dialStart := time.Now()
	dialCtx, cancelDial := context.WithTimeout(ctx, p.cfg.DialTimeout)
	dialer := &net.Dialer{Timeout: p.cfg.DialTimeout}
	conn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	cancelDial()
	dialDur := time.Since(dialStart)
	// Stamp lastDialAt AFTER DialContext completes so the next goroutine cannot even start DialContext
	// until >= interval has elapsed after this dial's SYN+ACK reached upstream Accept().
	p.lastDialAt = time.Now()
	return conn, paceDur, dialDur, err
}

func (p *ProxyServer) recordActiveDelta(delta int64) {
	cur := p.activeConns.Add(delta)
	if delta > 0 {
		for {
			prev := p.peakConns.Load()
			if cur <= prev || p.peakConns.CompareAndSwap(prev, cur) {
				break
			}
		}
	}
}

func (p *ProxyServer) logSemaphoreSaturated(reason string) {
	if p.logger == nil {
		return
	}
	now := time.Now().UnixNano()
	prev := p.lastSatLogNS.Load()
	if now-prev < int64(5*time.Second) {
		return
	}
	if p.lastSatLogNS.CompareAndSwap(prev, now) {
		p.logger.Log("SEMAPHORE_SATURATED", map[string]any{
			"reason":            reason,
			"max_conns":         p.cfg.MaxActiveConns,
			"active_conns":      p.activeConns.Load(),
			"queued_conns":      p.queuedConns.Load(),
			"semaphore_rejects": p.semRejects.Load(),
			"pressure_reaps":    p.totalPressureReaps.Load(),
		})
	}
}

// tuneTCPConn applies TCP_NODELAY and 8s keepalive (< 15s CG-NAT silent drop)
// without explicitly setting SO_RCVBUF/SO_SNDBUF (preserving Windows 11 Receive Window Auto-Tuning).
func (p *ProxyServer) tuneTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	ka := p.cfg.TCPKeepAlivePeriod
	if ka <= 0 {
		ka = DefaultTCPKeepAlivePeriod
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(ka)
}

func (p *ProxyServer) handleClient(ctx context.Context, localConn net.Conn) {
	defer p.connWG.Done()
	defer localConn.Close()

	acquired, queueWait, rejectReason := p.acquireSemaphore(ctx)
	if !acquired {
		if ctx.Err() == nil {
			p.semRejects.Add(1)
			p.logSemaphoreSaturated(rejectReason)
			if p.metrics != nil {
				p.metrics.EmitConn(ConnMetric{
					QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
					CloseReason:     rejectReason,
					CopyBufferBytes: p.copyBufSize,
				})
			}
		}
		return
	}
	defer func() { <-p.sem }()

	p.totalConnsWindow.Add(1)
	p.recordActiveDelta(1)
	defer p.recordActiveDelta(-1)

	if !p.trackConn(localConn) {
		return
	}
	defer p.untrackConn(localConn)

	p.tuneTCPConn(localConn)

	// Acquire upstream endpoint (either pool-routed hysteresis/weighted lease or static single-tunnel address).
	tunnelID := "tunnel-1"
	targetAddr := p.upstreamAddr
	usePMTU576 := p.singlePMTU576Safe.Load()
	var lease UpstreamLease
	if p.selector != nil {
		var leaseErr error
		lease, leaseErr = p.selector.AcquireEndpoint(ctx)
		if leaseErr != nil {
			p.dialFailWindow.Add(1)
			if p.metrics != nil {
				p.metrics.EmitConn(ConnMetric{
					QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
					CloseReason:     "no_healthy_tunnel",
					CopyBufferBytes: p.copyBufSize,
				})
			}
			return
		}
		defer lease.Release()
		tunnelID = lease.TunnelID
		targetAddr = lease.Addr
		usePMTU576 = lease.PMTU576Safe
	}
	effBufSz := p.effectiveCopyBufSize(usePMTU576)

	remoteConn, paceDur, dialDur, err := p.pacedDialUpstream(ctx, targetAddr)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		p.dialFailWindow.Add(1)
		if p.selector != nil {
			p.selector.NotifyDialFailure(tunnelID, err)
		}
		if p.onDialFailure != nil {
			p.onDialFailure(err)
		}
		if p.metrics != nil {
			p.metrics.EmitConn(ConnMetric{
				TunnelID:        tunnelID,
				UpstreamAddr:    targetAddr,
				QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
				DialPaceMS:      float64(paceDur.Microseconds()) / 1000.0,
				DialRTTMS:       float64(dialDur.Microseconds()) / 1000.0,
				CloseReason:     "dial_fail",
				CopyBufferBytes: effBufSz,
			})
		}
		return
	}
	p.dialOKWindow.Add(1)
	p.recordDialRTT(dialDur)
	if p.selector != nil {
		p.selector.NotifyDialSuccess(tunnelID, dialDur)
	}
	if p.onDialSuccess != nil {
		p.onDialSuccess()
	}
	defer remoteConn.Close()

	if !p.trackConn(remoteConn) {
		return
	}
	defer p.untrackConn(remoteConn)

	p.tuneTCPConn(remoteConn)

	activeStart := time.Now()
	bytesUp, bytesDown, closeReason, pressureReaped := p.relayBidirectional(localConn, remoteConn, tunnelID, usePMTU576)
	if p.metrics != nil {
		p.metrics.EmitConn(ConnMetric{
			TunnelID:        tunnelID,
			UpstreamAddr:    targetAddr,
			QueueWaitMS:     float64(queueWait.Microseconds()) / 1000.0,
			DialPaceMS:      float64(paceDur.Microseconds()) / 1000.0,
			DialRTTMS:       float64(dialDur.Microseconds()) / 1000.0,
			ActiveMS:        float64(time.Since(activeStart).Microseconds()) / 1000.0,
			BytesUp:         bytesUp,
			BytesDown:       bytesDown,
			CloseReason:     closeReason,
			PressureReaped:  pressureReaped,
			CopyBufferBytes: effBufSz,
		})
	}
}

func (p *ProxyServer) relayBidirectional(localConn, remoteConn net.Conn, tunnelID string, usePMTU576 bool) (uint64, uint64, string, bool) {
	idle := p.cfg.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	streamIdle := p.effectiveStreamingIdleTimeout()
	drain := p.cfg.HalfCloseDrainTimeout
	if drain <= 0 || drain > idle {
		drain = idle
	}
	stalledMaxBytes := int64(p.cfg.StalledHandshakeMaxDownBytes)
	if stalledMaxBytes < 0 {
		stalledMaxBytes = 0
	}

	var connUpBytes atomic.Uint64
	var connDownBytes atomic.Int64

	relay := &activeRelay{}
	relay.touch()

	var (
		wg              sync.WaitGroup
		upClean         atomic.Bool
		downClean       atomic.Bool
		recordedOutcome atomic.Bool
		closeReasonMu   sync.Mutex
		closeReason     = "half_close_clean"
	)

	var localDC, remoteDC *deadlineConn
	localDC = &deadlineConn{
		Conn:              localConn,
		idleTimeout:       idle,
		streamIdleTimeout: streamIdle,
		drainTimeout:      drain,
		onReadBytes: func(n int) {
			now := time.Now()
			relay.touchAt(now)
			relay.upBytes.Add(int64(n))
			connUpBytes.Add(uint64(n))
			p.bytesUpWindow.Add(uint64(n))
			p.totalBytesUp.Add(uint64(n))
			if !downClean.Load() {
				remoteDC.refreshReadDeadline(now)
			}
		},
	}
	remoteDC = &deadlineConn{
		Conn:              remoteConn,
		idleTimeout:       idle,
		streamIdleTimeout: streamIdle,
		drainTimeout:      drain,
		onReadBytes: func(n int) {
			now := time.Now()
			relay.touchAt(now)
			totDown := connDownBytes.Add(int64(n))
			relay.downBytes.Store(totDown)
			p.bytesDownWindow.Add(uint64(n))
			p.totalBytesDown.Add(uint64(n))
			if totDown > stalledMaxBytes {
				localDC.promoteToStreaming()
				remoteDC.promoteToStreaming()
			}
			if !upClean.Load() {
				localDC.refreshReadDeadline(now)
			}
			if totDown >= wanVerifiedMinDownBytes {
				p.lastBytesMovedNS.Store(now.UnixNano())
				if p.selector != nil {
					p.selector.NotifyWANBytes(tunnelID, uint64(n))
				}
			}
		},
	}
	relay.localDC = localDC
	relay.remoteDC = remoteDC

	p.relaysMu.Lock()
	p.relays[relay] = struct{}{}
	p.relaysMu.Unlock()
	defer func() {
		p.relaysMu.Lock()
		delete(p.relays, relay)
		p.relaysMu.Unlock()
	}()

	wg.Add(2)

	classifyErr := func(dc *deadlineConn, err error) {
		if !recordedOutcome.CompareAndSwap(false, true) {
			return
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			if relay.pressureReaped.Load() || dc.pressureReaped.Load() {
				p.pressureReapsWindow.Add(1)
				p.totalPressureReaps.Add(1)
				closeReasonMu.Lock()
				closeReason = "pressure_idle_reap"
				closeReasonMu.Unlock()
				return
			}
			if dc.draining.Load() {
				p.drainTimeoutsWindow.Add(1)
				p.totalDrainTimeouts.Add(1)
				closeReasonMu.Lock()
				closeReason = "drain_timeout"
				closeReasonMu.Unlock()
			} else {
				p.idleReapsWindow.Add(1)
				closeReasonMu.Lock()
				closeReason = "idle_reap"
				closeReasonMu.Unlock()
			}
			return
		}
		p.abruptErrorsWindow.Add(1)
		p.totalAbruptErrors.Add(1)
		closeReasonMu.Lock()
		closeReason = "abrupt_error"
		closeReasonMu.Unlock()
	}

	bufPool := &p.copyBufPool
	if usePMTU576 && p.cfg.PMTU576SafeMode {
		bufPool = &p.copyBufPool8K
	}

	// Direction 1: local -> remote
	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)

		_, err := io.CopyBuffer(remoteDC, localDC, *bufPtr)
		if err == nil {
			upClean.Store(true)
			if cw, ok := remoteConn.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			remoteDC.shortenReadDeadline()
		} else {
			classifyErr(localDC, err)
			_ = localConn.Close()
			_ = remoteConn.Close()
		}
	}()

	// Direction 2: remote -> local
	go func() {
		defer wg.Done()
		bufPtr := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufPtr)

		_, err := io.CopyBuffer(localDC, remoteDC, *bufPtr)
		if err == nil {
			downClean.Store(true)
			if cw, ok := localConn.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			localDC.shortenReadDeadline()
		} else {
			classifyErr(remoteDC, err)
			_ = remoteConn.Close()
			_ = localConn.Close()
		}
	}()

	wg.Wait()
	if upClean.Load() && downClean.Load() {
		p.halfCloseCleanWindow.Add(1)
	}
	down := connDownBytes.Load()
	if down < 0 {
		down = 0
	}
	closeReasonMu.Lock()
	cr := closeReason
	closeReasonMu.Unlock()
	return connUpBytes.Load(), uint64(down), cr, relay.pressureReaped.Load()
}
