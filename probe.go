package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ChildExitResult captures the exit status and stderr tail of a supervised gh/ssh process.
type ChildExitResult struct {
	ExitCode   int
	Err        error
	StderrTail string
	Uptime     time.Duration
}

// BootProbeMetrics breaks down boot readiness latency into TCP listener open vs E2E SOCKS5 handshake.
type BootProbeMetrics struct {
	InitialRTT       time.Duration
	SpawnToPortOpen  time.Duration
	PortOpenToSOCKS5 time.Duration
	TotalBootWait    time.Duration
	Attempts         int
}

// BootQualityReport summarizes the Two-Stage pre-traffic 5-tuple Fast-Lane Boot Gate check.
type BootQualityReport struct {
	Accepted       bool
	Reason         string
	Samples        int
	Failures       int
	MinMS          int64
	P50MS          int64
	MaxMS          int64
	JitterMS       int64
	SlowBoot       bool
	BootDurMS      int64
	MicroPayloadOK bool
	MicroPayloadMS int64
	PeerMedianMS   float64
	UnderlayRawMS  float64
	RelativeRho    float64
}

// IsGitHubHost returns true if target (host or host:port) belongs to github.com or githubusercontent.com.
// Used as a hard WAF/anti-bot invariant: underlay baseline probing MUST NEVER touch GitHub endpoints.
func IsGitHubHost(target string) bool {
	s := strings.TrimSpace(target)
	if s == "" {
		return false
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "github.com" || strings.HasSuffix(host, ".github.com") {
		return true
	}
	if host == "githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com") {
		return true
	}
	return false
}

// MeasureUnderlayBaseline measures direct underlay RTT B_raw(t) (TCP connect + minimal TLS ClientHello
// reply, bypassing SSH tunnels completely) against non-GitHub targets (e.g. 20.120.56.11:443, 1.1.1.1:443).
// Enforces the hard WAF safety guard rejecting any GitHub hostname.
func MeasureUnderlayBaseline(ctx context.Context, targets []string, timeout time.Duration) (time.Duration, string, error) {
	if len(targets) == 0 {
		targets = []string{"1.1.1.1:443", "20.120.56.11:443"}
	}
	if timeout <= 0 {
		timeout = DefaultUnderlayProbeTimeout
	}
	for _, t := range targets {
		if IsGitHubHost(t) {
			return 0, t, fmt.Errorf("underlay baseline refused GitHub host target %q (WAF safety invariant)", t)
		}
	}

	var lastErr error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		rtt, err := probeDirectTLS(ctx, target, timeout)
		if err == nil {
			return rtt, target, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no underlay baseline targets succeeded")
	}
	return 0, "", lastErr
}

func probeDirectTLS(ctx context.Context, targetAddr string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	if parentDL, ok := ctx.Deadline(); ok && parentDL.Before(deadline) {
		deadline = parentDL
	}
	dialCtx, cancelDial := context.WithDeadline(ctx, deadline)
	dialer := &net.Dialer{Timeout: time.Until(deadline)}
	conn, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	cancelDial()
	if err != nil {
		return 0, fmt.Errorf("underlay dial %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancel()

	_ = conn.SetDeadline(deadline)
	// Measure strictly 1 WAN RTT (TLS ClientHello -> ServerHello on the established TCP socket)
	// matching ProbeSOCKS5's 1-RTT CHANNEL_OPEN semantics without 2x TCP+TLS double-counting
	// or carrier SYN-proxy distortion.
	tlsStart := time.Now()
	if _, err := conn.Write(minimalTLSClientHelloProbe()); err != nil {
		return 0, fmt.Errorf("underlay write %s: %w", targetAddr, err)
	}
	var resp [5]byte
	n, err := conn.Read(resp[:])
	if n > 0 {
		return time.Since(tlsStart), nil
	}
	if err != nil {
		return 0, fmt.Errorf("underlay read %s: %w", targetAddr, err)
	}
	return 0, fmt.Errorf("underlay read %s: 0 bytes", targetAddr)
}

// ComputeRelativeOverhead calculates baseline-normalized tunnel overhead rho_i(t) = EWMA_RTT_i / max(B_raw, 50ms).
// Distinguishes genuine slow 5-tuple relay lanes from network-wide cellular congestion (e.g. weak 4G/LTE vs broadband).
func ComputeRelativeOverhead(ewmaRTTMS, baselineMS float64) float64 {
	if ewmaRTTMS <= 0 {
		return 1.0
	}
	denom := baselineMS
	if denom < 50.0 {
		denom = 50.0
	}
	return ewmaRTTMS / denom
}

// EvaluateBaselineNormalizedLane classifies a tunnel lane as "fast", "mediocre", or "slow_lane"
// relative to the live direct underlay baseline B_raw(t).
func EvaluateBaselineNormalizedLane(ewmaRTTMS, baselineMS, fastRatio, evictRatio float64) string {
	if fastRatio <= 1.0 {
		fastRatio = DefaultFastLaneMaxRatio
	}
	if evictRatio <= fastRatio {
		evictRatio = DefaultSlowLaneEvictRatio
	}
	rho := ComputeRelativeOverhead(ewmaRTTMS, baselineMS)
	if rho <= fastRatio {
		return "fast"
	}
	if rho > evictRatio {
		return "slow_lane"
	}
	return "mediocre"
}

// isConnRefused detects loopback ECONNREFUSED / Windows WSAECONNREFUSED (10061) errors.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")
}

// ProbeSOCKS5 executes a real RFC 1928 SOCKS5 no-auth greeting + CONNECT handshake
// through proxyAddr to targetAddr, proving end-to-end Azure Relay + Codespace sshd liveness.
func ProbeSOCKS5(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (time.Duration, error) {
	conn, rtt, err := dialSOCKS5(ctx, proxyAddr, targetAddr, timeout)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return rtt, nil
}

// ProbeSOCKS5MicroPayload executes Stage 2 of the v6 Boot Gate: opens a real SOCKS5 CONNECT
// and sends a minimal bidirectional probe payload to prove live byte flow through the tunnel
// (catching half-open blackholed relays that answer CONNECT but drop application data).
func ProbeSOCKS5MicroPayload(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	start := time.Now()
	deadline := start.Add(timeout)
	if parentDL, ok := ctx.Deadline(); ok && parentDL.Before(deadline) {
		deadline = parentDL
	}

	conn, _, err := dialSOCKS5(ctx, proxyAddr, targetAddr, time.Until(deadline))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancel()

	_ = conn.SetDeadline(deadline)

	probePayload := minimalTLSClientHelloProbe()
	if _, err := conn.Write(probePayload); err != nil {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("micro-payload write: %w", ctx.Err())
		}
		return 0, fmt.Errorf("micro-payload write: %w", err)
	}

	var resp [5]byte
	n, err := conn.Read(resp[:])
	if n > 0 {
		return time.Since(start), nil
	}
	if ctx.Err() != nil {
		return 0, fmt.Errorf("micro-payload read: %w", ctx.Err())
	}
	if err != nil {
		return 0, fmt.Errorf("micro-payload read: %w", err)
	}
	return 0, errors.New("micro-payload read: 0 bytes returned")
}

// minimalTLSClientHelloProbe returns a compact, RFC-compliant TLS 1.2 ClientHello record (51 bytes)
// that triggers an immediate ServerHello or TLS Alert from any TLS :443 endpoint and echoes cleanly on echo mocks.
func minimalTLSClientHelloProbe() []byte {
	body := make([]byte, 0, 43)
	body = append(body, 0x03, 0x03)
	for i := 0; i < 32; i++ {
		body = append(body, byte(0x41+i))
	}
	body = append(body, 0x00)       // session id len = 0
	body = append(body, 0x00, 0x02) // cipher suites len = 2
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00) // compression methods: 1 (null)
	body = append(body, 0x00, 0x00) // extensions len = 0

	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01, 0x00, byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func dialSOCKS5(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, time.Duration, error) {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	start := time.Now()
	deadline := start.Add(timeout)
	if parentDL, ok := ctx.Deadline(); ok && parentDL.Before(deadline) {
		deadline = parentDL
	}

	dialCtx, cancelDial := context.WithDeadline(ctx, deadline)
	dialer := &net.Dialer{Timeout: time.Until(deadline)}
	conn, err := dialer.DialContext(dialCtx, "tcp", proxyAddr)
	cancelDial()
	if err != nil {
		return nil, 0, fmt.Errorf("socks5 dial %s: %w", proxyAddr, err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancel()

	_ = conn.SetDeadline(deadline)

	wrapErr := func(stage string, err error) error {
		_ = conn.Close()
		if ctx.Err() != nil {
			return fmt.Errorf("%s: %w", stage, ctx.Err())
		}
		return fmt.Errorf("%s: %w", stage, err)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, 0, wrapErr("socks5 greeting write", err)
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		return nil, 0, wrapErr("socks5 greeting read", err)
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		_ = conn.Close()
		return nil, 0, fmt.Errorf("socks5 unexpected method response: %x", methodResp)
	}

	req, err := buildSOCKS5ConnectRequest(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, 0, wrapErr("socks5 connect write", err)
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, 0, wrapErr("socks5 connect reply read", err)
	}
	if hdr[0] != 0x05 {
		_ = conn.Close()
		return nil, 0, fmt.Errorf("socks5 invalid reply version: 0x%02x", hdr[0])
	}
	if hdr[1] != 0x00 {
		_ = conn.Close()
		return nil, 0, fmt.Errorf("socks5 connect rejected: rep=0x%02x", hdr[1])
	}

	var addrLen int
	switch hdr[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		var lb [1]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil, 0, wrapErr("socks5 domain len read", err)
		}
		addrLen = int(lb[0])
	default:
		_ = conn.Close()
		return nil, 0, fmt.Errorf("socks5 invalid atyp: 0x%02x", hdr[3])
	}
	tail := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, tail); err != nil {
		return nil, 0, wrapErr("socks5 bind addr read", err)
	}

	return conn, time.Since(start), nil
}

func buildSOCKS5ConnectRequest(targetAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid probe target %q: %w", targetAddr, err)
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || portNum == 0 {
		return nil, fmt.Errorf("invalid probe port %q", portStr)
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = make([]byte, 0, 4+4+2)
			buf = append(buf, 0x05, 0x01, 0x00, 0x01)
			buf = append(buf, ip4...)
		} else {
			ip16 := ip.To16()
			buf = make([]byte, 0, 4+16+2)
			buf = append(buf, 0x05, 0x01, 0x00, 0x04)
			buf = append(buf, ip16...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid probe domain length: %d", len(host))
		}
		buf = make([]byte, 0, 4+1+len(host)+2)
		buf = append(buf, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	buf = append(buf, portBytes[:]...)
	return buf, nil
}

// ErrChildExitedDuringBoot indicates the supervised gh/ssh process died before readiness.
var ErrChildExitedDuringBoot = errors.New("child process exited during boot probe")

// WaitForTunnelReady multiplexes E2E SOCKS5 readiness probes against childExitCh and bootTimeout.
func WaitForTunnelReady(
	ctx context.Context,
	childExitCh <-chan ChildExitResult,
	proxyAddr string,
	targetAddr string,
	bootTimeout time.Duration,
	probeTimeout time.Duration,
	pollInterval time.Duration,
	probeFn func(context.Context, string, string, time.Duration) (time.Duration, error),
) (time.Duration, *ChildExitResult, error) {
	metrics, early, err := WaitForTunnelReadyDetailed(
		ctx, childExitCh, proxyAddr, targetAddr, bootTimeout, probeTimeout, pollInterval, probeFn,
	)
	return metrics.InitialRTT, early, err
}

// WaitForTunnelReadyDetailed performs E2E SOCKS5 readiness probing while recording phase timings.
func WaitForTunnelReadyDetailed(
	ctx context.Context,
	childExitCh <-chan ChildExitResult,
	proxyAddr string,
	targetAddr string,
	bootTimeout time.Duration,
	probeTimeout time.Duration,
	pollInterval time.Duration,
	probeFn func(context.Context, string, string, time.Duration) (time.Duration, error),
) (BootProbeMetrics, *ChildExitResult, error) {
	if probeFn == nil {
		probeFn = ProbeSOCKS5
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}

	if childExitCh != nil {
		select {
		case res := <-childExitCh:
			return BootProbeMetrics{}, &res, ErrChildExitedDuringBoot
		default:
		}
	}

	start := time.Now()
	var portOpenAt time.Time
	attempts := 0

	bootCtx, cancelBoot := context.WithTimeout(ctx, bootTimeout)
	defer cancelBoot()

	exitCaptured := make(chan ChildExitResult, 1)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		if childExitCh == nil {
			<-bootCtx.Done()
			return
		}
		select {
		case res := <-childExitCh:
			exitCaptured <- res
			cancelBoot()
		case <-bootCtx.Done():
		}
	}()
	defer func() {
		cancelBoot()
		<-watcherDone
	}()

	pollTimer := time.NewTimer(pollInterval)
	if !pollTimer.Stop() {
		select {
		case <-pollTimer.C:
		default:
		}
	}
	defer pollTimer.Stop()

	var lastErr error
	for {
		attempts++
		rtt, err := probeFn(bootCtx, proxyAddr, targetAddr, probeTimeout)
		if err == nil {
			now := time.Now()
			if portOpenAt.IsZero() {
				portOpenAt = now.Add(-rtt)
				if portOpenAt.Before(start) {
					portOpenAt = start
				}
			}
			return BootProbeMetrics{
				InitialRTT:       rtt,
				SpawnToPortOpen:  portOpenAt.Sub(start),
				PortOpenToSOCKS5: now.Sub(portOpenAt),
				TotalBootWait:    now.Sub(start),
				Attempts:         attempts,
			}, nil, nil
		}
		if portOpenAt.IsZero() && !isConnRefused(err) {
			portOpenAt = time.Now()
		}
		lastErr = err

		pollTimer.Reset(pollInterval)
		select {
		case res := <-exitCaptured:
			return BootProbeMetrics{}, &res, ErrChildExitedDuringBoot
		case <-bootCtx.Done():
			select {
			case res := <-exitCaptured:
				return BootProbeMetrics{}, &res, ErrChildExitedDuringBoot
			default:
			}
			if ctx.Err() != nil {
				return BootProbeMetrics{}, nil, ctx.Err()
			}
			return BootProbeMetrics{}, nil, fmt.Errorf("boot readiness timeout after %s (last probe err: %v)", bootTimeout, lastErr)
		case <-pollTimer.C:
		}
	}
}

// EvaluateBootQuality decides whether a freshly booted tunnel should be accepted before opening traffic.
// Preserves exact v4/v5 decision semantics verified by UT-15.
func EvaluateBootQuality(cfg Config, bootDuration time.Duration, rtts []time.Duration, failures int) BootQualityReport {
	slowBoot := cfg.BootSlowThreshold > 0 && bootDuration >= cfg.BootSlowThreshold
	rep := BootQualityReport{
		Accepted:       true,
		Reason:         "ok",
		Samples:        len(rtts),
		Failures:       failures,
		SlowBoot:       slowBoot,
		BootDurMS:      bootDuration.Milliseconds(),
		MicroPayloadOK: true,
	}

	if len(rtts) > 0 {
		sorted := make([]time.Duration, len(rtts))
		copy(sorted, rtts)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		minD := sorted[0]
		maxD := sorted[len(sorted)-1]
		p50D := sorted[(len(sorted)-1)/2]
		jitterD := maxD - minD

		rep.MinMS = minD.Milliseconds()
		rep.P50MS = p50D.Milliseconds()
		rep.MaxMS = maxD.Milliseconds()
		rep.JitterMS = jitterD.Milliseconds()

		if cfg.BootQualitySamples <= 1 {
			rep.Reason = "gate_disabled"
			return rep
		}

		if failures > 0 {
			rep.Accepted = false
			rep.Reason = "qualification_probe_failed"
			return rep
		}
		if cfg.BootQualityMaxRTT > 0 && p50D > cfg.BootQualityMaxRTT {
			rep.Accepted = false
			rep.Reason = "idle_rtt_exceeded"
			return rep
		}
		if cfg.BootQualityMaxJitter > 0 && jitterD > cfg.BootQualityMaxJitter {
			rep.Accepted = false
			rep.Reason = "idle_jitter_exceeded"
			return rep
		}
		if slowBoot && cfg.BootSlowMaxRTT > 0 && p50D > cfg.BootSlowMaxRTT {
			rep.Accepted = false
			rep.Reason = "slow_boot_elevated_rtt"
			return rep
		}
		if slowBoot && cfg.BootSlowMaxJitter > 0 && jitterD > cfg.BootSlowMaxJitter {
			rep.Accepted = false
			rep.Reason = "slow_boot_elevated_jitter"
			return rep
		}
		return rep
	}

	if cfg.BootQualitySamples > 1 && failures > 0 {
		rep.Accepted = false
		rep.Reason = "qualification_probe_failed"
	}
	return rep
}

// EvaluateFastLaneGate applies NetShaper v6's Two-Stage 5-Tuple Fast-Lane Boot Gate:
//   - Stage 1: EvaluateBootQuality + empirical slow-lane ceiling (BootFastLaneMaxRTT) + dynamic peer median check.
//   - Stage 2: Micro-payload bidirectional byte-flow verification (rejects half-open blackholed relays).
func EvaluateFastLaneGate(
	cfg Config,
	bootDuration time.Duration,
	rtts []time.Duration,
	failures int,
	peerMedianMS float64,
	microPayloadOK bool,
	microPayloadRTT time.Duration,
) BootQualityReport {
	rep := EvaluateBootQuality(cfg, bootDuration, rtts, failures)
	rep.PeerMedianMS = round2(peerMedianMS)
	rep.MicroPayloadOK = microPayloadOK
	rep.MicroPayloadMS = microPayloadRTT.Milliseconds()

	if !rep.Accepted {
		return rep
	}
	if cfg.BootQualitySamples <= 1 {
		return rep
	}
	if cfg.BootFastLaneMaxRTT > 0 && rep.P50MS > cfg.BootFastLaneMaxRTT.Milliseconds() {
		rep.Accepted = false
		rep.Reason = "mci_slow_lane_detected"
		return rep
	}
	if peerMedianMS > 0 {
		dynCeiling := peerMedianMS * 2.5
		if dynCeiling < 600.0 {
			dynCeiling = 600.0
		}
		if float64(rep.P50MS) > dynCeiling {
			rep.Accepted = false
			rep.Reason = "slow_lane_vs_peer"
			return rep
		}
	}
	if cfg.BootMicroPayloadCheck && !microPayloadOK {
		rep.Accepted = false
		rep.Reason = "micro_payload_failed"
		return rep
	}
	return rep
}

// EvaluateFastLaneGateNormalized extends EvaluateFastLaneGate with v6.3 dynamic underlay baseline B_raw(t)
// relative overhead scoring (rho = P50 / max(B_raw, 50ms)) and underlay-normalized RTT/jitter ceilings so a
// 650ms tunnel is rejected on clean 140ms Wi-Fi (rho=4.64x) yet a healthy cold-booted tunnel on a congested
// 450-800ms WAN underlay (e.g. p50=563ms, jitter=442ms, rho=0.96 on B_raw=586.69ms) is accepted.
func EvaluateFastLaneGateNormalized(
	cfg Config,
	bootDuration time.Duration,
	rtts []time.Duration,
	failures int,
	peerMedianMS float64,
	underlayRawMS float64,
	microPayloadOK bool,
	microPayloadRTT time.Duration,
) BootQualityReport {
	// On high-baseline cellular/WAN links (e.g. 450-800ms), relax static RTT and jitter ceilings
	// proportionally to B_raw so healthy cold-booted tunnels (including >=13s cold boots with
	// p50=563ms, jitter=442ms, rho=0.96 on B_raw=586.69ms) are NOT falsely rejected with
	// slow_boot_elevated_rtt or slow_boot_elevated_jitter.
	// On clean B_raw <= 250ms (default 220ms), adaptiveMax <= 550ms, adaptiveSlowMax <= 467ms (< 550ms),
	// adaptiveMaxJitter <= 495ms (< 700ms), and adaptiveSlowJitter <= 374ms (< 400ms), preserving
	// 100% UT-15 / UT-19 / UT-31 / ST-14 static parity.
	effCfg := cfg
	if underlayRawMS > 0 {
		const (
			maxAdaptiveFastRTT    = 1800 * time.Millisecond
			maxAdaptiveSlowRTT    = 1500 * time.Millisecond
			maxAdaptiveFastJitter = 1400 * time.Millisecond
			maxAdaptiveSlowJitter = 1100 * time.Millisecond
		)
		fastRatio := cfg.FastLaneMaxRatio
		if fastRatio < 1.0 {
			fastRatio = DefaultFastLaneMaxRatio
		}
		adaptiveMax := time.Duration(underlayRawMS*fastRatio) * time.Millisecond
		if adaptiveMax > maxAdaptiveFastRTT {
			adaptiveMax = maxAdaptiveFastRTT
		}
		if adaptiveMax > effCfg.BootQualityMaxRTT && effCfg.BootQualityMaxRTT > 0 {
			effCfg.BootQualityMaxRTT = adaptiveMax
		}
		if adaptiveMax > effCfg.BootFastLaneMaxRTT && effCfg.BootFastLaneMaxRTT > 0 {
			effCfg.BootFastLaneMaxRTT = adaptiveMax
		}
		slowRatio := fastRatio * 0.85
		if slowRatio < 1.6 {
			slowRatio = 1.6
		}
		if slowRatio > fastRatio {
			slowRatio = fastRatio
		}
		adaptiveSlowMax := time.Duration(underlayRawMS*slowRatio) * time.Millisecond
		if adaptiveSlowMax > maxAdaptiveSlowRTT {
			adaptiveSlowMax = maxAdaptiveSlowRTT
		}
		if adaptiveSlowMax > effCfg.BootSlowMaxRTT && effCfg.BootSlowMaxRTT > 0 {
			effCfg.BootSlowMaxRTT = adaptiveSlowMax
		}

		maxJitterRatio := fastRatio * 0.90
		if maxJitterRatio < 1.75 {
			maxJitterRatio = 1.75
		}
		if maxJitterRatio > fastRatio {
			maxJitterRatio = fastRatio
		}
		adaptiveMaxJitter := time.Duration(underlayRawMS*maxJitterRatio) * time.Millisecond
		if adaptiveMaxJitter > maxAdaptiveFastJitter {
			adaptiveMaxJitter = maxAdaptiveFastJitter
		}
		if adaptiveMaxJitter > effCfg.BootQualityMaxJitter && effCfg.BootQualityMaxJitter > 0 {
			effCfg.BootQualityMaxJitter = adaptiveMaxJitter
		}

		slowJitterRatio := slowRatio * 0.80
		if slowJitterRatio < 1.45 {
			slowJitterRatio = 1.45
		}
		if slowJitterRatio > fastRatio {
			slowJitterRatio = fastRatio
		}
		adaptiveSlowJitter := time.Duration(underlayRawMS*slowJitterRatio) * time.Millisecond
		if adaptiveSlowJitter > maxAdaptiveSlowJitter {
			adaptiveSlowJitter = maxAdaptiveSlowJitter
		}
		if adaptiveSlowJitter > effCfg.BootSlowMaxJitter && effCfg.BootSlowMaxJitter > 0 {
			effCfg.BootSlowMaxJitter = adaptiveSlowJitter
		}
	}

	rep := EvaluateFastLaneGate(effCfg, bootDuration, rtts, failures, peerMedianMS, microPayloadOK, microPayloadRTT)
	rep.UnderlayRawMS = round2(underlayRawMS)
	if underlayRawMS > 0 && rep.P50MS > 0 {
		rho := ComputeRelativeOverhead(float64(rep.P50MS), underlayRawMS)
		rep.RelativeRho = round2(rho)
		evictRatio := cfg.SlowLaneEvictRatio
		if evictRatio <= 1.0 {
			evictRatio = DefaultSlowLaneEvictRatio
		}
		if rep.Accepted && cfg.BootQualitySamples > 1 && rho > evictRatio {
			rep.Accepted = false
			rep.Reason = "slow_lane_vs_underlay_baseline"
		}
	}
	return rep
}
