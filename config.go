package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultCodespaceName = "my-codespace"
	DefaultLocalPort     = uint16(1080)
	DefaultGHPort        = uint16(1081)

	// Multiplexed SSH channel & pooling defaults calibrated for constrained CG-NAT / cellular links:
	// Outer WAN connection caps apply to separate TCP sockets to the relay VIP.
	// Each 'gh codespace ssh -D' worker uses 1 outer WAN TCP socket and multiplexes all local
	// SOCKS5 streams as RFC 4254 direct-tcpip SSH channels inside it (PoolSize=2 -> 2 outer WAN
	// sockets, well below common carrier per-destination TCP knees).
	// Raising SSH channel concurrency to MaxActiveConns=64 (PerTunnelMaxConns=32) eliminates
	// persistent HTTP/2 and SSE starvation on multi-origin web applications while preserving
	// conservative GitHub API WAF budgets and adaptive 8 KiB PMTU=576 framing.
	DefaultPoolSize                     = 2
	DefaultRecommendedMaxPoolSize       = 3
	DefaultMaxPoolSize                  = 4
	DefaultMaxActiveConns               = 64
	DefaultPerTunnelMaxConns            = 32
	DefaultMaxQueuedConns               = 128 // absorbs 60-128+ multi-origin browser bursts without instant queue_full RST storms
	DefaultCopyBufferSize               = 16 * 1024
	DefaultPMTU576CopyBufSize           = 8 * 1024 // 8 KiB adaptive step-down when relay resolves to PMTU=576 VIP (20.120.56.11)
	DefaultProbeInterval                = 25 * time.Second
	DefaultDegradedProbeInterval        = 8 * time.Second
	DefaultProbeTimeout                 = 12 * time.Second
	DefaultProbeTarget                  = "1.1.1.1:443"
	DefaultBootTimeout                  = 90 * time.Second
	DefaultDialTimeout                  = 2 * time.Second
	DefaultIdleTimeout                  = 60 * time.Second  // avoids prematurely closing preconnected browser HTTP/2 keepalive sockets
	DefaultPressureIdleTimeout          = 12 * time.Second  // aggressive reaper for stalled handshakes / 0B-128B zombies under load
	DefaultStreamingIdleTimeout         = 180 * time.Second // protects established SSE/WebChannel/HTTP2 streams (>128B down) across long pauses
	DefaultStreamingPressureIdleTimeout = 20 * time.Second  // strictly < SemaphoreWaitTimeout (25s) to guarantee zero pressure-reap deadlock at 64/64 saturation
	DefaultStalledHandshakeMaxDownBytes = 128               // sockets with <=128B downstream (e.g. 0B zombies, 2B/13B SOCKS5 stalls) reap fast
	DefaultPressureThresholdPct         = 75                // activate pressure reaping at >=75% slot utilization or QueuedConns>0
	DefaultHalfCloseDrainTimeout        = 15 * time.Second  // progress-resetting bounded drain after FIN
	DefaultTCPKeepAlivePeriod           = 8 * time.Second   // strictly < 15s aggressive CG-NAT silent idle drop
	DefaultStopTimeout                  = 10 * time.Second
	DefaultDegradedRTTThreshold         = 4000 * time.Millisecond
	DefaultBreakerThreshold             = 5
	DefaultBreakerMinWindow             = 45 * time.Second
	DefaultLoopbackRefusedThreshold     = 3
	DefaultBackoffMin                   = 2 * time.Second
	DefaultBackoffMax                   = 30 * time.Second
	DefaultSemaphoreWaitTimeout         = 25 * time.Second // strictly > StreamingPressureIdleTimeout (20s) so queued requests never starve behind saturated slots
	DefaultDialPaceInterval             = 0                // loopback ssh -D CHANNEL_OPEN emits 0 outer WAN TCP SYNs; 0ms avoids Windows timer HoL serialization (pacedDialUpstream stays active when >0)
	DefaultSummaryLogInterval           = 60 * time.Second
	DefaultSSHAliveInterval             = 10 // strictly < 15s CG-NAT idle drop (dead-tunnel detection in 30s)
	DefaultSSHAliveCountMax             = 3
	DefaultSSHConnectTimeout            = 15

	// Pre-traffic two-stage 5-tuple fast-lane boot gate.
	DefaultBootQualitySamples    = 3
	DefaultBootQualityMaxRetries = 2
	DefaultBootQualityMaxRTT     = 850 * time.Millisecond
	DefaultBootQualityMaxJitter  = 700 * time.Millisecond
	DefaultBootSlowThreshold     = 13 * time.Second
	DefaultBootSlowMaxRTT        = 550 * time.Millisecond
	DefaultBootSlowMaxJitter     = 400 * time.Millisecond
	DefaultBootFastLaneMaxRTT    = 1200 * time.Millisecond

	// v6.3 Dynamic Direct Underlay Baseline B_raw(t), Schmitt-Trigger Hysteresis & Chronic Slow-Lane Eviction.
	DefaultUnderlayProbeInterval   = 35 * time.Second
	DefaultUnderlayProbeTimeout    = 5 * time.Second
	DefaultUnderlayProbeTargets    = "1.1.1.1:443,20.120.56.11:443" // Direct unimodal underlay first — NEVER github.com / api.github.com
	DefaultUnderlayBaselineMS      = 250.0
	DefaultHysteresisDwellWindow   = 25 * time.Second
	DefaultHysteresisRelMargin     = 0.30
	DefaultHysteresisAbsMargin     = 100 * time.Millisecond
	DefaultFastLaneMaxRatio        = 2.2 // rho <= 2.2x qualifies for balanced dual/multi-active HoL sharing
	DefaultSlowLaneEvictRatio      = 3.5 // rho > 3.5x sustained triggers chronic slow-lane diversion & eviction
	DefaultSlowLaneEvictWindow     = 30 * time.Second
	DefaultSlowLaneUnderlayCeiling = 800 * time.Millisecond // if B_raw > 800ms, underlay itself is congested; do not evict workers

	// GitHub API & Anti-Bot/WAF Guard (Module 1).
	DefaultGitHubMaxCallsPer5Min      = 6
	DefaultGitHubMaxCallsPerHour      = 24
	DefaultGitHubMinCallSpacing       = 2 * time.Second // v6.3: minimum spacing between consecutive gh CLI calls for WAF/bot safety
	DefaultGitHubRateLimitBaseBackoff = 15 * time.Second
	DefaultGitHubRateLimitMaxBackoff  = 5 * time.Minute
	DefaultGitHubWarmCacheTTL         = 10 * time.Minute

	DefaultLogFileName     = "netshaper_history.log"
	DefaultMetricsFileName = "netshaper_metrics.ndjson"
)

// Config holds all runtime parameters for NetShaper v6.4.
type Config struct {
	CodespaceName                string
	LocalHost                    string
	LocalPort                    uint16
	GHHost                       string
	GHPort                       uint16
	PoolSize                     int
	MaxActiveConns               int
	PerTunnelMaxConns            int
	MaxQueuedConns               int
	CopyBufferSize               int
	PMTU576SafeMode              bool
	PMTU576CopyBufSize           int
	ProbeInterval                time.Duration
	DegradedProbeInterval        time.Duration
	ProbeTimeout                 time.Duration
	ProbeTarget                  string
	BootTimeout                  time.Duration
	DialTimeout                  time.Duration
	IdleTimeout                  time.Duration
	PressureIdleTimeout          time.Duration
	StreamingIdleTimeout         time.Duration
	StreamingPressureIdleTimeout time.Duration
	StalledHandshakeMaxDownBytes int
	PressureThresholdPct         int
	HalfCloseDrainTimeout        time.Duration
	TCPKeepAlivePeriod           time.Duration
	StopTimeout                  time.Duration
	StopOnExit                   bool
	DegradedRTTThreshold         time.Duration
	BreakerThreshold             int
	BreakerMinWindow             time.Duration
	LoopbackRefusedThreshold     int
	BackoffMin                   time.Duration
	BackoffMax                   time.Duration
	SemaphoreWaitTimeout         time.Duration
	DialPaceInterval             time.Duration
	SummaryLogInterval           time.Duration
	SSHServerAliveInterval       int
	SSHServerAliveCountMax       int
	SSHConnectTimeout            int
	BootQualitySamples           int
	BootQualityMaxRetries        int
	BootQualityMaxRTT            time.Duration
	BootQualityMaxJitter         time.Duration
	BootSlowThreshold            time.Duration
	BootSlowMaxRTT               time.Duration
	BootSlowMaxJitter            time.Duration
	BootFastLaneMaxRTT           time.Duration
	BootMicroPayloadCheck        bool
	UnderlayProbeInterval        time.Duration
	UnderlayProbeTimeout         time.Duration
	UnderlayProbeTargets         string
	UnderlayBaselineMS           float64
	HysteresisDwellWindow        time.Duration
	HysteresisRelMargin          float64
	HysteresisAbsMargin          time.Duration
	FastLaneMaxRatio             float64
	SlowLaneEvictRatio           float64
	SlowLaneEvictWindow          time.Duration
	SlowLaneUnderlayCeiling      time.Duration
	GitHubMaxCallsPer5Min        int
	GitHubMaxCallsPerHour        int
	GitHubMinCallSpacing         time.Duration
	GitHubRateLimitBase          time.Duration
	GitHubRateLimitMax           time.Duration
	GitHubWarmCacheTTL           time.Duration
	CodespaceCachePath           string
	WarmupCodespaceOnBoot        bool
	PreflightNetHygiene          bool
	LogFile                      string
	MetricsFile                  string
	Headless                     bool
	CodespaceExplicit            bool
}

// DefaultConfig returns production-hardened defaults calibrated for constrained CG-NAT links and OpenSSH multiplexing.
func DefaultConfig() Config {
	return Config{
		CodespaceName:                DefaultCodespaceName,
		LocalHost:                    "127.0.0.1",
		LocalPort:                    DefaultLocalPort,
		GHHost:                       "127.0.0.1",
		GHPort:                       DefaultGHPort,
		PoolSize:                     DefaultPoolSize,
		MaxActiveConns:               DefaultMaxActiveConns,
		PerTunnelMaxConns:            DefaultPerTunnelMaxConns,
		MaxQueuedConns:               DefaultMaxQueuedConns,
		CopyBufferSize:               DefaultCopyBufferSize,
		PMTU576SafeMode:              true,
		PMTU576CopyBufSize:           DefaultPMTU576CopyBufSize,
		ProbeInterval:                DefaultProbeInterval,
		DegradedProbeInterval:        DefaultDegradedProbeInterval,
		ProbeTimeout:                 DefaultProbeTimeout,
		ProbeTarget:                  DefaultProbeTarget,
		BootTimeout:                  DefaultBootTimeout,
		DialTimeout:                  DefaultDialTimeout,
		IdleTimeout:                  DefaultIdleTimeout,
		PressureIdleTimeout:          DefaultPressureIdleTimeout,
		StreamingIdleTimeout:         DefaultStreamingIdleTimeout,
		StreamingPressureIdleTimeout: DefaultStreamingPressureIdleTimeout,
		StalledHandshakeMaxDownBytes: DefaultStalledHandshakeMaxDownBytes,
		PressureThresholdPct:         DefaultPressureThresholdPct,
		HalfCloseDrainTimeout:        DefaultHalfCloseDrainTimeout,
		TCPKeepAlivePeriod:           DefaultTCPKeepAlivePeriod,
		StopTimeout:                  DefaultStopTimeout,
		StopOnExit:                   true,
		DegradedRTTThreshold:         DefaultDegradedRTTThreshold,
		BreakerThreshold:             DefaultBreakerThreshold,
		BreakerMinWindow:             DefaultBreakerMinWindow,
		LoopbackRefusedThreshold:     DefaultLoopbackRefusedThreshold,
		BackoffMin:                   DefaultBackoffMin,
		BackoffMax:                   DefaultBackoffMax,
		SemaphoreWaitTimeout:         DefaultSemaphoreWaitTimeout,
		DialPaceInterval:             DefaultDialPaceInterval,
		SummaryLogInterval:           DefaultSummaryLogInterval,
		SSHServerAliveInterval:       DefaultSSHAliveInterval,
		SSHServerAliveCountMax:       DefaultSSHAliveCountMax,
		SSHConnectTimeout:            DefaultSSHConnectTimeout,
		BootQualitySamples:           DefaultBootQualitySamples,
		BootQualityMaxRetries:        DefaultBootQualityMaxRetries,
		BootQualityMaxRTT:            DefaultBootQualityMaxRTT,
		BootQualityMaxJitter:         DefaultBootQualityMaxJitter,
		BootSlowThreshold:            DefaultBootSlowThreshold,
		BootSlowMaxRTT:               DefaultBootSlowMaxRTT,
		BootSlowMaxJitter:            DefaultBootSlowMaxJitter,
		BootFastLaneMaxRTT:           DefaultBootFastLaneMaxRTT,
		BootMicroPayloadCheck:        true,
		UnderlayProbeInterval:        DefaultUnderlayProbeInterval,
		UnderlayProbeTimeout:         DefaultUnderlayProbeTimeout,
		UnderlayProbeTargets:         DefaultUnderlayProbeTargets,
		UnderlayBaselineMS:           DefaultUnderlayBaselineMS,
		HysteresisDwellWindow:        DefaultHysteresisDwellWindow,
		HysteresisRelMargin:          DefaultHysteresisRelMargin,
		HysteresisAbsMargin:          DefaultHysteresisAbsMargin,
		FastLaneMaxRatio:             DefaultFastLaneMaxRatio,
		SlowLaneEvictRatio:           DefaultSlowLaneEvictRatio,
		SlowLaneEvictWindow:          DefaultSlowLaneEvictWindow,
		SlowLaneUnderlayCeiling:      DefaultSlowLaneUnderlayCeiling,
		GitHubMaxCallsPer5Min:        DefaultGitHubMaxCallsPer5Min,
		GitHubMaxCallsPerHour:        DefaultGitHubMaxCallsPerHour,
		GitHubMinCallSpacing:         DefaultGitHubMinCallSpacing,
		GitHubRateLimitBase:          DefaultGitHubRateLimitBaseBackoff,
		GitHubRateLimitMax:           DefaultGitHubRateLimitMaxBackoff,
		GitHubWarmCacheTTL:           DefaultGitHubWarmCacheTTL,
		CodespaceCachePath:           "",
		WarmupCodespaceOnBoot:        false, // v6.3: 'gh codespace start' does not exist; serialized tunnel-1->tunnel-2 boot handles cold starts cleanly
		PreflightNetHygiene:          true,
		LogFile:                      DefaultLogFileName,
		MetricsFile:                  DefaultMetricsFileName,
	}
}

func envOrString(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envOrUint16(key string, fallback uint16) uint16 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil && n > 0 {
			return uint16(n)
		}
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envOrNonNegInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return fallback
}

func envOrFloat64(key string, fallback float64) float64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envOrDuration(key string, fallback time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

func envOrNonNegDuration(key string, fallback time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			return d
		}
	}
	return fallback
}

func envOrBool(key string, fallback bool) bool {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

// ParseConfig parses CLI flags with environment variable fallbacks.
func ParseConfig(args []string) (Config, error) {
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("NetShaper", flag.ContinueOnError)

	localPort := uint(envOrUint16("NETSHAPER_LOCAL_PORT", cfg.LocalPort))
	ghPort := uint(envOrUint16("NETSHAPER_GH_PORT", cfg.GHPort))

	fs.StringVar(&cfg.CodespaceName, "codespace", envOrString("NETSHAPER_CODESPACE", cfg.CodespaceName), "GitHub Codespace name")
	fs.UintVar(&localPort, "local-port", localPort, "Local TCP SOCKS5 proxy port exposed to applications (default 1080)")
	fs.UintVar(&ghPort, "gh-port", ghPort, "Base upstream ssh -D SOCKS5 port (default 1081; pool occupies gh-port..gh-port+pool-size-1)")
	fs.IntVar(&cfg.PoolSize, "pool-size", envOrInt("NETSHAPER_POOL_SIZE", cfg.PoolSize), "Parallel upstream gh codespace ssh tunnels (recommended 2..3, hard cap 4)")
	fs.IntVar(&cfg.MaxActiveConns, "max-conns", envOrInt("NETSHAPER_MAX_CONNS", cfg.MaxActiveConns), "Global max concurrent multiplexed SSH channels across pool (default 64; outer WAN TCP sockets = pool-size)")
	fs.IntVar(&cfg.PerTunnelMaxConns, "per-tunnel-max-conns", envOrInt("NETSHAPER_PER_TUNNEL_MAX_CONNS", cfg.PerTunnelMaxConns), "Max concurrent SSH channels per upstream ssh -D worker (default 32)")
	fs.IntVar(&cfg.MaxQueuedConns, "max-queued-conns", envOrNonNegInt("NETSHAPER_MAX_QUEUED_CONNS", cfg.MaxQueuedConns), "Bounded waiting queue depth before fast-fail rejection (default 128 for multi-origin browser bursts)")
	fs.IntVar(&cfg.CopyBufferSize, "copy-buffer-bytes", envOrInt("NETSHAPER_COPY_BUFFER_BYTES", cfg.CopyBufferSize), "Per-direction TCP relay copy buffer size in bytes (default 16384 for PMTU=576 safety)")
	fs.BoolVar(&cfg.PMTU576SafeMode, "pmtu576-safe-mode", envOrBool("NETSHAPER_PMTU576_SAFE_MODE", cfg.PMTU576SafeMode), "Adaptively step down copy buffer to 8 KiB when worker WAN remote resolves to PMTU=576 relay VIP 20.120.56.11")
	fs.IntVar(&cfg.PMTU576CopyBufSize, "pmtu576-copy-buffer-bytes", envOrInt("NETSHAPER_PMTU576_COPY_BUFFER_BYTES", cfg.PMTU576CopyBufSize), "Adaptive copy buffer size in bytes when PMTU=576 relay VIP is detected (default 8192)")
	fs.DurationVar(&cfg.SemaphoreWaitTimeout, "semaphore-wait", envOrNonNegDuration("NETSHAPER_SEMAPHORE_WAIT", cfg.SemaphoreWaitTimeout), "Max time a client connection queues for an upstream slot before rejection (default 25s, strictly > streaming-pressure-idle-timeout)")
	fs.DurationVar(&cfg.DialPaceInterval, "dial-pace-interval", envOrNonNegDuration("NETSHAPER_DIAL_PACE_INTERVAL", cfg.DialPaceInterval), "Minimum serialized spacing between consecutive upstream dials to ssh -D (default 0; loopback CHANNEL_OPEN uses existing outer TCP)")
	fs.IntVar(&cfg.SSHServerAliveInterval, "ssh-alive-interval", envOrInt("NETSHAPER_SSH_ALIVE_INTERVAL", cfg.SSHServerAliveInterval), "OpenSSH ServerAliveInterval in seconds (default 10, strictly < 15s CG-NAT idle drop)")
	fs.IntVar(&cfg.SSHServerAliveCountMax, "ssh-alive-count-max", envOrInt("NETSHAPER_SSH_ALIVE_COUNT_MAX", cfg.SSHServerAliveCountMax), "OpenSSH ServerAliveCountMax missed keepalives before disconnect (default 3)")
	fs.IntVar(&cfg.SSHConnectTimeout, "ssh-connect-timeout", envOrInt("NETSHAPER_SSH_CONNECT_TIMEOUT", cfg.SSHConnectTimeout), "OpenSSH ConnectTimeout in seconds passed to 'gh codespace ssh'")
	fs.DurationVar(&cfg.ProbeInterval, "probe-interval", envOrDuration("NETSHAPER_PROBE_INTERVAL", cfg.ProbeInterval), "Periodic E2E SOCKS5 health probe interval when healthy")
	fs.DurationVar(&cfg.DegradedProbeInterval, "degraded-probe-interval", envOrDuration("NETSHAPER_DEGRADED_PROBE_INTERVAL", cfg.DegradedProbeInterval), "Re-probe interval while tunnel is DEGRADED")
	fs.DurationVar(&cfg.ProbeTimeout, "probe-timeout", envOrDuration("NETSHAPER_PROBE_TIMEOUT", cfg.ProbeTimeout), "Single E2E SOCKS5 probe timeout")
	fs.StringVar(&cfg.ProbeTarget, "probe-target", envOrString("NETSHAPER_PROBE_TARGET", cfg.ProbeTarget), "Remote host:port for E2E SOCKS5 CONNECT readiness/health probe")
	fs.DurationVar(&cfg.BootTimeout, "boot-timeout", envOrDuration("NETSHAPER_BOOT_TIMEOUT", cfg.BootTimeout), "Max cold-boot wait budget for Codespace SSH tunnel")
	fs.DurationVar(&cfg.DialTimeout, "dial-timeout", envOrDuration("NETSHAPER_DIAL_TIMEOUT", cfg.DialTimeout), "Loopback dial timeout to upstream ssh -D port")
	fs.DurationVar(&cfg.IdleTimeout, "idle-timeout", envOrDuration("NETSHAPER_IDLE_TIMEOUT", cfg.IdleTimeout), "Normal sliding per-connection idle read/write deadline (default 60s)")
	fs.DurationVar(&cfg.PressureIdleTimeout, "pressure-idle-timeout", envOrDuration("NETSHAPER_PRESSURE_IDLE_TIMEOUT", cfg.PressureIdleTimeout), "Aggressive idle deadline for stalled handshakes / low-byte zombies under pressure (default 12s)")
	fs.DurationVar(&cfg.StreamingIdleTimeout, "streaming-idle-timeout", envOrDuration("NETSHAPER_STREAMING_IDLE_TIMEOUT", cfg.StreamingIdleTimeout), "Protected idle timeout for established streaming connections (>128B down, default 180s)")
	fs.DurationVar(&cfg.StreamingPressureIdleTimeout, "streaming-pressure-idle-timeout", envOrDuration("NETSHAPER_STREAMING_PRESSURE_IDLE_TIMEOUT", cfg.StreamingPressureIdleTimeout), "Pressure idle timeout for established streaming connections (>128B down, default 20s < 25s semaphore-wait)")
	fs.IntVar(&cfg.StalledHandshakeMaxDownBytes, "stalled-handshake-max-down-bytes", envOrNonNegInt("NETSHAPER_STALLED_HANDSHAKE_MAX_DOWN_BYTES", cfg.StalledHandshakeMaxDownBytes), "Downstream byte ceiling classifying stalled handshakes for aggressive reaping (default 128)")
	fs.IntVar(&cfg.PressureThresholdPct, "pressure-threshold-pct", envOrInt("NETSHAPER_PRESSURE_THRESHOLD_PCT", cfg.PressureThresholdPct), "Active slot percentage threshold that activates pressure idle reaping (default 75)")
	fs.DurationVar(&cfg.HalfCloseDrainTimeout, "half-close-timeout", envOrDuration("NETSHAPER_HALF_CLOSE_TIMEOUT", cfg.HalfCloseDrainTimeout), "Progress-resetting reverse-stream drain watchdog after TCP half-close (FIN)")
	fs.DurationVar(&cfg.TCPKeepAlivePeriod, "tcp-keepalive", envOrDuration("NETSHAPER_TCP_KEEPALIVE", cfg.TCPKeepAlivePeriod), "TCP keepalive period (default 8s, strictly below 15s CG-NAT silent idle drop)")
	fs.DurationVar(&cfg.StopTimeout, "stop-timeout", envOrDuration("NETSHAPER_STOP_TIMEOUT", cfg.StopTimeout), "Bounded timeout for 'gh codespace stop' on shutdown")
	fs.BoolVar(&cfg.StopOnExit, "stop-on-exit", envOrBool("NETSHAPER_STOP_ON_EXIT", cfg.StopOnExit), "Run 'gh codespace stop' on program shutdown (skipped automatically if no tunnel ever reached HEALTHY)")
	fs.DurationVar(&cfg.DegradedRTTThreshold, "degraded-rtt", envOrDuration("NETSHAPER_DEGRADED_RTT", cfg.DegradedRTTThreshold), "SOCKS5 probe RTT above which tunnel is marked DEGRADED")
	fs.IntVar(&cfg.BreakerThreshold, "breaker-threshold", envOrInt("NETSHAPER_BREAKER_THRESHOLD", cfg.BreakerThreshold), "Consecutive failed E2E probes required before tripping zombie circuit breaker")
	fs.DurationVar(&cfg.BreakerMinWindow, "breaker-min-window", envOrDuration("NETSHAPER_BREAKER_MIN_WINDOW", cfg.BreakerMinWindow), "Minimum sustained outage window without WAN bytes before tripping breaker")
	fs.IntVar(&cfg.LoopbackRefusedThreshold, "loopback-refused-threshold", envOrInt("NETSHAPER_LOOPBACK_REFUSED_THRESHOLD", cfg.LoopbackRefusedThreshold), "Consecutive loopback ECONNREFUSED dials that fast-fail immediately")
	fs.IntVar(&cfg.BootQualitySamples, "boot-quality-samples", envOrNonNegInt("NETSHAPER_BOOT_QUALITY_SAMPLES", cfg.BootQualitySamples), "Pre-traffic E2E SOCKS5 RTT qualification samples before accepting lane (<=1 disables)")
	fs.IntVar(&cfg.BootQualityMaxRetries, "boot-quality-max-retries", envOrNonNegInt("NETSHAPER_BOOT_QUALITY_MAX_RETRIES", cfg.BootQualityMaxRetries), "Max pre-traffic 5-tuple re-rolls if initial tunnel lands in slow lane")
	fs.DurationVar(&cfg.BootQualityMaxRTT, "boot-quality-max-rtt", envOrDuration("NETSHAPER_BOOT_QUALITY_MAX_RTT", cfg.BootQualityMaxRTT), "Max median idle RTT accepted by pre-traffic boot quality gate")
	fs.DurationVar(&cfg.BootQualityMaxJitter, "boot-quality-max-jitter", envOrDuration("NETSHAPER_BOOT_QUALITY_MAX_JITTER", cfg.BootQualityMaxJitter), "Max idle RTT jitter accepted by pre-traffic boot quality gate")
	fs.DurationVar(&cfg.BootSlowThreshold, "boot-slow-threshold", envOrDuration("NETSHAPER_BOOT_SLOW_THRESHOLD", cfg.BootSlowThreshold), "Boot duration above which stricter idle RTT/jitter checks apply")
	fs.DurationVar(&cfg.BootSlowMaxRTT, "boot-slow-max-rtt", envOrDuration("NETSHAPER_BOOT_SLOW_MAX_RTT", cfg.BootSlowMaxRTT), "Max median idle RTT accepted after a slow boot")
	fs.DurationVar(&cfg.BootSlowMaxJitter, "boot-slow-max-jitter", envOrDuration("NETSHAPER_BOOT_SLOW_MAX_JITTER", cfg.BootSlowMaxJitter), "Max idle jitter accepted after a slow boot")
	fs.DurationVar(&cfg.BootFastLaneMaxRTT, "boot-fast-lane-max-rtt", envOrDuration("NETSHAPER_BOOT_FAST_LANE_MAX_RTT", cfg.BootFastLaneMaxRTT), "Hard upper bound distinguishing a fast relay lane (~310ms) from a throttled lane (~2.5-4.3s)")
	fs.BoolVar(&cfg.BootMicroPayloadCheck, "boot-micro-payload-check", envOrBool("NETSHAPER_BOOT_MICRO_PAYLOAD_CHECK", cfg.BootMicroPayloadCheck), "Enable Stage 2 micro-payload bidirectional probe during boot qualification")
	fs.DurationVar(&cfg.UnderlayProbeInterval, "underlay-probe-interval", envOrDuration("NETSHAPER_UNDERLAY_PROBE_INTERVAL", cfg.UnderlayProbeInterval), "Direct underlay baseline B_raw(t) probe cadence (default 35s, bypasses SSH & GitHub)")
	fs.DurationVar(&cfg.UnderlayProbeTimeout, "underlay-probe-timeout", envOrDuration("NETSHAPER_UNDERLAY_PROBE_TIMEOUT", cfg.UnderlayProbeTimeout), "Single direct underlay baseline probe timeout (default 5s)")
	fs.StringVar(&cfg.UnderlayProbeTargets, "underlay-probe-targets", envOrString("NETSHAPER_UNDERLAY_PROBE_TARGETS", cfg.UnderlayProbeTargets), "Comma-separated direct TLS:443 underlay baseline targets (never github.com)")
	fs.DurationVar(&cfg.HysteresisDwellWindow, "hysteresis-dwell-window", envOrDuration("NETSHAPER_HYSTERESIS_DWELL_WINDOW", cfg.HysteresisDwellWindow), "Continuous dwell duration before promoting Primary or switching routing mode (default 25s)")
	fs.Float64Var(&cfg.HysteresisRelMargin, "hysteresis-rel-margin", envOrFloat64("NETSHAPER_HYSTERESIS_REL_MARGIN", cfg.HysteresisRelMargin), "Minimum relative score improvement required to promote Primary (default 0.30)")
	fs.DurationVar(&cfg.HysteresisAbsMargin, "hysteresis-abs-margin", envOrDuration("NETSHAPER_HYSTERESIS_ABS_MARGIN", cfg.HysteresisAbsMargin), "Minimum absolute RTT advantage required to promote Primary (default 100ms)")
	fs.Float64Var(&cfg.FastLaneMaxRatio, "fast-lane-max-ratio", envOrFloat64("NETSHAPER_FAST_LANE_MAX_RATIO", cfg.FastLaneMaxRatio), "Max relative overhead rho_i = RTT_i / B_raw for balanced multi-active sharing (default 2.2)")
	fs.Float64Var(&cfg.SlowLaneEvictRatio, "slow-lane-evict-ratio", envOrFloat64("NETSHAPER_SLOW_LANE_EVICT_RATIO", cfg.SlowLaneEvictRatio), "Relative overhead rho_i threshold for chronic slow-lane diversion & eviction (default 3.5)")
	fs.DurationVar(&cfg.SlowLaneEvictWindow, "slow-lane-evict-window", envOrDuration("NETSHAPER_SLOW_LANE_EVICT_WINDOW", cfg.SlowLaneEvictWindow), "Continuous slow-lane duration before diverting traffic and rerolling worker (default 30s)")
	fs.DurationVar(&cfg.SlowLaneUnderlayCeiling, "slow-lane-underlay-ceiling", envOrDuration("NETSHAPER_SLOW_LANE_UNDERLAY_CEILING", cfg.SlowLaneUnderlayCeiling), "Skip slow-lane eviction when direct underlay baseline B_raw exceeds this ceiling (default 800ms)")
	fs.IntVar(&cfg.GitHubMaxCallsPer5Min, "gh-max-calls-5m", envOrInt("NETSHAPER_GH_MAX_CALLS_5M", cfg.GitHubMaxCallsPer5Min), "Max gh codespace invocations allowed in any sliding 5-minute window")
	fs.IntVar(&cfg.GitHubMaxCallsPerHour, "gh-max-calls-hour", envOrInt("NETSHAPER_GH_MAX_CALLS_HOUR", cfg.GitHubMaxCallsPerHour), "Max gh codespace invocations allowed in any sliding 60-minute window")
	fs.DurationVar(&cfg.GitHubMinCallSpacing, "gh-min-call-spacing", envOrNonNegDuration("NETSHAPER_GH_MIN_CALL_SPACING", cfg.GitHubMinCallSpacing), "Minimum inter-call spacing between consecutive gh CLI calls for WAF/bot safety (default 2s)")
	fs.StringVar(&cfg.CodespaceCachePath, "codespace-cache-file", envOrString("NETSHAPER_CODESPACE_CACHE_FILE", cfg.CodespaceCachePath), "Persistent JSON cache file path for warm Codespace VM state")
	fs.BoolVar(&cfg.WarmupCodespaceOnBoot, "warmup-codespace-on-boot", envOrBool("NETSHAPER_WARMUP_CODESPACE_ON_BOOT", cfg.WarmupCodespaceOnBoot), "Deprecated no-op flag retained for CLI compatibility (serialized tunnel-1->tunnel-2 boot is always active)")
	fs.BoolVar(&cfg.PreflightNetHygiene, "preflight-net-hygiene", envOrBool("NETSHAPER_PREFLIGHT_NET_HYGIENE", cfg.PreflightNetHygiene), "Run read-only Windows Firewall & TCP stack diagnostic preflight on startup")
	fs.StringVar(&cfg.LogFile, "log-file", envOrString("NETSHAPER_LOG_FILE", cfg.LogFile), "Append-only persistent supervisor telemetry log file path")
	fs.StringVar(&cfg.MetricsFile, "metrics-file", envOrString("NETSHAPER_METRICS_FILE", cfg.MetricsFile), "Orthogonal structured NDJSON data-plane/pool metrics stream path")
	fs.BoolVar(&cfg.Headless, "headless", envOrBool("NETSHAPER_HEADLESS", false), "Run in legacy headless CLI mode instead of the native Windows 11 UI")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if strings.TrimSpace(os.Getenv("NETSHAPER_CODESPACE")) != "" {
		cfg.CodespaceExplicit = true
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "codespace" {
			cfg.CodespaceExplicit = true
		}
	})

	if localPort == 0 || localPort > 65535 {
		return cfg, fmt.Errorf("invalid local-port: %d", localPort)
	}
	if ghPort == 0 || ghPort > 65535 {
		return cfg, fmt.Errorf("invalid gh-port: %d", ghPort)
	}
	cfg.LocalPort = uint16(localPort)
	cfg.GHPort = uint16(ghPort)

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// PoolPorts returns the exact slice of upstream localhost ports owned by the tunnel pool.
func (c Config) PoolPorts() []uint16 {
	n := c.PoolSize
	if n < 1 {
		n = 1
	}
	ports := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		ports = append(ports, c.GHPort+uint16(i))
	}
	return ports
}

// ParsedUnderlayTargets returns trimmed non-empty direct underlay probe targets.
func (c Config) ParsedUnderlayTargets() []string {
	raw := strings.TrimSpace(c.UnderlayProbeTargets)
	if raw == "" {
		raw = DefaultUnderlayProbeTargets
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Validate enforces structural and empirical safety invariants on Config.
func (c Config) Validate() error {
	if strings.TrimSpace(c.CodespaceName) == "" {
		return errors.New("codespace name must not be empty")
	}
	if c.LocalPort == 0 || c.GHPort == 0 {
		return errors.New("ports must be in 1..65535")
	}
	if c.PoolSize < 1 || c.PoolSize > DefaultMaxPoolSize {
		return fmt.Errorf("pool-size must be in 1..%d, got %d", DefaultMaxPoolSize, c.PoolSize)
	}
	if int(c.GHPort)+c.PoolSize-1 > 65535 {
		return fmt.Errorf("gh-port (%d) + pool-size (%d) exceeds 65535", c.GHPort, c.PoolSize)
	}
	for _, p := range c.PoolPorts() {
		if p == c.LocalPort {
			return fmt.Errorf("local-port (%d) overlaps with upstream pool port (%d)", c.LocalPort, p)
		}
		if p == 10808 {
			return fmt.Errorf("upstream pool port (%d) must not overlap Xray inbound port 10808", p)
		}
	}
	if c.LocalPort == 10808 {
		return errors.New("local-port must not overlap Xray inbound port 10808")
	}
	if c.MaxActiveConns < 1 {
		return fmt.Errorf("max-conns must be >= 1, got %d", c.MaxActiveConns)
	}
	if c.PerTunnelMaxConns < 1 {
		return fmt.Errorf("per-tunnel-max-conns must be >= 1, got %d", c.PerTunnelMaxConns)
	}
	if c.MaxQueuedConns < 0 {
		return fmt.Errorf("max-queued-conns must be >= 0, got %d", c.MaxQueuedConns)
	}
	if c.CopyBufferSize < 4096 || c.CopyBufferSize > 256*1024 {
		return fmt.Errorf("copy-buffer-bytes must be in [4096, 262144], got %d", c.CopyBufferSize)
	}
	if c.PMTU576SafeMode && (c.PMTU576CopyBufSize < 4096 || c.PMTU576CopyBufSize > c.CopyBufferSize) {
		return fmt.Errorf("pmtu576-copy-buffer-bytes (%d) must be in [4096, copy-buffer-bytes=%d]", c.PMTU576CopyBufSize, c.CopyBufferSize)
	}
	if c.DialTimeout <= 0 || c.IdleTimeout <= 0 || c.HalfCloseDrainTimeout <= 0 {
		return errors.New("timeouts must be positive")
	}
	if c.PressureIdleTimeout <= 0 || c.PressureIdleTimeout > c.IdleTimeout {
		return fmt.Errorf("pressure-idle-timeout (%s) must be in (0, idle-timeout=%s]", c.PressureIdleTimeout, c.IdleTimeout)
	}
	if c.StreamingIdleTimeout < 0 || c.StreamingPressureIdleTimeout < 0 {
		return errors.New("streaming idle timeouts must be >= 0")
	}
	if c.StalledHandshakeMaxDownBytes < 0 {
		return errors.New("stalled-handshake-max-down-bytes must be >= 0")
	}
	if c.PressureThresholdPct < 10 || c.PressureThresholdPct > 100 {
		return fmt.Errorf("pressure-threshold-pct must be in [10, 100], got %d", c.PressureThresholdPct)
	}
	if c.TCPKeepAlivePeriod <= 0 {
		return errors.New("tcp-keepalive must be positive")
	}
	if c.SemaphoreWaitTimeout < 0 {
		return errors.New("semaphore wait timeout must be >= 0")
	}
	if c.DialPaceInterval < 0 {
		return errors.New("dial pace interval must be >= 0")
	}
	if c.SSHServerAliveInterval < 0 {
		return fmt.Errorf("ssh-alive-interval must be >= 0 (0 = default %ds), got %d", DefaultSSHAliveInterval, c.SSHServerAliveInterval)
	}
	if c.SSHServerAliveCountMax < 0 {
		return fmt.Errorf("ssh-alive-count-max must be >= 0 (0 = default %d), got %d", DefaultSSHAliveCountMax, c.SSHServerAliveCountMax)
	}
	if c.SSHConnectTimeout < 0 {
		return fmt.Errorf("ssh connect timeout must be >= 0 (0 = default %ds), got %d", DefaultSSHConnectTimeout, c.SSHConnectTimeout)
	}
	if c.BreakerThreshold < 1 {
		return errors.New("breaker threshold must be >= 1")
	}
	if c.BreakerMinWindow < 0 {
		return errors.New("breaker min window must be >= 0")
	}
	if c.LoopbackRefusedThreshold < 1 {
		return errors.New("loopback refused threshold must be >= 1")
	}
	if c.BootQualityMaxRetries < 0 {
		return errors.New("boot quality max retries must be >= 0")
	}
	if c.GitHubMaxCallsPer5Min < 1 || c.GitHubMaxCallsPerHour < c.GitHubMaxCallsPer5Min {
		return fmt.Errorf("invalid GitHub API budget: 5m=%d hour=%d", c.GitHubMaxCallsPer5Min, c.GitHubMaxCallsPerHour)
	}
	if c.GitHubMinCallSpacing < 0 {
		return errors.New("gh-min-call-spacing must be >= 0")
	}
	if c.HysteresisRelMargin < 0 || c.HysteresisRelMargin >= 1.0 {
		return fmt.Errorf("hysteresis-rel-margin must be in [0, 1), got %.2f", c.HysteresisRelMargin)
	}
	if c.FastLaneMaxRatio < 1.0 || c.SlowLaneEvictRatio <= c.FastLaneMaxRatio {
		return fmt.Errorf("invalid lane ratios: fast=%.2f evict=%.2f", c.FastLaneMaxRatio, c.SlowLaneEvictRatio)
	}
	for _, t := range c.ParsedUnderlayTargets() {
		if IsGitHubHost(t) {
			return fmt.Errorf("underlay-probe-targets must NEVER contain GitHub host %q", t)
		}
	}
	return nil
}

// LocalAddr returns host:port for the client-facing listener.
func (c Config) LocalAddr() string {
	return fmt.Sprintf("%s:%d", c.LocalHost, c.LocalPort)
}

// GHAddr returns host:port for the primary upstream ssh -D SOCKS5 endpoint.
func (c Config) GHAddr() string {
	return fmt.Sprintf("%s:%d", c.GHHost, c.GHPort)
}

// GHAddrForPort returns host:port for a specific upstream worker port.
func (c Config) GHAddrForPort(port uint16) string {
	host := strings.TrimSpace(c.GHHost)
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// ResolveLogPath resolves a relative log or metrics file path next to the running executable.
func ResolveLogPath(logFile string) string {
	if filepath.IsAbs(logFile) {
		return logFile
	}
	exe, err := os.Executable()
	if err != nil {
		return logFile
	}
	return filepath.Join(filepath.Dir(exe), logFile)
}
