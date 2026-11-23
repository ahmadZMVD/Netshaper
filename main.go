package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg, err := ParseConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("[Fatal] Invalid configuration: %v", err)
	}
	if cfg.CodespaceCachePath == "" {
		cfg.CodespaceCachePath = DefaultCodespaceStateCachePath()
	}

	// Default to native Windows 11 UI unless --headless is explicitly requested.
	// WatchStdinForQuit is NEVER started in GUI mode where os.Stdin is NUL/EOF under -H=windowsgui.
	if !cfg.Headless {
		if err := RunPlatformUI(cfg); err != nil {
			log.Fatalf("[Fatal] UI exited with error: %v", err)
		}
		// Guaranteed full OS process termination after Win32 message loop, GDI+ shutdown,
		// JobObject child teardown, and single-instance mutex release have all completed.
		os.Exit(0)
	}

	runHeadlessCLI(cfg)
}

func runHeadlessCLI(cfg Config) {
	if cfg.PoolSize > DefaultRecommendedMaxPoolSize {
		log.Printf("[Warn] PoolSize=%d exceeds recommended WAN/GitHub WAF sweet spot (2..%d); ensure GitHub API budget (%d/5m, %d/hr) is respected.",
			cfg.PoolSize, DefaultRecommendedMaxPoolSize, cfg.GitHubMaxCallsPer5Min, cfg.GitHubMaxCallsPerHour)
	}

	logPath := ResolveLogPath(cfg.LogFile)
	eventLogger, err := NewEventLogger(logPath)
	if err != nil {
		log.Fatalf("[Fatal] Unable to open persistent log %q: %v", logPath, err)
	}

	var metricsEmitter *MetricsEmitter
	if cfg.MetricsFile != "" {
		metricsPath := ResolveLogPath(cfg.MetricsFile)
		metricsEmitter, err = NewMetricsEmitter(metricsPath, eventLogger.SessionID())
		if err != nil {
			log.Printf("[Warn] Unable to open orthogonal metrics stream %q: %v (continuing without NDJSON metrics)", metricsPath, err)
		}
	}

	sup := NewSupervisor(cfg, eventLogger, SupervisorDeps{
		StderrEcho: os.Stderr,
		Metrics:    metricsEmitter,
		OnStateChange: func(from, to SupervisorState) {
			log.Printf("[Supervisor] %s -> %s", from, to)
			if to == StateHealthy && from != StateDegraded {
				log.Printf("[System] NetShaper v7.0 HEALTHY on %s | Pool=%d workers (ports %v, <=%d/worker, <=%d global SSH channels, queue=%d/%s, pace=%s) | Idle=%s (Stalled=%s, Stream=%s/%s) | KeepAlive=%s | Hysteresis=%s | APIGuard=%d/5m,%d/hr (spacing=%s)",
					cfg.LocalAddr(), cfg.PoolSize, cfg.PoolPorts(), cfg.PerTunnelMaxConns, cfg.MaxActiveConns,
					cfg.MaxQueuedConns, cfg.SemaphoreWaitTimeout, cfg.DialPaceInterval,
					cfg.IdleTimeout, cfg.PressureIdleTimeout, cfg.StreamingIdleTimeout, cfg.StreamingPressureIdleTimeout,
					cfg.TCPKeepAlivePeriod, cfg.HysteresisDwellWindow,
					cfg.GitHubMaxCallsPer5Min, cfg.GitHubMaxCallsPerHour, cfg.GitHubMinCallSpacing)
				log.Println("==================================================")
				log.Println("  PRESS 'q' OR 'Ctrl+C' FOR SAFE BOUNDED SHUTDOWN")
				log.Println("==================================================")
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\n[System] Received signal %v. Initiating ordered bounded shutdown...\n", sig)
		sup.RequestShutdown(fmt.Sprintf("signal:%v", sig))
		cancel()
	}()

	// WatchStdinForQuit runs ONLY in --headless CLI mode.
	go WatchStdinForQuit(os.Stdin, func() {
		fmt.Println("\n[System] 'q' pressed. Initiating ordered bounded shutdown...")
		sup.RequestShutdown("stdin_q")
		cancel()
	})

	log.Printf("[System] NetShaper v7.0 headless mode starting | Codespace=%s | Local=%s | Pool=%d (%v) | GlobalCap=%d | PerTunnelCap=%d | DialPace=%s | Queue=%d/%s | Idle=%s/%s Stream=%s/%s | KA=%s | SSHAlive=%dsx%d | Buf=%dB (PMTU576Safe=%v:%dB) | Underlay=%s | Hysteresis=%s | SlowEvict=%.1fx/%s | APIGuard=%d/5m,%d/hr (%s) | Log=%s | Metrics=%s",
		cfg.CodespaceName, cfg.LocalAddr(), cfg.PoolSize, cfg.PoolPorts(),
		cfg.MaxActiveConns, cfg.PerTunnelMaxConns, cfg.DialPaceInterval, cfg.MaxQueuedConns, cfg.SemaphoreWaitTimeout,
		cfg.IdleTimeout, cfg.PressureIdleTimeout, cfg.StreamingIdleTimeout, cfg.StreamingPressureIdleTimeout,
		cfg.TCPKeepAlivePeriod, cfg.SSHServerAliveInterval, cfg.SSHServerAliveCountMax,
		cfg.CopyBufferSize, cfg.PMTU576SafeMode, cfg.PMTU576CopyBufSize,
		cfg.UnderlayProbeInterval, cfg.HysteresisDwellWindow, cfg.SlowLaneEvictRatio, cfg.SlowLaneEvictWindow,
		cfg.GitHubMaxCallsPer5Min, cfg.GitHubMaxCallsPerHour, cfg.GitHubMinCallSpacing,
		logPath, cfg.MetricsFile)

	if err := sup.Run(ctx); err != nil {
		log.Printf("[Error] Supervisor exited with error: %v", err)
		os.Exit(1)
	}
	log.Println("[System] NetShaper v7.0 shutdown complete.")
}
