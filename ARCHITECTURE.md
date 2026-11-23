# NetShaper Architecture

This document details the internal state machines, routing mathematics, data-plane concurrency controls, Win32/GDI+ UI isolation model, and API rate-limiting safeguards in NetShaper v7.0 (core engine v6.4).

---

## 1. Subsystem Topology & State Machines

NetShaper separates lifecycle orchestration, tunnel supervision, multiplexed TCP relaying, and UI presentation into isolated components:

```text
+-------------------------------------------------------------------+
| UI Layer (ui_windows.go / ui_unix.go) - OS Thread T0 (Win32)      |
|  - Wait-free reads only (AtomicTelemetry / CachedSnapshot)        |
|  - 250ms coalesced repaint timer; DIB freed on hideToTray()       |
+-------------------------------+-----------------------------------+
                                | Commands / Atomic Snapshot Pointer
                                v
+-------------------------------------------------------------------+
| Bridge (ui_bridge.go) - SessionController                         |
|  - Serialized lifecycleWorker FSM (IDLE/STARTING/RUNNING/STOPPING)|
|  - 1Hz snapshotPublisher; 500-line O(1) TerminalRingBuffer        |
+-------------------------------+-----------------------------------+
                                |
                                v
+-------------------------------------------------------------------+
| Supervisor (supervisor.go)                                        |
|  - ProcessJob (KILL_ON_JOB_CLOSE), PortInspector, NetHygiene      |
|  - GitHubGuard (WAF budget), UnderlayProbeLoop (B_raw(t))         |
+---------------+-----------------------------------+---------------+
                |                                   |
                v                                   v
+-------------------------------+   +-------------------------------+
| ProxyServer (proxy.go)        |   | TunnelPool (tunnel_pool.go)   |
|  - 127.0.0.1:1080 listener    |-->|  - PoolSize = 2 workers       |
|  - 64 global / 128 wait queue |   |  - 127.0.0.1:1081..1082       |
|  - Two-tier pressure reaper   |   |  - EWMA RTT/jitter + hysteresis|
+-------------------------------+   +-------------------------------+
```

### Worker & Supervisor Lifecycle States

Each `TunnelInstance` (and the aggregate `Supervisor`) progresses through strict operational states:

- `BOOTING`: Spawns `gh codespace ssh -D 127.0.0.1:<port>` inside the OS `ProcessJob`. Boots are serialized (worker 0 completes boot before worker 1 starts) to prevent concurrent VM-start HTTP 400 races on cold Codespaces.
- `PROBING`: Runs the two-stage pre-traffic quality gate:
  1. Stage 1: `BootQualitySamples = 3` E2E SOCKS5 CONNECT RTT samples to `1.1.1.1:443`.
  2. Stage 2: Bidirectional micro-payload probe (`ProbeSOCKS5MicroPayload`) verifying actual payload transit rather than just TCP handshake acceptance.
  Workers that fail the lane gate are terminated and re-rolled (up to `BootQualityMaxRetries = 2`, gated by `GitHubGuard`).
- `HEALTHY`: Active in the pool. Subject to periodic E2E health probes (`25s` cadence) and passive WAN byte tracking.
- `DEGRADED`: Entered when E2E probe RTT exceeds `DegradedRTTThreshold` (`4000ms`) or transient errors occur; probe cadence tightens to `8s`.
- `RECONNECTING`: Entered when the zombie circuit breaker trips (`5` consecutive failed probes across at least `45s` with zero WAN bytes), on `3` consecutive loopback `ECONNREFUSED` dials, or upon chronic slow-lane eviction.
- `SHUTDOWN`: Terminal state. Stops accepting new connections, closes active relays, terminates the `ProcessJob`, and executes a bounded `gh codespace stop` if and only if at least one worker reached `HEALTHY` during the session.

### SessionController Serialized FSM (`ui_bridge.go`)

UI actions (`Start`, `Stop`, `ReAuth`, `Shutdown`) enqueue onto a serialized `lifecycleWorker` goroutine so rapid button clicks or tray commands cannot spawn overlapping supervisors:

`IDLE -> STARTING -> RUNNING -> STOPPING -> IDLE`

`ShutdownAndWait(timeout)` cancels the supervisor context, closes the `ProcessJob` immediately on `ctx.Done()`, and waits up to the bounded timeout before returning to the Win32 teardown sequence.

---

## 2. Baseline-Normalized Quality Scoring & Schmitt-Trigger Hysteresis

Fixed RTT thresholds misclassify healthy tunnels during temporary ISP-wide congestion. NetShaper decouples underlay latency from SSH/relay lane quality using an independent direct underlay probe loop.

### Direct Underlay Baseline `B_raw(t)`

Every `UnderlayProbeInterval` (`35s`), the supervisor measures 1-RTT direct TLS ClientHello->ServerHello latency against non-GitHub endpoints (`1.1.1.1:443,20.120.56.11:443`, unimodal first, strictly validated by `IsGitHubHost()` so `github.com` and `api.github.com` are never probed), with `2.0x` upward outlier winsorization to yield `B_raw(t)`.

### Worker Relative Overhead & Score

For each healthy worker `i`, let `RTT_i` be its EWMA probe RTT and `J_i` its EWMA jitter. Its relative overhead over the underlay is:

```text
rho_i = RTT_i / max(B_raw(t), 50ms)
```

Worker selection uses a baseline-normalized quality score combining `RTT_i`, jitter penalty, and active slot load.

### Three-Layer Schmitt-Trigger Hysteresis (`TunnelPool.EvaluateRoutingMode`)

To prevent route flapping between workers, `TunnelPool` maintains three routing modes:

1. `primary_preferred`: Default when one worker is materially faster. Traffic prefers the primary worker until its slot cap is reached, then spills over to the secondary.
2. `balanced`: Entered when both workers satisfy `rho_i <= FastLaneMaxRatio (2.2)` and remain close in latency, distributing new streams via Power-of-Two-Choices (P2C) to minimize head-of-line blocking.
3. `single_primary`: Entered when only one worker is healthy or when the secondary worker is flagged as a chronic slow lane.

Mode transitions and primary promotions require **all three** guard conditions simultaneously:

- **Dwell window**: The candidate advantage must hold continuously for `HysteresisDwellWindow` (`25s`).
- **Relative margin**: Candidate score must beat the current primary by at least `HysteresisRelMargin` (`30%`).
- **Absolute margin**: Candidate RTT must beat the current primary by at least `HysteresisAbsMargin` (`100ms`).

### Chronic Slow-Lane Diversion & Guard-Gated Eviction

If a `TunnelHealthy` or `TunnelDegraded` worker sustains `rho_i > SlowLaneEvictRatio (3.5)` continuously for `SlowLaneEvictWindow (30s)` **and** the direct underlay itself is not congested (`B_raw(t) <= SlowLaneUnderlayCeiling (800ms)`), the pool diverts new traffic away from that worker immediately. Re-rolling (evicting) the worker checks `GitHubGuard.CanAllowNonConsuming()` first; if the API guard is locked out or near budget exhaustion, eviction is deferred (`WORKER_SLOW_LANE_EVICT_DEFERRED`) rather than risking a WAF ban.

---

## 3. Multiplexed SOCKS5 Data Plane & Concurrency Control

### Outer Socket Economy vs. Inner SSH Channels

Each `gh codespace ssh -D` worker establishes **one** outer WAN TCP connection to the Codespace relay VIP and multiplexes SOCKS5 streams inside it as RFC 4254 `direct-tcpip` channels:

- `PoolSize = 2`: Only 2 outer WAN TCP sockets are maintained.
- `MaxActiveConns = 64` (`PerTunnelMaxConns = 32`): Absorbs concurrent HTTP/2, SSE, and WebSocket sessions from multi-origin web apps without multiplying outer WAN sockets.
- `MaxQueuedConns = 128`: Bounded burst queue for sudden page-load spikes; requests beyond 128 fail fast instead of allocating unbounded goroutines.
- `DialPaceInterval = 0`: Because loopback `ssh -D` channel opens emit zero outer WAN TCP `SYN` packets, loopback dials are not artificially serialized by default (while `pacedDialUpstream` with `dialLaunchMu` remains active whenever `DialPaceInterval > 0`).

### Two-Tier Streaming-Aware Pressure Reaper & Deadlock-Freedom

Under load (`activeSlots >= 75%` or `queuedConns > 0`), `pressureReapLoop` classifies each active relay by its cumulative downstream bytes, reaps all stalled handshakes first, and reaps established streams strictly **oldest-idle first** only up to the bounded deficit needed to drop below the `65%` low-water mark (`41/64`) plus queued demand:

| Stream Class | Criteria | Normal Idle Timeout | Pressure Idle Timeout |
| :--- | :--- | :--- | :--- |
| Stalled handshake / zombie | `downBytes <= 128B` | `60s` (`IdleTimeout`) | `12s` (`PressureIdleTimeout`) |
| Established / streaming | `downBytes > 128B` | `180s` (`StreamingIdleTimeout`) | `20s` (`StreamingPressureIdleTimeout`) |

**Mathematical deadlock-freedom invariant**:

```text
StreamingPressureIdleTimeout (20s) < SemaphoreWaitTimeout (25s)
```

Even in a worst-case 64/64 saturation event filled entirely with idle established streams, the pressure reaper is guaranteed to reclaim slots within `20s` (5 seconds before queued waiters expire at `25s`), preventing queue-timeout cascade deadlocks.

### CG-NAT Keepalive & Adaptive PMTU=576 Framing

- **CG-NAT survival**: Both `TCPKeepAlivePeriod = 8s` and OpenSSH `ServerAliveInterval = 10s` (`ServerAliveCountMax = 3`, 30s dead-tunnel detection) sit strictly below common 15-second aggressive CG-NAT silent idle drop thresholds.
- **Adaptive copy buffers**: `ProxyServer` maintains pooled `16 KiB` (`copyBufPool`) and `8 KiB` (`copyBufPool8K`) buffers. When `LookupProcessTreeWANRemotes` detects that a worker's outer TCP socket terminates on a PMTU=576 relay VIP (`20.120.56.11`), `UpstreamLease.PMTU576Safe` activates the 8 KiB buffer path automatically.
- **Bounded half-close drain**: After a TCP `FIN`, `HalfCloseDrainTimeout = 15s` uses a progress-resetting watchdog so active reverse downloads finish while wedged half-closed peers cannot pin slots indefinitely.

---

## 4. Win32 Thread Affinity, Zero-Lock UI Isolation & ABI Safety

### Thread Affinity (`T0`) & Window Lifecycle

`RunPlatformUI` pins the calling goroutine to a single OS thread via `runtime.LockOSThread()`, initializes `gdiplus.dll` (`GdiplusStartup`), acquires the single-instance mutex (`Local\NetShaperV7_SingleInstance`), registers the window class, and drives the Win32 message loop:

- **Second-instance launch**: Detects the existing mutex, broadcasts `WM_APP_SHOW_EXISTING` to restore the active window, and exits immediately.
- **Minimize (`WM_SYSCOMMAND` -> `SC_MINIMIZE`)**: Calls `hideToTray()`, hiding the window, stopping the `250ms` UI timer, and destroying the 32bpp DIB backbuffer so background memory and CPU remain minimal.
- **Close (`WM_CLOSE`) & Tray Exit**: Calls `requestFullExit()` (never `hideToTray()`), which immediately hides the window (`SW_HIDE`), kills the repaint timer, deletes the tray icon (`NIM_DELETE`), blocks on `SessionController.ShutdownAndWait`, calls `DestroyWindow`, detaches `HFONT` from child `EDIT` controls (`WM_SETFONT(0, 0)`) and destroys child controls before `theme.destroy()`, posts `PostQuitMessage(0)`, unregisters the window class, calls `GdiplusShutdown`, closes the mutex handle, and returns to `main.go` for `os.Exit(0)`.
- **Explorer restart recovery**: Registers `"TaskbarCreated"` so the tray icon is automatically re-added if `explorer.exe` restarts.

### Zero-Lock Data-Plane Isolation

The UI and bridge layers are statically audited (`verify_static.py`) to forbid any locking calls into `ProxyServer`, `TunnelPool`, or `GitHubGuard`:

- `ProxyServer.AtomicTelemetry()` reads lock-free atomic counters.
- `TunnelPool.CachedSnapshot()` and `GitHubGuard.CachedSnapshot()` load immutable `atomic.Pointer` snapshots published on state transitions.
- `EventLogger.SetObserver()` appends formatted log lines into `TerminalRingBuffer` (500-line `O(1)` circular buffer) without invoking `PostMessageW`. The UI polls a dirty mask on its `250ms` timer only while visible.

### Win64 AMD64 ABI & GDI Handle Discipline

- **No float32 register ABI mismatches**: On Windows AMD64, float arguments in parameter positions 1-4 must be passed in XMM registers, which Go's `syscall.LazyProc.Call` does not do. `ui_windows.go` avoids `GdipCreateFont` and uses `GdipCreateFontFromLogfontW` (pure pointer/integer arguments) for all GDI+ font creation.
- **No `unsafe.Pointer(uintptr)` casts**: All Win32 callbacks and pointer conversions pass `go vet -unsafeptr` cleanly, and deferred syscalls wrap pointer dereferences in closures.
- **No `AllocConsole`**: Interactive `gh auth login` runs in an isolated child console via `CREATE_NEW_CONSOLE` (`0x00000010`), so closing the auth console cannot terminate the GUI process. Silent background `gh` and `netsh` calls use `CREATE_NO_WINDOW` (`0x08000000`).
- **Deterministic GDI/USER handle teardown**: Every DPI switch (`WM_DPICHANGED`) and window destruction detaches the native `EDIT` control font (`WM_SETFONT(0, 0)`) before destroying the old `HFONT`. `UT-40` verifies `GetGuiResources(GR_GDIOBJECTS)` and `GetGuiResources(GR_USEROBJECTS)` stay at `delta == 0` across back-to-back multi-DPI soak cycles.

---

## 5. GitHub API / WAF Guard (`github_guard.go`)

All `gh codespace` control-plane invocations pass through `GitHubGuard`:

- **Sliding-window budgets**: Hard limits of `6` calls per `5m` and `24` calls per `1h`, with a `2s` minimum spacing (`min_call_spacing`) between consecutive CLI calls. Budgets are in-memory only and reset to `0/6` and `0/24` on every launch.
- **HTTP 429 & `Retry-After`**: Parses both numeric seconds and RFC 9110 HTTP-date `Retry-After` headers (`ParseRetryAfterAt`), applying exponential backoff (`15s` base up to `5m` max).
- **HTTP 400 concurrent-start classification**: Classifies `"too many codespaces starting"` as `FailureVMTransition`, applying a dedicated cooldown instead of tight-looping.
- **Intra-session stopped brake**: If a session detects the Codespace stopped externally, `MarkSessionStopped` blocks redundant churn until cleared.
- **Billing-scope HTTP 403 isolation**: On-demand quota checks (`RequestQuotaCheck`) classify missing billing-scope `403` responses via `IsQuotaBillingScope403()` without penalizing or tripping the tunnel WAF guard.
- **Zero nonexistent CLI verbs**: Production code never invokes `gh codespace start`; serialized worker boot handles cold Codespace wakeups natively.
