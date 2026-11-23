# NetShaper

NetShaper is a native, zero-CGO SOCKS5 proxy supervisor and desktop utility written in Go. It manages a pool of multiplexed `gh codespace ssh -D` tunnels behind a single local SOCKS5 endpoint (`127.0.0.1:1080`) for high-jitter, aggressive CG-NAT, and low-PMTU networks.

## Overview

Running a raw `gh codespace ssh -D` session directly on unstable or aggressively NATed networks fails in several predictable ways:

- **Silent CG-NAT state drops**: Idle TCP sockets are silently dropped after ~15 seconds without sending a `RST` or `FIN`, leaving half-open zombie tunnels.
- **Relay lane variance**: Individual TCP 5-tuples can land on degraded relay paths (2-4s RTT) while parallel 5-tuples on the same link remain fast (~250-350ms RTT).
- **PMTU blackholing**: Relay endpoints enforcing an effective PMTU of 576 bytes stall large burst writes unless framing is stepped down.
- **Multi-origin browser bursts**: Opening modern web applications spawns dozens of concurrent HTTP/2, SSE, and WebSocket streams that can starve naive fixed-slot proxies.
- **API rate limits and WAF lockouts**: Unbounded reconnect loops hammer GitHub's API and trigger HTTP 429 or concurrent VM start HTTP 400 errors.

NetShaper addresses these failure modes with a local supervisory data plane, baseline-normalized lane routing, a sliding-window GitHub API guard, OS process-job orphan prevention, and a lightweight Win32/GDI+ desktop interface.

## Traffic Architecture

```text
+---------------+       +------------------------+       +---------------------------+
| Local Client  | ----> | NetShaper SOCKS5 Proxy | ----> | TunnelPool (PoolSize = 2) |
| (Browser/App) |       |    127.0.0.1:1080      |       | 127.0.0.1:1081 .. :1082   |
+---------------+       +------------------------+       +-------------+-------------+
                                                                       |
                                                   2 outer WAN TCP sockets (RFC 4254 mux)
                                                   up to 64 global / 32 per-worker channels
                                                                       v
                        +------------------------+       +---------------------------+
                        |       Internet         | <---- |  GitHub Codespace Relay   |
                        |   (Egress via SSH -D)  |       |   (gh codespace ssh -D)   |
                        +------------------------+       +---------------------------+
```

## Key Capabilities

- **Zero-CGO Native Windows 11 UI**: Built directly on Win32, `gdiplus.dll`, and DWM (`DWMWA_USE_IMMERSIVE_DARK_MODE`, `DWMWA_SYSTEMBACKDROP_TYPE` Acrylic/Mica) with `PerMonitorV2` DPI scaling. Compiles with `CGO_ENABLED=0` and zero external UI runtimes.
- **Zero-Lock UI Isolation**: The UI thread never acquires data-plane or supervisor mutexes. Telemetry flows through wait-free `atomic.Pointer` snapshots (`AtomicTelemetry()`, `TunnelPool.CachedSnapshot()`, `GitHubGuard.CachedSnapshot()`), and logs write into a bounded 500-line `O(1)` ring buffer coalesced onto a 250ms repaint timer.
- **ProcessJob Orphan Prevention**: Child `gh` and `ssh` processes run inside a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) on Windows or an isolated process group on Unix, ensuring clean teardown on normal exit or crash.
- **Two-Stage 5-Tuple Boot Quality Gate**: New workers undergo pre-traffic SOCKS5 RTT/jitter sampling plus a bidirectional micro-payload check before accepting client traffic, re-rolling slow 5-tuples automatically within the API budget.
- **Baseline-Normalized Schmitt-Trigger Hysteresis**: Direct underlay probes (`B_raw(t)`) normalize worker RTTs (`rho_i = EWMA_RTT_i / max(B_raw, 50ms)`). Mode switches (`primary_preferred`, `balanced`, `single_primary`) enforce a 25s dwell window, 30% relative / 100ms absolute promotion margins, and guard-gated eviction of chronic slow lanes (`rho > 3.5x`).
- **Streaming-Aware Two-Tier Pressure Reaper**: Differentiates stalled handshakes (`<=128B` downstream, 12s pressure timeout) from established HTTP/2 or SSE streams (`>128B` downstream, 180s idle / 20s pressure timeout). Enforces `StreamingPressureIdleTimeout (20s) < SemaphoreWaitTimeout (25s)` to prevent saturation deadlocks.
- **Adaptive PMTU=576 Framing**: Steps relay copy buffers down from 16 KiB to 8 KiB automatically when a worker's WAN endpoint resolves to a PMTU=576 relay VIP (`20.120.56.11`).
- **Sliding-Window GitHub API Guard**: Enforces 6 calls per 5 minutes, 24 calls per hour, 2-second minimum call spacing, RFC 9110 `Retry-After` parsing on HTTP 429, concurrent-start HTTP 400 backoff, and isolated billing HTTP 403 handling on quota checks.
- **Read-Only Host Hygiene Preflight**: Audits outbound firewall rules and TCP parameters without ever mutating OS network settings.

## Prerequisites

- **Go 1.22+** (pure Go, `CGO_ENABLED=0`, uses `math/rand/v2`; no C compiler or `gcc` required)
- **GitHub CLI (`gh`)** installed and available on `PATH`
- An active GitHub Codespace and authenticated CLI session:

```bash
gh auth login
gh auth refresh -h github.com -s codespace
```

## Quick Start & Build

### Windows 11 (`cmd.exe`)

```bat
set CGO_ENABLED=0
go build -trimpath -ldflags "-H=windowsgui -s -w" -o NetShaper.exe .
NetShaper.exe -codespace your-codespace-name
```

### Windows 11 (PowerShell)

```powershell
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-H=windowsgui -s -w" -o NetShaper.exe .
.\NetShaper.exe -codespace your-codespace-name
```

### Headless CLI Mode (Windows / Linux / macOS)

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o netshaper .
./netshaper --headless -codespace your-codespace-name
```

## Usage & Window Lifecycle

- **SOCKS5 Proxy Endpoint**: Configure your browser or local proxy client to use `SOCKS5` at `127.0.0.1:1080` (with remote DNS resolution enabled).
- **Minimize (`_`)**: Hides the window to the Windows system tray, stops the 250ms UI repaint timer, and frees the 32bpp DIB backbuffer (~0% idle UI CPU).
- **System Tray Menu**: Right-click the tray icon to `Show / Hide NetShaper`, `Start / Stop Tunnel`, `Copy Proxy (127.0.0.1:1080)`, or `Exit NetShaper`.
- **Close (`X`) & Tray `Exit NetShaper`**: Immediately hides the window, removes the tray icon, runs a bounded graceful shutdown (`gh codespace stop` if a tunnel reached `HEALTHY`), terminates the Job Object, destroys all GDI/GDI+ handles, and exits the process cleanly (`os.Exit(0)`).
- **WAF Guard Budget**: Sliding-window API counters always initialize at `0/6 (5m)` and `0/24 (1h)` on each fresh launch and are never persisted to disk.

## Configuration

### Primary CLI Flags & Environment Variables

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `-codespace` | `NETSHAPER_CODESPACE` | `my-codespace` | Target GitHub Codespace name |
| `-local-port` | `NETSHAPER_LOCAL_PORT` | `1080` | Client-facing local SOCKS5 port |
| `-gh-port` | `NETSHAPER_GH_PORT` | `1081` | Base port for upstream `ssh -D` workers (`1081..1082`) |
| `-pool-size` | `NETSHAPER_POOL_SIZE` | `2` | Parallel upstream SSH tunnel workers (1..4) |
| `-max-conns` | `NETSHAPER_MAX_CONNS` | `64` | Global max concurrent multiplexed SSH channels |
| `-per-tunnel-max-conns` | `NETSHAPER_PER_TUNNEL_MAX_CONNS` | `32` | Max concurrent SSH channels per worker |
| `-max-queued-conns` | `NETSHAPER_MAX_QUEUED_CONNS` | `128` | Bounded burst wait queue depth |
| `-pmtu576-copy-buffer-bytes` | `NETSHAPER_PMTU576_COPY_BUFFER_BYTES` | `8192` | Adaptive copy buffer size for PMTU=576 relay VIPs |
| `-tcp-keepalive` | `NETSHAPER_TCP_KEEPALIVE` | `8s` | TCP keepalive period (strictly < 15s CG-NAT drop) |
| `-ssh-alive-interval` | `NETSHAPER_SSH_ALIVE_INTERVAL` | `10` | OpenSSH `ServerAliveInterval` in seconds |
| `-ssh-alive-count-max` | `NETSHAPER_SSH_ALIVE_COUNT_MAX` | `3` | Missed SSH keepalives before disconnect |
| `-streaming-pressure-idle-timeout` | `NETSHAPER_STREAMING_PRESSURE_IDLE_TIMEOUT` | `20s` | Pressure idle timeout for established streams (< 25s wait) |
| `-semaphore-wait` | `NETSHAPER_SEMAPHORE_WAIT` | `25s` | Max queue wait time for an upstream slot |
| `-gh-max-calls-5m` | `NETSHAPER_GH_MAX_CALLS_5M` | `6` | Sliding 5-minute GitHub CLI invocation cap |
| `-gh-max-calls-hour` | `NETSHAPER_GH_MAX_CALLS_HOUR` | `24` | Sliding 60-minute GitHub CLI invocation cap |
| `-gh-min-call-spacing` | `NETSHAPER_GH_MIN_CALL_SPACING` | `2s` | Minimum spacing between consecutive `gh` calls |
| `-hysteresis-dwell-window` | `NETSHAPER_HYSTERESIS_DWELL_WINDOW` | `25s` | Continuous dwell time before routing mode/primary change |
| `-stop-on-exit` | `NETSHAPER_STOP_ON_EXIT` | `true` | Run `gh codespace stop` on shutdown if a worker reached `HEALTHY` |
| `--headless` | `NETSHAPER_HEADLESS` | `false` | Run in headless terminal mode without launching the GUI |

Run `NetShaper.exe -h` for the full flag list.

### UI Persistence (`netshaper_ui.json`) & Precedence

When using the desktop UI, the last selected Codespace name, tray preference, and GitHub account are saved beside the executable in `netshaper_ui.json`:

```json
{
  "codespace_name": "your-codespace-name",
  "local_port": 1080
}
```

**Precedence rule**: Passing `-codespace` on the command line or setting `NETSHAPER_CODESPACE` sets `CodespaceExplicit=true` and overrides the saved value in `netshaper_ui.json` for that session.

## Testing & Verification

### Go Test Suite (61 Tests: `UT-01..UT-40`, `ST-01..ST-21`)

```powershell
$env:CGO_ENABLED = "0"
go vet ./...
go test -v -count=1 ./...
```

On Windows, `UT-40` (`ui_stress_windows_test.go`) executes a real Win32/GDI+ multi-DPI stress soak (4,000 painted frames, 200 DPI transitions, 40 tray hide/restore cycles, 10 `TaskbarCreated` recoveries, and dual-cycle `GetGuiResources` handle leak verification asserting `delta == 0`).

### Static Audit & Discrete-Event Simulation

```bash
python3 verify_static.py
python3 simulate_v6.py
```

- `verify_static.py` checks Go lexical balance, unused imports, Windows/Unix platform parity, read-only OS hygiene, zero-lock UI isolation, Win32 ABI safety, and all runtime/test contracts.
- `simulate_v6.py` executes the 7 discrete-event simulations (5-tuple lanes, queue starvation, PMTU framing, API budget, cold start burst cap, adaptive hysteresis, and persistent HTTP/2 bursts).

## Architecture Deep-Dive

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed state machines, baseline-normalized quality formulas, deadlock-freedom proofs, and Win32 thread-affinity design notes.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
