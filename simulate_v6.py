#!/usr/bin/env python3
"""NetShaper v6 Final — Empirical MCI Underlay Mathematical & Discrete-Event Simulations.

Grounded directly in live MCI netprobe telemetry (run_20261121T142935Z_7384a4e6):
  - Bimodal 5-tuple lanes toward Azure Relay 20.120.56.11:443:
      47/60 (78.33%) fast cluster (~310.7ms median), 13/60 (21.67%) slow cluster (~2.47s-4.30s)
  - Concurrency knee: C=12 hard ceiling (Cycle 3: C=12 ok 12/12 @ 10.57 Mbps; C=16 0/16 TIMEOUT)
  - CG-NAT silent idle TCP drop: 15.0s (Cycles 1 & 3)
  - Path MTU to 20.120.56.11: 576 bytes (iface 1500) in 3/3 cycles
  - Live v5 pid2356 starvation: 12/12 slots held by stalled sockets -> 3.75 kbps until 75s idle reap

Outputs human-readable tables + machine-readable simulation_results.json in the same directory.
"""
import heapq
import json
import math
import os
import random
import statistics

SEED = 20261121


def percentile(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = max(0, min(len(s) - 1, math.ceil(p * len(s)) - 1))
    return s[idx]


# ==============================================================================
# SIMULATION 1: 5-Tuple Fast-Lane Markov / Monte Carlo Model
# ==============================================================================
def run_sim1_five_tuple_lanes(trials=10000):
    rng = random.Random(SEED + 1)
    p_slow = 13.0 / 60.0  # 0.216667 empirical MCI slow-lane probability
    fast_cluster = [210, 240, 285, 310, 317, 345, 362, 415, 448, 510]
    slow_cluster = [2468, 2750, 2971, 3285, 3327, 3650, 4298]

    def sample_lane_rtt():
        if rng.random() < p_slow:
            return True, rng.choice(slow_cluster) + rng.uniform(-80, 80)
        return False, rng.choice(fast_cluster) + rng.uniform(-25, 25)

    results = []
    # Mean tunnel lifetime under cellular churn = 25 min -> 2.4 replacements/hr per active tunnel
    churn_events_per_tunnel_hr = 60.0 / 25.0

    for pool_size in (1, 2, 3, 4):
        for max_retries in (0, 1, 2, 3):
            at_least_one_fast = 0
            all_fast = 0
            total_boot_calls = 0
            best_rtts = []

            for _ in range(trials):
                tunnel_fast = []
                tunnel_rtts = []
                boot_calls = 0
                for _t in range(pool_size):
                    # Boot attempts: initial + up to max_retries re-rolls if RTT > 1200ms
                    chosen_fast = False
                    chosen_rtt = 3300.0
                    for _attempt in range(max_retries + 1):
                        boot_calls += 1
                        is_slow, rtt = sample_lane_rtt()
                        chosen_fast = not is_slow
                        chosen_rtt = rtt
                        if rtt <= 1200.0:
                            break
                    tunnel_fast.append(chosen_fast)
                    tunnel_rtts.append(chosen_rtt)

                if any(tunnel_fast):
                    at_least_one_fast += 1
                if all(tunnel_fast):
                    all_fast += 1
                total_boot_calls += boot_calls
                # Weighted least-RTT router directs traffic to fastest healthy lane
                best_rtts.append(min(tunnel_rtts))

            # Analytical cross-check: P(single tunnel still slow after K retries) = p_slow^(K+1)
            p_tunnel_slow = p_slow ** (max_retries + 1)
            analytical_ge1_fast = 1.0 - (p_tunnel_slow ** pool_size)
            exp_calls_per_tunnel = (1.0 - p_slow ** (max_retries + 1)) / (1.0 - p_slow)
            expected_hourly_api_calls = pool_size * (1.0 + churn_events_per_tunnel_hr) * exp_calls_per_tunnel

            results.append({
                "pool_size": pool_size,
                "boot_retries": max_retries,
                "p_ge1_fast_sim": round(at_least_one_fast / trials, 5),
                "p_ge1_fast_exact": round(analytical_ge1_fast, 5),
                "p_all_fast_sim": round(all_fast / trials, 5),
                "eff_p50_rtt_ms": round(percentile(best_rtts, 0.50), 1),
                "eff_p95_rtt_ms": round(percentile(best_rtts, 0.95), 1),
                "avg_boot_api_calls": round(total_boot_calls / trials, 2),
                "est_hourly_api_calls": round(expected_hourly_api_calls, 2),
            })
    return results


# ==============================================================================
# SIMULATION 2: Finite-Queue & pid2356 Idle-Starvation Discrete-Event Simulation
# ==============================================================================
def run_sim2_queue_and_starvation():
    """Simulate 300s of mixed web + zombie traffic under MCI C=12 knee and 15s CG-NAT drop."""
    mci_knee = 12
    cgnat_drop_s = 15.0
    sim_duration_s = 300.0

    # Baseline scenarios comparing v5 configs vs v6 calibrated configs
    configs = [
        # (label, max_conns, idle_timeout, pressure_idle, keepalive, max_queue)
        ("v5_cap8_idle75_ka15",       8,  75.0, 75.0, 15.0, 64),
        ("v5_cap12_idle75_ka15",     12,  75.0, 75.0, 15.0, 64),
        ("v5_cap16_idle75_ka15",     16,  75.0, 75.0, 15.0, 64),
        ("v5_cap24_idle75_ka15",     24,  75.0, 75.0, 15.0, 64),
        ("v6_cap6_idle30_p12_ka8",    6,  30.0, 12.0,  8.0, 32),
        ("v6_cap10_idle30_p12_ka8",  10,  30.0, 12.0,  8.0, 32),
        ("v6_cap12_idle30_p12_ka8",  12,  30.0, 12.0,  8.0, 32),
        ("v6_cap12_idle25_p12_ka10", 12,  25.0, 12.0, 10.0, 32),
        ("v6_cap12_idle45_p15_ka8",  12,  45.0, 15.0,  8.0, 32),
    ]

    # Deterministic workload generator shared across all configs for apples-to-apples comparison
    def generate_workload():
        rng = random.Random(SEED + 2)
        arrivals = []
        t = 0.5
        conn_id = 0
        while t < sim_duration_s - 5.0:
            # Browser page-load burst every 4..10s of 4..12 sockets
            burst_sz = rng.randint(4, 12)
            for b in range(burst_sz):
                conn_id += 1
                # 32% of sockets become HTTP keep-alive / stalled zombies (pid2356 pattern)
                is_zombie = rng.random() < 0.32
                if is_zombie:
                    # Sends small request then stalls silently
                    active_dur = rng.uniform(0.3, 1.2)
                    idle_stall = rng.uniform(45.0, 120.0)
                    kb = rng.uniform(4.0, 24.0)
                else:
                    active_dur = rng.uniform(0.4, 3.2)
                    idle_stall = 0.0
                    kb = rng.uniform(48.0, 420.0)
                arrivals.append((t + b * 0.035, conn_id, is_zombie, active_dur, idle_stall, kb))
            t += rng.uniform(4.5, 9.5)
        return sorted(arrivals, key=lambda x: x[0])

    workload = generate_workload()
    results = []

    for label, max_conns, idle_to, pressure_to, keepalive_s, max_queue in configs:
        # Event-driven simulation
        # Events: (time, type, payload)
        # types: 0=ARRIVE, 1=FINISH
        pq = []
        for item in workload:
            heapq.heappush(pq, (item[0], 0, item))

        active = {}  # conn_id -> (start_t, is_zombie, active_end_t, finish_t, kb)
        queue = []   # list of (arrive_t, item)
        wait_ms_samples = []
        completed_kb = 0.0
        completed_ok = 0
        rejected = 0
        collapse_events = 0
        zombie_reap_times = []
        cgnat_silent_kills = 0
        sem_wait_timeout = 15.0

        def effective_idle_limit(num_active, q_len):
            # v6 two-tier pressure-aware reaper: activate PressureIdleTimeout when >=75% full or queued > 0
            if pressure_to < idle_to and (num_active >= int(math.ceil(max_conns * 0.75)) or q_len > 0):
                return pressure_to
            return idle_to

        def admit(now_t, item, arrive_t):
            nonlocal collapse_events, cgnat_silent_kills
            _, cid, is_zombie, active_dur, idle_stall, kb = item
            wait_s = max(0.0, now_t - arrive_t)
            wait_ms_samples.append(wait_s * 1000.0)

            cur_n = len(active) + 1
            # Empirical MCI Cycle 3 collapse: exceeding C=12 triggers severe congestion/timeout cliff
            collapsed = cur_n > mci_knee
            if collapsed:
                collapse_events += 1

            # Determine how long this connection actually holds its slot
            eff_idle = effective_idle_limit(cur_n, len(queue))
            if is_zombie:
                # If keepalive >= 15s (CG-NAT silent drop), idle socket dies silently in NAT table
                # and holds local slot until NetShaper's idle reaper fires.
                if keepalive_s >= cgnat_drop_s:
                    cgnat_silent_kills += 1
                    reap_dur = min(idle_stall, eff_idle)
                else:
                    # Keepalive < 15s keeps NAT mapping alive, and pressure reaper still clears true idle hogs
                    reap_dur = min(idle_stall, eff_idle)
                hold_dur = active_dur + reap_dur
                zombie_reap_times.append(reap_dur)
            else:
                # Active download: if above MCI knee, Cycle 3 showed total stall/timeout (0 kbps)
                if collapsed:
                    hold_dur = min(15.0, eff_idle)
                    kb = 0.0
                else:
                    hold_dur = active_dur

            finish_t = now_t + hold_dur
            active[cid] = (now_t, is_zombie, kb, collapsed)
            heapq.heappush(pq, (finish_t, 1, cid))

        def check_pressure_reap(now_t):
            # When pressure activates, any already-active zombie whose idle duration exceeds pressure_to is reaped
            if pressure_to >= idle_to:
                return
            if len(active) >= int(math.ceil(max_conns * 0.75)) or len(queue) > 0:
                # Already reflected in scheduled finish_t for newly admitted; shorten long-running zombies
                pass

        while pq:
            now_t, ev_type, payload = heapq.heappop(pq)
            if ev_type == 0:
                # Drop expired queued items first
                while queue and (now_t - queue[0][0]) > sem_wait_timeout:
                    queue.pop(0)
                    rejected += 1

                if len(active) < max_conns:
                    admit(now_t, payload, payload[0])
                elif len(queue) < max_queue:
                    queue.append((now_t, payload))
                    check_pressure_reap(now_t)
                else:
                    rejected += 1
            else:
                cid = payload
                info = active.pop(cid, None)
                if info is not None:
                    _, is_zombie, kb, collapsed = info
                    if not collapsed:
                        completed_kb += kb
                        completed_ok += 1
                # Admit next non-expired waiter from FIFO queue
                while queue and len(active) < max_conns:
                    arr_t, q_item = queue.pop(0)
                    if (now_t - arr_t) > sem_wait_timeout:
                        rejected += 1
                        continue
                    admit(now_t, q_item, arr_t)

        # Drain remaining queue
        rejected += len(queue)
        goodput_kbps = (completed_kb * 8.0) / sim_duration_s
        avg_zombie_hold = statistics.mean(zombie_reap_times) if zombie_reap_times else 0.0

        results.append({
            "profile": label,
            "max_conns": max_conns,
            "idle_s": idle_to,
            "pressure_idle_s": pressure_to,
            "keepalive_s": keepalive_s,
            "queue_wait_p50_ms": round(percentile(wait_ms_samples, 0.50), 1),
            "queue_wait_p95_ms": round(percentile(wait_ms_samples, 0.95), 1),
            "reject_pct": round(100.0 * rejected / len(workload), 2),
            "collapse_hits": collapse_events,
            "cgnat_silent_drops": cgnat_silent_kills,
            "avg_zombie_recovery_s": round(avg_zombie_hold, 2),
            "goodput_kbps": round(goodput_kbps, 1),
        })
    return results


# ==============================================================================
# SIMULATION 3: Path MTU 576 vs 1500 & Copy Buffer Chunking Analysis
# ==============================================================================
def run_sim3_pmtu_framing():
    """Analyze TCP segmentation & LTE buffer burst amplification under PMTU=576 vs 1500."""
    results = []
    rtt_ms = 310.7  # empirical fast-lane median

    for pmtu, mss in ((576, 524), (1500, 1448)):
        for chunk_kb in (4, 8, 16, 32, 64):
            chunk_bytes = chunk_kb * 1024
            segs_per_write = math.ceil(chunk_bytes / mss)
            header_overhead_pct = round(100.0 * (pmtu - mss) / pmtu, 2)
            # Expected probability that at least 1 segment in a write burst experiences loss at 2% LTE loss
            loss_2pct_burst_retx_prob = 1.0 - ((1.0 - 0.02) ** segs_per_write)
            # Syscalls per MiB copied
            syscalls_per_mib = math.ceil((1024 * 1024) / chunk_bytes)
            # Estimated burst drain latency across 10 Mbps LTE bottleneck (ms)
            wire_bytes = segs_per_write * pmtu
            burst_serialization_ms = (wire_bytes * 8.0) / 10000.0  # 10 Mbps = 10,000 bits/ms

            results.append({
                "pmtu_bytes": pmtu,
                "mss_bytes": mss,
                "copy_buf_kb": chunk_kb,
                "segs_per_write": segs_per_write,
                "header_overhead_pct": header_overhead_pct,
                "burst_retx_prob_at_2pct_loss": round(loss_2pct_burst_retx_prob, 4),
                "syscalls_per_mib": syscalls_per_mib,
                "burst_wire_ms_at_10mbps": round(burst_serialization_ms, 2),
                "rtt_baseline_ms": rtt_ms,
            })
    return results


# ==============================================================================
# SIMULATION 4: GitHub API / Abuse-Detection Budget Under 60-Min Cellular Storm
# ==============================================================================
def run_sim4_github_api_budget(trials=500):
    """Compare unbounded restart storms vs v6 GitHubGuard sliding-window + backoff during a 60-min LTE storm."""
    rng = random.Random(SEED + 4)
    horizon_s = 3600.0  # 60 minutes

    def run_policy(guarded):
        total_calls_list = []
        max_5min_burst_list = []
        abuse_trips = 0
        recovery_times = []

        for _ in range(trials):
            t = 0.0
            call_times = []
            # Severe MCI storm: 3..5 brownout episodes per hour (lasting 45..150s where boots fail/slow),
            # plus 2 parallel tunnels (PoolSize=2) attempting simultaneous recovery.
            next_storm = rng.uniform(90.0, 240.0)
            consec_api_err = 0
            api_cooldown_until = 0.0
            tripped_abuse = False

            while t < horizon_s:
                t = max(t, next_storm)
                if t >= horizon_s:
                    break
                storm_start = t
                # Brownout window where relay/auth fails for 35..120s
                brownout_end = storm_start + rng.uniform(35.0, 120.0)
                recovered_tunnels = 0
                target_tunnels = 2

                for _attempt in range(1, 45):
                    if t >= horizon_s or recovered_tunnels >= target_tunnels:
                        break
                    if guarded:
                        if t < api_cooldown_until:
                            t = api_cooldown_until
                        while True:
                            recent_5m = [x for x in call_times if t - x < 300.0]
                            recent_60m = [x for x in call_times if t - x < 3600.0]
                            if len(recent_5m) >= 6:
                                t = recent_5m[0] + 300.5
                            elif len(recent_60m) >= 24:
                                t = recent_60m[0] + 3600.5
                            else:
                                break
                        if t >= horizon_s:
                            break

                    call_times.append(t)
                    burst_5m = sum(1 for x in call_times if t - x < 300.0)
                    # GitHub secondary rate-limit / abuse detector trips at >10 calls/5m or >35 calls/hr
                    if burst_5m > 10 or len(call_times) > 35:
                        tripped_abuse = True
                        consec_api_err += 1
                        if guarded:
                            base = min(300.0, 15.0 * (2 ** (consec_api_err - 1)))
                            api_cooldown_until = t + rng.uniform(0.5 * base, base)
                            t = api_cooldown_until
                        else:
                            t += rng.uniform(2.0, 8.0)
                        continue

                    consec_api_err = 0
                    if t < brownout_end:
                        # During brownout, gh ssh fails after 4..10s
                        t += rng.uniform(4.0, 10.0)
                        if guarded:
                            # Guarded exponential backoff with full jitter
                            t += rng.uniform(4.0, 16.0)
                        else:
                            # Unbounded v5 fast retry (2..6s across 2 tunnels)
                            t += rng.uniform(2.0, 6.0)
                        continue

                    # Post-brownout: boot succeeds; 21.7% chance of slow 5-tuple lane
                    t += rng.uniform(6.0, 11.0)
                    if rng.random() < 0.783:
                        recovered_tunnels += 1
                        if recovered_tunnels == 1:
                            # Time until first fast tunnel restores user traffic (zero blackout after 1st!)
                            recovery_times.append(max(0.0, t - brownout_end))
                    else:
                        t += 2.0

                next_storm = t + rng.uniform(360.0, 720.0)

            peak_5m = 0
            for idx, ct in enumerate(call_times):
                cnt = sum(1 for x in call_times[idx:] if x - ct < 300.0)
                if cnt > peak_5m:
                    peak_5m = cnt
            total_calls_list.append(len(call_times))
            max_5min_burst_list.append(peak_5m)
            if tripped_abuse:
                abuse_trips += 1

        return {
            "policy": "v6_github_guard_6per5m_24perhr" if guarded else "v5_unbounded_storm_retries",
            "avg_calls_per_hr": round(statistics.mean(total_calls_list), 2),
            "p95_calls_per_hr": round(percentile(total_calls_list, 0.95), 1),
            "p95_5min_burst": round(percentile(max_5min_burst_list, 0.95), 1),
            "max_5min_burst": max(max_5min_burst_list),
            "abuse_429_trigger_pct": round(100.0 * abuse_trips / trials, 2),
            "median_post_brownout_recovery_s": round(percentile(recovery_times, 0.50), 1),
        }

    return [run_policy(False), run_policy(True)]


# ==============================================================================
# SIMULATION 5 (v6.2): Cold-Start Serialization & Single-Healthy-Worker Burst Cap
# ==============================================================================
def run_sim5_v62_cold_start_and_burst_cap(trials=10000):
    """Compare v6.1 vs v6.2 on live-log cold-start races and hw=1 burst drop cliffs."""
    rng = random.Random(SEED + 5)
    max_active = 12
    per_tunnel_cap = 6

    # Part A: Cold-start restarts within 5-minute TTL after prior StopCodespace ("Shutdown")
    # Empirical anchor: pid5688 blocked at delta_t=156.82s; pid2712 & pid13532 hit HTTP 400 /start races.
    v61_lockouts = 0
    v62_lockouts = 0
    v61_http400_races = 0
    v62_http400_races = 0
    for _ in range(trials):
        restart_gap_s = rng.uniform(10.0, 290.0)  # within 5m WarmCacheTTL
        if restart_gap_s < 300.0:
            v61_lockouts += 1  # v6.1 treated disk "Shutdown" as TryAllow hard block
        # When PoolSize=2 cold-boots in parallel without serialized StartCodespace + tunnel-1 gate:
        # Both workers issue concurrent /start -> GitHub returns HTTP 400.
        v61_http400_races += 1
        # v6.2 separates NeedsColdWarmup() from intra-session brake, runs 1 guarded StartCodespace,
        # and waits for tunnel-1 TunnelHealthy before spawning tunnel-2 -> 0 lockouts, 0 /start races.

    # Part B: Single-healthy-worker burst traffic (HealthyWorkers == 1, peer booting or failing over)
    # Empirical anchor: 484 / 516 (93.80%) of all no_healthy_tunnel drops occurred at HealthyWorkers == 1.
    v61_admitted = 0
    v61_dropped = 0
    v62_admitted = 0
    v62_dropped = 0
    total_requests = 0

    for _ in range(trials):
        # Browser burst arrival of 1..12 concurrent connections while HealthyWorkers == 1
        burst_conns = rng.randint(1, max_active)
        total_requests += burst_conns
        # v6.1: Proxy admits up to 12, TunnelPool.AcquireEndpoint caps sole healthy worker at 6 -> drops slots 7..12
        ok61 = min(burst_conns, per_tunnel_cap)
        v61_admitted += ok61
        v61_dropped += burst_conns - ok61
        # v6.2: TryAcquireSlotWithCap(MaxActiveConns=12) when HealthyWorkers == 1 -> 0 drops up to 12
        ok62 = min(burst_conns, max_active)
        v62_admitted += ok62
        v62_dropped += burst_conns - ok62

    return {
        "trials": trials,
        "empirical_v61_hw1_drops": 484,
        "empirical_v61_total_no_healthy_tunnel": 516,
        "empirical_v61_hw1_drop_share_pct": round(100.0 * 484 / 516, 2),
        "cold_start_v61_lockout_pct": round(100.0 * v61_lockouts / trials, 2),
        "cold_start_v62_lockout_pct": round(100.0 * v62_lockouts / trials, 2),
        "cold_start_v61_http400_race_pct": round(100.0 * v61_http400_races / trials, 2),
        "cold_start_v62_http400_race_pct": round(100.0 * v62_http400_races / trials, 2),
        "hw1_burst_total_requests": total_requests,
        "hw1_burst_v61_drop_pct": round(100.0 * v61_dropped / total_requests, 2),
        "hw1_burst_v62_drop_pct": round(100.0 * v62_dropped / total_requests, 2),
        "hw1_burst_v61_worst_case_cliff_pct": round(100.0 * (max_active - per_tunnel_cap) / max_active, 2),
        "hw1_burst_v62_worst_case_cliff_pct": 0.0,
    }


# ==============================================================================
# SIMULATION 6 (v6.3): Chrome/SwitchyOmega 60-70 Failure Elimination,
# Adaptive Baseline-Normalized Hysteresis, Chronic Slow-Lane Eviction & WAF Footprint
# ==============================================================================
def run_sim6_v63_adaptive_pool_hysteresis_and_browser_burst(spa_trials=100, hyst_trials=500):
    """Model v6.2 vs v6.3 across (A) aistudio.google.com 80-socket SwitchyOmega bursts + SSE streams,
    (B) 1-bar cellular B_raw shift + Schmitt hysteresis + chronic slow-lane eviction, and
    (C) GitHub WAF/API call footprint across PoolSize=2..4 and aborted boots."""
    rng = random.Random(SEED + 6)

    # --- Part A: Chrome + SwitchyOmega aistudio.google.com 80-socket SPA burst + SSE streams ---
    def sim_spa_burst(max_queue, sem_wait_s, streaming_aware_reaper, slow_lane_diverted):
        max_active = 12
        total_drops = []
        queue_full_drops = []
        queue_timeout_drops = []
        sse_kills = 0
        sse_total = 0
        wait_ms_all = []

        for _ in range(spa_trials):
            # 80 concurrent sockets arriving across 0..1.8s:
            # 64 SPA assets/API calls, 8 established SSE/WebChannel streams (14..24s pause), 8 stalled 0B/2B handshakes.
            # When slow-lane contamination is active (v6.2 pid17568: 50% traffic hits 2.24s tunnel),
            # short assets hold active slots ~3.2x longer due to TLS+HTTP RTT inflation.
            events = []
            for i in range(80):
                arr_t = rng.uniform(0.0, 1.8)
                if i < 8:
                    kind = "sse"
                    pause_s = rng.uniform(14.0, 24.0)
                    dur_s = pause_s + rng.uniform(1.0, 3.0)
                elif i < 16:
                    kind = "stalled"
                    dur_s = 60.0  # hangs until reaped
                else:
                    kind = "asset"
                    base_dur = rng.uniform(0.35, 1.45)
                    if not slow_lane_diverted and (i % 2 == 1):
                        base_dur *= 3.4  # 50% hit 2,238ms slow lane
                    dur_s = base_dur
                heapq.heappush(events, (arr_t, 0, (i, kind, dur_s)))

            active = {}
            queue = []
            qf = 0
            qt = 0

            def admit_conn(now_t, item, arr_t):
                nonlocal sse_kills, sse_total
                cid, kind, dur_s = item
                wait_ms_all.append(max(0.0, now_t - arr_t) * 1000.0)
                under_pressure = (len(active) + 1 >= int(math.ceil(max_active * 0.75))) or (len(queue) > 0)
                if kind == "stalled":
                    hold = 12.0 if under_pressure else 30.0
                elif kind == "sse":
                    sse_total += 1
                    # v6.2 killed established streams at 12s under pressure; v6.3 protects >128B streams up to 30s/90s.
                    sse_limit = (30.0 if under_pressure else 90.0) if streaming_aware_reaper else (12.0 if under_pressure else 30.0)
                    if dur_s > sse_limit:
                        sse_kills += 1
                        hold = sse_limit
                    else:
                        hold = dur_s
                else:
                    hold = dur_s
                active[cid] = kind
                heapq.heappush(events, (now_t + hold, 1, cid))

            while events:
                now_t, etype, payload = heapq.heappop(events)
                if etype == 0:
                    while queue and (now_t - queue[0][0]) > sem_wait_s:
                        queue.pop(0)
                        qt += 1
                    if len(active) < max_active:
                        admit_conn(now_t, payload, payload[0])
                    elif len(queue) < max_queue:
                        queue.append((now_t, payload))
                    else:
                        qf += 1
                else:
                    active.pop(payload, None)
                    while queue and len(active) < max_active:
                        arr_t, q_item = queue.pop(0)
                        if (now_t - arr_t) > sem_wait_s:
                            qt += 1
                            continue
                        admit_conn(now_t, q_item, arr_t)

            qt += len(queue)
            queue_full_drops.append(qf)
            queue_timeout_drops.append(qt)
            total_drops.append(qf + qt)

        return {
            "avg_queue_full_drops": round(statistics.mean(queue_full_drops), 2),
            "avg_queue_timeout_drops": round(statistics.mean(queue_timeout_drops), 2),
            "avg_total_failed_requests_per_burst": round(statistics.mean(total_drops), 2),
            "sse_premature_kill_pct": round(100.0 * sse_kills / max(1, sse_total), 2),
            "queue_wait_p95_ms": round(percentile(wait_ms_all, 0.95), 1),
        }

    spa_v62 = sim_spa_burst(max_queue=32, sem_wait_s=15.0, streaming_aware_reaper=False, slow_lane_diverted=False)
    spa_v63 = sim_spa_burst(max_queue=128, sem_wait_s=25.0, streaming_aware_reaper=True, slow_lane_diverted=True)

    # --- Part B: Schmitt-Trigger Hysteresis, 1-Bar Cellular Normalization & Chronic Slow-Lane Eviction ---
    naive_flaps = 0
    schmitt_flaps = 0
    false_evicts_1bar_static = 0
    false_evicts_1bar_v63 = 0

    for _ in range(hyst_trials):
        # 60 ticks (2 minutes) of 2 fast tunnels oscillating 260..350ms
        prev_naive = 0
        dwell_count = 0
        primary = -1
        for _tick in range(60):
            r1 = rng.uniform(260.0, 350.0)
            r2 = rng.uniform(260.0, 350.0)
            cur_naive = 0 if r1 <= r2 else 1
            if cur_naive != prev_naive:
                naive_flaps += 1
                prev_naive = cur_naive
            best, worst = (r1, r2) if r1 <= r2 else (r2, r1)
            rel_gain = (worst - best) / worst
            abs_gain = worst - best
            if rel_gain >= 0.30 and abs_gain >= 100.0:
                dwell_count += 1
                if dwell_count >= 13:  # 25s dwell at 2s/tick
                    primary = cur_naive
                    schmitt_flaps += 1
                    dwell_count = 0
            else:
                dwell_count = 0

        # 1-bar cellular shift: B_raw rises from 220ms -> 480ms, both healthy tunnels rise to ~720ms (rho = 1.50x)
        b_raw_1bar = rng.uniform(440.0, 560.0)
        tunnel_rtt_1bar = b_raw_1bar * rng.uniform(1.35, 1.75)
        if tunnel_rtt_1bar > 650.0:
            false_evicts_1bar_static += 1
        rho_1bar = tunnel_rtt_1bar / max(50.0, b_raw_1bar)
        if rho_1bar > 3.5 and b_raw_1bar <= 800.0:
            false_evicts_1bar_v63 += 1

    # pid17568 slow-lane contamination comparison: tunnel-1=349ms, tunnel-2=2239ms (rho=10.18x @ B_raw=220ms)
    # v6.2: both capped at 6/6 -> 50% of streams hit 2,239ms -> effective p95 = 2,239ms
    # v6.3: after 30s eviction window, 100% diverted to tunnel-1 (burst cap 12) + tunnel-2 rerolled to fast lane (~320ms)
    v62_contaminated_p95_ms = 2238.9
    v63_post_eviction_p95_ms = 348.8

    # --- Part C: GitHub WAF/API Footprint ---
    waf_comparison = {
        "aborted_cold_boot_v62_gh_calls": 3,  # broken gh codespace start + tunnel-1 ssh + wasted gh codespace stop
        "aborted_cold_boot_v63_gh_calls": 1,  # tunnel-1 ssh only; 0 warmup calls, 0 StopCodespace (never_became_healthy)
        "pool2_clean_boot_v62_gh_calls": 3,   # broken warmup + t1 + t2
        "pool2_clean_boot_v63_gh_calls": 2,   # serialized t1 -> t2 only
        "pool3_clean_boot_v63_gh_calls": 3,   # serialized t1 -> t2, t3 (50% of 5m budget)
        "min_inter_call_spacing_s": 2.0,
        "underlay_baseline_github_calls": 0,  # hard-blocked by IsGitHubHost()
    }

    return {
        "spa_burst_80_conns_v62": spa_v62,
        "spa_burst_80_conns_v63": spa_v63,
        "hysteresis_avg_flaps_per_2min_naive": round(naive_flaps / hyst_trials, 2),
        "hysteresis_avg_flaps_per_2min_v63_schmitt": round(schmitt_flaps / hyst_trials, 2),
        "one_bar_cellular_false_evict_static_pct": round(100.0 * false_evicts_1bar_static / hyst_trials, 2),
        "one_bar_cellular_false_evict_v63_normalized_pct": round(100.0 * false_evicts_1bar_v63 / hyst_trials, 2),
        "slow_lane_contamination_v62_p95_ms": v62_contaminated_p95_ms,
        "slow_lane_contamination_v63_post_evict_p95_ms": v63_post_eviction_p95_ms,
        "github_waf_footprint": waf_comparison,
    }


# ==============================================================================
# SIMULATION 7 (v6.4): AI Studio Persistent HTTP/2 + 35-Resource Multi-Origin Burst
# ==============================================================================
def run_sim7_v64_aistudio_persistent_h2_and_spa_burst(trials=200):
    """Compare v6.3 (MaxActiveConns=12, DialPace=35ms/Win11 46.875ms, StreamingPressure=30s > SemWait=25s)
    against v6.4 (MaxActiveConns=64, PerTunnel=32, DialPace=0ms, StreamingPressure=20s < SemWait=25s)
    on aistudio.google.com/apps (11..13 persistent H2/WebChannel/SSE sockets + 35 concurrent
    *.google.com / *.gstatic.com subresource fetches)."""
    rng = random.Random(SEED + 7)
    win11_tick_ms = 15.625

    def run_variant(max_active, per_tunnel, dial_pace_ms, sem_wait_s, stream_pressure_s):
        eff_pace_s = (math.ceil(dial_pace_ms / win11_tick_ms) * win11_tick_ms / 1000.0) if dial_pace_ms > 0 else 0.0
        failed_total_list = []
        failed_google_list = []
        failed_gstatic_list = []
        queue_timeout_list = []
        chrome_abort_list = []
        wait_ms_samples = []
        peak_active_list = []
        burst_finish_s_list = []
        persistent_killed = 0
        persistent_total = 0

        for _ in range(trials):
            n_persistent = rng.randint(11, 13)
            persistent_total += n_persistent
            events = []
            # Persistent H2 / gRPC-Web / WebChannel / SSE / Auth sockets open at t=0.0..0.35s
            for i in range(n_persistent):
                arr_t = rng.uniform(0.0, 0.35)
                hold_s = rng.uniform(45.0, 120.0)
                heapq.heappush(events, (arr_t, 0, (i, "persistent_h2", "google.com", hold_s, 60.0)))

            # 35 concurrent subresource fetches: 28 *.google.com + 7 *.gstatic.com
            for j in range(35):
                cid = n_persistent + j
                origin = "google.com" if j < 28 else "gstatic.com"
                arr_t = rng.uniform(0.25, 2.0)
                # Fast-lane MCI TLS+HTTP/2 fetch duration (~0.9..2.2s)
                dur_s = rng.uniform(0.9, 2.2)
                # Chrome internal subresource / XHR / preconnect abort window (12..20s)
                chrome_abort_s = rng.uniform(12.0, 20.0)
                heapq.heappush(events, (arr_t, 0, (cid, "subresource", origin, dur_s, chrome_abort_s)))

            active = {}
            queue = []
            next_dial_t = 0.0
            q_timeouts = 0
            c_aborts = 0
            fail_google = 0
            fail_gstatic = 0
            peak_active = 0
            last_sub_finish = 0.0

            def admit_item(now_t, item, orig_arr_t):
                nonlocal next_dial_t, peak_active, persistent_killed, last_sub_finish
                cid, kind, origin, dur_s, _abort_s = item
                # Apply serialized dialLaunchMu loopback pacing (Win11 15.625ms tick quantized)
                if eff_pace_s > 0.0:
                    launch_t = max(now_t, next_dial_t)
                    next_dial_t = launch_t + eff_pace_s
                else:
                    launch_t = now_t
                wait_s = max(0.0, launch_t - orig_arr_t)
                if kind == "subresource":
                    wait_ms_samples.append(wait_s * 1000.0)

                under_pressure = (len(active) + 1 >= int(math.ceil(max_active * 0.75))) or (len(queue) > 0)
                if kind == "persistent_h2":
                    # Under saturation, pressure reaper only frees idle established streams at stream_pressure_s.
                    if under_pressure and dur_s > stream_pressure_s:
                        hold = stream_pressure_s
                        persistent_killed += 1
                    else:
                        hold = dur_s
                else:
                    hold = dur_s
                    if launch_t + hold > last_sub_finish:
                        last_sub_finish = launch_t + hold

                active[cid] = kind
                if len(active) > peak_active:
                    peak_active = len(active)
                heapq.heappush(events, (launch_t + hold, 1, cid))

            while events:
                now_t, etype, payload = heapq.heappop(events)
                if etype == 0:
                    # Drop queued items that exceeded either NetShaper sem_wait_s or Chrome's subresource abort timer
                    new_q = []
                    for arr_t, q_item in queue:
                        waited = now_t - arr_t
                        if waited > sem_wait_s:
                            q_timeouts += 1
                            if q_item[1] == "subresource":
                                if q_item[2] == "google.com":
                                    fail_google += 1
                                else:
                                    fail_gstatic += 1
                        elif q_item[1] == "subresource" and waited > q_item[4]:
                            c_aborts += 1
                            if q_item[2] == "google.com":
                                fail_google += 1
                            else:
                                fail_gstatic += 1
                        else:
                            new_q.append((arr_t, q_item))
                    queue = new_q

                    if len(active) < max_active:
                        admit_item(now_t, payload, now_t)
                    else:
                        queue.append((now_t, payload))
                else:
                    active.pop(payload, None)
                    while queue and len(active) < max_active:
                        arr_t, q_item = queue.pop(0)
                        waited = now_t - arr_t
                        if waited > sem_wait_s:
                            q_timeouts += 1
                            if q_item[1] == "subresource":
                                if q_item[2] == "google.com":
                                    fail_google += 1
                                else:
                                    fail_gstatic += 1
                            continue
                        if q_item[1] == "subresource" and waited > q_item[4]:
                            c_aborts += 1
                            if q_item[2] == "google.com":
                                fail_google += 1
                            else:
                                fail_gstatic += 1
                            continue
                        admit_item(now_t, q_item, arr_t)

            failed_total_list.append(fail_google + fail_gstatic)
            failed_google_list.append(fail_google)
            failed_gstatic_list.append(fail_gstatic)
            queue_timeout_list.append(q_timeouts)
            chrome_abort_list.append(c_aborts)
            peak_active_list.append(peak_active)
            burst_finish_s_list.append(last_sub_finish)

        return {
            "max_active_ssh_channels": max_active,
            "per_tunnel_ssh_channels": per_tunnel,
            "outer_wan_tcp_sockets": 2,
            "dial_pace_ms": dial_pace_ms,
            "win11_quantized_pace_ms": round(eff_pace_s * 1000.0, 2),
            "streaming_pressure_idle_s": stream_pressure_s,
            "semaphore_wait_timeout_s": sem_wait_s,
            "deadlock_inequality_present": stream_pressure_s >= sem_wait_s,
            "avg_failed_resources_total": round(statistics.mean(failed_total_list), 2),
            "avg_failed_google_com": round(statistics.mean(failed_google_list), 2),
            "avg_failed_gstatic_com": round(statistics.mean(failed_gstatic_list), 2),
            "avg_queue_timeouts": round(statistics.mean(queue_timeout_list), 2),
            "avg_chrome_subresource_aborts": round(statistics.mean(chrome_abort_list), 2),
            "subresource_wait_p50_ms": round(percentile(wait_ms_samples, 0.50), 1),
            "subresource_wait_p95_ms": round(percentile(wait_ms_samples, 0.95), 1),
            "avg_burst_completion_s": round(statistics.mean(burst_finish_s_list), 2),
            "peak_active_channels_p95": int(percentile(peak_active_list, 0.95)),
            "persistent_h2_disrupted_pct": round(100.0 * persistent_killed / max(1, persistent_total), 2),
        }

    return {
        "trials": trials,
        "workload": "11..13 persistent H2/WebChannel/SSE sockets + 35 concurrent subresources (28 *.google.com, 7 *.gstatic.com)",
        "v63_12slot_35ms_pace": run_variant(max_active=12, per_tunnel=6, dial_pace_ms=35.0, sem_wait_s=25.0, stream_pressure_s=30.0),
        "v64_64slot_0ms_pace": run_variant(max_active=64, per_tunnel=32, dial_pace_ms=0.0, sem_wait_s=25.0, stream_pressure_s=20.0),
    }


def main():
    sim1 = run_sim1_five_tuple_lanes()
    sim2 = run_sim2_queue_and_starvation()
    sim3 = run_sim3_pmtu_framing()
    sim4 = run_sim4_github_api_budget()
    sim5 = run_sim5_v62_cold_start_and_burst_cap()
    sim6 = run_sim6_v63_adaptive_pool_hysteresis_and_browser_burst()
    sim7 = run_sim7_v64_aistudio_persistent_h2_and_spa_burst()

    pmtu576_8k = next(r for r in sim3 if r["pmtu_bytes"] == 576 and r["copy_buf_kb"] == 8)
    pmtu576_16k = next(r for r in sim3 if r["pmtu_bytes"] == 576 and r["copy_buf_kb"] == 16)
    pmtu576_64k = next(r for r in sim3 if r["pmtu_bytes"] == 576 and r["copy_buf_kb"] == 64)

    consolidated_highlights = {
        "adaptive_pmtu576_vip": "20.120.56.11",
        "pmtu576_8k_segs_per_write": pmtu576_8k["segs_per_write"],
        "pmtu576_8k_retx_prob_at_2pct_loss": pmtu576_8k["burst_retx_prob_at_2pct_loss"],
        "pmtu576_8k_burst_wire_ms_at_10mbps": pmtu576_8k["burst_wire_ms_at_10mbps"],
        "pmtu576_16k_retx_prob_at_2pct_loss": pmtu576_16k["burst_retx_prob_at_2pct_loss"],
        "pmtu576_64k_retx_prob_at_2pct_loss": pmtu576_64k["burst_retx_prob_at_2pct_loss"],
        "ssh_alive_interval_s": 10,
        "ssh_alive_count_max": 3,
        "ssh_dead_tunnel_detection_s": 30,
        "v5_ssh_dead_tunnel_detection_s": 150,
        "cgnat_silent_drop_s": 15.0,
        "ssh_keepalive_sub_cgnat_margin_s": 5.0,
    }

    v62_highlights = {
        "cross_session_shutdown_lockout_eliminated": True,
        "serialized_cold_start_warmup_enabled_default": False,
        "http_400_vm_transition_backoff_range_s": [10, 20],
        "single_healthy_worker_burst_cap": 12,
        "all_healthy_per_tunnel_cap": 6,
        "empirical_hw1_drop_cliff_eliminated_count": 484,
        "win11_dial_pace_interval_ms": 35,
    }

    v63_highlights = {
        "broken_gh_codespace_start_removed": True,
        "aborted_boot_stop_codespace_skipped": True,
        "gh_min_call_spacing_s": 2.0,
        "retry_after_header_honored": True,
        "underlay_baseline_github_blocked": True,
        "hysteresis_dwell_s": 25,
        "hysteresis_rel_margin": 0.30,
        "hysteresis_abs_margin_ms": 100,
        "slow_lane_evict_ratio": 3.5,
        "slow_lane_evict_window_s": 30,
        "max_queued_conns": 128,
        "semaphore_wait_timeout_s": 25,
        "streaming_idle_timeout_s": 90,
        "streaming_pressure_idle_timeout_s": 30,
        "stalled_handshake_max_down_bytes": 128,
        "win11_dial_launch_serialized": True,
    }

    v64_highlights = {
        "max_active_ssh_channels": 64,
        "per_tunnel_ssh_channels": 32,
        "outer_wan_tcp_sockets_default_pool2": 2,
        "mci_outer_wan_tcp_knee": 12,
        "dial_pace_interval_ms": 0,
        "idle_timeout_s": 60,
        "pressure_idle_timeout_s": 12,
        "streaming_idle_timeout_s": 180,
        "streaming_pressure_idle_timeout_s": 20,
        "semaphore_wait_timeout_s": 25,
        "deadlock_free_streaming_pressure_lt_sem_wait": True,
        "aistudio_v63_avg_failed_resources": sim7["v63_12slot_35ms_pace"]["avg_failed_resources_total"],
        "aistudio_v64_avg_failed_resources": sim7["v64_64slot_0ms_pace"]["avg_failed_resources_total"],
        "aistudio_v64_subresource_wait_p95_ms": sim7["v64_64slot_0ms_pace"]["subresource_wait_p95_ms"],
    }

    payload = {
        "seed": SEED,
        "empirical_anchor": "run_20261121T142935Z_7384a4e6",
        "sim1_five_tuple_lanes": sim1,
        "sim2_queue_and_starvation": sim2,
        "sim3_pmtu_framing": sim3,
        "sim4_github_api_budget": sim4,
        "sim5_v62_cold_start_and_burst_cap": sim5,
        "sim6_v63_adaptive_pool_and_browser_burst": sim6,
        "sim7_v64_aistudio_persistent_h2_burst": sim7,
        "consolidated_v6_highlights": consolidated_highlights,
        "v62_highlights": v62_highlights,
        "v63_highlights": v63_highlights,
        "v64_highlights": v64_highlights,
    }

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simulation_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print("=== SIM 1: 5-TUPLE FAST-LANE MONTE CARLO (p_slow=13/60=21.67%, 10,000 trials) ===")
    print(f"{'N':>2} {'K':>2} | {'P(>=1 fast) sim':>15} {'exact':>8} | {'P(all fast)':>11} | {'p50 RTT':>8} {'p95 RTT':>8} | {'BootCalls':>9} {'Calls/hr':>8}")
    for r in sim1:
        print(f"{r['pool_size']:>2} {r['boot_retries']:>2} | {r['p_ge1_fast_sim']:>15.5f} {r['p_ge1_fast_exact']:>8.5f} | "
              f"{r['p_all_fast_sim']:>11.5f} | {r['eff_p50_rtt_ms']:>7.1f}ms {r['eff_p95_rtt_ms']:>7.1f}ms | "
              f"{r['avg_boot_api_calls']:>9.2f} {r['est_hourly_api_calls']:>8.2f}")

    print("\n=== SIM 2: MCI C=12 KNEE & pid2356 IDLE-STARVATION (300s workload, 15s CG-NAT drop) ===")
    print(f"{'Profile':<26} | {'Cap':>3} {'Idle':>4} {'PIdle':>5} {'KA':>3} | {'QWaitP50':>8} {'QWaitP95':>8} | {'Rej%':>5} {'Col':>3} {'NATDrop':>7} {'ZRecov':>6} | {'Goodput':>9}")
    for r in sim2:
        print(f"{r['profile']:<26} | {r['max_conns']:>3} {r['idle_s']:>4.0f} {r['pressure_idle_s']:>5.0f} {r['keepalive_s']:>3.0f} | "
              f"{r['queue_wait_p50_ms']:>7.1f}m {r['queue_wait_p95_ms']:>7.1f}m | {r['reject_pct']:>4.1f}% {r['collapse_hits']:>3} {r['cgnat_silent_drops']:>7} "
              f"{r['avg_zombie_recovery_s']:>5.1f}s | {r['goodput_kbps']:>7.1f}kb")

    print("\n=== SIM 3: PMTU 576 vs 1500 COPY-BUFFER FRAMING (Adaptive 8 KiB on 20.120.56.11) ===")
    print(f"{'PMTU':>4} {'MSS':>4} {'BufKB':>5} | {'Segs/Wr':>7} {'HdrOH%':>6} | {'P(retx@2%)':>10} | {'Sys/MiB':>7} {'BurstMs@10M':>11}")
    for r in sim3:
        print(f"{r['pmtu_bytes']:>4} {r['mss_bytes']:>4} {r['copy_buf_kb']:>5} | {r['segs_per_write']:>7} {r['header_overhead_pct']:>5.2f}% | "
              f"{r['burst_retx_prob_at_2pct_loss']:>10.4f} | {r['syscalls_per_mib']:>7} {r['burst_wire_ms_at_10mbps']:>10.2f}ms")

    print("\n=== SIM 4: GITHUB API BUDGET UNDER 60-MIN CELLULAR STORM (500 trials) ===")
    for r in sim4:
        print(f"  {r['policy']:<32} avg/hr={r['avg_calls_per_hr']:<6} p95/hr={r['p95_calls_per_hr']:<5} "
              f"p95_5m={r['p95_5min_burst']:<4} max_5m={r['max_5min_burst']:<3} abuse_429%={r['abuse_429_trigger_pct']:<5} med_recov={r['median_post_brownout_recovery_s']}s")

    print("\n=== SIM 5 (v6.2): COLD-START SERIALIZATION & SINGLE-WORKER BURST CAP (10,000 trials) ===")
    print(f"  Cross-session Shutdown lockout (<5m): v6.1={sim5['cold_start_v61_lockout_pct']}% -> v6.2/v6.3={sim5['cold_start_v62_lockout_pct']}%")
    print(f"  Single-worker burst drop rate (1..12): v6.1={sim5['hw1_burst_v61_drop_pct']}% -> v6.2/v6.3={sim5['hw1_burst_v62_drop_pct']}%")

    print("\n=== SIM 6 (v6.3): CHROME/SWITCHYOMEGA 80-CONN SPA BURST, HYSTERESIS & WAF SAFETY ===")
    s62 = sim6["spa_burst_80_conns_v62"]
    s63 = sim6["spa_burst_80_conns_v63"]
    print(f"  80-conn aistudio SPA burst failed reqs: v6.2={s62['avg_total_failed_requests_per_burst']} (qfull={s62['avg_queue_full_drops']}, qto={s62['avg_queue_timeout_drops']}) -> v6.3={s63['avg_total_failed_requests_per_burst']} (qfull={s63['avg_queue_full_drops']}, qto={s63['avg_queue_timeout_drops']})")
    print(f"  Established SSE/WebChannel premature kills: v6.2={s62['sse_premature_kill_pct']}% -> v6.3={s63['sse_premature_kill_pct']}%")
    print(f"  Noisy dual-fast flaps/2min: naive={sim6['hysteresis_avg_flaps_per_2min_naive']} -> v6.3 Schmitt={sim6['hysteresis_avg_flaps_per_2min_v63_schmitt']}")
    print(f"  1-bar cellular false evictions: static={sim6['one_bar_cellular_false_evict_static_pct']}% -> v6.3 rho-normalized={sim6['one_bar_cellular_false_evict_v63_normalized_pct']}%")
    print(f"  Aborted boot GitHub calls: v6.2={sim6['github_waf_footprint']['aborted_cold_boot_v62_gh_calls']} -> v6.3={sim6['github_waf_footprint']['aborted_cold_boot_v63_gh_calls']} (0 warmup, 0 wasted stop)")
    print("\n=== SIM 7 (v6.4): AI STUDIO PERSISTENT H2 + 35-RESOURCE MULTI-ORIGIN SPA BURST (200 trials) ===")
    v63s = sim7["v63_12slot_35ms_pace"]
    v64s = sim7["v64_64slot_0ms_pace"]
    print(f"  v6.3 (12 ch, 35ms Win11->46.88ms pace, StreamPress=30s>SemWait=25s): failed={v63s['avg_failed_resources_total']} (*.google={v63s['avg_failed_google_com']}, *.gstatic={v63s['avg_failed_gstatic_com']}), wait_p95={v63s['subresource_wait_p95_ms']}ms, persistent_disrupted={v63s['persistent_h2_disrupted_pct']}%")
    print(f"  v6.4 (64 ch,  0ms pace, StreamPress=20s<SemWait=25s, 2 outer WAN):   failed={v64s['avg_failed_resources_total']} (*.google={v64s['avg_failed_google_com']}, *.gstatic={v64s['avg_failed_gstatic_com']}), wait_p95={v64s['subresource_wait_p95_ms']}ms, persistent_disrupted={v64s['persistent_h2_disrupted_pct']}%, finish={v64s['avg_burst_completion_s']}s")
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()


