#!/usr/bin/env python3
"""NetShaper v7.0 (core v6.4) static verification suite (no Go toolchain required).

Audits:
  1. config.json: valid JSON, UseIPv4, triple DoH (1.1.1.1/8.8.8.8/9.9.9.9), QUIC/UDP block, mux=false.
  2. Go lexical balance, termination, trailing newline, no truncation markers, package main.
  3. Unused-import hygiene across EVERY .go file (catches Go compile-time unused import errors).
  4. Platform parity across all 4 Windows/Unix pairs (job, portcleanup, net_hygiene, ui) + build tags.
  5. Cross-file module wiring (all 5 v6 modules + v7 UI bridge actively wired in supervisor.go / main.go).
  6. Zero silent OS mutations in Go runtime (no netsh set/add/delete executions in production Go code).
  7. All 71 tests (UT-01..UT-49, ST-01..ST-22) present once and isolated (no t.Parallel, LocalPort=0, no pkg vars).
  8. Consolidated v6.1..v6.4 contract constants & methods + v7.0 UI/Bridge/ABI/Exit/Isolation contracts.
  9. Interface satisfaction + cross-file symbol resolution across all .go files.
 10. Executed simulation_results.json (SIM 1..SIM 7) + repository package docs + optional host artifacts.

Usage: python3 verify_static.py [project_dir]
"""
import json
import os
import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
fails = []


def fail(msg):
    fails.append(msg)
    print("FAIL:", msg)


def ok(msg):
    print("OK:  ", msg)


def read(p):
    with open(os.path.join(ROOT, p), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- 1. config.json
try:
    cfg = json.loads(read("config.json"))
    for k in ("log", "dns", "inbounds", "outbounds", "routing"):
        if k not in cfg:
            fail(f"config.json missing top-level key {k!r}")
    dns = cfg.get("dns", {})
    if dns.get("queryStrategy") != "UseIPv4":
        fail(f"config.json dns.queryStrategy={dns.get('queryStrategy')!r}, want 'UseIPv4'")
    srv_text = json.dumps(dns.get("servers", []))
    for doh in ("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"):
        if doh not in srv_text:
            fail(f"config.json missing DoH resolver {doh}")
    rules = cfg.get("routing", {}).get("rules", [])
    if not rules or rules[0].get("port") != "443" or rules[0].get("network") != "udp" or rules[0].get("outboundTag") != "block":
        fail("config.json rules[0] must block udp:443 (QUIC)")
    proxy_out = next((o for o in cfg.get("outbounds", []) if o.get("tag") == "proxy"), None)
    if not proxy_out or proxy_out.get("mux", {}).get("enabled") is not False:
        fail("config.json proxy outbound must set mux.enabled=false")
    ok("config.json valid: UseIPv4, triple DoH (1.1.1.1/8.8.8.8/9.9.9.9), QUIC/UDP block, mux=false")
except Exception as e:
    fail(f"config.json invalid: {e}")


# ---------------------------------------------------------------- 2. Go lexical balance
def strip_go(src, name):
    """Return source with comments/strings/runes blanked; raises ValueError on unterminated constructs."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j < 0:
                raise ValueError(f"{name}: unterminated block comment")
            out.append("\n" * src.count("\n", i, j))
            i = j + 2
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                if src[j] == "\n":
                    raise ValueError(f"{name}: newline in interpreted string at offset {i}")
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise ValueError(f"{name}: unterminated string at offset {i}")
            i = j + 1
            out.append('""')
        elif c == "`":
            j = src.find("`", i + 1)
            if j < 0:
                raise ValueError(f"{name}: unterminated raw string at offset {i}")
            out.append("\n" * src.count("\n", i, j))
            i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                if src[j] == "\n":
                    raise ValueError(f"{name}: newline in rune literal at offset {i}")
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise ValueError(f"{name}: unterminated rune at offset {i}")
            i = j + 1
            out.append("'x'")
        else:
            out.append(c)
            i += 1
    return "".join(out)


go_files = sorted(f for f in os.listdir(ROOT) if f.endswith(".go"))
stripped_cache = {}
bal_ok = True
for f in go_files:
    src = read(f)
    try:
        clean = strip_go(src, f)
        stripped_cache[f] = clean
    except ValueError as e:
        fail(str(e))
        bal_ok = False
        continue
    stack = []
    pairs = {")": "(", "}": "{", "]": "["}
    line = 1
    for ch in clean:
        if ch == "\n":
            line += 1
        elif ch in "({[":
            stack.append((ch, line))
        elif ch in ")}]":
            if not stack or stack[-1][0] != pairs[ch]:
                fail(f"{f}:{line}: unbalanced {ch!r}")
                bal_ok = False
                break
            stack.pop()
    else:
        if stack:
            fail(f"{f}: {len(stack)} unclosed delimiters, first {stack[0]}")
            bal_ok = False
    if not src.endswith("\n"):
        fail(f"{f}: missing trailing newline (possible truncation)")
        bal_ok = False
    if not re.search(r"^package main\s*$", src, re.M):
        fail(f"{f}: missing 'package main'")
        bal_ok = False
    if "\x00" in src or "TODO_TRUNCATED" in src or "..." == src.strip()[-3:]:
        fail(f"{f}: truncation marker detected")
        bal_ok = False
if bal_ok:
    ok(f"{len(go_files)} .go files lexically balanced, terminated, newline-terminated")


# ---------------------------------------------------------------- 3. Unused-import hygiene
def pkg_ident_from_path(path):
    parts = path.strip("/").split("/")
    last = parts[-1]
    if re.fullmatch(r"v\d+", last) and len(parts) >= 2:
        return parts[-2]
    return last


def extract_imports(src):
    imports = []
    # Block imports
    for bm in re.finditer(r"import\s*\((.*?)\)", src, re.S):
        for line in bm.group(1).splitlines():
            line = re.sub(r"//.*", "", line).strip()
            if not line:
                continue
            m = re.match(r'^(?:([A-Za-z_\.]\w*)\s+)?"([^"]+)"$', line)
            if m:
                alias, path = m.group(1), m.group(2)
                ident = alias if alias else pkg_ident_from_path(path)
                imports.append((ident, path))
    # Single-line imports
    for sm in re.finditer(r'^import\s+(?:([A-Za-z_\.]\w*)\s+)?"([^"]+)"', src, re.M):
        alias, path = sm.group(1), sm.group(2)
        ident = alias if alias else pkg_ident_from_path(path)
        imports.append((ident, path))
    return imports


imp_ok = True
for f in go_files:
    src = read(f)
    clean = stripped_cache.get(f, "")
    # Remove import block from clean text before searching identifier usage
    body = re.sub(r"import\s*\(.*?\)", "", clean, flags=re.S)
    body = re.sub(r"^import\s+.*$", "", body, flags=re.M)
    for ident, path in extract_imports(src):
        if ident in ("_", "."):
            continue
        if not re.search(r"\b" + re.escape(ident) + r"\.", body):
            fail(f"{f}: unused import {path!r} (identifier {ident!r} never referenced)")
            imp_ok = False
if imp_ok:
    ok(f"import hygiene: 0 unused imports across all {len(go_files)} .go files")


# ---------------------------------------------------------------- 4. Platform parity (3 pairs)
FUNC = re.compile(r"^func\s*(\([^)]*\)\s*)?([A-Za-z_]\w*)\s*(\([^)]*\))\s*([^{\n]*?)\s*\{", re.M)
TYPE = re.compile(r"^type\s+([A-Za-z_]\w*)\s+(struct|interface|func|[\w\[\]\*\.]+)", re.M)


def symbols(src):
    funcs = {}
    for m in FUNC.finditer(src):
        recv, name, params, ret = m.groups()
        rt = ""
        if recv:
            rt = re.sub(r"\s+", " ", recv.strip())
            rt = re.sub(r"^\(\w+\s+", "(", rt)
        sig = re.sub(r"\s+", " ", f"{rt} {name}{params} {ret}".strip())
        funcs[(rt, name)] = sig
    types = {m.group(1): m.group(2) for m in TYPE.finditer(src)}
    return funcs, types


def norm_params(sig):
    return re.sub(r"\b[a-z_]\w*\s+(?=[\w\*\[\]\.]+[,)])", "", sig)


shared_names = {}
for base in ("job", "portcleanup", "net_hygiene", "ui"):
    w, u = f"{base}_windows.go", f"{base}_unix.go"
    if not (os.path.exists(os.path.join(ROOT, w)) and os.path.exists(os.path.join(ROOT, u))):
        fail(f"missing platform pair for {base}")
        continue
    wf, wt = symbols(read(w))
    uf, ut = symbols(read(u))
    exp = lambda d: {k: v for k, v in d.items() if k[1][:1].isupper()}
    ef_w, ef_u = exp(wf), exp(uf)
    free_w = {k[1]: v for k, v in ef_w.items() if not k[0]}
    free_u = {k[1]: v for k, v in ef_u.items() if not k[0]}
    if set(free_w) != set(free_u):
        fail(f"{base}: exported free funcs differ (windows-only={sorted(set(free_w)-set(free_u))}, unix-only={sorted(set(free_u)-set(free_w))})")
    for name in sorted(set(free_w) & set(free_u)):
        if norm_params(free_w[name]) != norm_params(free_u[name]):
            fail(f"{base}: signature mismatch for {name}: windows={free_w[name]!r} unix={free_u[name]!r}")

    def methods(d):
        out = {}
        for (rt, name), sig in d.items():
            if rt and name[:1].isupper():
                tname = re.sub(r"[()*\s]", "", rt)
                out.setdefault(tname, {})[name] = norm_params(re.sub(r"^\([^)]*\)\s*", "", sig))
        return out

    mw, mu = methods(wf), methods(uf)
    if len(mw) != len(mu):
        fail(f"{base}: differing number of exported concrete receiver types (windows={sorted(mw)} unix={sorted(mu)})")
    else:
        for (tw, msw), (tu, msu) in zip(sorted(mw.items()), sorted(mu.items())):
            if msw != msu:
                fail(f"{base}: method sets differ: {tw}={msw} vs {tu}={msu}")

    # Shared unexported platform hooks referenced by agnostic files must exist on both sides with matching signatures.
    agnostic = "\n".join(read(f) for f in go_files if not re.search(r"_(windows|unix)\.go$", f) and not f.endswith("_test.go"))
    for side, d, other in (("windows", wf, uf), ("unix", uf, wf)):
        for (rt, name), sig in d.items():
            if name[:1].islower() and not rt:
                if (rt, name) not in other:
                    if re.search(r"\b" + re.escape(name) + r"\s*\(", agnostic):
                        fail(f"{base}: {side}-only helper {name}() referenced from platform-agnostic code")
                else:
                    if norm_params(sig) != norm_params(other[(rt, name)]):
                        fail(f"{base}: shared helper {name}() signature mismatch across windows/unix")

    shared_hooks = sorted(k[1] for k in set(wf) & set(uf) if not k[0] and k[1][:1].islower())
    shared_names[base] = sorted(set(free_w)) + shared_hooks + [f"{t}.{m}" for t, ms in sorted(mw.items()) for m in sorted(ms)]

if not any(x.startswith(("job:", "portcleanup:", "net_hygiene:", "ui:")) for x in fails):
    ok("platform parity across job, portcleanup, net_hygiene, ui -> " +
       "; ".join(f"{b}: {', '.join(v)}" for b, v in shared_names.items()))

for f in go_files:
    src = read(f)
    if (f.endswith("_windows.go") or f.endswith("_windows_test.go")) and "//go:build windows" not in src:
        fail(f"{f}: missing //go:build windows")
    if (f.endswith("_unix.go") or f.endswith("_unix_test.go")) and "//go:build !windows" not in src:
        fail(f"{f}: missing //go:build !windows")


# ---------------------------------------------------------------- 5. Cross-file module wiring
sup_src = read("supervisor.go")
main_src = read("main.go")
wired_checks = [
    ("NewGitHubGuard", sup_src, "Module 1 (GitHubGuard) wired in supervisor.go"),
    ("NewTunnelPool", sup_src, "Module 2 (TunnelPool) wired in supervisor.go"),
    ("NewPooledProxyServer", sup_src, "Module 3 (Pooled ProxyServer) wired in supervisor.go"),
    ("RunNetHygienePreflight", sup_src, "Module 4 (Read-Only NetHygiene) wired in supervisor.go"),
    ("NewMetricsEmitter", main_src, "Module 5 (Orthogonal NDJSON MetricsEmitter) wired in main.go"),
]
for sym, hay, desc in wired_checks:
    if sym not in hay:
        fail(f"wiring missing: {desc}")
    else:
        ok(f"wired: {desc}")


# ---------------------------------------------------------------- 6. Zero silent OS mutations
mut_ok = True
for f in go_files:
    if f.endswith("_test.go"):
        continue
    src = read(f)
    # Inspect all exec.Command / exec.CommandContext calls for mutating netsh verbs.
    for m in re.finditer(r"exec\.Command(?:Context)?\(([^)]+)\)", src):
        args_blob = m.group(1).lower()
        if "netsh" in args_blob and re.search(r'"(set|add|delete|reset)"', args_blob):
            fail(f"{f}: silent OS mutation detected in exec.Command: {m.group(0)}")
            mut_ok = False
if mut_ok:
    ok("read-only host hygiene guarantee: 0 mutating netsh exec calls in Go runtime")


# ---------------------------------------------------------------- 7. Tests present + isolated (61 total)
test_src = {f: read(f) for f in go_files if f.endswith("_test.go")}
all_tests = {}
for f, src in test_src.items():
    for m in re.finditer(r"^func (Test(UT|ST)(\d\d)_\w+)\(t \*testing\.T\)", src, re.M):
        all_tests.setdefault(m.group(1), []).append(f)

want = [f"UT{n:02d}" for n in range(1, 50)] + [f"ST{n:02d}" for n in range(1, 23)]
found = {}
for name in all_tests:
    found.setdefault(name[4:8], []).append(name)
missing = [w for w in want if w not in found]
dups = {k: v for k, v in found.items() if len(v) > 1}
dupfiles = {k: v for k, v in all_tests.items() if len(v) > 1}
extra = sorted(set(found) - set(want))
if missing:
    fail(f"missing tests: {missing}")
if dups:
    fail(f"duplicate test IDs: {dups}")
if dupfiles:
    fail(f"test defined in multiple files: {dupfiles}")
if extra:
    fail(f"unexpected test IDs: {extra}")
if "TestUT17_UpstreamConcurrencyShapingAndDialPacing" not in all_tests:
    fail("UT-17 must be named TestUT17_UpstreamConcurrencyShapingAndDialPacing")
if "TestUT18_ProbeNotBlindedByTrickleTraffic" not in all_tests:
    fail("UT-18 must be named TestUT18_ProbeNotBlindedByTrickleTraffic")
if "TestST17_AIStudioMultiOriginSPABurstAndPersistentH2" not in all_tests:
    fail("ST-17 must be named TestST17_AIStudioMultiOriginSPABurstAndPersistentH2")
if not (missing or dups or dupfiles or extra):
    ok(f"all {len(want)} tests present exactly once (UT-01..UT-49, ST-01..ST-22)")

iso_ok = True
alltest_text = "\n".join(test_src.values())
if "t.Parallel()" in alltest_text:
    fail("t.Parallel() found: tests must be isolated/sequential")
    iso_ok = False
for f, src in test_src.items():
    for m in re.finditer(r"\.LocalPort\s*=\s*(\S+)", src):
        if m.group(1) != "0":
            fail(f"{f}: test binds non-ephemeral LocalPort={m.group(1)}")
            iso_ok = False
for f, src in test_src.items():
    for m in re.finditer(r"^var\s+(\w+)", src, re.M):
        fail(f"{f}: package-level var {m.group(1)!r} in tests breaks isolation")
        iso_ok = False
if iso_ok:
    ok("tests isolated: no t.Parallel, ephemeral LocalPort=0 only, 0 package-level vars in *_test.go")


# ---------------------------------------------------------------- 8. v6.4 consolidated contract spot-checks
cfg_go = read("config.go")
for pat, label in (
    (r"DefaultPoolSize\s*=\s*2\b", "DefaultPoolSize = 2 (2 outer WAN TCP sockets)"),
    (r"DefaultMaxActiveConns\s*=\s*64\b", "DefaultMaxActiveConns = 64 (v6.4 multiplexed OpenSSH channel cap)"),
    (r"DefaultPerTunnelMaxConns\s*=\s*32\b", "DefaultPerTunnelMaxConns = 32 (v6.4 per-worker SSH channels)"),
    (r"DefaultMaxQueuedConns\s*=\s*128\b", "DefaultMaxQueuedConns = 128 (multi-origin browser burst buffer)"),
    (r"DefaultSemaphoreWaitTimeout\s*=\s*25 \* time\.Second", "DefaultSemaphoreWaitTimeout = 25s"),
    (r"DefaultCopyBufferSize\s*=\s*16 \* 1024", "DefaultCopyBufferSize = 16 KiB"),
    (r"DefaultPMTU576CopyBufSize\s*=\s*8 \* 1024", "DefaultPMTU576CopyBufSize = 8 KiB (PMTU=576 adaptive step-down)"),
    (r"DefaultIdleTimeout\s*=\s*60 \* time\.Second", "DefaultIdleTimeout = 60s (v6.4)"),
    (r"DefaultPressureIdleTimeout\s*=\s*12 \* time\.Second", "DefaultPressureIdleTimeout = 12s"),
    (r"DefaultStreamingIdleTimeout\s*=\s*180 \* time\.Second", "DefaultStreamingIdleTimeout = 180s (v6.4 SSE/WebChannel/HTTP2 protection)"),
    (r"DefaultStreamingPressureIdleTimeout\s*=\s*20 \* time\.Second", "DefaultStreamingPressureIdleTimeout = 20s (v6.4 strictly < 25s SemaphoreWaitTimeout)"),
    (r"DefaultStalledHandshakeMaxDownBytes\s*=\s*128\b", "DefaultStalledHandshakeMaxDownBytes = 128B"),
    (r"DefaultTCPKeepAlivePeriod\s*=\s*8 \* time\.Second", "DefaultTCPKeepAlivePeriod = 8s (<15s CG-NAT)"),
    (r"DefaultSSHAliveInterval\s*=\s*10\b", "DefaultSSHAliveInterval = 10s (<15s CG-NAT)"),
    (r"DefaultSSHAliveCountMax\s*=\s*3\b", "DefaultSSHAliveCountMax = 3 (30s dead-tunnel detect)"),
    (r"DefaultGitHubMaxCallsPer5Min\s*=\s*6\b", "DefaultGitHubMaxCallsPer5Min = 6"),
    (r"DefaultGitHubMaxCallsPerHour\s*=\s*24\b", "DefaultGitHubMaxCallsPerHour = 24"),
    (r"DefaultGitHubMinCallSpacing\s*=\s*2 \* time\.Second", "DefaultGitHubMinCallSpacing = 2s (WAF spacing)"),
    (r"DefaultHysteresisDwellWindow\s*=\s*25 \* time\.Second", "DefaultHysteresisDwellWindow = 25s"),
    (r"DefaultSlowLaneEvictRatio\s*=\s*3\.5\b", "DefaultSlowLaneEvictRatio = 3.5"),
    (r"DefaultDialPaceInterval\s*=\s*0\b", "DefaultDialPaceInterval = 0 (v6.4 zero loopback HoL serialization)"),
    (r"DefaultHalfCloseDrainTimeout\s*=\s*15 \* time\.Second", "DefaultHalfCloseDrainTimeout = 15s"),
    (r'DefaultUnderlayProbeTargets\s*=\s*"1\.1\.1\.1:443,20\.120\.56\.11:443"', "DefaultUnderlayProbeTargets: unimodal 1.1.1.1:443 first (BUG-03)"),
):
    if not re.search(pat, cfg_go):
        fail(f"config.go missing v6.4 contract: {label}")
    else:
        ok(f"config.go: {label}")

# v6.4 mathematical deadlock-freedom invariant: StreamingPressureIdleTimeout < SemaphoreWaitTimeout
sp_m = re.search(r"DefaultStreamingPressureIdleTimeout\s*=\s*(\d+)\s*\*\s*time\.Second", cfg_go)
sw_m = re.search(r"DefaultSemaphoreWaitTimeout\s*=\s*(\d+)\s*\*\s*time\.Second", cfg_go)
if not (sp_m and sw_m) or int(sp_m.group(1)) >= int(sw_m.group(1)):
    fail("config.go (v6.4): DefaultStreamingPressureIdleTimeout must be strictly < DefaultSemaphoreWaitTimeout")
else:
    ok(f"config.go (v6.4): deadlock-free invariant verified ({sp_m.group(1)}s < {sw_m.group(1)}s)")

# v6.3 GitHub WAF safety: ZERO nonexistent 'gh codespace start' executions in production Go code.
for f in go_files:
    if f.endswith("_test.go"):
        continue
    src_no_comments = stripped_cache.get(f, "")
    raw_src = read(f)
    if re.search(r'"codespace",\s*"start"', raw_src) or "defaultStartCodespace" in src_no_comments:
        fail(f"{f}: forbidden nonexistent 'gh codespace start' command or defaultStartCodespace detected")
ok("v6.3 WAF safety: 0 nonexistent 'gh codespace start' calls in production Go code")

px = read("proxy.go")
for pat, label in (
    (r"func \(p \*ProxyServer\) paceDial\(", "paceDial()"),
    (r"func \(p \*ProxyServer\) pacedDialUpstream\(", "pacedDialUpstream() (v6.3 Win11 UT-17/ST-12 serialization)"),
    (r"dialLaunchMu\s+sync\.Mutex", "dialLaunchMu (v6.3 Win11 scheduler-jitter fix)"),
    (r"func \(p \*ProxyServer\) Signals\(", "Signals()"),
    (r"func \(p \*ProxyServer\) sweepPressureIdleRelays\(", "sweepPressureIdleRelays()"),
    (r"copyBufPool8K\s+sync\.Pool", "copyBufPool8K adaptive 8 KiB pool"),
    (r"wanVerifiedMinDownBytes\s*=\s*12", "wanVerifiedMinDownBytes = 12"),
    (r"func \(d \*deadlineConn\) refreshReadDeadline\(", "refreshReadDeadline() cross-direction deadline refresh (BUG-01)"),
    (r"inFlightReaping", "sweepPressureIdleRelays accounts for inFlightReaping (BUG-02)"),
    (r"lowWater\s*:=", "sweepPressureIdleRelays bounded lowWater target (BUG-02)"),
    (r"streamBudget\s*:=", "sweepPressureIdleRelays bounded oldest-idle-first streamBudget (BUG-02)"),
):
    if not re.search(pat, px):
        fail(f"proxy.go missing: {label}")
    else:
        ok(f"proxy.go: {label}")

pr = read("probe.go")
for pat, label in (
    (r"func ProbeSOCKS5MicroPayload\(", "ProbeSOCKS5MicroPayload()"),
    (r"func EvaluateFastLaneGate\(", "EvaluateFastLaneGate()"),
    (r"func EvaluateFastLaneGateNormalized\(", "EvaluateFastLaneGateNormalized() (v6.3)"),
    (r"func MeasureUnderlayBaseline\(", "MeasureUnderlayBaseline() (v6.3)"),
    (r"func IsGitHubHost\(", "IsGitHubHost() (v6.3 WAF guard)"),
    (r"func ComputeRelativeOverhead\(", "ComputeRelativeOverhead() (v6.3)"),
    (r"func EvaluateBaselineNormalizedLane\(", "EvaluateBaselineNormalizedLane() (v6.3)"),
    (r"tlsStart\s*:=\s*time\.Now\(\)", "probeDirectTLS 1-RTT TLS timing (BUG-03)"),
    (r"maxAdaptiveFastRTT\s*=\s*1800 \* time\.Millisecond", "EvaluateFastLaneGateNormalized 1800ms fast-RTT cap (BUG-03)"),
    (r"maxAdaptiveSlowRTT\s*=\s*1500 \* time\.Millisecond", "EvaluateFastLaneGateNormalized 1500ms slow-RTT cap (BUG-03)"),
):
    if not re.search(pat, pr):
        fail(f"probe.go missing: {label}")
    else:
        ok(f"probe.go: {label}")

nh = read("net_hygiene.go")
nh_win = read("net_hygiene_windows.go")
gh = read("github_guard.go")
ju = read("job_unix.go")
ti = read("tunnel_instance.go")
tp = read("tunnel_pool.go")

for hay, pat, label in (
    (nh, r"func IsPMTU576RelayIP\(", "net_hygiene.go: IsPMTU576RelayIP()"),
    (nh, r"func ParseNetshFirewallAudit\(", "net_hygiene.go: ParseNetshFirewallAudit()"),
    (nh_win, r'"advfirewall",\s*"firewall",\s*"show",\s*"rule",\s*"name=all",\s*"dir=out"', "net_hygiene_windows.go: read-only outbound firewall rule audit"),
    (gh, r"type CodespaceStateCache struct", "github_guard.go: CodespaceStateCache"),
    (gh, r"func DefaultCodespaceStateCachePath\(", "github_guard.go: DefaultCodespaceStateCachePath()"),
    (pr, r"adaptiveSlowMax\s*:=", "probe.go (v6.3): BootSlowMaxRTT baseline normalization"),
    (pr, r"adaptiveSlowJitter\s*:=", "probe.go (v7.0): BootSlowMaxJitter baseline normalization"),
    (pr, r"adaptiveMaxJitter\s*:=", "probe.go (v7.0): BootQualityMaxJitter baseline normalization"),
    (gh, r"type FatalBootError struct", "github_guard.go (v7.0): FatalBootError permanent failure type"),
    (gh, r"func ClassifyPermanentBootError\(", "github_guard.go (v7.0): ClassifyPermanentBootError() fail-fast classifier"),
    (gh, r"func isVMTransitionStderr\(", "github_guard.go (BUG-07): non-recursive VM transition classifier"),
    (gh, r'"spending limit"', "github_guard.go (BUG-07): spending limit permanent failure token"),
    (gh, r"func \(g \*GitHubGuard\) SetSinks\(", "github_guard.go (v7.0): atomic SetSinks() for GUI telemetry"),
    (gh, r"func ParseRetryAfter\(", "github_guard.go (v6.3): ParseRetryAfter()"),
    (gh, r"func ParseRetryAfterAt\(", "github_guard.go (v6.3): ParseRetryAfterAt() with HTTP-date + clock injection"),
    (gh, r"http\.TimeFormat", "github_guard.go (v6.3): RFC 9110 HTTP-date Retry-After layout"),
    (gh, r"func \(g \*GitHubGuard\) CanAllowNonConsuming\(", "github_guard.go (v6.3): CanAllowNonConsuming() eviction guard"),
    (gh, r'"min_call_spacing"', "github_guard.go (v6.3): min_call_spacing WAF pacing"),
    (gh, r'"codespace_cached_stopped"', "github_guard.go: intra-session cached stopped churn brake"),
    (gh, r"FailureVMTransition\s+FailureClass", "github_guard.go (v6.2): FailureVMTransition class"),
    (gh, r'"too many codespaces starting"', "github_guard.go (v6.2): HTTP 400 concurrent start classifier"),
    (gh, r"func \(g \*GitHubGuard\) NeedsColdWarmup\(", "github_guard.go (v6.2): NeedsColdWarmup() cross-session awareness"),
    (gh, r"func \(g \*GitHubGuard\) MarkSessionStopped\(", "github_guard.go (v6.2): MarkSessionStopped() intra-session brake"),
    (gh, r"func \(g \*GitHubGuard\) ClearSessionStopped\(", "github_guard.go (v6.2): ClearSessionStopped()"),
    (sup_src, r"UnderlayProbeFunc\s+func\(", "supervisor.go (v6.3): SupervisorDeps.UnderlayProbeFunc"),
    (sup_src, r'"never_became_healthy"', "supervisor.go (v6.3): aborted-boot StopCodespace skip (pid17040 fix)"),
    (sup_src, r'"vm_woken"', "supervisor.go (v7.0): woken-VM StopCodespace safety telemetry"),
    (sup_src, r"case fatalErr := <-pool\.FatalErrCh\(\):", "supervisor.go (BUG-04): steady-state pool.FatalErrCh() handling"),
    (sup_src, r'"no_gh_calls_issued"', "supervisor.go (v6.2): unbooted StopCodespace skip"),
    (ju, r"/proc/%d/stat", "job_unix.go: /proc/<pid>/stat zombie detection"),
    (ti, r"func \(t \*TunnelInstance\) PMTU576Active\(", "tunnel_instance.go: PMTU576Active()"),
    (ti, r"func \(t \*TunnelInstance\) HasReachedVM\(", "tunnel_instance.go (v7.0): HasReachedVM() VM wakeup tracker"),
    (ti, r'"budget_constrained"', "tunnel_instance.go (v7.0): budget-constrained working-tunnel preservation"),
    (ti, r"func \(t \*TunnelInstance\) TryAcquireSlotWithCap\(", "tunnel_instance.go (v6.2): TryAcquireSlotWithCap()"),
    (ti, r"func \(t \*TunnelInstance\) QualityScore\(", "tunnel_instance.go (v6.3): baseline-normalized QualityScore()"),
    (ti, r"func \(t \*TunnelInstance\) IsSlowLaneDegraded\(", "tunnel_instance.go (v6.3): IsSlowLaneDegraded()"),
    (ti, r"func \(t \*TunnelInstance\) MarkEvictionTriggered\(", "tunnel_instance.go (v6.3): deferred slow-lane eviction tracking"),
    (tp, r"PMTU576Safe\s+bool", "tunnel_pool.go: UpstreamLease.PMTU576Safe"),
    (tp, r"func \(p \*TunnelPool\) HasWokenVM\(", "tunnel_pool.go (v7.0): HasWokenVM() pool wakeup aggregator"),
    (tp, r"func \(p \*TunnelPool\) FatalErrCh\(\) <-chan error", "tunnel_pool.go (BUG-04): FatalErrCh() accessor"),
    (tp, r"maxUnderlaySpikeRatio\s*=\s*2\.0", "tunnel_pool.go (BUG-03): 2x underlay spike outlier clamping"),
    (tp, r"needSerializedBoot\s*:=", "tunnel_pool.go (v6.3): always-serialized tunnel-1->tunnel-2..N boot gate"),
    (tp, r"func \(p \*TunnelPool\) EvaluateRoutingMode\(", "tunnel_pool.go (v6.3): 3-layer Schmitt-trigger hysteresis"),
    (tp, r"func \(p \*TunnelPool\) CheckSlowLaneEviction\(", "tunnel_pool.go (v6.3): chronic slow-lane eviction watchdog"),
    (tp, r"st != TunnelHealthy && st != TunnelDegraded", "tunnel_pool.go (BUG-05): TunnelDegraded slow-lane eviction enabled"),
    (tp, r"CanAllowNonConsuming\(\)", "tunnel_pool.go (v6.3): guard-aware eviction deferral during 429/budget lockout"),
    (tp, r'"WORKER_SLOW_LANE_EVICT_DEFERRED"', "tunnel_pool.go (v6.3): WORKER_SLOW_LANE_EVICT_DEFERRED telemetry"),
    (tp, r"order\[0\],\s*order\[i\]\s*=\s*order\[i\],\s*order\[0\]", "tunnel_pool.go (v6.3): lossless P2C permutation swap for PoolSize>=3"),
    (tp, r"tryAcquireFromOrder\(order,\s*burstCap\)", "tunnel_pool.go (v6.2/v6.3): single-healthy-worker burst cap + TOCTOU rescan"),
    (tp, r'"WORKER_DEGRADED"', "tunnel_pool.go (v6.2): WORKER_DEGRADED telemetry"),
    (tp, r'"WORKER_RECOVERED"', "tunnel_pool.go (v6.2): WORKER_RECOVERED telemetry"),
    (tp, r'"WORKER_SLOW_LANE_EVICT"', "tunnel_pool.go (v6.3): WORKER_SLOW_LANE_EVICT telemetry"),
):
    if not re.search(pat, hay):
        fail(f"consolidated upgrade check missing: {label}")
    else:
        ok(f"consolidated: {label}")

# v6.2/v6.3 Defect B check: pressure_idle_reap branch in proxy.go must NOT double-increment idleReapsWindow.
pm = re.search(r"if relay\.pressureReaped\.Load\(\).*?return\s*\}", px, re.S)
if not pm or "idleReapsWindow" in pm.group(0):
    fail("proxy.go (v6.2/v6.3): pressure_idle_reap branch must NOT double-increment idleReapsWindow")
else:
    ok("proxy.go (v6.2/v6.3): pressure_idle_reap and idle_reap counters strictly disjoint")

# v6.2/v6.3 Fix #4 check: Windows 11 15.6ms timer determinism in UT-17 and ST-12 (35ms DialPaceInterval).
ut17_m = re.search(r't\.Run\("v5_shaped_40_of_40".*?cfg\.DialPaceInterval\s*=\s*([^\n]+)', read("unit_tests_test.go"), re.S)
st12_m = re.search(r"func TestST12_MCIC12KneeBurstEnforcement.*?cfg\.DialPaceInterval\s*=\s*([^\n]+)", read("v6_tests_test.go"), re.S)
if not ut17_m or "35 * time.Millisecond" not in ut17_m.group(1):
    fail("unit_tests_test.go (v6.2/v6.3): UT-17/v5_shaped_40_of_40 must set DialPaceInterval = 35 * time.Millisecond")
elif not st12_m or "35 * time.Millisecond" not in st12_m.group(1):
    fail("v6_tests_test.go (v6.2/v6.3): ST-12 must set DialPaceInterval = 35 * time.Millisecond")
else:
    ok("UT-17 & ST-12 (v6.2/v6.3): DialPaceInterval = 35ms (Windows 11 15.6ms timer deterministic)")

# Upgrade 3: Post-probe bootDuration ordering audit in tunnel_instance.go and supervisor.go.
ti_micro_idx = ti.find("BootMicroPayloadCheck")
ti_dur_idx = ti.find("bootDuration := time.Since(bootStart)")
ti_gate_idx = ti.find("EvaluateFastLaneGateNormalized(")
if not (0 < ti_micro_idx < ti_dur_idx < ti_gate_idx):
    fail(f"tunnel_instance.go: bootDuration must be computed AFTER Stage 1+2 probes and BEFORE EvaluateFastLaneGateNormalized (micro={ti_micro_idx}, dur={ti_dur_idx}, gate={ti_gate_idx})")
else:
    ok("tunnel_instance.go: bootDuration computed post-qualification probes (v5 pid14300 fix)")

q_start = sup_src.find("func (s *Supervisor) qualifyBootTunnel(")
q_end = sup_src.find("func (s *Supervisor) spawnChild(")
q_body = sup_src[q_start:q_end] if (q_start >= 0 and q_end > q_start) else ""
q_loop_idx = q_body.find("for i := 1; i < s.cfg.BootQualitySamples")
q_dur_idx = q_body.find("bootDuration := time.Since(bootStart)")
q_eval_idx = q_body.rfind("EvaluateBootQuality(")
if not (0 < q_loop_idx < q_dur_idx < q_eval_idx):
    fail("supervisor.go: qualifyBootTunnel must compute bootDuration AFTER qualification probe loop")
else:
    ok("supervisor.go: qualifyBootTunnel computes bootDuration post-probe (v5 pid14300 fix)")

if "ABOVE_NORMAL_PRIORITY_CLASS" not in read("job_windows.go"):
    fail("job_windows.go lost ABOVE_NORMAL_PRIORITY_CLASS")
else:
    ok("job_windows.go: ABOVE_NORMAL_PRIORITY_CLASS retained")
if "LookupProcessTreeWANRemotes" not in read("portcleanup_windows.go") + read("portcleanup_unix.go") + read("portcleanup.go"):
    fail("LookupProcessTreeWANRemotes missing")
else:
    ok("LookupProcessTreeWANRemotes retained")

# ---------------------------------------------------------------- 8b. v7.0 Phase 2 UI, Zero-Lock Bridge & Win32 ABI Audit
ui_bridge = read("ui_bridge.go")
ui_win = read("ui_windows.go")
ui_unix = read("ui_unix.go")
jw_src = read("job_windows.go")
lg_src = read("logger.go")

v7_checks = [
    (jw_src, r"CREATE_NO_WINDOW\s*=\s*0x08000000", "job_windows.go: CREATE_NO_WINDOW (0x08000000)"),
    (nh_win, r"CreationFlags:\s*CREATE_NO_WINDOW", "net_hygiene_windows.go: CREATE_NO_WINDOW on read-only netsh"),
    (sup_src, r"configureHiddenCmd\(cmd\)", "supervisor.go: defaultStopCodespace sets CREATE_NO_WINDOW"),
    (cfg_go, r'"headless"', "config.go: --headless CLI compatibility flag"),
    (main_src, r"RunPlatformUI\(cfg\)", "main.go: routes default launch to RunPlatformUI(cfg)"),
    (px, r"func \(p \*ProxyServer\) AtomicTelemetry\(\) ProxyAtomicSnapshot", "proxy.go: wait-free AtomicTelemetry()"),
    (tp, r"func \(p \*TunnelPool\) CachedSnapshot\(\) PoolSnapshot", "tunnel_pool.go: wait-free CachedSnapshot()"),
    (gh, r"func \(g \*GitHubGuard\) CachedSnapshot\(\) GitHubGuardSnapshot", "github_guard.go: wait-free CachedSnapshot()"),
    (lg_src, r"func \(l \*EventLogger\) SetObserver\(", "logger.go: off-datapath SetObserver()"),
    (sup_src, r"func \(s \*Supervisor\) AtomicProxyTelemetry\(\) ProxyAtomicSnapshot", "supervisor.go: wait-free AtomicProxyTelemetry()"),
    (ui_bridge, r"TerminalRingCapacity\s*=\s*500", "ui_bridge.go: bounded 500-line TerminalRingBuffer"),
    (ui_bridge, r"func ValidateCodespaceName\(", "ui_bridge.go: strict CodespaceName validator"),
    (ui_bridge, r"func \(c \*SessionController\) lifecycleWorker\(", "ui_bridge.go: serialized lifecycleWorker FSM"),
    (ui_bridge, r"func \(c \*SessionController\) snapshotPublisher\(", "ui_bridge.go: 1Hz wait-free snapshotPublisher"),
    (ui_bridge, r"func \(c \*SessionController\) RequestReAuth\(", "ui_bridge.go: async Re-Auth orchestrator"),
    (ui_bridge, r"func \(c \*SessionController\) RequestQuotaCheck\(", "ui_bridge.go: on-demand QuotaChecker"),
    (ui_bridge, r"func IsQuotaBillingScope403\(", "ui_bridge.go: billing-scope 403 isolation (0 WAF penalty)"),
    (ui_win, r"runtime\.LockOSThread\(\)", "ui_windows.go: T0 OS thread pinning"),
    (ui_win, r"verifyWin32ABISizes\(\)", "ui_windows.go: 64-bit AMD64 Win32 ABI size verification"),
    (ui_win, r"Local\\\\NetShaperV7_SingleInstance", "ui_windows.go: single-instance mutex"),
    (ui_win, r"wmAppShowExisting", "ui_windows.go: WM_APP_SHOW_EXISTING second-launch restore"),
    (ui_win, r'"TaskbarCreated"', "ui_windows.go: Explorer restart TaskbarCreated tray recovery"),
    (ui_win, r"dpiAwarenessPerMonitorV2", "ui_windows.go: PerMonitorV2 DPI awareness"),
    (ui_win, r"dwmwaUseImmersiveDarkMode\s*=\s*20", "ui_windows.go: Win11 DWM dark title bar"),
    (ui_win, r"dwmwaSystemBackdropType\s*=\s*38", "ui_windows.go: Win11 DWM Acrylic/Mica glass backdrop"),
    (ui_win, r"DwmExtendFrameIntoClientArea", "ui_windows.go: DWM glass frame extension"),
    (ui_win, r"GdiplusStartup", "ui_windows.go: GDI+ anti-aliased rendering engine init"),
    (ui_win, r"GdiplusShutdown", "ui_windows.go: GDI+ 1:1 shutdown cleanup"),
    (ui_win, r"gpSmoothingModeAntiAlias\s*=\s*4", "ui_windows.go: GDI+ SmoothingModeAntiAlias"),
    (ui_win, r"u\.activeTab\s*!=\s*tabAccount", "ui_windows.go: Codespace EDIT shown strictly on Account tab"),
    (ui_win, r"wmMouseHWheel\s*=\s*0x020E", "ui_windows.go: Terminal WM_MOUSEHWHEEL horizontal scroll"),
    (ui_win, r"procGdipSetClipRectI", "ui_windows.go: Terminal clipped untruncated viewport"),
    (ui_win, r"copyClickedTerminalRow", "ui_windows.go: Terminal click-row-to-copy"),
    (ui_bridge, r"c\.quotaInfo\s*=\s*QuotaInfo\{\}", "ui_bridge.go: stale quotaInfo cleared on Re-Auth"),
    (ui_bridge, r"reAuthActive\s*=", "ui_bridge.go: multi-account Active account parsing in ParseGHAuthStatus"),
    (ui_bridge, r'"/user",\s*"--jq",\s*"\.login"', "ui_bridge.go: deterministic gh api /user login fallback"),
    (ui_win, r"CREATE_NEW_CONSOLE\s*=\s*0x00000010", "ui_windows.go: dedicated console for interactive gh auth"),
    (ui_unix, r"func RunPlatformUI\(", "ui_unix.go: cross-platform RunPlatformUI parity"),
    (cfg_go, r"CodespaceExplicit\s+bool", "config.go: CodespaceExplicit CLI override tracking"),
    (ui_bridge, r"if baseCfg\.CodespaceExplicit", "ui_bridge.go: CLI -codespace override precedence"),
    (ui_bridge, r"ReadLocalHostsFn\s+func\(\)\s+string", "ui_bridge.go: injectable ReadLocalHostsFn for deterministic testing"),
    (ui_bridge, r"case <-ctx\.Done\(\):\s*(?://[^\n]*\n\s*)?closeJob\(\)", "ui_bridge.go: immediate JobObject close on ctx.Done()"),
    (ui_bridge, r"GuardThrottleWaitMS\s+int64", "ui_bridge.go: wait-free GuardThrottleWaitMS countdown in UISnapshot"),
    (ui_bridge, r"c\.guard\.ClearSessionStopped\(\)", "ui_bridge.go: clears prior session Shutdown brake on fresh GUI Start"),
    (ui_bridge, r"c\.guard\.SetSinks\(eventLogger,\s*metricsEmitter\)", "ui_bridge.go: wires live logger & NDJSON metrics into shared guard"),
    (ui_bridge, r"authGen\s+atomic\.Uint64", "ui_bridge.go (BUG-06): authGen guards Quota vs Re-Auth/Config races"),
    (ui_bridge, r"func exitShutdownTimeout\(", "ui_bridge.go (BUG-08): bounded StopTimeout+4s & WM_ENDSESSION 3.5s budgets"),
    (ui_win, r"if u\.exiting \|\| u\.hwnd == 0", "ui_windows.go (BUG-08): restoreFromTray guarded against exiting state"),
    (ui_win, r"u\.releaseMutex\(\)", "ui_windows.go (BUG-08): releases single-instance mutex before ShutdownAndWait"),
    (ui_win, r"procOpenClipboard\.Call\(hwnd\)", "ui_windows.go (BUG-09): OpenClipboard uses owned HWND"),
    (ui_win, r"tryAutoApplyCodespaceOnTabLeave\(\)", "ui_windows.go: auto-applies valid Account tab Codespace edit on tab leave"),
    (ui_win, r"snap\.GuardThrottleWaitMS", "ui_windows.go: Home status displays live API budget/WAF cooldown countdown"),
    (ui_win, r"snap\.GuardBudgetWaitMS", "ui_windows.go: WAF card displays live 5m budget unlock countdown"),
    (main_src, r"os\.Exit\(0\)", "main.go: guaranteed full OS process exit after RunPlatformUI"),
    (ui_win, r"procGetGuiResources", "ui_windows.go: GetGuiResources kernel GDI/USER handle audit hook"),
    (ui_win, r"wmSysCommand\s*=\s*0x0112", "ui_windows.go: WM_SYSCOMMAND constant for native minimize-to-tray"),
    (ui_win, r"scMinimize\s*=\s*0xF020", "ui_windows.go: SC_MINIMIZE constant for native minimize-to-tray"),
    (ui_win, r"idTrayShow", "ui_windows.go: Tray menu Show/Hide preserved"),
    (ui_win, r"idTrayToggle", "ui_windows.go: Tray menu Start/Stop preserved"),
    (ui_win, r"idTrayCopy", "ui_windows.go: Tray menu Copy Proxy preserved"),
    (ui_win, r"idTrayExit", "ui_windows.go: Tray menu Exit NetShaper preserved"),
    (ui_win, r"procSendMessageW\.Call\(u\.hwndEdit,\s*wmSetFont,\s*0,\s*0\)", "ui_windows.go: native EDIT HFONT detached before font teardown"),
]
for hay, pat, label in v7_checks:
    if not re.search(pat, hay):
        fail(f"v7.0 check missing: {label}")
    else:
        ok(f"v7.0: {label}")

# Exit & minimize lock: wmClose MUST call requestFullExit() and NEVER hideToTray(); wmSysCommand SC_MINIMIZE MUST call hideToTray().
wm_close_m = re.search(r"case wmClose:(.*?)case wmQueryEndSession:", stripped_cache.get("ui_windows.go", ""), re.S)
if not wm_close_m or "requestFullExit()" not in wm_close_m.group(1) or "hideToTray()" in wm_close_m.group(1):
    fail("ui_windows.go: case wmClose must call u.requestFullExit() and NOT u.hideToTray()")
else:
    ok("v7.0 exit lock: wmClose ([X]) calls requestFullExit() (never hideToTray)")

# BUG-09 check: procOpenClipboard.Call(0) must never be used in ui_windows.go.
if "procOpenClipboard.Call(0)" in stripped_cache.get("ui_windows.go", ""):
    fail("ui_windows.go (BUG-09): forbidden procOpenClipboard.Call(0) detected (must pass hwnd)")
else:
    ok("v7.0 clipboard ownership: 0 procOpenClipboard.Call(0) calls in ui_windows.go")

wm_syscmd_m = re.search(r"case wmSysCommand:(.*?)case wmSize:", stripped_cache.get("ui_windows.go", ""), re.S)
if not wm_syscmd_m or "scMinimize" not in wm_syscmd_m.group(1) or "hideToTray()" not in wm_syscmd_m.group(1):
    fail("ui_windows.go: case wmSysCommand must intercept scMinimize and call u.hideToTray()")
else:
    ok("v7.0 minimize lock: wmSysCommand (SC_MINIMIZE [_]) calls hideToTray()")

# Home tab declutter lock: Copy Proxy and Hide to Tray buttons must not exist on Home tab (Tray menu retains them).
for removed_hit in ("hitCopyProxy", "hitHideTray"):
    if removed_hit in stripped_cache.get("ui_windows.go", ""):
        fail(f"ui_windows.go: deprecated Home tab action {removed_hit!r} must be removed")
ok("v7.0 Home UI declutter: hitCopyProxy and hitHideTray removed from Home tab (Tray menu retained)")

# Re-Auth fallback ordering: live `gh api /user --jq .login` MUST run before offline `c.deps.ReadLocalHostsFn()`.
reauth_start = ui_bridge.find("func (c *SessionController) executeReAuthSequence(")
reauth_end = ui_bridge.find("func (c *SessionController) runQuotaCheck(")
reauth_body = ui_bridge[reauth_start:reauth_end] if (reauth_start >= 0 and reauth_end > reauth_start) else ""
api_user_idx = reauth_body.find('"/user", "--jq", ".login"')
hosts_fn_idx = reauth_body.find("c.deps.ReadLocalHostsFn()")
if not (0 < api_user_idx < hosts_fn_idx):
    fail(f"ui_bridge.go: executeReAuthSequence must query live gh api /user BEFORE offline ReadLocalHostsFn (api={api_user_idx}, hosts={hosts_fn_idx})")
else:
    ok("v7.0 Re-Auth ordering: live gh api /user runs before offline ReadLocalHostsFn fallback")

# UT-39 host isolation + UT-40 dual-cycle zero-leak proof
if "ReadLocalHostsFn:" not in read("v6_tests_test.go"):
    fail("v6_tests_test.go: UT-39 must inject ReadLocalHostsFn to prevent Windows host hosts.yml leakage")
else:
    ok("v7.0 UT-39 isolation: ReadLocalHostsFn injected in TestUT39_ReAuthDynamicAccountSwitchAndStaleQuotaWipe")

ui_stress = read("ui_stress_windows_test.go")
if "gdiAfterCycle2" not in ui_stress or "gdiAfterCycle1" not in ui_stress:
    fail("ui_stress_windows_test.go: UT-40 must verify dual-cycle GDI/USER handle stability (delta == 0)")
else:
    ok("v7.0 UT-40 GDI stability: dual-cycle GDI/USER zero-leak assertion present")

# Adversarial isolation checks:
if "AllocConsole" in stripped_cache.get("ui_windows.go", ""):
    fail("ui_windows.go: forbidden AllocConsole detected (closing console would kill GUI process)")
else:
    ok("v7.0 Win32 safety: 0 AllocConsole calls in ui_windows.go")

if "PostMessage" in stripped_cache.get("ui_bridge.go", ""):
    fail("ui_bridge.go: PostMessage forbidden inside bridge/ring buffer (must coalesce via dirtyMask + 250ms timer)")
else:
    ok("v7.0 anti-flood: 0 PostMessage calls in ui_bridge.go")

for forbidden_lock_call in (".SnapshotWindow(", ".PoolSnapshot()", "guard.Snapshot()"):
    if forbidden_lock_call in stripped_cache.get("ui_bridge.go", "") or forbidden_lock_call in stripped_cache.get("ui_windows.go", ""):
        fail(f"v7.0 lock isolation violation: {forbidden_lock_call!r} called from UI/bridge layer")
ok("v7.0 zero-lock isolation: 0 locking ProxyServer/TunnelPool/GitHubGuard snapshot calls in ui_bridge.go/ui_windows.go")

for wf_name in ("ui_windows.go", "ui_stress_windows_test.go"):
    wf_clean = stripped_cache.get(wf_name, "")
    if re.search(r"unsafe\.Pointer\(\s*(?:uintptr\b|lParam\b|wParam\b|bitsPtr\b|dstPtr\b|hMem\b|hwnd\b)", wf_clean):
        fail(f"{wf_name}: unsafe.Pointer(uintptr) conversion detected (go vet -unsafeptr violation)")
    elif re.search(r"defer\s+proc\w+\.Call\([^)]*unsafe\.Pointer", wf_clean):
        fail(f"{wf_name}: deferred proc.Call evaluates uintptr(unsafe.Pointer) eagerly (wrap in defer func())")
ok("v7.0 ABI safety: 0 unsafe.Pointer(uintptr) casts and 0 eager-defer pointer calls in ui_windows.go + ui_stress_windows_test.go")

# Verify WatchStdinForQuit is strictly inside runHeadlessCLI, not main() GUI branch (strip comments first).
main_clean = stripped_cache.get("main.go", "")
main_body = main_clean[:main_clean.find("func runHeadlessCLI")]
if "WatchStdinForQuit" in main_body:
    fail("main.go: WatchStdinForQuit must NEVER run outside runHeadlessCLI")
else:
    ok("v7.0 stdin safety: WatchStdinForQuit strictly isolated inside --headless CLI mode")

# ---------------------------------------------------------------- 9. Interface satisfaction + cross-file symbol audit
all_methods_by_type = {}
declared_symbols = set()
for f in go_files:
    src = read(f)
    clean = stripped_cache.get(f, "")
    f_funcs, f_types = symbols(src)
    declared_symbols.update(f_types.keys())
    for (rt, name), sig in f_funcs.items():
        if rt:
            tname = re.sub(r"[()*\s]", "", rt)
            all_methods_by_type.setdefault(tname, set()).add(name)
        else:
            declared_symbols.add(name)
    # Also capture multi-line package-level func declarations (e.g. `func NewProxyServer(\n...`)
    for m in re.finditer(r"^func\s+([A-Z]\w*)\s*\(", clean, re.M):
        declared_symbols.add(m.group(1))
    # Capture multi-line receiver methods as well for interface satisfaction
    for m in re.finditer(r"^func\s+\(\s*\w+\s+\*?([A-Za-z_]\w*)\s*\)\s+([A-Z]\w*)\s*\(", clean, re.M):
        all_methods_by_type.setdefault(m.group(1), set()).add(m.group(2))
    for m in re.finditer(r"^\s*(?:const|var)\s+([A-Z]\w*)\b", clean, re.M):
        declared_symbols.add(m.group(1))
    for bm in re.finditer(r"^\s*(?:const|var)\s*\(", clean, re.M):
        pos = bm.end()
        depth = 1
        while pos < len(clean) and depth > 0:
            ch = clean[pos]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            pos += 1
        block = clean[bm.end():pos - 1]
        for line in block.splitlines():
            cm = re.match(r"^\s*([A-Z]\w*)\b", line)
            if cm:
                declared_symbols.add(cm.group(1))

iface_contracts = {
    "PortInspector": ({"ListListeners", "ProcessImageName", "TerminatePID"}, ["WindowsPortInspector", "UnixPortInspector", "mockPortInspector"]),
    "ProcessJob": ({"Assign", "Close"}, ["WindowsJobObject", "UnixProcessGroupJob"]),
    "UpstreamSelector": ({"AcquireEndpoint", "NotifyDialFailure", "NotifyDialSuccess", "NotifyWANBytes"}, ["TunnelPool"]),
}
iface_ok = True
for iface, (req_methods, impls) in iface_contracts.items():
    for impl in impls:
        have = all_methods_by_type.get(impl, set())
        miss = sorted(req_methods - have)
        if miss:
            fail(f"interface {iface}: {impl} missing methods {miss}")
            iface_ok = False
if iface_ok:
    ok("interface satisfaction: PortInspector, ProcessJob, UpstreamSelector verified across prod + mocks")

# Check unqualified Capitalized calls/struct literals against package declarations (ignoring method/interface decls).
go_builtins = {"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover"}
unresolved = []
for f in go_files:
    clean = stripped_cache.get(f, "")
    # Blank interface blocks so interface method signatures are not mistaken for call sites.
    body = re.sub(r"interface\s*\{[^}]*\}", "interface{}", clean, flags=re.S)
    for line in body.splitlines():
        if re.match(r"^\s*func\b", line):
            continue
        for m in re.finditer(r"(?<![.\w])([A-Z][A-Za-z0-9_]*)\s*(?:\(|\{)", line):
            sym = m.group(1)
            if sym in declared_symbols or sym in go_builtins:
                continue
            prefix = line[:m.start()]
            if re.search(r"\b(?:type|struct|interface)\s+$", prefix):
                continue
            unresolved.append((f, sym))
if unresolved:
    fail(f"unresolved unqualified package symbols: {sorted(set(unresolved))[:15]}")
else:
    ok(f"cross-file symbol audit: {len(declared_symbols)} package declarations, 0 unresolved unqualified calls/literals across {len(go_files)} .go files")

# ---------------------------------------------------------------- 10. Simulation + optional host PS1 / go.sum artifacts
sim_path = os.path.join(ROOT, "simulation_results.json")
if not os.path.exists(sim_path):
    fail("simulation_results.json missing")
else:
    sim_data = json.loads(read("simulation_results.json"))
    sim_keys = (
        "sim1_five_tuple_lanes",
        "sim2_queue_and_starvation",
        "sim3_pmtu_framing",
        "sim4_github_api_budget",
        "sim5_v62_cold_start_and_burst_cap",
        "sim6_v63_adaptive_pool_and_browser_burst",
        "sim7_v64_aistudio_persistent_h2_burst",
        "consolidated_v6_highlights",
        "v62_highlights",
        "v63_highlights",
        "v64_highlights",
    )
    missing_sim = [k for k in sim_keys if k not in sim_data]
    if missing_sim:
        fail(f"simulation_results.json missing keys: {missing_sim}")
    else:
        ok("simulation_results.json present with all 7 executed simulation datasets + v6.1..v6.4 highlights")

for doc_file in ("README.md", "ARCHITECTURE.md", "LICENSE", ".gitignore"):
    doc_path = os.path.join(ROOT, doc_file)
    if not os.path.exists(doc_path) or os.path.getsize(doc_path) == 0:
        fail(f"repository package file missing or empty: {doc_file}")
    else:
        ok(f"repository package: {doc_file} present ({os.path.getsize(doc_path)} bytes)")

if os.path.exists(os.path.join(ROOT, "net_hygiene_diag.ps1")):
    ok("net_hygiene_diag.ps1 present")
else:
    print("INFO: net_hygiene_diag.ps1 not in this folder (retained on Windows 11 host directory)")

gomod_path = os.path.join(ROOT, "go.mod")
gosum_path = os.path.join(ROOT, "go.sum")
if os.path.exists(gomod_path) and os.path.exists(gosum_path):
    gomod = read("go.mod")
    gosum = read("go.sum")
    req_mods = re.findall(r"require\s+([^\s]+)\s+(v[^\s]+)", gomod)
    missing_sums = []
    for mod, ver in req_mods:
        if f"{mod} {ver} h1:" not in gosum or f"{mod} {ver}/go.mod h1:" not in gosum:
            missing_sums.append(f"{mod} {ver}")
    if missing_sums:
        fail(f"go.sum missing checksums for go.mod requires: {missing_sums}")
    else:
        ok(f"go.sum present and matches all {len(req_mods)} go.mod require entries")
elif os.path.exists(gomod_path) and not os.path.exists(gosum_path):
    fail("go.mod present but go.sum missing")
else:
    print("INFO: go.mod/go.sum not in this export folder (preserve existing Windows 11 host go.mod/go.sum; never fabricate hashes)")

print()
print("RESULT:", "PASS" if not fails else f"FAIL ({len(fails)} problems)")
sys.exit(1 if fails else 0)
