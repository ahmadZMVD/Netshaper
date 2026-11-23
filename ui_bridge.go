package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Dirty-flag bitmask coalescing background updates into the 250ms UI repaint timer.
// Background goroutines NEVER invoke PostMessageW per log line or telemetry tick.
const (
	DirtyNone      uint32 = 0
	DirtyTelemetry uint32 = 1 << 0
	DirtyLogs      uint32 = 1 << 1
	DirtyAuth      uint32 = 1 << 2
	DirtyQuota     uint32 = 1 << 3
	DirtyConfig    uint32 = 1 << 4
	DirtyAll       uint32 = DirtyTelemetry | DirtyLogs | DirtyAuth | DirtyQuota | DirtyConfig
)

const (
	TerminalRingCapacity = 500
	TerminalMaxLineBytes = 256
	uiConfigFileName     = "netshaper_ui.json"
	defaultQuotaTimeout  = 10 * time.Second
	defaultSnapInterval  = 1 * time.Second
)

// LogSeverity classifies terminal ring lines for crisp visual hierarchy.
type LogSeverity uint8

const (
	LogInfo LogSeverity = iota
	LogSuccess
	LogWarn
	LogError
)

// TerminalLine is one bounded, UTF-8-safe entry stored inside TerminalRingBuffer.
type TerminalLine struct {
	Seq       uint64
	Timestamp string
	Severity  LogSeverity
	Text      string
}

// TerminalRingBuffer provides O(1) bounded memory (max 500 lines x <=256B = ~152 KB)
// with a private leaf mutex and atomic dirty-flag coalescing (0 Win32 messages per log line).
type TerminalRingBuffer struct {
	mu      sync.Mutex
	lines   [TerminalRingCapacity]TerminalLine
	head    int
	count   int
	nextSeq uint64
	dirty   *atomic.Uint32
}

// NewTerminalRingBuffer constructs a fixed-capacity ring buffer wired to dirtyMask.
func NewTerminalRingBuffer(dirtyMask *atomic.Uint32) *TerminalRingBuffer {
	if dirtyMask == nil {
		dirtyMask = &atomic.Uint32{}
	}
	return &TerminalRingBuffer{dirty: dirtyMask}
}

// truncateUTF8 cleans newlines/control characters and truncates s to <= maxBytes on a UTF-8 rune boundary.
func truncateUTF8(s string, maxBytes int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if maxBytes < 4 || len(s) <= maxBytes {
		return s
	}
	limit := maxBytes - 3
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + "..."
}

// Append stores one formatted line in O(1) time/memory and sets DirtyLogs atomically.
func (rb *TerminalRingBuffer) Append(sev LogSeverity, text string) {
	rb.AppendAt(time.Now(), sev, text)
}

// AppendAt stores one formatted line with an explicit timestamp (deterministic for unit tests).
func (rb *TerminalRingBuffer) AppendAt(ts time.Time, sev LogSeverity, text string) {
	if rb == nil {
		return
	}
	clean := truncateUTF8(text, TerminalMaxLineBytes)
	if clean == "" {
		return
	}
	entry := TerminalLine{
		Timestamp: ts.Format("15:04:05"),
		Severity:  sev,
		Text:      clean,
	}
	rb.mu.Lock()
	rb.nextSeq++
	entry.Seq = rb.nextSeq
	if rb.count < TerminalRingCapacity {
		idx := (rb.head + rb.count) % TerminalRingCapacity
		rb.lines[idx] = entry
		rb.count++
	} else {
		rb.lines[rb.head] = entry
		rb.head = (rb.head + 1) % TerminalRingCapacity
	}
	rb.mu.Unlock()

	if rb.dirty != nil {
		rb.dirty.Or(DirtyLogs)
	}
}

// SnapshotInto copies buffered lines oldest-to-newest into dst (reusing capacity) with 0 core locks.
func (rb *TerminalRingBuffer) SnapshotInto(dst []TerminalLine) []TerminalLine {
	if rb == nil {
		return dst[:0]
	}
	rb.mu.Lock()
	n := rb.count
	if cap(dst) < n {
		dst = make([]TerminalLine, n)
	} else {
		dst = dst[:n]
	}
	for i := 0; i < n; i++ {
		dst[i] = rb.lines[(rb.head+i)%TerminalRingCapacity]
	}
	rb.mu.Unlock()
	return dst
}

// Len returns the current number of retained lines (always in 0..TerminalRingCapacity).
func (rb *TerminalRingBuffer) Len() int {
	if rb == nil {
		return 0
	}
	rb.mu.Lock()
	n := rb.count
	rb.mu.Unlock()
	return n
}

// TotalAppended returns the monotonic count of all lines ever appended (including evicted entries).
func (rb *TerminalRingBuffer) TotalAppended() uint64 {
	if rb == nil {
		return 0
	}
	rb.mu.Lock()
	seq := rb.nextSeq
	rb.mu.Unlock()
	return seq
}

// Clear empties the terminal ring buffer and marks the log viewport dirty.
func (rb *TerminalRingBuffer) Clear() {
	if rb == nil {
		return
	}
	rb.mu.Lock()
	rb.head = 0
	rb.count = 0
	rb.mu.Unlock()
	if rb.dirty != nil {
		rb.dirty.Or(DirtyLogs)
	}
}

// FormatLogRecord converts an EventLogger record into a concise human-readable terminal line.
func FormatLogRecord(rec LogRecord) (LogSeverity, string) {
	sev := LogInfo
	ev := rec.Event
	f := rec.Fields

	strField := func(k string) string {
		if f == nil {
			return ""
		}
		if v, ok := f[k]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	switch ev {
	case "STATE_TRANSITION":
		to := strField("to")
		if to == string(StateHealthy) {
			sev = LogSuccess
		} else if to == string(StateDegraded) || to == string(StateReconnecting) {
			sev = LogWarn
		}
		return sev, fmt.Sprintf("[Supervisor] %s -> %s", strField("from"), to)
	case "BOOT_READY":
		sev = LogSuccess
		if mode := strField("mode"); mode == "multi_tunnel_pool" {
			return sev, fmt.Sprintf("[Ready] %s | pool=%s/%s | route=%s | underlay=%sms",
				strField("local_addr"), strField("healthy_workers"), strField("pool_size"),
				strField("routing_mode"), strField("underlay_baseline_ms"))
		}
		return sev, fmt.Sprintf("[Ready] %s | p50=%sms | wan=%s",
			strField("local_addr"), strField("boot_quality_p50_ms"), strField("gh_wan_remote"))
	case "SESSION_START":
		return LogInfo, fmt.Sprintf("[Start] codespace=%s local=:%s pool=%s max_ch=%s",
			strField("codespace"), strField("local_port"), strField("pool_size"), strField("max_conns"))
	case "SHUTDOWN_COMPLETE":
		sev = LogInfo
		skip := strField("stop_skipped_reason")
		if skip != "" {
			return sev, fmt.Sprintf("[Stop] done (%s) | codespace stop skipped: %s", strField("reason"), skip)
		}
		if strField("stop_codespace_invoked") == "true" {
			if errStr := strField("stop_error"); errStr != "" {
				return LogWarn, fmt.Sprintf("[Stop] done (%s) | codespace stop err: %s", strField("reason"), errStr)
			}
			return LogSuccess, fmt.Sprintf("[Stop] done (%s) | codespace stopped (%sms)", strField("reason"), strField("stop_duration_ms"))
		}
		return sev, fmt.Sprintf("[Stop] shutdown complete (%s)", strField("reason"))
	case "POOL_WORKER_FAILOVER":
		return LogWarn, fmt.Sprintf("[Pool] failover %s (:%s) reason=%s healthy_peers=%s",
			strField("tunnel_id"), strField("port"), strField("reason"), strField("healthy_peers"))
	case "POOL_PRIMARY_SWITCH":
		return LogInfo, fmt.Sprintf("[Route] %s -> %s (%s)", strField("from"), strField("to"), strField("reason"))
	case "WORKER_DEGRADED", "DEGRADED_TRIP":
		return LogWarn, fmt.Sprintf("[Degraded] %s reason=%s", strField("tunnel_id"), strField("reason"))
	case "WORKER_RECOVERED", "RECOVERY_FROM_DEGRADED":
		return LogSuccess, fmt.Sprintf("[Recovered] %s rtt=%sms", strField("tunnel_id"), strField("recovery_probe_rtt_ms"))
	case "WORKER_SLOW_LANE_EVICT":
		return LogWarn, fmt.Sprintf("[Pool] slow-lane evict %s rtt=%sms rho=%s",
			strField("tunnel_id"), strField("ewma_rtt_ms"), strField("relative_rho"))
	case "WORKER_SLOW_LANE_EVICT_DEFERRED":
		return LogWarn, fmt.Sprintf("[Pool] slow-lane evict deferred (%s) for %s", strField("defer_reason"), strField("tunnel_id"))
	case "GITHUB_API_BACKOFF":
		return LogError, fmt.Sprintf("[WAF Guard] backoff class=%s cooldown=%sms", strField("failure_class"), strField("cooldown_ms"))
	case "GITHUB_API_THROTTLED":
		return LogWarn, fmt.Sprintf("[WAF Guard] throttled (%s) wait=%sms 5m=%s 1h=%s",
			strField("block_reason"), strField("wait_ms"), strField("calls_last_5m"), strField("calls_last_hour"))
	case "SEMAPHORE_SATURATED":
		return LogWarn, fmt.Sprintf("[Proxy] saturated (%s) active=%s/%s queued=%s",
			strField("reason"), strField("active_conns"), strField("max_conns"), strField("queued_conns"))
	case "CHILD_START_ERROR", "LISTEN_BIND_ERROR", "BOOT_TIMEOUT", "ZOMBIE_BREAKER_TRIP":
		return LogError, fmt.Sprintf("[%s] %s %s", ev, strField("reason"), strField("error"))
	case "FATAL_BOOT_ERROR":
		return LogError, fmt.Sprintf("[Fatal] %s", strField("message"))
	case "BOOT_QUALITY_REJECT":
		return LogWarn, fmt.Sprintf("[BootGate] rejected %s (%s) p50=%sms jitter=%sms rho=%s",
			strField("tunnel_id"), strField("reason"), strField("p50_ms"), strField("jitter_ms"), strField("relative_rho"))
	case "BOOT_QUALITY_ACCEPTED_BEST_EFFORT":
		return LogWarn, fmt.Sprintf("[BootGate] best-effort %s (%s) p50=%sms rho=%s",
			strField("tunnel_id"), strField("reason"), strField("p50_ms"), strField("relative_rho"))
	case "POOL_SUMMARY":
		return LogInfo, fmt.Sprintf("[Stats] workers=%s/%s p50=%sms active=%s up=%skbps down=%skbps",
			strField("healthy_workers"), strField("pool_size"), strField("aggregate_p50_ms"),
			strField("active_conns"), strField("throughput_up_kbps"), strField("throughput_down_kbps"))
	default:
		if errStr := strField("error"); errStr != "" {
			return LogWarn, fmt.Sprintf("[%s] %s", ev, errStr)
		}
		if reason := strField("reason"); reason != "" {
			return LogInfo, fmt.Sprintf("[%s] %s", ev, reason)
		}
		return LogInfo, fmt.Sprintf("[%s]", ev)
	}
}

// -----------------------------------------------------------------------------
// Portable UI Config & Strict Codespace Name Validation
// -----------------------------------------------------------------------------

var codespaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$`)

// ValidateCodespaceName enforces strict GitHub Codespace naming and blocks flag injection (leading '-').
func ValidateCodespaceName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("codespace name cannot be empty")
	}
	if trimmed != name {
		return errors.New("codespace name must not have leading or trailing whitespace")
	}
	if strings.HasPrefix(trimmed, "-") {
		return errors.New("codespace name must not start with '-'")
	}
	if !codespaceNameRe.MatchString(trimmed) {
		return errors.New("codespace name must be 2..128 alphanumeric/._- characters")
	}
	return nil
}

// UIConfig holds portable user UI preferences stored in netshaper_ui.json next to NetShaper.exe.
type UIConfig struct {
	CodespaceName  string `json:"codespace_name"`
	MinimizeToTray bool   `json:"minimize_to_tray"`
	LastAccount    string `json:"last_account,omitempty"`
}

// DefaultUIConfig returns portable defaults seeded with defaultCodespace.
func DefaultUIConfig(defaultCodespace string) UIConfig {
	if strings.TrimSpace(defaultCodespace) == "" {
		defaultCodespace = DefaultCodespaceName
	}
	return UIConfig{
		CodespaceName:  strings.TrimSpace(defaultCodespace),
		MinimizeToTray: true,
	}
}

// ResolveUIConfigPaths returns the preferred portable exe-adjacent path and %AppData%/UserConfigDir fallback.
func ResolveUIConfigPaths() (primary string, fallback string) {
	primary = ResolveLogPath(uiConfigFileName)
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	fallback = filepath.Join(dir, "NetShaper", uiConfigFileName)
	return primary, fallback
}

// LoadUIConfig loads netshaper_ui.json from explicitPath (if non-empty) or portable exe-adjacent / fallback path.
func LoadUIConfig(defaultCodespace string, explicitPath string) (UIConfig, string) {
	def := DefaultUIConfig(defaultCodespace)
	var candidates []string
	if strings.TrimSpace(explicitPath) != "" {
		candidates = []string{explicitPath}
	} else {
		p, fb := ResolveUIConfigPaths()
		candidates = []string{p, fb}
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var parsed UIConfig
		if err := json.Unmarshal(data, &parsed); err != nil {
			continue
		}
		if err := ValidateCodespaceName(strings.TrimSpace(parsed.CodespaceName)); err != nil {
			parsed.CodespaceName = def.CodespaceName
		} else {
			parsed.CodespaceName = strings.TrimSpace(parsed.CodespaceName)
		}
		return parsed, path
	}
	return def, candidates[0]
}

func writeJSONAtomic(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// SaveUIConfig atomically persists netshaper_ui.json to preferredPath (falling back to %AppData%\NetShaper if read-only).
func SaveUIConfig(cfg UIConfig, preferredPath string) (string, error) {
	if err := ValidateCodespaceName(cfg.CodespaceName); err != nil {
		return "", err
	}
	primary, fallback := ResolveUIConfigPaths()
	target := strings.TrimSpace(preferredPath)
	if target == "" {
		target = primary
	}
	if err := writeJSONAtomic(target, cfg); err == nil {
		return target, nil
	} else if target == fallback {
		return "", err
	}
	if err := writeJSONAtomic(fallback, cfg); err != nil {
		return "", err
	}
	return fallback, nil
}

// -----------------------------------------------------------------------------
// Controller FSM, Immutable UI Snapshot, Re-Auth & On-Demand Quota Checker
// -----------------------------------------------------------------------------

// ControllerState is the serialized lifecycle FSM owned solely by SessionController.
type ControllerState string

const (
	CtrlStopped   ControllerState = "STOPPED"
	CtrlStarting  ControllerState = "STARTING"
	CtrlRunning   ControllerState = "RUNNING"
	CtrlDegraded  ControllerState = "DEGRADED"
	CtrlStopping  ControllerState = "STOPPING"
	CtrlReauthing ControllerState = "REAUTHING"
)

// AuthInfo summarizes local GitHub CLI authentication status.
type AuthInfo struct {
	LoggedIn   bool
	Username   string
	Scopes     string
	CheckedAt  time.Time
	StatusText string
	Error      string
}

// QuotaInfo summarizes strictly on-demand Codespaces machine tier and optional billing usage.
type QuotaInfo struct {
	Checked           bool
	Loading           bool
	CheckedAt         time.Time
	CodespaceName     string
	CodespaceState    string
	MachineName       string
	MachineDisplay    string
	CPUs              int
	MemoryGB          int
	StorageGB         int
	BillingAvailable  bool
	CoreHoursUsed     float64
	CoreHoursIncluded float64
	BillingNote       string
	SessionDuration   time.Duration
	GuardBlocked      string
	Error             string
}

// UISnapshot is a 100% immutable value snapshot read wait-free by the Win32 UI thread T0.
type UISnapshot struct {
	State            ControllerState
	SupervisorState  SupervisorState
	CodespaceName    string
	LocalAddr        string
	PoolSize         int
	HealthyWorkers   int
	DegradedWorkers  int
	RoutingMode      string
	PrimaryTunnelID  string
	LatencyP50MS     float64
	UnderlayMS       float64
	ActiveConns      int64
	PeakConns        int64
	MaxActiveConns   int
	QueuedConns      int64
	SemaphoreRejects uint64
	BytesUp          uint64
	BytesDown        uint64
	SessionStartedAt time.Time
	Uptime           time.Duration
	GuardCalls5Min      int
	GuardMax5Min        int
	GuardCallsHour      int
	GuardMaxHour        int
	GuardCooldownMS     int64
	GuardBudgetWaitMS   int64
	GuardThrottleWaitMS int64
	GuardThrottleReason string
	GuardRateLimits     int64
	Workers          []TunnelSnapshot
	LastError        string
	Auth             AuthInfo
	Quota            QuotaInfo
	CanEditCodespace bool
	ConfigPath       string
}

// ControllerDeps enables deterministic dependency injection for unit/chaos testing without network calls.
type ControllerDeps struct {
	SupervisorDepsFactory func(cfg Config, guard *GitHubGuard, metrics *MetricsEmitter) SupervisorDeps
	OpenLogger            func(cfg Config) (*EventLogger, error)
	OpenMetrics           func(cfg Config, sessionID string) (*MetricsEmitter, error)
	RunInteractiveGH      func(ctx context.Context, args ...string) (int, error)
	RunSilentGH           func(ctx context.Context, args ...string) (stdout string, stderr string, exitCode int, err error)
	ReadLocalHostsFn      func() string
	UIConfigPath          string
	CachePath             string
	SnapshotInterval      time.Duration
	QuotaTimeout          time.Duration
	NowFn                 func() time.Time
	OnStateTransition     func(ControllerState)
}

// SessionController strictly decouples the Win32 UI from Supervisor, TunnelPool, ProxyServer, and GitHubGuard.
// All Supervisor creation, Run(ctx), teardown joins (<-runDoneCh), and Re-Auth run on ONE serialized lifecycleWorker.
type SessionController struct {
	deps  ControllerDeps
	guard *GitHubGuard // Single process-lifetime GitHubGuard (immune to rapid Start/Stop spam)

	cfgMu      sync.RWMutex
	baseCfg    Config
	uiCfg      UIConfig
	uiCfgPath  string
	lastErr    string
	authInfo   AuthInfo
	quotaInfo  QuotaInfo
	ctrlState  ControllerState
	sessionAt  time.Time

	// Private leaf lock solely for cancelling the active Supervisor run (never touched by ProxyServer/TunnelPool).
	runMu           sync.Mutex
	activeSupRef    *Supervisor
	activeRunCancel context.CancelFunc

	// Monotonic generation counter & leaf-locked cancel func isolating in-flight Quota checks from Re-Auth / Config edits.
	authGen        atomic.Uint64
	quotaCancelMu  sync.Mutex
	quotaCancel    context.CancelFunc
	quotaCancelGen uint64

	// Wait-free atomic bridge read by snapshotPublisher and Win32 thread T0.
	activeSup  atomic.Pointer[Supervisor]
	latestSnap atomic.Pointer[UISnapshot]
	dirtyMask  atomic.Uint32
	logs       *TerminalRingBuffer

	desiredRunning  atomic.Bool
	desiredGen      atomic.Uint64
	reauthRequested atomic.Bool
	quotaBusy       atomic.Bool
	shuttingDown    atomic.Bool

	wakeCh     chan struct{}
	snapWakeCh chan struct{}
	stopCtx    context.Context
	stopCancel context.CancelFunc
	wg         sync.WaitGroup
	startOnce  sync.Once
	closeOnce  sync.Once
}

// exitShutdownTimeout computes the bounded ShutdownAndWait budget for interactive exit
// (StopTimeout + 4s headroom for dead-WAN StopCodespace + JobObject + log flush) versus
// Windows OS logoff/shutdown (WM_ENDSESSION, capped at 3500ms below WaitToKillAppTimeout=5s).
func exitShutdownTimeout(stopTimeout time.Duration, endSession bool) time.Duration {
	if endSession {
		return 3500 * time.Millisecond
	}
	if stopTimeout <= 0 {
		stopTimeout = DefaultStopTimeout
	}
	return stopTimeout + 4*time.Second
}

// NewSessionController initializes the decoupled UI bridge with one shared process-lifetime GitHubGuard.
func NewSessionController(baseCfg Config, deps ControllerDeps) *SessionController {
	if baseCfg.CodespaceCachePath == "" {
		if deps.CachePath != "" {
			baseCfg.CodespaceCachePath = deps.CachePath
		} else {
			baseCfg.CodespaceCachePath = DefaultCodespaceStateCachePath()
		}
	}
	uiCfg, cfgPath := LoadUIConfig(baseCfg.CodespaceName, deps.UIConfigPath)
	if baseCfg.CodespaceExplicit {
		if err := ValidateCodespaceName(strings.TrimSpace(baseCfg.CodespaceName)); err == nil {
			baseCfg.CodespaceName = strings.TrimSpace(baseCfg.CodespaceName)
			uiCfg.CodespaceName = baseCfg.CodespaceName
		}
	} else if err := ValidateCodespaceName(uiCfg.CodespaceName); err == nil {
		baseCfg.CodespaceName = uiCfg.CodespaceName
	}

	if deps.SnapshotInterval <= 0 {
		deps.SnapshotInterval = defaultSnapInterval
	}
	if deps.QuotaTimeout <= 0 {
		deps.QuotaTimeout = defaultQuotaTimeout
	}
	if deps.NowFn == nil {
		deps.NowFn = time.Now
	}
	if deps.OpenLogger == nil {
		deps.OpenLogger = func(cfg Config) (*EventLogger, error) {
			return NewEventLogger(ResolveLogPath(cfg.LogFile))
		}
	}
	if deps.OpenMetrics == nil {
		deps.OpenMetrics = func(cfg Config, sessionID string) (*MetricsEmitter, error) {
			if cfg.MetricsFile == "" {
				return nil, nil
			}
			return NewMetricsEmitter(ResolveLogPath(cfg.MetricsFile), sessionID)
		}
	}
	if deps.RunInteractiveGH == nil {
		deps.RunInteractiveGH = defaultRunInteractiveGH
	}
	if deps.RunSilentGH == nil {
		deps.RunSilentGH = defaultRunSilentGH
	}
	if deps.ReadLocalHostsFn == nil {
		deps.ReadLocalHostsFn = ReadLocalGHHostsUsername
	}

	// Single process-lifetime GitHubGuard shared across all Supervisor runs and manual Quota checks.
	guard := NewGitHubGuard(baseCfg, nil, nil)

	stopCtx, stopCancel := context.WithCancel(context.Background())
	c := &SessionController{
		deps:       deps,
		guard:      guard,
		baseCfg:    baseCfg,
		uiCfg:      uiCfg,
		uiCfgPath:  cfgPath,
		ctrlState:  CtrlStopped,
		wakeCh:     make(chan struct{}, 1),
		snapWakeCh: make(chan struct{}, 1),
		stopCtx:    stopCtx,
		stopCancel: stopCancel,
	}
	c.logs = NewTerminalRingBuffer(&c.dirtyMask)

	// Passive local disk read of GitHub CLI hosts.yml — 0 network calls, 0 gh subprocess spawns!
	if user := deps.ReadLocalHostsFn(); user != "" {
		c.authInfo = AuthInfo{
			LoggedIn:   true,
			Username:   user,
			StatusText: "Authenticated (local gh config)",
		}
	} else if uiCfg.LastAccount != "" {
		c.authInfo = AuthInfo{
			LoggedIn:   true,
			Username:   uiCfg.LastAccount,
			StatusText: "Last saved account",
		}
	} else {
		c.authInfo = AuthInfo{
			LoggedIn:   false,
			StatusText: "Not verified — click Switch Account / Re-Auth",
		}
	}

	c.logs.Append(LogInfo, fmt.Sprintf("[UI] NetShaper v7.0 ready | codespace=%s | proxy=%s | pool=%d",
		baseCfg.CodespaceName, baseCfg.LocalAddr(), baseCfg.PoolSize))
	c.publishSnapshotNow()
	return c
}

// Start launches the serialized lifecycleWorker and 1Hz wait-free snapshotPublisher.
func (c *SessionController) Start() {
	c.startOnce.Do(func() {
		c.wg.Add(2)
		go c.lifecycleWorker()
		go c.snapshotPublisher()
	})
}

// Logs returns the bounded O(1) terminal ring buffer.
func (c *SessionController) Logs() *TerminalRingBuffer {
	return c.logs
}

// Guard returns the single process-lifetime GitHubGuard instance.
func (c *SessionController) Guard() *GitHubGuard {
	return c.guard
}

// Snapshot returns the latest immutable UISnapshot with 0 mutex acquisitions.
func (c *SessionController) Snapshot() UISnapshot {
	if ptr := c.latestSnap.Load(); ptr != nil {
		return *ptr
	}
	return UISnapshot{State: CtrlStopped, CanEditCodespace: true}
}

// ConsumeDirty atomically returns and clears all pending UI dirty flags.
func (c *SessionController) ConsumeDirty() uint32 {
	return c.dirtyMask.Swap(DirtyNone)
}

// DirtyMask returns the current pending UI dirty flags without clearing them.
func (c *SessionController) DirtyMask() uint32 {
	return c.dirtyMask.Load()
}

func (c *SessionController) signalWake() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

func (c *SessionController) signalSnapshot() {
	select {
	case c.snapWakeCh <- struct{}{}:
	default:
	}
}

func (c *SessionController) setCtrlState(st ControllerState) {
	c.cfgMu.Lock()
	changed := c.ctrlState != st
	c.ctrlState = st
	c.cfgMu.Unlock()
	c.publishSnapshotNow()
	if changed && c.deps.OnStateTransition != nil {
		c.deps.OnStateTransition(st)
	}
}

func (c *SessionController) setLastError(msg string) {
	c.cfgMu.Lock()
	c.lastErr = msg
	c.cfgMu.Unlock()
	c.publishSnapshotNow()
}

// RequestStart queues a non-blocking start intent coalesced into desiredRunning.
func (c *SessionController) RequestStart() {
	if c.shuttingDown.Load() {
		return
	}
	if c.reauthRequested.Load() {
		c.logs.Append(LogWarn, "[UI] Re-Auth is in progress; wait for authentication to finish")
		return
	}
	c.desiredRunning.Store(true)
	c.desiredGen.Add(1)
	c.signalWake()
}

// RequestStop immediately signals shutdown to any active Supervisor and clears desiredRunning.
func (c *SessionController) RequestStop() {
	c.desiredRunning.Store(false)
	c.desiredGen.Add(1)
	c.cancelActiveRun("ui_stop")
	c.signalWake()
}

// ToggleStartStop toggles desired running state cleanly from UI button or tray menu.
func (c *SessionController) ToggleStartStop() {
	snap := c.Snapshot()
	if snap.State == CtrlStopped && !c.desiredRunning.Load() {
		c.RequestStart()
		return
	}
	c.RequestStop()
}

func (c *SessionController) cancelActiveRun(reason string) {
	c.runMu.Lock()
	sup := c.activeSupRef
	cancel := c.activeRunCancel
	c.runMu.Unlock()

	if sup != nil {
		sup.RequestShutdown(reason)
	}
	if cancel != nil {
		cancel()
	}
}

func (c *SessionController) setQuotaCancel(gen uint64, cancel context.CancelFunc) {
	c.quotaCancelMu.Lock()
	prev := c.quotaCancel
	c.quotaCancel = cancel
	c.quotaCancelGen = gen
	c.quotaCancelMu.Unlock()
	if prev != nil {
		prev()
	}
}

func (c *SessionController) clearQuotaCancel(gen uint64) {
	c.quotaCancelMu.Lock()
	if c.quotaCancelGen == gen {
		c.quotaCancel = nil
	}
	c.quotaCancelMu.Unlock()
}

func (c *SessionController) cancelInFlightQuota() {
	c.quotaCancelMu.Lock()
	cancel := c.quotaCancel
	c.quotaCancel = nil
	c.quotaCancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SetCodespaceName validates, persists to netshaper_ui.json, and updates active Config + GitHubGuard cache.
// Strictly rejected while a tunnel session is active so start/stop codespace names can never drift.
func (c *SessionController) SetCodespaceName(name string) error {
	trimmed := strings.TrimSpace(name)
	if err := ValidateCodespaceName(trimmed); err != nil {
		c.logs.Append(LogError, "[Config] Invalid codespace name: "+err.Error())
		return err
	}

	c.cfgMu.Lock()
	if c.ctrlState != CtrlStopped || c.desiredRunning.Load() {
		c.cfgMu.Unlock()
		err := errors.New("stop the active tunnel before changing Codespace name")
		c.logs.Append(LogWarn, "[Config] "+err.Error())
		return err
	}
	c.baseCfg.CodespaceName = trimmed
	c.uiCfg.CodespaceName = trimmed
	c.lastErr = ""
	c.quotaInfo = QuotaInfo{}
	c.authGen.Add(1)
	uiCfgCopy := c.uiCfg
	prefPath := c.uiCfgPath
	cachePath := c.baseCfg.CodespaceCachePath
	c.cfgMu.Unlock()

	c.cancelInFlightQuota()
	savedPath, saveErr := SaveUIConfig(uiCfgCopy, prefPath)
	if saveErr != nil {
		c.logs.Append(LogWarn, fmt.Sprintf("[Config] Updated in memory (disk save failed: %v)", saveErr))
	} else {
		c.cfgMu.Lock()
		c.uiCfgPath = savedPath
		c.cfgMu.Unlock()
		c.logs.Append(LogSuccess, fmt.Sprintf("[Config] Codespace set to %s (saved %s)", trimmed, filepath.Base(savedPath)))
	}

	// Re-bind persistent warm-state cache to the new codespace name immediately.
	if c.guard != nil && strings.TrimSpace(cachePath) != "" {
		c.guard.SetStateCache(NewCodespaceStateCache(trimmed, cachePath))
	}
	c.dirtyMask.Or(DirtyConfig | DirtyQuota)
	c.publishSnapshotNow()
	return nil
}

// RequestReAuth triggers asynchronous account switch / re-auth on lifecycleWorker (never blocks UI thread T0).
func (c *SessionController) RequestReAuth() error {
	if c.shuttingDown.Load() {
		return errors.New("controller shutting down")
	}
	if !c.reauthRequested.CompareAndSwap(false, true) {
		return errors.New("re-auth already in progress")
	}
	c.authGen.Add(1)
	c.cancelInFlightQuota()
	c.desiredRunning.Store(false)
	c.desiredGen.Add(1)
	c.cancelActiveRun("ui_reauth")
	c.logs.Append(LogInfo, "[Auth] Switch Account / Re-Auth requested — stopping active tunnel...")
	c.signalWake()
	return nil
}

// RequestQuotaCheck executes a strictly manual, GitHubGuard-gated Codespace quota/machine query.
// Zero background timers ever invoke this function.
func (c *SessionController) RequestQuotaCheck() bool {
	if c.shuttingDown.Load() {
		return false
	}
	if !c.quotaBusy.CompareAndSwap(false, true) {
		return false
	}

	gen := c.authGen.Load()
	qParentCtx, qParentCancel := context.WithCancel(c.stopCtx)
	c.setQuotaCancel(gen, qParentCancel)

	c.cfgMu.Lock()
	if c.authGen.Load() != gen {
		c.cfgMu.Unlock()
		c.clearQuotaCancel(gen)
		qParentCancel()
		c.quotaBusy.Store(false)
		return false
	}
	c.quotaInfo.Loading = true
	c.quotaInfo.Error = ""
	c.quotaInfo.GuardBlocked = ""
	c.cfgMu.Unlock()
	c.dirtyMask.Or(DirtyQuota)
	c.publishSnapshotNow()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() {
			c.clearQuotaCancel(gen)
			qParentCancel()
			c.quotaBusy.Store(false)
		}()
		c.runQuotaCheck(qParentCtx, gen)
	}()
	return true
}

// ShutdownAndWait performs a bounded ordered shutdown of any active Supervisor and exits background workers.
func (c *SessionController) ShutdownAndWait(timeout time.Duration) {
	c.closeOnce.Do(func() {
		c.shuttingDown.Store(true)
		c.desiredRunning.Store(false)
		c.desiredGen.Add(1)
		c.cancelInFlightQuota()
		c.cancelActiveRun("ui_exit")
		c.signalWake()
		c.stopCancel()

		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()
		if timeout <= 0 {
			timeout = 14 * time.Second
		}
		select {
		case <-done:
		case <-time.After(timeout):
		}
	})
}

// -----------------------------------------------------------------------------
// Serialized Lifecycle Worker (ONLY goroutine allowed to run Supervisor / Re-Auth)
// -----------------------------------------------------------------------------

func (c *SessionController) lifecycleWorker() {
	defer c.wg.Done()

	for {
		if c.shuttingDown.Load() {
			c.setCtrlState(CtrlStopped)
			return
		}

		if c.reauthRequested.Load() {
			c.executeReAuthSequence()
			continue
		}

		if c.desiredRunning.Load() {
			c.runSingleSupervisorSession()
			continue
		}

		select {
		case <-c.wakeCh:
		case <-c.stopCtx.Done():
			c.setCtrlState(CtrlStopped)
			return
		}
	}
}

func (c *SessionController) runSingleSupervisorSession() {
	c.cfgMu.RLock()
	cfg := c.baseCfg
	c.cfgMu.RUnlock()

	if err := ValidateCodespaceName(cfg.CodespaceName); err != nil {
		c.desiredRunning.Store(false)
		c.setLastError(err.Error())
		c.logs.Append(LogError, "[Start] Aborted: "+err.Error())
		c.setCtrlState(CtrlStopped)
		return
	}

	// In production GUI mode (no mock SupervisorDepsFactory), fail fast with 0 API calls
	// if the unconfigured placeholder "my-codespace" is still set.
	if c.deps.SupervisorDepsFactory == nil && strings.EqualFold(cfg.CodespaceName, DefaultCodespaceName) && !cfg.CodespaceExplicit {
		msg := "Set Codespace name in Account tab first"
		c.desiredRunning.Store(false)
		c.setLastError(msg)
		c.logs.Append(LogError, "[Start] Aborted: placeholder 'my-codespace' is not configured — enter your Codespace name in Account tab and click Apply")
		c.setCtrlState(CtrlStopped)
		return
	}

	c.setLastError("")
	c.setCtrlState(CtrlStarting)

	// Starting a brand-new user session clears any previous session's Shutdown churn brake
	// while strictly preserving sliding 5m/1h API budgets and active WAF 429 cooldowns.
	if c.guard != nil {
		c.guard.ClearSessionStopped()
		if strings.TrimSpace(cfg.CodespaceCachePath) != "" {
			c.guard.SetStateCache(NewCodespaceStateCache(cfg.CodespaceName, cfg.CodespaceCachePath))
		}
	}

	eventLogger, err := c.deps.OpenLogger(cfg)
	if err != nil {
		c.desiredRunning.Store(false)
		c.setLastError("log open failed: " + err.Error())
		c.logs.Append(LogError, "[Start] Unable to open log file: "+err.Error())
		c.setCtrlState(CtrlStopped)
		return
	}
	// Attach off-datapath observer invoked strictly on EventLogger.writerLoop().
	eventLogger.SetObserver(func(rec LogRecord) {
		sev, line := FormatLogRecord(rec)
		c.logs.Append(sev, line)
	})

	var metricsEmitter *MetricsEmitter
	if c.deps.OpenMetrics != nil {
		if m, mErr := c.deps.OpenMetrics(cfg, eventLogger.SessionID()); mErr == nil {
			metricsEmitter = m
		}
	}
	if c.guard != nil {
		c.guard.SetSinks(eventLogger, metricsEmitter)
		defer c.guard.SetSinks(nil, nil)
		if gs := c.guard.CachedSnapshot(); gs.ThrottleWaitMS > 0 {
			c.logs.Append(LogWarn, fmt.Sprintf("[WAF Guard] Waiting %s (%s) before spawning gh",
				FormatDurationShort(time.Duration(gs.ThrottleWaitMS)*time.Millisecond), gs.ThrottleReason))
		}
	}

	var supDeps SupervisorDeps
	if c.deps.SupervisorDepsFactory != nil {
		supDeps = c.deps.SupervisorDepsFactory(cfg, c.guard, metricsEmitter)
	} else {
		supDeps = SupervisorDeps{
			Metrics:     metricsEmitter,
			GitHubGuard: c.guard,
		}
	}
	// Enforce single shared process-lifetime GitHubGuard even if custom factory omitted it.
	if supDeps.GitHubGuard == nil {
		supDeps.GitHubGuard = c.guard
	}
	prevOnState := supDeps.OnStateChange
	supDeps.OnStateChange = func(from, to SupervisorState) {
		if prevOnState != nil {
			prevOnState(from, to)
		}
		var newState ControllerState
		var changed bool
		switch to {
		case StateHealthy:
			c.cfgMu.Lock()
			changed = c.ctrlState != CtrlRunning
			c.ctrlState = CtrlRunning
			newState = CtrlRunning
			if c.sessionAt.IsZero() {
				c.sessionAt = c.deps.NowFn()
			}
			c.cfgMu.Unlock()
		case StateDegraded:
			c.cfgMu.Lock()
			changed = c.ctrlState != CtrlDegraded
			c.ctrlState = CtrlDegraded
			newState = CtrlDegraded
			c.cfgMu.Unlock()
		case StateShutdown:
			c.cfgMu.Lock()
			changed = c.ctrlState != CtrlStopping
			c.ctrlState = CtrlStopping
			newState = CtrlStopping
			c.cfgMu.Unlock()
		default:
			c.cfgMu.Lock()
			if c.ctrlState != CtrlStopping {
				changed = c.ctrlState != CtrlStarting
				c.ctrlState = CtrlStarting
				newState = CtrlStarting
			}
			c.cfgMu.Unlock()
		}
		c.signalSnapshot()
		if changed && c.deps.OnStateTransition != nil {
			c.deps.OnStateTransition(newState)
		}
	}

	sup := NewSupervisor(cfg, eventLogger, supDeps)
	runCtx, runCancel := context.WithCancel(context.Background())
	runDoneCh := make(chan error, 1)

	c.cfgMu.Lock()
	c.sessionAt = time.Time{}
	c.cfgMu.Unlock()

	c.runMu.Lock()
	c.activeSupRef = sup
	c.activeRunCancel = runCancel
	c.runMu.Unlock()
	c.activeSup.Store(sup)

	// If Stop or Re-Auth raced right before we stored activeSupRef, cancel immediately before spawning Run().
	if !c.desiredRunning.Load() || c.shuttingDown.Load() || c.reauthRequested.Load() {
		sup.RequestShutdown("ui_stop_before_run")
		runCancel()
	}

	go func() {
		runDoneCh <- sup.Run(runCtx)
	}()

	var runErr error
	running := true
	for running {
		select {
		case runErr = <-runDoneCh:
			running = false
		case <-c.wakeCh:
			if !c.desiredRunning.Load() || c.shuttingDown.Load() || c.reauthRequested.Load() {
				c.setCtrlState(CtrlStopping)
				sup.RequestShutdown("ui_stop")
				runCancel()
			}
		case <-c.stopCtx.Done():
			c.setCtrlState(CtrlStopping)
			sup.RequestShutdown("ui_exit")
			runCancel()
		}
	}

	// Strictly joined <-runDoneCh: executeOrderedShutdown() has 100% completed!
	runCancel()
	c.runMu.Lock()
	c.activeSupRef = nil
	c.activeRunCancel = nil
	c.runMu.Unlock()
	c.activeSup.Store(nil)

	if runErr != nil && c.desiredRunning.Load() && !c.shuttingDown.Load() {
		c.desiredRunning.Store(false)
		c.setLastError(runErr.Error())
		c.logs.Append(LogError, "[Supervisor] Exited with error: "+runErr.Error())
	}

	c.cfgMu.Lock()
	changed := c.ctrlState != CtrlStopped
	c.sessionAt = time.Time{}
	c.ctrlState = CtrlStopped
	c.cfgMu.Unlock()
	c.publishSnapshotNow()
	if changed && c.deps.OnStateTransition != nil {
		c.deps.OnStateTransition(CtrlStopped)
	}
}

func (c *SessionController) executeReAuthSequence() {
	defer c.reauthRequested.Store(false)
	c.authGen.Add(1)
	c.cancelInFlightQuota()
	c.setCtrlState(CtrlReauthing)
	c.setLastError("")

	// Immediately clear any stale quota/VM metadata from the previous account.
	c.cfgMu.Lock()
	cachePath := c.baseCfg.CodespaceCachePath
	csName := c.baseCfg.CodespaceName
	c.quotaInfo = QuotaInfo{}
	c.cfgMu.Unlock()
	c.dirtyMask.Or(DirtyQuota)

	// Step 0: Wipe stale codespace_state_cache.json and clear cached stopped brake.
	if strings.TrimSpace(cachePath) != "" {
		if err := os.Remove(cachePath); err == nil {
			c.logs.Append(LogInfo, "[Auth] Cleared stale codespace_state_cache.json")
		} else if !errors.Is(err, os.ErrNotExist) {
			c.logs.Append(LogWarn, fmt.Sprintf("[Auth] Could not remove state cache: %v", err))
		}
		if c.guard != nil {
			c.guard.ClearSessionStopped()
			c.guard.SetStateCache(NewCodespaceStateCache(csName, cachePath))
		}
	}

	authCtx, cancel := context.WithTimeout(c.stopCtx, 5*time.Minute)
	defer cancel()

	// Step 1: Interactive `gh auth login` in its own dedicated console window (never AllocConsole inside NetShaper.exe!).
	c.logs.Append(LogInfo, "[Auth] Step 1/2: Running 'gh auth login' in interactive console...")
	code1, err1 := c.deps.RunInteractiveGH(authCtx, "auth", "login")
	if err1 != nil || code1 != 0 {
		msg := fmt.Sprintf("gh auth login exited with code %d", code1)
		if err1 != nil {
			msg = fmt.Sprintf("gh auth login failed: %v", err1)
		}
		c.logs.Append(LogError, "[Auth] "+msg)
		c.cfgMu.Lock()
		c.authInfo.Error = msg
		c.authInfo.StatusText = "Re-Auth aborted"
		c.authInfo.CheckedAt = c.deps.NowFn()
		c.cfgMu.Unlock()
		c.dirtyMask.Or(DirtyAuth)
		c.setCtrlState(CtrlStopped)
		return
	}
	c.logs.Append(LogSuccess, "[Auth] Step 1/2 complete: gh auth login succeeded")

	// Step 2: Interactive `gh auth refresh -h github.com -s codespace`.
	c.logs.Append(LogInfo, "[Auth] Step 2/2: Running 'gh auth refresh -h github.com -s codespace'...")
	code2, err2 := c.deps.RunInteractiveGH(authCtx, "auth", "refresh", "-h", "github.com", "-s", "codespace")
	if err2 != nil || code2 != 0 {
		msg := fmt.Sprintf("gh auth refresh exited with code %d", code2)
		if err2 != nil {
			msg = fmt.Sprintf("gh auth refresh failed: %v", err2)
		}
		c.logs.Append(LogError, "[Auth] "+msg)
		c.cfgMu.Lock()
		c.authInfo.Error = msg
		c.authInfo.StatusText = "Codespace scope refresh failed"
		c.authInfo.CheckedAt = c.deps.NowFn()
		c.cfgMu.Unlock()
		c.dirtyMask.Or(DirtyAuth)
		c.setCtrlState(CtrlStopped)
		return
	}
	c.logs.Append(LogSuccess, "[Auth] Step 2/2 complete: codespace scope refreshed")

	// Step 3: Silent hidden `gh auth status` to refresh active username & scopes (multi-account aware).
	statusCtx, statusCancel := context.WithTimeout(c.stopCtx, c.deps.QuotaTimeout)
	stdout, stderr, _, stErr := c.deps.RunSilentGH(statusCtx, "auth", "status")
	statusCancel()

	combined := stdout + "\n" + stderr
	info := ParseGHAuthStatus(combined)
	info.CheckedAt = c.deps.NowFn()

	// Fallback A: query live hidden `gh api /user --jq .login` before falling back to local hosts.yml,
	// so live account switches never return a stale host username from disk.
	if info.Username == "" {
		uCtx, uCancel := context.WithTimeout(c.stopCtx, c.deps.QuotaTimeout)
		uOut, _, uCode, uErr := c.deps.RunSilentGH(uCtx, "api", "/user", "--jq", ".login")
		uCancel()
		if uErr == nil && uCode == 0 {
			login := strings.Trim(strings.TrimSpace(uOut), `"'`)
			if login != "" && !strings.ContainsAny(login, " \t\r\n") {
				info.LoggedIn = true
				info.Username = login
				info.StatusText = "Authenticated (GitHub API)"
			}
		}
	}

	// Fallback B: offline local GitHub CLI hosts.yml read if both `gh auth status` and live API failed.
	if info.Username == "" {
		if localUser := c.deps.ReadLocalHostsFn(); localUser != "" {
			info.LoggedIn = true
			info.Username = localUser
			info.StatusText = "Authenticated (local gh config)"
		}
	}

	if stErr != nil && !info.LoggedIn {
		info.Error = stErr.Error()
		info.StatusText = "Auth status check failed"
	}

	c.authGen.Add(1)
	c.cancelInFlightQuota()
	c.cfgMu.Lock()
	c.authInfo = info
	c.quotaInfo = QuotaInfo{}
	c.uiCfg.LastAccount = info.Username
	uiCfgCopy := c.uiCfg
	prefPath := c.uiCfgPath
	c.cfgMu.Unlock()

	if info.Username != "" {
		_, _ = SaveUIConfig(uiCfgCopy, prefPath)
		c.logs.Append(LogSuccess, fmt.Sprintf("[Auth] Active GitHub account: @%s", info.Username))
	} else {
		c.logs.Append(LogInfo, "[Auth] Re-Auth sequence completed")
	}

	c.dirtyMask.Or(DirtyAuth | DirtyQuota)
	c.setCtrlState(CtrlStopped)
}

// -----------------------------------------------------------------------------
// Strictly On-Demand Quota Checker (0 Background Calls, 403 Scope Safe)
// -----------------------------------------------------------------------------

func (c *SessionController) runQuotaCheck(qParentCtx context.Context, gen uint64) {
	if c.authGen.Load() != gen || qParentCtx.Err() != nil {
		return
	}

	c.cfgMu.RLock()
	csName := c.baseCfg.CodespaceName
	sessionAt := c.sessionAt
	c.cfgMu.RUnlock()

	var sessDur time.Duration
	if !sessionAt.IsZero() {
		sessDur = c.deps.NowFn().Sub(sessionAt)
		if sessDur < 0 {
			sessDur = 0
		}
	}

	// Gate 1: GitHubGuard budget + spacing + cooldown check.
	if c.guard != nil {
		allowed, wait, blockReason := c.guard.TryAllow("ui_quota_codespaces")
		if !allowed {
			msg := fmt.Sprintf("Blocked by WAF guard (%s, wait %s)", blockReason, wait.Round(time.Second))
			c.cfgMu.Lock()
			if c.authGen.Load() != gen {
				c.cfgMu.Unlock()
				return
			}
			c.logs.Append(LogWarn, "[Quota] "+msg)
			c.quotaInfo.Loading = false
			c.quotaInfo.CheckedAt = c.deps.NowFn()
			c.quotaInfo.GuardBlocked = msg
			c.quotaInfo.SessionDuration = sessDur
			c.cfgMu.Unlock()
			c.dirtyMask.Or(DirtyQuota)
			c.publishSnapshotNow()
			return
		}
	}

	c.logs.Append(LogInfo, "[Quota] Querying GitHub Codespaces API (on-demand)...")
	qCtx, cancel := context.WithTimeout(qParentCtx, c.deps.QuotaTimeout)
	stdout, stderr, code, err := c.deps.RunSilentGH(qCtx, "api", "/user/codespaces")
	cancel()

	if c.authGen.Load() != gen {
		return
	}

	if err != nil || code != 0 {
		combined := strings.TrimSpace(stderr)
		if combined == "" && err != nil {
			combined = err.Error()
		}
		// Only penalize GitHubGuard on genuine rate-limit/WAF/429 signatures.
		if c.guard != nil && IsQuotaRateLimitOrWAF(combined) {
			c.guard.RecordFailure(combined)
		}
		errMsg := truncateUTF8(combined, 140)
		c.cfgMu.Lock()
		if c.authGen.Load() != gen {
			c.cfgMu.Unlock()
			return
		}
		c.logs.Append(LogError, "[Quota] /user/codespaces failed: "+errMsg)
		c.quotaInfo.Loading = false
		c.quotaInfo.Checked = true
		c.quotaInfo.CheckedAt = c.deps.NowFn()
		c.quotaInfo.SessionDuration = sessDur
		c.quotaInfo.Error = errMsg
		c.cfgMu.Unlock()
		c.dirtyMask.Or(DirtyQuota)
		c.publishSnapshotNow()
		return
	}

	qInfo, ownerLogin, parseErr := ParseCodespacesAPIJSON([]byte(stdout), csName)
	qInfo.Checked = true
	qInfo.Loading = false
	qInfo.CheckedAt = c.deps.NowFn()
	qInfo.SessionDuration = sessDur
	if parseErr != nil {
		qInfo.Error = parseErr.Error()
		c.cfgMu.Lock()
		if c.authGen.Load() != gen {
			c.cfgMu.Unlock()
			return
		}
		c.logs.Append(LogWarn, "[Quota] "+parseErr.Error())
		c.quotaInfo = qInfo
		c.cfgMu.Unlock()
		c.dirtyMask.Or(DirtyQuota)
		c.publishSnapshotNow()
		return
	}

	if ownerLogin != "" {
		c.cfgMu.Lock()
		if c.authGen.Load() != gen {
			c.cfgMu.Unlock()
			return
		}
		if !strings.EqualFold(c.authInfo.Username, ownerLogin) {
			c.authInfo.LoggedIn = true
			c.authInfo.Username = ownerLogin
			c.authInfo.StatusText = "Verified via Codespaces API"
			c.uiCfg.LastAccount = ownerLogin
		}
		c.cfgMu.Unlock()
	}

	if c.authGen.Load() != gen || qParentCtx.Err() != nil {
		return
	}

	// Optional Billing Usage query — strictly gated by GitHubGuard spacing (2s) and isolated from 403 scope penalties.
	if ownerLogin != "" && ValidateCodespaceName(ownerLogin) == nil {
		billingAllowed := true
		if c.guard != nil {
			ok, wait, why := c.guard.TryAllow("ui_quota_billing")
			if !ok && why == "min_call_spacing" && wait > 0 && wait <= 3*time.Second {
				tm := time.NewTimer(wait + 25*time.Millisecond)
				select {
				case <-tm.C:
					if c.authGen.Load() != gen {
						return
					}
					ok, _, why = c.guard.TryAllow("ui_quota_billing")
				case <-qParentCtx.Done():
					tm.Stop()
					return
				case <-c.stopCtx.Done():
					tm.Stop()
					ok = false
				}
			}
			if !ok {
				billingAllowed = false
				qInfo.BillingNote = fmt.Sprintf("Billing check skipped (%s) — showing machine tier", why)
			}
		}

		if billingAllowed {
			bCtx, bCancel := context.WithTimeout(qParentCtx, c.deps.QuotaTimeout)
			bOut, bErrOut, bCode, bErr := c.deps.RunSilentGH(bCtx, "api", fmt.Sprintf("/users/%s/settings/billing/usage", ownerLogin))
			bCancel()

			if c.authGen.Load() != gen {
				return
			}

			if bErr == nil && bCode == 0 {
				if used, inc, ok := ParseBillingUsageJSON([]byte(bOut)); ok {
					qInfo.BillingAvailable = true
					qInfo.CoreHoursUsed = used
					qInfo.CoreHoursIncluded = inc
					qInfo.BillingNote = "Live GitHub billing usage"
				} else {
					qInfo.BillingAvailable = false
					qInfo.BillingNote = "No Codespaces billing items reported — showing machine tier"
				}
			} else {
				combinedB := strings.TrimSpace(bErrOut)
				if combinedB == "" && bErr != nil {
					combinedB = bErr.Error()
				}
				// CRITICAL: Separate missing billing-scope HTTP 403 from real WAF/rate-limit 429!
				// Billing-scope 403 MUST NEVER call guard.RecordFailure() or block tunnel boots.
				if IsQuotaRateLimitOrWAF(combinedB) {
					if c.guard != nil {
						c.guard.RecordFailure(combinedB)
					}
					qInfo.BillingNote = "Billing query rate-limited (WAF guard engaged)"
				} else if IsQuotaBillingScope403(combinedB) {
					qInfo.BillingAvailable = false
					qInfo.BillingNote = "Billing scope unavailable (HTTP 403) — using machine tier & local timer"
				} else {
					qInfo.BillingAvailable = false
					qInfo.BillingNote = "Billing endpoint unavailable — using machine tier & local timer"
				}
			}
		}
	} else {
		qInfo.BillingNote = "Showing machine tier & local session timer"
	}

	c.cfgMu.Lock()
	if c.authGen.Load() != gen {
		c.cfgMu.Unlock()
		return
	}
	c.quotaInfo = qInfo
	c.cfgMu.Unlock()

	c.logs.Append(LogSuccess, fmt.Sprintf("[Quota] %s | state=%s | %s (%d vCPU, %dGB RAM)",
		qInfo.CodespaceName, qInfo.CodespaceState, qInfo.MachineDisplay, qInfo.CPUs, qInfo.MemoryGB))
	c.dirtyMask.Or(DirtyQuota | DirtyAuth)
	c.publishSnapshotNow()
}

// -----------------------------------------------------------------------------
// Wait-Free 1Hz Snapshot Publisher (0 Locks on ProxyServer / TunnelPool / GitHubGuard)
// -----------------------------------------------------------------------------

func (c *SessionController) snapshotPublisher() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.deps.SnapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCtx.Done():
			return
		case <-ticker.C:
			c.publishSnapshotNow()
		case <-c.snapWakeCh:
			c.publishSnapshotNow()
		}
	}
}

func (c *SessionController) publishSnapshotNow() {
	c.cfgMu.RLock()
	cfg := c.baseCfg
	ctrlSt := c.ctrlState
	lastErr := c.lastErr
	auth := c.authInfo
	quota := c.quotaInfo
	sessAt := c.sessionAt
	cfgPath := c.uiCfgPath
	c.cfgMu.RUnlock()

	now := c.deps.NowFn()
	var uptime time.Duration
	if !sessAt.IsZero() && (ctrlSt == CtrlRunning || ctrlSt == CtrlDegraded) {
		uptime = now.Sub(sessAt)
		if uptime < 0 {
			uptime = 0
		}
	}
	if quota.Checked && !sessAt.IsZero() {
		quota.SessionDuration = uptime
	}

	snap := UISnapshot{
		State:            ctrlSt,
		SupervisorState:  StateShutdown,
		CodespaceName:    cfg.CodespaceName,
		LocalAddr:        cfg.LocalAddr(),
		PoolSize:         cfg.PoolSize,
		MaxActiveConns:   cfg.MaxActiveConns,
		SessionStartedAt: sessAt,
		Uptime:           uptime,
		LastError:        lastErr,
		Auth:             auth,
		Quota:            quota,
		CanEditCodespace: ctrlSt == CtrlStopped && !c.desiredRunning.Load(),
		ConfigPath:       cfgPath,
	}

	// Wait-free GitHubGuard shadow snapshot (0 mutexes).
	if c.guard != nil {
		gs := c.guard.CachedSnapshot()
		snap.GuardCalls5Min = gs.CallsLast5Min
		snap.GuardMax5Min = gs.MaxCallsPer5Min
		snap.GuardCallsHour = gs.CallsLastHour
		snap.GuardMaxHour = gs.MaxCallsPerHour
		snap.GuardCooldownMS = gs.CooldownRemainingMS
		snap.GuardBudgetWaitMS = gs.BudgetWaitMS
		snap.GuardThrottleWaitMS = gs.ThrottleWaitMS
		snap.GuardThrottleReason = gs.ThrottleReason
		snap.GuardRateLimits = gs.RateLimitHits
	}

	// Wait-free Supervisor / ProxyServer / TunnelPool shadow reads (0 shared mutexes!).
	if sup := c.activeSup.Load(); sup != nil {
		snap.SupervisorState = sup.AtomicState()
		if ba := sup.AtomicBoundLocalAddr(); ba != "" {
			snap.LocalAddr = ba
		}
		pt := sup.AtomicProxyTelemetry()
		snap.ActiveConns = pt.ActiveConns
		snap.PeakConns = pt.PeakConns
		snap.QueuedConns = pt.QueuedConns
		snap.SemaphoreRejects = pt.SemaphoreRejects
		snap.BytesUp = pt.TotalBytesUp
		snap.BytesDown = pt.TotalBytesDown

		ps := sup.AtomicPoolSnapshot()
		if ps.PoolSize > 0 {
			snap.PoolSize = ps.PoolSize
		}
		snap.HealthyWorkers = ps.HealthyWorkers
		snap.DegradedWorkers = ps.DegradedWorkers
		snap.RoutingMode = ps.RoutingMode
		snap.PrimaryTunnelID = ps.PrimaryTunnelID
		snap.LatencyP50MS = ps.AggregateP50MS
		snap.UnderlayMS = ps.UnderlayBaselineMS
		if len(ps.Workers) > 0 {
			snap.Workers = make([]TunnelSnapshot, len(ps.Workers))
			copy(snap.Workers, ps.Workers)
		}
	}

	c.latestSnap.Store(&snap)
	c.dirtyMask.Or(DirtyTelemetry)
}

// -----------------------------------------------------------------------------
// Default Subprocess Runners & Pure Parsers
// -----------------------------------------------------------------------------

// defaultRunInteractiveGH spawns gh.exe directly (never cmd.exe) inside a dedicated console
// window (CREATE_NEW_CONSOLE, Stdin/Stdout/Stderr = nil) contained in a ProcessJob so closing
// NetShaper kills any lingering interactive auth console and its child tree immediately.
func defaultRunInteractiveGH(ctx context.Context, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	configureInteractiveConsoleCmd(cmd)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	job, jobErr := NewProcessJob()
	if err := cmd.Start(); err != nil {
		if jobErr == nil && job != nil {
			_ = job.Close()
		}
		return -1, err
	}
	var closeOnce sync.Once
	closeJob := func() {
		if jobErr == nil && job != nil {
			closeOnce.Do(func() {
				_ = job.Close()
			})
		}
	}
	doneCh := make(chan struct{})
	if jobErr == nil && job != nil && cmd.Process != nil {
		_ = job.Assign(cmd.Process.Pid)
		defer closeJob()
		go func() {
			select {
			case <-ctx.Done():
				// Immediately close the JobObject on shutdown/cancel so conhost.exe + gh.exe terminate in <10ms.
				closeJob()
			case <-doneCh:
			}
		}()
	}

	err := cmd.Wait()
	close(doneCh)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), err
		}
		return -1, err
	}
	return 0, nil
}

// defaultRunSilentGH executes a bounded hidden gh CLI query (CREATE_NO_WINDOW + ProcessJob).
func defaultRunSilentGH(ctx context.Context, args ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	ConfigureChildCmd(cmd)
	configureHiddenCmd(cmd)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	job, jobErr := NewProcessJob()
	if err := cmd.Start(); err != nil {
		if jobErr == nil && job != nil {
			_ = job.Close()
		}
		return "", "", -1, err
	}
	var closeOnce sync.Once
	closeJob := func() {
		if jobErr == nil && job != nil {
			closeOnce.Do(func() {
				_ = job.Close()
			})
		}
	}
	doneCh := make(chan struct{})
	if jobErr == nil && job != nil && cmd.Process != nil {
		_ = job.Assign(cmd.Process.Pid)
		defer closeJob()
		go func() {
			select {
			case <-ctx.Done():
				closeJob()
			case <-doneCh:
			}
		}()
	}

	err := cmd.Wait()
	close(doneCh)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return outBuf.String(), errBuf.String(), exitErr.ExitCode(), err
		}
		return outBuf.String(), errBuf.String(), -1, err
	}
	return outBuf.String(), errBuf.String(), 0, nil
}

// ReadLocalGHHostsUsername passively reads the github.com user from local GitHub CLI hosts.yml (0 network calls).
func ReadLocalGHHostsUsername() string {
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(dir, "GitHub CLI", "hosts.yml"),
		filepath.Join(dir, "gh", "hosts.yml"),
	}
	for _, p := range candidates {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		inGH := false
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(line, "github.com:") {
				inGH = true
				continue
			}
			if inGH && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inGH = false
			}
			if inGH && strings.HasPrefix(trimmed, "user:") {
				u := strings.TrimSpace(strings.TrimPrefix(trimmed, "user:"))
				u = strings.Trim(u, `"'`)
				if u != "" {
					return u
				}
			}
		}
	}
	return ""
}

var (
	reAuthAccount = regexp.MustCompile(`(?i)logged in to\s+\S+\s+(?:account|as)\s+([A-Za-z0-9._-]+)`)
	reAuthScopes  = regexp.MustCompile(`(?i)token scopes:\s*(.+)`)
	reAuthActive  = regexp.MustCompile(`(?i)active account:\s*(true|false)`)
)

// ParseGHAuthStatus parses `gh auth status` text output into AuthInfo.
// Handles multi-account `gh` v2.40+ output by preferring the block marked `Active account: true`.
func ParseGHAuthStatus(out string) AuthInfo {
	var best AuthInfo
	var current AuthInfo
	hasCurrent := false
	currentActive := false

	flush := func() {
		if !hasCurrent || !current.LoggedIn {
			return
		}
		if currentActive || !best.LoggedIn {
			best = current
		}
	}

	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if m := reAuthAccount.FindStringSubmatch(line); len(m) == 2 {
			flush()
			current = AuthInfo{
				LoggedIn:   true,
				Username:   strings.Trim(m[1], `"'()`),
				StatusText: "Authenticated",
			}
			hasCurrent = true
			currentActive = false
			continue
		}
		if !hasCurrent {
			continue
		}
		if m := reAuthActive.FindStringSubmatch(line); len(m) == 2 {
			currentActive = strings.EqualFold(m[1], "true")
			continue
		}
		if m := reAuthScopes.FindStringSubmatch(line); len(m) == 2 {
			current.Scopes = strings.TrimSpace(strings.ReplaceAll(m[1], "'", ""))
		}
	}
	flush()

	if !best.LoggedIn {
		return AuthInfo{StatusText: "Not logged in"}
	}
	return best
}

// IsQuotaRateLimitOrWAF returns true ONLY for genuine rate-limit / WAF / 429 / Retry-After responses.
// Deliberately excludes plain HTTP 403 missing-scope billing errors so GitHubGuard is never poisoned.
func IsQuotaRateLimitOrWAF(stderr string) bool {
	low := strings.ToLower(stderr)
	tokens := []string{
		"http 429",
		"429 too many requests",
		"too many requests",
		"secondary rate limit",
		"api rate limit exceeded",
		"rate limit",
		"abuse detection",
		"retry-after",
		"waf",
		"bot detection",
	}
	for _, tok := range tokens {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

// IsQuotaBillingScope403 reports whether stderr indicates a billing-permission HTTP 403/404 without WAF throttling.
func IsQuotaBillingScope403(stderr string) bool {
	if IsQuotaRateLimitOrWAF(stderr) {
		return false
	}
	low := strings.ToLower(stderr)
	for _, tok := range []string{"http 403", "403", "forbidden", "resource not accessible", "scope", "must have admin", "http 404"} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

type ghCodespacesResponse struct {
	Codespaces []struct {
		Name    string `json:"name"`
		State   string `json:"state"`
		Owner   struct {
			Login string `json:"login"`
		} `json:"owner"`
		Machine struct {
			Name           string `json:"name"`
			DisplayName    string `json:"display_name"`
			CPUs           int    `json:"cpus"`
			MemoryInBytes  int64  `json:"memory_in_bytes"`
			StorageInBytes int64  `json:"storage_in_bytes"`
		} `json:"machine"`
	} `json:"codespaces"`
}

// ParseCodespacesAPIJSON parses `gh api /user/codespaces` JSON and matches targetName.
func ParseCodespacesAPIJSON(raw []byte, targetName string) (QuotaInfo, string, error) {
	var resp ghCodespacesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return QuotaInfo{}, "", fmt.Errorf("invalid codespaces JSON: %w", err)
	}
	if len(resp.Codespaces) == 0 {
		return QuotaInfo{CodespaceName: targetName, CodespaceState: "Not Found"}, "", errors.New("no codespaces found on account")
	}

	idx := -1
	for i, cs := range resp.Codespaces {
		if strings.EqualFold(cs.Name, targetName) {
			idx = i
			break
		}
	}
	if idx < 0 {
		idx = 0
	}
	cs := resp.Codespaces[idx]
	disp := strings.TrimSpace(cs.Machine.DisplayName)
	if disp == "" {
		disp = cs.Machine.Name
	}
	if disp == "" {
		disp = fmt.Sprintf("%d-core machine", cs.Machine.CPUs)
	}
	info := QuotaInfo{
		CodespaceName:  cs.Name,
		CodespaceState: cs.State,
		MachineName:    cs.Machine.Name,
		MachineDisplay: disp,
		CPUs:           cs.Machine.CPUs,
		MemoryGB:       int(cs.Machine.MemoryInBytes / (1024 * 1024 * 1024)),
		StorageGB:      int(cs.Machine.StorageInBytes / (1024 * 1024 * 1024)),
	}
	if !strings.EqualFold(cs.Name, targetName) && targetName != "" {
		info.BillingNote = fmt.Sprintf("Configured '%s' not found; showing '%s'", targetName, cs.Name)
	}
	return info, strings.TrimSpace(cs.Owner.Login), nil
}

// ParseBillingUsageJSON extracts Codespaces core-hours usage from GitHub billing JSON responses.
func ParseBillingUsageJSON(raw []byte) (usedHours float64, includedHours float64, ok bool) {
	var doc struct {
		UsageItems []struct {
			Product  string  `json:"product"`
			SKU      string  `json:"sku"`
			Quantity float64 `json:"quantity"`
			UnitType string  `json:"unitType"`
		} `json:"usageItems"`
		TotalMinutesUsed     float64 `json:"total_minutes_used"`
		IncludedMinutes      float64 `json:"included_minutes"`
		TotalCoreHoursUsed   float64 `json:"total_core_hours_used"`
		IncludedCoreHours    float64 `json:"included_core_hours"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, 0, false
	}
	if doc.TotalCoreHoursUsed > 0 || doc.IncludedCoreHours > 0 {
		return round2(doc.TotalCoreHoursUsed), round2(doc.IncludedCoreHours), true
	}
	if doc.TotalMinutesUsed > 0 || doc.IncludedMinutes > 0 {
		return round2(doc.TotalMinutesUsed / 60.0), round2(doc.IncludedMinutes / 60.0), true
	}
	var sum float64
	found := false
	for _, item := range doc.UsageItems {
		if strings.Contains(strings.ToLower(item.Product), "codespace") &&
			strings.Contains(strings.ToLower(item.UnitType), "hour") {
			sum += item.Quantity
			found = true
		}
	}
	if found {
		return round2(sum), 120.0, true
	}
	return 0, 0, false
}

// FormatBytesShort formats a byte count concisely for the compact transfer summary card.
func FormatBytesShort(b uint64) string {
	const (
		kb = 1024.0
		mb = kb * 1024.0
		gb = mb * 1024.0
	)
	fb := float64(b)
	switch {
	case fb >= gb:
		return fmt.Sprintf("%.2f GB", fb/gb)
	case fb >= mb:
		return fmt.Sprintf("%.1f MB", fb/mb)
	case fb >= kb:
		return fmt.Sprintf("%.0f KB", fb/kb)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatDurationShort formats an elapsed uptime duration compactly (e.g. 04m 18s or 1h 12m).
func FormatDurationShort(d time.Duration) string {
	if d <= 0 {
		return "00s"
	}
	sec := int(d.Seconds())
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	if h > 0 {
		return fmt.Sprintf("%dh %02dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%02dm %02ds", m, s)
	}
	return fmt.Sprintf("%02ds", s)
}
