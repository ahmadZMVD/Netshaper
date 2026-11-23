package main

import (
	"context"
	"encoding/json"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FailureClass distinguishes network-layer slow/dropped lanes from GitHub API throttling and auth errors.
type FailureClass string

const (
	FailureNetworkLane   FailureClass = "network_lane"
	FailureAPIRateLimit  FailureClass = "api_rate_limit"
	FailureVMTransition  FailureClass = "vm_transition"
	FailureAuthOrStopped FailureClass = "auth_or_stopped"
)

// FatalBootError represents a permanent, non-retriable gh CLI / Codespace error
// (e.g., HTTP 404 non-existent codespace or HTTP 401/unauthenticated CLI) that must
// abort immediately instead of retrying and exhausting the 5-minute GitHub API budget.
type FatalBootError struct {
	Code    string
	Message string
	Stderr  string
}

func (e *FatalBootError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func isVMTransitionStderr(lower string) bool {
	for _, tok := range []string{
		"too many codespaces starting",
		"http 400",
		"shutting down",
		"codespace is currently",
	} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// ClassifyPermanentBootError inspects gh/ssh stderr and returns a *FatalBootError ONLY for
// strictly permanent, non-retriable failures (non-existent codespace HTTP 404, spending limit /
// suspended codespace, or missing/expired GitHub CLI authentication/scope). Transient network
// timeouts, HTTP 429/WAF rate limits, HTTP 400 concurrent VM starts, and HTTP 5xx relay errors
// ALWAYS return nil so normal retry/backoff applies.
func ClassifyPermanentBootError(stderrTail string) *FatalBootError {
	trimmed := strings.TrimSpace(stderrTail)
	if trimmed == "" {
		return nil
	}
	if IsQuotaRateLimitOrWAF(trimmed) {
		return nil
	}
	lower := strings.ToLower(trimmed)
	if isVMTransitionStderr(lower) {
		return nil
	}

	for _, tok := range []string{
		"http 404",
		"404 not found",
		"codespace not found",
		"no codespaces found",
		"no codespaces available",
		"no such codespace",
	} {
		if strings.Contains(lower, tok) {
			return &FatalBootError{
				Code:    "codespace_not_found",
				Message: "Codespace not found (404) — check Account tab",
				Stderr:  trimmed,
			}
		}
	}

	if strings.Contains(lower, "spending limit") {
		return &FatalBootError{
			Code:    "spending_limit",
			Message: "Codespaces spending limit reached — check GitHub billing",
			Stderr:  trimmed,
		}
	}

	if strings.Contains(lower, "codespace is suspended") {
		return &FatalBootError{
			Code:    "codespace_suspended",
			Message: "Codespace is suspended — check GitHub Codespaces",
			Stderr:  trimmed,
		}
	}

	for _, tok := range []string{
		"http 401",
		"unauthorized",
		"gh auth login",
		"gh auth refresh",
		"not logged into any github hosts",
		"authentication failed",
		"missing required scope",
		"permission denied (publickey)",
	} {
		if strings.Contains(lower, tok) {
			return &FatalBootError{
				Code:    "auth_required",
				Message: "GitHub auth required — Re-Auth in Account tab",
				Stderr:  trimmed,
			}
		}
	}
	return nil
}

// GitHubGuardSnapshot captures current sliding-window budget and anti-bot/WAF backoff telemetry.
type GitHubGuardSnapshot struct {
	CallsLast5Min       int    `json:"calls_last_5m"`
	MaxCallsPer5Min     int    `json:"max_calls_5m"`
	CallsLastHour       int    `json:"calls_last_hour"`
	MaxCallsPerHour     int    `json:"max_calls_hour"`
	MinCallSpacingMS    int64  `json:"min_call_spacing_ms"`
	TotalAllowed        int64  `json:"total_allowed"`
	TotalThrottled      int64  `json:"total_throttled"`
	RateLimitHits       int64  `json:"rate_limit_hits"`
	VMTransitionHits    int64  `json:"vm_transition_hits"`
	AuthOrStoppedHits   int64  `json:"auth_or_stopped_hits"`
	CooldownRemainingMS int64  `json:"cooldown_remaining_ms"`
	BudgetWaitMS        int64  `json:"budget_wait_ms"`
	ThrottleWaitMS      int64  `json:"throttle_wait_ms"`
	ThrottleReason      string `json:"throttle_reason,omitempty"`
	CodespaceWarm       bool   `json:"codespace_warm"`
}

// codespaceStateCacheEntry is the on-disk JSON schema for persistent warm Codespace VM state.
type codespaceStateCacheEntry struct {
	Codespace string    `json:"codespace"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CodespaceStateCache persists the last observed Codespace VM state (e.g. "Available" vs "Shutdown")
// across NetShaper restarts using atomic temp+rename writes (0o700 dir / 0o600 file).
type CodespaceStateCache struct {
	mu        sync.Mutex
	path      string
	codespace string
	state     string
	updatedAt time.Time
	nowFn     func() time.Time
}

// DefaultCodespaceStateCachePath returns the default per-user config cache location
// (<UserConfigDir>/NetShaper/codespace_state_cache.json).
func DefaultCodespaceStateCachePath() string {
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "NetShaper", "codespace_state_cache.json")
}

// NewCodespaceStateCache initializes a persistent cache for codespaceName at path and loads any existing entry.
func NewCodespaceStateCache(codespaceName, path string) *CodespaceStateCache {
	c := &CodespaceStateCache{
		path:      strings.TrimSpace(path),
		codespace: strings.TrimSpace(codespaceName),
		nowFn:     time.Now,
	}
	_ = c.Load()
	return c
}

// Load reads the persisted JSON state if present and matching this cache's Codespace name.
func (c *CodespaceStateCache) Load() error {
	if c == nil || c.path == "" {
		return nil
	}
	data, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}
	var entry codespaceStateCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}
	if entry.Codespace != "" && c.codespace != "" && entry.Codespace != c.codespace {
		return nil
	}
	c.mu.Lock()
	c.state = entry.State
	c.updatedAt = entry.UpdatedAt
	c.mu.Unlock()
	return nil
}

// Get returns the cached Codespace state if it is non-empty and within maxAge.
func (c *CodespaceStateCache) Get(maxAge time.Duration) (string, bool) {
	if c == nil || maxAge <= 0 {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == "" || c.updatedAt.IsZero() {
		return "", false
	}
	age := c.nowFn().Sub(c.updatedAt)
	if age < 0 || age > maxAge {
		return "", false
	}
	return c.state, true
}

// IsStopped returns true when a fresh cached state explicitly indicates the Codespace VM is Shutdown/Stopped.
func (c *CodespaceStateCache) IsStopped(maxAge time.Duration) bool {
	st, ok := c.Get(maxAge)
	if !ok {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(st))
	return low == "shutdown" || low == "stopped" || low == "unavailable"
}

// Set updates the cached Codespace state and atomically persists it to disk when path is configured.
func (c *CodespaceStateCache) Set(state string) error {
	if c == nil {
		return nil
	}
	now := c.nowFn().UTC()
	c.mu.Lock()
	c.state = strings.TrimSpace(state)
	c.updatedAt = now
	entry := codespaceStateCacheEntry{
		Codespace: c.codespace,
		State:     c.state,
		UpdatedAt: now,
	}
	path := c.path
	c.mu.Unlock()

	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

var (
	reRetryAfterLine   = regexp.MustCompile(`(?im)retry-after\s*[:=]\s*([^\r\n;]+)`)
	reRetryAfterDigits = regexp.MustCompile(`^(\d+)\b`)
	reRetryAfterText   = regexp.MustCompile(`(?i)(?:retry\s+after|wait\s+at\s+least|try\s+again\s+in)\s+(\d+)\s*(?:s|sec|second)`)
)

// ParseRetryAfter extracts an explicit Retry-After delay (delta-seconds or RFC 9110 HTTP-date)
// from GitHub CLI/API stderr text relative to time.Now(). Returns 0 if absent or in the past.
func ParseRetryAfter(stderrTail string) time.Duration {
	return ParseRetryAfterAt(stderrTail, time.Now())
}

// ParseRetryAfterAt extracts an explicit Retry-After delay (delta-seconds or RFC 9110 HTTP-date:
// http.TimeFormat / RFC1123 / RFC1123Z / RFC850 / ANSIC) relative to now for deterministic clock testing.
func ParseRetryAfterAt(stderrTail string, now time.Time) time.Duration {
	if strings.TrimSpace(stderrTail) == "" {
		return 0
	}
	if m := reRetryAfterLine.FindStringSubmatch(stderrTail); len(m) == 2 {
		val := strings.TrimSpace(m[1])
		// 1. Delta-seconds (e.g. "45" or "120 seconds").
		if dm := reRetryAfterDigits.FindStringSubmatch(val); len(dm) == 2 {
			if secs, err := strconv.Atoi(dm[1]); err == nil && secs > 0 {
				return time.Duration(secs) * time.Second
			}
		}
		// 2. HTTP-date formats per RFC 9110 §5.6.7.
		dateLayouts := []string{
			http.TimeFormat,
			time.RFC1123,
			time.RFC1123Z,
			time.RFC850,
			time.ANSIC,
		}
		cleanVal := strings.Trim(val, `"' `)
		candidates := []string{cleanVal}
		if fields := strings.Fields(cleanVal); len(fields) > 4 {
			if len(fields) >= 6 {
				candidates = append(candidates, strings.Join(fields[:6], " "))
			}
			if len(fields) >= 5 {
				candidates = append(candidates, strings.Join(fields[:5], " "))
			}
			candidates = append(candidates, strings.Join(fields[:4], " "))
		}
		for _, cand := range candidates {
			for _, layout := range dateLayouts {
				if ts, err := time.Parse(layout, cand); err == nil {
					if d := ts.Sub(now); d > 0 {
						return d
					}
					return 0
				}
			}
		}
	}
	// 3. Natural-language fallback ("retry after 30 seconds", "try again in 60s").
	if m := reRetryAfterText.FindStringSubmatch(stderrTail); len(m) == 2 {
		if secs, err := strconv.Atoi(m[1]); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

// GitHubGuard enforces sliding-window GitHub CLI invocation budgets, minimum inter-call spacing,
// HTTP 429/403/WAF secondary rate-limit detection with Retry-After parsing and full-jitter exponential
// backoff, and persistent warm Codespace state caching (Module 1).
type GitHubGuard struct {
	mu             sync.Mutex
	maxPer5Min     int
	maxPerHour     int
	minCallSpacing time.Duration
	rateLimitBase  time.Duration
	rateLimitMax   time.Duration
	warmCacheTTL   time.Duration
	loggerPtr      atomic.Pointer[EventLogger]
	metricsPtr     atomic.Pointer[MetricsEmitter]
	stateCache     *CodespaceStateCache
	nowFn          func() time.Time
	rng            *rand.Rand

	callTimes           []time.Time
	lastCallAt          time.Time
	cooldownUntil       time.Time
	cooldownReason      string
	rateLimitStreak     int
	warmUntil           time.Time
	sessionStopped      bool
	sessionStoppedUntil time.Time

	totalAllowed      int64
	totalThrottled    int64
	rateLimitHits     int64
	vmTransitionHits  int64
	authOrStoppedHits int64

	publishedSnap         atomic.Pointer[GitHubGuardSnapshot]
	publishedTimes        atomic.Pointer[[]time.Time]
	cooldownUntilNS       atomic.Int64
	cooldownReasonPtr     atomic.Pointer[string]
	sessionStoppedUntilNS atomic.Int64
}

// NewGitHubGuard constructs a thread-safe API budget & WAF guard from Config.
func NewGitHubGuard(cfg Config, logger *EventLogger, metrics *MetricsEmitter) *GitHubGuard {
	max5 := cfg.GitHubMaxCallsPer5Min
	if max5 < 1 {
		max5 = DefaultGitHubMaxCallsPer5Min
	}
	max60 := cfg.GitHubMaxCallsPerHour
	if max60 < max5 {
		max60 = DefaultGitHubMaxCallsPerHour
	}
	spacing := cfg.GitHubMinCallSpacing
	if spacing < 0 {
		spacing = 0
	}
	base := cfg.GitHubRateLimitBase
	if base <= 0 {
		base = DefaultGitHubRateLimitBaseBackoff
	}
	maxB := cfg.GitHubRateLimitMax
	if maxB < base {
		maxB = DefaultGitHubRateLimitMaxBackoff
	}
	warmTTL := cfg.GitHubWarmCacheTTL
	if warmTTL <= 0 {
		warmTTL = DefaultGitHubWarmCacheTTL
	}
	g := &GitHubGuard{
		maxPer5Min:     max5,
		maxPerHour:     max60,
		minCallSpacing: spacing,
		rateLimitBase:  base,
		rateLimitMax:   maxB,
		warmCacheTTL:   warmTTL,
		nowFn:          time.Now,
	}
	g.loggerPtr.Store(logger)
	g.metricsPtr.Store(metrics)
	if strings.TrimSpace(cfg.CodespaceCachePath) != "" {
		cache := NewCodespaceStateCache(cfg.CodespaceName, cfg.CodespaceCachePath)
		g.stateCache = cache
		if st, ok := cache.Get(warmTTL); ok && strings.EqualFold(st, "Available") {
			g.warmUntil = g.nowFn().Add(warmTTL)
		}
	}
	g.publishSnapshotLocked(g.nowFn())
	return g
}

// SetSinks atomically updates the EventLogger and MetricsEmitter used by this shared guard
// across GUI session lifecycles without replacing the process-lifetime GitHubGuard instance.
func (g *GitHubGuard) SetSinks(logger *EventLogger, metrics *MetricsEmitter) {
	if g == nil {
		return
	}
	g.loggerPtr.Store(logger)
	g.metricsPtr.Store(metrics)
}

// SetStateCache attaches an explicit persistent CodespaceStateCache (useful for deterministic testing).
func (g *GitHubGuard) SetStateCache(cache *CodespaceStateCache) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stateCache = cache
	if cache != nil {
		if st, ok := cache.Get(g.warmCacheTTL); ok && strings.EqualFold(st, "Available") {
			g.warmUntil = g.nowFn().Add(g.warmCacheTTL)
		}
	}
	g.publishSnapshotLocked(g.nowFn())
}

// MarkCodespaceState explicitly records an observed Codespace VM state ("Available", "Shutdown", etc.)
// in both the in-memory warm window and the optional persistent disk cache.
func (g *GitHubGuard) MarkCodespaceState(state string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	now := g.nowFn()
	low := strings.ToLower(strings.TrimSpace(state))
	if low == "available" {
		g.warmUntil = now.Add(g.warmCacheTTL)
		g.sessionStopped = false
		g.sessionStoppedUntil = time.Time{}
	} else if low == "shutdown" || low == "stopped" || low == "unavailable" {
		g.warmUntil = time.Time{}
		g.sessionStopped = true
		g.sessionStoppedUntil = now.Add(g.warmCacheTTL)
	}
	cache := g.stateCache
	g.publishSnapshotLocked(now)
	g.mu.Unlock()
	if cache != nil {
		_ = cache.Set(state)
	}
}

// MarkSessionStopped explicitly engages the intra-session churn brake when the current session
// observes a stopped/shutdown Codespace VM (and persists "Shutdown" to disk cache if configured).
func (g *GitHubGuard) MarkSessionStopped() {
	g.MarkCodespaceState("Shutdown")
}

// ClearSessionStopped lifts any active intra-session stopped brake so subsequent tunnel boots may proceed.
func (g *GitHubGuard) ClearSessionStopped() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.sessionStopped = false
	g.sessionStoppedUntil = time.Time{}
	g.publishSnapshotLocked(g.nowFn())
	g.mu.Unlock()
}

// NeedsColdWarmup reports cross-session cold-start awareness: true when the Codespace is not
// currently warm and the persistent disk cache explicitly recorded a recent Shutdown/Stopped state.
// Unlike the intra-session churn brake, NeedsColdWarmup NEVER blocks TryAllow on fresh startup.
func (g *GitHubGuard) NeedsColdWarmup() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.nowFn()
	if now.Before(g.warmUntil) {
		return false
	}
	if g.stateCache != nil && g.stateCache.IsStopped(g.warmCacheTTL) {
		return true
	}
	return false
}

// ClassifyStderr inspects gh/ssh stderr output to separate GitHub WAF/bot/rate limits,
// transient Codespace VM transitions (HTTP 400 / concurrent start / shutting down),
// auth/stopped-codespace errors, and ordinary cellular network/relay failures.
func ClassifyStderr(stderrTail string) FailureClass {
	lower := strings.ToLower(stderrTail)
	if lower == "" {
		return FailureNetworkLane
	}
	// Permanent auth/scope/404/billing failures (including "HTTP 403: missing required scope")
	// MUST classify as FailureAuthOrStopped instead of triggering WAF rate-limit cooldowns.
	if ClassifyPermanentBootError(stderrTail) != nil {
		return FailureAuthOrStopped
	}
	rateLimitTokens := []string{
		"http 429",
		"429 too many requests",
		"too many requests",
		"secondary rate limit",
		"api rate limit exceeded",
		"rate limit",
		"abuse detection",
		"http 403",
		"forbidden",
		"waf",
		"bot detection",
		"retry-after",
	}
	for _, tok := range rateLimitTokens {
		if strings.Contains(lower, tok) {
			return FailureAPIRateLimit
		}
	}
	if isVMTransitionStderr(lower) {
		return FailureVMTransition
	}
	authStoppedTokens := []string{
		"http 401",
		"unauthorized",
		"gh auth login",
		"authentication failed",
		"codespace is stopped",
		"codespace not found",
		"http 404",
	}
	for _, tok := range authStoppedTokens {
		if strings.Contains(lower, tok) {
			return FailureAuthOrStopped
		}
	}
	return FailureNetworkLane
}

func (g *GitHubGuard) pruneLocked(now time.Time) {
	cutoff := now.Add(-time.Hour)
	idx := 0
	for idx < len(g.callTimes) && !g.callTimes[idx].After(cutoff) {
		idx++
	}
	if idx > 0 {
		g.callTimes = append(g.callTimes[:0], g.callTimes[idx:]...)
	}
}

func (g *GitHubGuard) countRecentLocked(now time.Time, window time.Duration) (int, time.Time) {
	cutoff := now.Add(-window)
	cnt := 0
	var earliest time.Time
	for _, ts := range g.callTimes {
		if ts.After(cutoff) {
			if cnt == 0 {
				earliest = ts
			}
			cnt++
		}
	}
	return cnt, earliest
}

// TryAllow checks whether a gh invocation may proceed immediately without blocking.
// Enforces intra-session stopped brake, WAF/rate-limit cooldown, minimum inter-call spacing,
// and sliding 5-minute / 60-minute budgets. If allowed, consumes one slot atomically.
func (g *GitHubGuard) TryAllow(reason string) (allowed bool, wait time.Duration, blockReason string) {
	if g == nil {
		return true, 0, ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFn()
	defer func() {
		g.publishSnapshotLocked(now)
	}()
	g.pruneLocked(now)

	if g.sessionStopped {
		if !g.sessionStoppedUntil.IsZero() && !now.Before(g.sessionStoppedUntil) {
			g.sessionStopped = false
			g.sessionStoppedUntil = time.Time{}
		} else {
			g.totalThrottled++
			return false, g.rateLimitBase, "codespace_cached_stopped"
		}
	}

	if now.Before(g.cooldownUntil) {
		g.totalThrottled++
		why := g.cooldownReason
		if why == "" {
			why = "api_rate_limit_cooldown"
		}
		return false, g.cooldownUntil.Sub(now), why
	}

	// v6.3 WAF / anti-bot burst protection: enforce minimum inter-call spacing between consecutive gh calls.
	if g.minCallSpacing > 0 && !g.lastCallAt.IsZero() {
		nextAllowed := g.lastCallAt.Add(g.minCallSpacing)
		if now.Before(nextAllowed) {
			g.totalThrottled++
			return false, nextAllowed.Sub(now), "min_call_spacing"
		}
	}

	c5, earliest5 := g.countRecentLocked(now, 5*time.Minute)
	if c5 >= g.maxPer5Min {
		g.totalThrottled++
		w := earliest5.Add(5 * time.Minute).Sub(now)
		if w < 50*time.Millisecond {
			w = 50 * time.Millisecond
		}
		return false, w, "budget_5m_exhausted"
	}

	c60, earliest60 := g.countRecentLocked(now, time.Hour)
	if c60 >= g.maxPerHour {
		g.totalThrottled++
		w := earliest60.Add(time.Hour).Sub(now)
		if w < 50*time.Millisecond {
			w = 50 * time.Millisecond
		}
		return false, w, "budget_hour_exhausted"
	}

	g.callTimes = append(g.callTimes, now)
	g.lastCallAt = now
	g.totalAllowed++
	snap := g.snapshotLocked(now)

	if m := g.metricsPtr.Load(); m != nil {
		m.Emit("api_guard", map[string]any{
			"action":          "allowed",
			"reason":          reason,
			"calls_last_5m":   snap.CallsLast5Min,
			"calls_last_hour": snap.CallsLastHour,
			"codespace_warm":  snap.CodespaceWarm,
		})
	}
	return true, 0, ""
}

// CanAllowNonConsuming performs a read-only check of whether a gh invocation would be permitted right now
// WITHOUT consuming a budget slot or incrementing throttle counters. Used by CheckSlowLaneEviction so a
// working-but-slow fallback worker is NEVER torn down into DEAD while GitHubGuard is cooling down or
// budget-exhausted (preventing single-point-of-failure 0-healthy-worker outages during WAF/429 lockouts).
func (g *GitHubGuard) CanAllowNonConsuming() (allowed bool, blockReason string) {
	if g == nil {
		return true, ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFn()
	g.pruneLocked(now)

	if g.sessionStopped {
		if !g.sessionStoppedUntil.IsZero() && !now.Before(g.sessionStoppedUntil) {
			g.sessionStopped = false
			g.sessionStoppedUntil = time.Time{}
		} else {
			return false, "codespace_cached_stopped"
		}
	}
	if now.Before(g.cooldownUntil) {
		why := g.cooldownReason
		if why == "" {
			why = "api_rate_limit_cooldown"
		}
		return false, why
	}
	if g.minCallSpacing > 0 && !g.lastCallAt.IsZero() && now.Before(g.lastCallAt.Add(g.minCallSpacing)) {
		return false, "min_call_spacing"
	}
	if c5, _ := g.countRecentLocked(now, 5*time.Minute); c5 >= g.maxPer5Min {
		return false, "budget_5m_exhausted"
	}
	if c60, _ := g.countRecentLocked(now, time.Hour); c60 >= g.maxPerHour {
		return false, "budget_hour_exhausted"
	}
	return true, ""
}

// Allow blocks until the GitHub API budget, spacing, & cooldown permit one `gh` invocation or ctx cancels.
func (g *GitHubGuard) Allow(ctx context.Context, reason string) error {
	if g == nil {
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, wait, blockReason := g.TryAllow(reason)
		if ok {
			return nil
		}
		if l := g.loggerPtr.Load(); l != nil {
			snap := g.Snapshot()
			l.Log("GITHUB_API_THROTTLED", map[string]any{
				"reason":          reason,
				"block_reason":    blockReason,
				"wait_ms":         wait.Milliseconds(),
				"calls_last_5m":   snap.CallsLast5Min,
				"calls_last_hour": snap.CallsLastHour,
				"rate_limit_hits": snap.RateLimitHits,
			})
		}
		if m := g.metricsPtr.Load(); m != nil {
			m.Emit("api_guard", map[string]any{
				"action":       "throttled",
				"reason":       reason,
				"block_reason": blockReason,
				"wait_ms":      wait.Milliseconds(),
			})
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// RecordFailure classifies a failed gh invocation and applies Retry-After + full-jitter exponential backoff
// on HTTP 429/403 WAF/rate-limit signatures.
func (g *GitHubGuard) RecordFailure(stderrTail string) (FailureClass, time.Duration) {
	cls := ClassifyStderr(stderrTail)
	if g == nil {
		return cls, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFn()
	var cooldown time.Duration
	retryAfter := ParseRetryAfterAt(stderrTail, now)

	switch cls {
	case FailureAPIRateLimit:
		g.rateLimitHits++
		g.rateLimitStreak++
		shift := g.rateLimitStreak - 1
		if shift > 6 {
			shift = 6
		}
		raw := float64(g.rateLimitBase) * math.Pow(2, float64(shift))
		if raw > float64(g.rateLimitMax) {
			raw = float64(g.rateLimitMax)
		}
		// Full jitter in [0.5 * raw, raw] to break synchronized retry storms.
		u := g.randFloat64Locked()
		cooldown = time.Duration(raw * (0.5 + 0.5*u))
		// Honor server-supplied Retry-After header when larger than computed backoff (capped at rateLimitMax).
		if retryAfter > cooldown {
			cooldown = retryAfter
			if g.rateLimitMax > 0 && cooldown > g.rateLimitMax {
				cooldown = g.rateLimitMax
			}
		}
		if until := now.Add(cooldown); until.After(g.cooldownUntil) {
			g.cooldownUntil = until
			g.cooldownReason = "api_rate_limit_cooldown"
		}
	case FailureVMTransition:
		g.vmTransitionHits++
		g.warmUntil = time.Time{} // VM is starting/shutting down; not yet confirmed Available
		minB := 10 * time.Second
		maxB := 20 * time.Second
		if g.rateLimitBase > 0 && g.rateLimitBase < minB {
			minB = g.rateLimitBase
			maxB = g.rateLimitBase * 2
		}
		if g.rateLimitMax > 0 && maxB > g.rateLimitMax {
			maxB = g.rateLimitMax
			if minB > maxB {
				minB = maxB
			}
		}
		u := g.randFloat64Locked()
		cooldown = minB + time.Duration(float64(maxB-minB)*u)
		if until := now.Add(cooldown); until.After(g.cooldownUntil) {
			g.cooldownUntil = until
			g.cooldownReason = "vm_transition_cooldown"
		}
	case FailureAuthOrStopped:
		g.authOrStoppedHits++
		g.warmUntil = time.Time{} // Codespace is stopped or auth invalid; invalidate warm cache
		lowTail := strings.ToLower(stderrTail)
		if strings.Contains(lowTail, "stopped") || strings.Contains(lowTail, "shutdown") {
			g.sessionStopped = true
			g.sessionStoppedUntil = now.Add(g.warmCacheTTL)
			if g.stateCache != nil {
				_ = g.stateCache.Set("Shutdown")
			}
		}
		if ClassifyPermanentBootError(stderrTail) != nil {
			// Permanent HTTP 404/401 errors abort immediately in Supervisor/TunnelPool;
			// do not engage a synthetic 15s rate-limit cooldown so fixing the Codespace name
			// or re-authenticating can retry right away (2s min_call_spacing still applies).
			g.publishSnapshotLocked(now)
			return cls, 0
		}
		cooldown = g.rateLimitBase
		if until := now.Add(cooldown); until.After(g.cooldownUntil) {
			g.cooldownUntil = until
			g.cooldownReason = "api_rate_limit_cooldown"
		}
	default:
		// Ordinary cellular drop or slow 5-tuple lane: do NOT penalize API rate-limit streak.
		return cls, 0
	}

	if l := g.loggerPtr.Load(); l != nil {
		l.Log("GITHUB_API_BACKOFF", map[string]any{
			"failure_class":      string(cls),
			"cooldown_ms":        cooldown.Milliseconds(),
			"retry_after_ms":     retryAfter.Milliseconds(),
			"rate_limit_streak":  g.rateLimitStreak,
			"rate_limit_hits":    g.rateLimitHits,
			"vm_transition_hits": g.vmTransitionHits,
		})
	}
	if m := g.metricsPtr.Load(); m != nil {
		m.Emit("api_guard", map[string]any{
			"action":             "backoff",
			"failure_class":      string(cls),
			"cooldown_ms":        cooldown.Milliseconds(),
			"retry_after_ms":     retryAfter.Milliseconds(),
			"rate_limit_streak":  g.rateLimitStreak,
			"vm_transition_hits": g.vmTransitionHits,
		})
	}
	g.publishSnapshotLocked(now)
	return cls, cooldown
}

// RecordSuccess clears any active API rate-limit streak or intra-session stopped brake
// and marks the Codespace VM warm ("Available").
func (g *GitHubGuard) RecordSuccess() {
	if g == nil {
		return
	}
	g.mu.Lock()
	now := g.nowFn()
	g.rateLimitStreak = 0
	g.sessionStopped = false
	g.sessionStoppedUntil = time.Time{}
	g.warmUntil = now.Add(g.warmCacheTTL)
	cache := g.stateCache
	g.publishSnapshotLocked(now)
	g.mu.Unlock()
	if cache != nil {
		_ = cache.Set("Available")
	}
}

// IsCodespaceWarm reports whether a recent successful SSH boot (or fresh persistent cache)
// proved the Codespace VM is running.
func (g *GitHubGuard) IsCodespaceWarm() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.nowFn().Before(g.warmUntil) {
		return true
	}
	if g.stateCache != nil {
		if st, ok := g.stateCache.Get(g.warmCacheTTL); ok && strings.EqualFold(st, "Available") {
			return true
		}
	}
	return false
}

func (g *GitHubGuard) randFloat64Locked() float64 {
	if g.rng != nil {
		return g.rng.Float64()
	}
	return rand.Float64()
}

func (g *GitHubGuard) snapshotLocked(now time.Time) GitHubGuardSnapshot {
	g.pruneLocked(now)
	c5, earliest5 := g.countRecentLocked(now, 5*time.Minute)
	c60, earliest60 := g.countRecentLocked(now, time.Hour)
	var remMS int64
	var throttleReason string
	if now.Before(g.cooldownUntil) {
		remMS = g.cooldownUntil.Sub(now).Milliseconds()
		throttleReason = g.cooldownReason
		if throttleReason == "" {
			throttleReason = "api_rate_limit_cooldown"
		}
	}
	var budgetWaitMS int64
	var budgetReason string
	if c5 >= g.maxPer5Min && !earliest5.IsZero() {
		if w := earliest5.Add(5 * time.Minute).Sub(now).Milliseconds(); w > budgetWaitMS {
			budgetWaitMS = w
			budgetReason = "budget_5m_exhausted"
		}
	}
	if c60 >= g.maxPerHour && !earliest60.IsZero() {
		if w := earliest60.Add(time.Hour).Sub(now).Milliseconds(); w > budgetWaitMS {
			budgetWaitMS = w
			budgetReason = "budget_hour_exhausted"
		}
	}
	throttleWaitMS := remMS
	if budgetWaitMS > throttleWaitMS {
		throttleWaitMS = budgetWaitMS
		throttleReason = budgetReason
	}
	if g.sessionStopped && !g.sessionStoppedUntil.IsZero() && now.Before(g.sessionStoppedUntil) {
		if w := g.sessionStoppedUntil.Sub(now).Milliseconds(); w > throttleWaitMS {
			throttleWaitMS = w
			throttleReason = "codespace_cached_stopped"
		}
	}
	return GitHubGuardSnapshot{
		CallsLast5Min:       c5,
		MaxCallsPer5Min:     g.maxPer5Min,
		CallsLastHour:       c60,
		MaxCallsPerHour:     g.maxPerHour,
		MinCallSpacingMS:    g.minCallSpacing.Milliseconds(),
		TotalAllowed:        g.totalAllowed,
		TotalThrottled:      g.totalThrottled,
		RateLimitHits:       g.rateLimitHits,
		VMTransitionHits:    g.vmTransitionHits,
		AuthOrStoppedHits:   g.authOrStoppedHits,
		CooldownRemainingMS: remMS,
		BudgetWaitMS:        budgetWaitMS,
		ThrottleWaitMS:      throttleWaitMS,
		ThrottleReason:      throttleReason,
		CodespaceWarm:       now.Before(g.warmUntil),
	}
}

// publishSnapshotLocked stores an immutable GitHubGuardSnapshot for wait-free UI observation.
// Caller must hold g.mu.
func (g *GitHubGuard) publishSnapshotLocked(now time.Time) {
	snap := g.snapshotLocked(now)
	g.publishedSnap.Store(&snap)

	timesCopy := make([]time.Time, len(g.callTimes))
	copy(timesCopy, g.callTimes)
	g.publishedTimes.Store(&timesCopy)

	if !g.cooldownUntil.IsZero() && g.cooldownUntil.After(now) {
		g.cooldownUntilNS.Store(g.cooldownUntil.UnixNano())
		r := g.cooldownReason
		if r == "" {
			r = "api_rate_limit_cooldown"
		}
		g.cooldownReasonPtr.Store(&r)
	} else {
		g.cooldownUntilNS.Store(0)
		g.cooldownReasonPtr.Store(nil)
	}
	if g.sessionStopped && !g.sessionStoppedUntil.IsZero() && g.sessionStoppedUntil.After(now) {
		g.sessionStoppedUntilNS.Store(g.sessionStoppedUntil.UnixNano())
	} else {
		g.sessionStoppedUntilNS.Store(0)
	}
}

// CachedSnapshot returns a wait-free copy of the latest published GitHubGuardSnapshot with 0 mutex acquisitions.
func (g *GitHubGuard) CachedSnapshot() GitHubGuardSnapshot {
	if g == nil {
		return GitHubGuardSnapshot{}
	}
	var snap GitHubGuardSnapshot
	if ptr := g.publishedSnap.Load(); ptr != nil {
		snap = *ptr
	}
	now := time.Now()
	if g.nowFn != nil {
		now = g.nowFn()
	}

	// Wait-free sliding-window recalculation so 5m/1h call counts and budget unlock countdowns
	// stay live every second even while no mutating GitHubGuard calls occur.
	var budgetWaitMS int64
	var budgetReason string
	if timesPtr := g.publishedTimes.Load(); timesPtr != nil {
		times := *timesPtr
		cutoff5 := now.Add(-5 * time.Minute)
		cutoff60 := now.Add(-time.Hour)
		c5 := 0
		c60 := 0
		var earliest5, earliest60 time.Time
		for _, ts := range times {
			if ts.After(cutoff60) {
				if c60 == 0 {
					earliest60 = ts
				}
				c60++
				if ts.After(cutoff5) {
					if c5 == 0 {
						earliest5 = ts
					}
					c5++
				}
			}
		}
		snap.CallsLast5Min = c5
		snap.CallsLastHour = c60
		if snap.MaxCallsPer5Min > 0 && c5 >= snap.MaxCallsPer5Min && !earliest5.IsZero() {
			if w := earliest5.Add(5 * time.Minute).Sub(now).Milliseconds(); w > budgetWaitMS {
				budgetWaitMS = w
				budgetReason = "budget_5m_exhausted"
			}
		}
		if snap.MaxCallsPerHour > 0 && c60 >= snap.MaxCallsPerHour && !earliest60.IsZero() {
			if w := earliest60.Add(time.Hour).Sub(now).Milliseconds(); w > budgetWaitMS {
				budgetWaitMS = w
				budgetReason = "budget_hour_exhausted"
			}
		}
	}
	snap.BudgetWaitMS = budgetWaitMS

	var cooldownMS int64
	var throttleReason string
	if untilNS := g.cooldownUntilNS.Load(); untilNS > 0 {
		if rem := time.Unix(0, untilNS).Sub(now).Milliseconds(); rem > 0 {
			cooldownMS = rem
			if rPtr := g.cooldownReasonPtr.Load(); rPtr != nil && *rPtr != "" {
				throttleReason = *rPtr
			} else {
				throttleReason = "api_rate_limit_cooldown"
			}
		}
	}
	snap.CooldownRemainingMS = cooldownMS

	throttleWaitMS := cooldownMS
	if budgetWaitMS > throttleWaitMS {
		throttleWaitMS = budgetWaitMS
		throttleReason = budgetReason
	}
	if ssNS := g.sessionStoppedUntilNS.Load(); ssNS > 0 {
		if rem := time.Unix(0, ssNS).Sub(now).Milliseconds(); rem > throttleWaitMS {
			throttleWaitMS = rem
			throttleReason = "codespace_cached_stopped"
		}
	}
	snap.ThrottleWaitMS = throttleWaitMS
	snap.ThrottleReason = throttleReason
	return snap
}

// Snapshot returns a thread-safe copy of the guard's sliding-window and backoff metrics.
func (g *GitHubGuard) Snapshot() GitHubGuardSnapshot {
	if g == nil {
		return GitHubGuardSnapshot{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshotLocked(g.nowFn())
}
