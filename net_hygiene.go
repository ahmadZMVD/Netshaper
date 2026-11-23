package main

import (
	"context"
	"strings"
)

// NetHygieneCheck represents one read-only OS/network stack diagnostic finding.
// NetShaper v6 NEVER mutates OS firewall, registry, or TCP stack settings silently at runtime.
type NetHygieneCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "ok" | "warn" | "info" | "unavailable"
	Observed    string `json:"observed"`
	Recommended string `json:"recommended,omitempty"`
}

// NetHygieneReport aggregates all read-only preflight host diagnostics.
type NetHygieneReport struct {
	Platform     string            `json:"platform"`
	ReadOnly     bool              `json:"read_only"`
	Checks       []NetHygieneCheck `json:"checks"`
	WarningCount int               `json:"warning_count"`
}

// ParseNetshTCPGlobal parses read-only output from `netsh int tcp show global`.
// Pure function so it can be unit-tested deterministically across all platforms.
func ParseNetshTCPGlobal(raw string) []NetHygieneCheck {
	kv := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.ToLower(strings.TrimSpace(parts[1]))
		if k != "" {
			kv[k] = v
		}
	}

	var checks []NetHygieneCheck

	if v, ok := kv["receive window auto-tuning level"]; ok {
		st := "ok"
		rec := ""
		if v != "normal" {
			st = "warn"
			rec = "netsh int tcp set global autotuninglevel=normal (run manually as Admin if needed)"
		}
		checks = append(checks, NetHygieneCheck{
			Name:        "tcp_autotuning",
			Status:      st,
			Observed:    v,
			Recommended: rec,
		})
	}

	if v, ok := kv["hystart"]; ok {
		st := "ok"
		rec := ""
		if v != "disabled" {
			st = "warn"
			rec = "netsh int tcp set global hystart=disabled (prevents premature Win11 HyStart++ cwnd exit on LTE jitter)"
		}
		checks = append(checks, NetHygieneCheck{
			Name:        "tcp_hystart",
			Status:      st,
			Observed:    v,
			Recommended: rec,
		})
	}

	if v, ok := kv["ecn capability"]; ok {
		st := "ok"
		rec := ""
		if v != "disabled" {
			st = "warn"
			rec = "netsh int tcp set global ecncapability=disabled (avoids middlebox ECN drops on cellular)"
		}
		checks = append(checks, NetHygieneCheck{
			Name:        "tcp_ecn",
			Status:      st,
			Observed:    v,
			Recommended: rec,
		})
	}

	if v, ok := kv["receive-side scaling state"]; ok {
		st := "ok"
		rec := ""
		if v != "enabled" {
			st = "warn"
			rec = "netsh int tcp set global rss=enabled"
		}
		checks = append(checks, NetHygieneCheck{
			Name:        "tcp_rss",
			Status:      st,
			Observed:    v,
			Recommended: rec,
		})
	}

	return checks
}

// ParseNetshFirewallSummary parses read-only output from `netsh advfirewall show allprofiles state`.
func ParseNetshFirewallSummary(raw string) NetHygieneCheck {
	lower := strings.ToLower(raw)
	if strings.TrimSpace(lower) == "" {
		return NetHygieneCheck{
			Name:     "windows_firewall_profiles",
			Status:   "unavailable",
			Observed: "empty_output",
		}
	}
	onCount := strings.Count(lower, "on")
	return NetHygieneCheck{
		Name:        "windows_firewall_profiles",
		Status:      "info",
		Observed:    strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, "\r", ""), "\n", " | ")),
		Recommended: func() string {
			if onCount > 0 {
				return "Verify outbound/loopback allow rules for NetShaper.exe, gh.exe, ssh.exe, xray.exe via net_hygiene_diag.ps1"
			}
			return ""
		}(),
	}
}

// IsPMTU576RelayIP returns true when a worker's observed WAN remote resolves to the legacy
// Azure Dev Tunnels Relay VIP empirically measured at PMTU=576 (MSS=524B) on constrained cellular/CG-NAT links.
func IsPMTU576RelayIP(remoteEndpoint string) bool {
	s := strings.TrimSpace(remoteEndpoint)
	if s == "" {
		return false
	}
	return s == "20.120.56.11" || strings.HasPrefix(s, "20.120.56.11:")
}

// splitFirewallRuleBlocks splits normalized netsh advfirewall rule output into individual rule blocks,
// handling both standard blank-line separation and compact single-newline Rule Name boundaries.
func splitFirewallRuleBlocks(normalized string) []string {
	var blocks []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur = cur[:0]
		}
	}
	for _, rawLine := range strings.Split(normalized, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			flush()
			continue
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "rule name:") && len(cur) > 0 {
			flush()
		}
		cur = append(cur, rawLine)
	}
	flush()
	return blocks
}

// ParseNetshFirewallAudit inspects strictly read-only output from
// `netsh advfirewall firewall show rule name=all dir=out` for ENABLED outbound Block rules
// targeting netshaper.exe, gh.exe, ssh.exe, or xray.exe. Disabled rules (Enabled: No) are ignored.
func ParseNetshFirewallAudit(raw string) []NetHygieneCheck {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")

	targetBins := []string{"netshaper.exe", "gh.exe", "ssh.exe", "xray.exe"}
	seen := make(map[string]bool)
	var checks []NetHygieneCheck

	for _, block := range splitFirewallRuleBlocks(normalized) {
		var ruleName, enabledVal, actionVal string
		for _, line := range strings.Split(block, "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			v := strings.TrimSpace(parts[1])
			vLow := strings.ToLower(v)
			switch k {
			case "rule name":
				ruleName = v
			case "enabled":
				enabledVal = vLow
			case "action":
				actionVal = vLow
			}
		}

		// Only flag ENABLED blocking rules.
		if !strings.Contains(actionVal, "block") {
			continue
		}
		if enabledVal == "no" || enabledVal == "false" {
			continue
		}

		blockLow := strings.ToLower(block)
		for _, bin := range targetBins {
			if strings.Contains(blockLow, bin) && !seen[bin] {
				seen[bin] = true
				obs := "enabled_outbound_block_rule"
				if ruleName != "" {
					obs = obs + " (" + ruleName + ")"
				}
				checks = append(checks, NetHygieneCheck{
					Name:        "firewall_block_" + bin,
					Status:      "warn",
					Observed:    obs,
					Recommended: "Remove or disable Windows Defender Firewall outbound Block rule for " + bin + " (see net_hygiene_diag.ps1)",
				})
			}
		}
	}

	return checks
}

// RunNetHygienePreflight runs read-only platform network diagnostics and logs results cleanly.
func RunNetHygienePreflight(ctx context.Context, logger *EventLogger, metrics *MetricsEmitter) NetHygieneReport {
	rep := inspectHostNetHygiene(ctx)
	rep.ReadOnly = true
	warns := 0
	for _, c := range rep.Checks {
		if c.Status == "warn" {
			warns++
		}
	}
	rep.WarningCount = warns

	if logger != nil {
		logger.Log("NET_HYGIENE_PREFLIGHT", map[string]any{
			"platform":      rep.Platform,
			"read_only":     rep.ReadOnly,
			"warning_count": rep.WarningCount,
			"checks":        rep.Checks,
		})
	}
	if metrics != nil {
		metrics.Emit("net_hygiene", map[string]any{
			"platform":      rep.Platform,
			"read_only":     rep.ReadOnly,
			"warning_count": rep.WarningCount,
			"checks":        rep.Checks,
		})
	}
	return rep
}
