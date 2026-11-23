//go:build windows

package main

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// inspectHostNetHygiene executes strictly READ-ONLY diagnostic queries (`netsh ... show ...`).
// It NEVER executes modifying commands (`set`, `add`, `delete`) or registry writes.
func inspectHostNetHygiene(ctx context.Context) NetHygieneReport {
	rep := NetHygieneReport{
		Platform: "windows",
		ReadOnly: true,
	}

	runReadOnly := func(args ...string) (string, error) {
		qCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		defer cancel()
		cmd := exec.CommandContext(qCtx, "netsh", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: CREATE_NO_WINDOW,
			HideWindow:    true,
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := runReadOnly("int", "tcp", "show", "global"); err == nil {
		rep.Checks = append(rep.Checks, ParseNetshTCPGlobal(out)...)
	} else {
		rep.Checks = append(rep.Checks, NetHygieneCheck{
			Name:     "tcp_global_query",
			Status:   "unavailable",
			Observed: err.Error(),
		})
	}

	if out, err := runReadOnly("advfirewall", "show", "allprofiles", "state"); err == nil {
		rep.Checks = append(rep.Checks, ParseNetshFirewallSummary(out))
	} else {
		rep.Checks = append(rep.Checks, NetHygieneCheck{
			Name:     "windows_firewall_profiles",
			Status:   "unavailable",
			Observed: err.Error(),
		})
	}

	if out, err := runReadOnly("advfirewall", "firewall", "show", "rule", "name=all", "dir=out"); err == nil {
		rep.Checks = append(rep.Checks, ParseNetshFirewallAudit(out)...)
	}

	if out, err := runReadOnly("int", "ipv4", "show", "subinterfaces"); err == nil {
		trimmed := strings.TrimSpace(out)
		if len(trimmed) > 512 {
			trimmed = trimmed[:512]
		}
		rep.Checks = append(rep.Checks, NetHygieneCheck{
			Name:        "ipv4_interface_mtu",
			Status:      "info",
			Observed:    strings.ReplaceAll(strings.ReplaceAll(trimmed, "\r", ""), "\n", " | "),
			Recommended: "Empirical Azure Relay 20.120.56.11 PMTU is 576B; NetShaper v6 defaults to 16KiB copy chunks and adaptively steps down to 8KiB on 20.120.56.11 without touching SO_SNDBUF/SO_RCVBUF",
		})
	}

	return rep
}
