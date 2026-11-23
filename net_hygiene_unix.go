//go:build !windows

package main

import "context"

// inspectHostNetHygiene returns a read-only informational report on non-Windows hosts.
func inspectHostNetHygiene(_ context.Context) NetHygieneReport {
	return NetHygieneReport{
		Platform: "unix",
		ReadOnly: true,
		Checks: []NetHygieneCheck{
			{
				Name:     "windows_net_hygiene",
				Status:   "info",
				Observed: "skipped_non_windows_host",
			},
		},
	}
}
