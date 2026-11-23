//go:build !windows

package main

import (
	"errors"
	"os/exec"
)

// RunPlatformUI falls back cleanly to headless CLI supervision on non-Windows hosts.
func RunPlatformUI(cfg Config) error {
	runHeadlessCLI(cfg)
	return nil
}

// configureHiddenCmd is a cross-platform no-op on Unix (no Win32 conhost.exe window flash).
func configureHiddenCmd(_ *exec.Cmd) {}

// configureInteractiveConsoleCmd configures process-group containment on non-Windows hosts.
func configureInteractiveConsoleCmd(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	configureChildCmdPlatform(cmd)
}

// copyTextToClipboard is a non-Windows stub matching ui_windows.go parity.
func copyTextToClipboard(_ uintptr, _ string) error {
	return errors.New("clipboard not supported on non-windows build")
}

// verifyExitReLaunchAndClipboardInvariants is a non-Windows stub matching ui_windows.go parity.
func verifyExitReLaunchAndClipboardInvariants() error {
	return nil
}
