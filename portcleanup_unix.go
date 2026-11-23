//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// UnixPortInspector is a minimal non-Windows fallback so unit/chaos tests compile cross-platform.
type UnixPortInspector struct{}

// NewPlatformPortInspector returns a non-Windows inspector stub.
func NewPlatformPortInspector() PortInspector {
	return &UnixPortInspector{}
}

func (u *UnixPortInspector) ListListeners() ([]TCPListenerEntry, error) {
	return nil, nil
}

func (u *UnixPortInspector) ProcessImageName(pid uint32) (string, error) {
	return "", errors.New("native Windows IP Helper API unavailable on non-Windows platform")
}

func (u *UnixPortInspector) TerminatePID(pid uint32) error {
	return syscall.Kill(int(pid), syscall.SIGKILL)
}

// LookupProcessWANRemote is a no-op stub on non-Windows hosts.
func LookupProcessWANRemote(pid uint32) string {
	return ""
}

// LookupProcessTreeWANRemotes is a no-op stub on non-Windows hosts.
func LookupProcessTreeWANRemotes(pid uint32) []string {
	return nil
}
