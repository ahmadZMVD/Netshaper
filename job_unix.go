//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// UnixProcessGroupJob provides process-group teardown parity with WindowsJobObject for cross-platform tests.
type UnixProcessGroupJob struct {
	mu     sync.Mutex
	pids   []int
	closed bool
}

// NewProcessJob creates a Unix process-group containment handle.
func NewProcessJob() (ProcessJob, error) {
	return &UnixProcessGroupJob{}, nil
}

// Assign registers a child process group leader for atomic teardown on Close().
func (j *UnixProcessGroupJob) Assign(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return fmt.Errorf("job already closed")
	}
	j.pids = append(j.pids, pid)
	return nil
}

// Close terminates every registered process group via SIGKILL.
func (j *UnixProcessGroupJob) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	for _, pid := range j.pids {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	j.pids = nil
	return nil
}

func configureChildCmdPlatform(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// DisableEcoQoS is a cross-platform no-op on non-Windows hosts.
func DisableEcoQoS() error {
	return nil
}

// TuneChildProcessQoS is a cross-platform no-op on non-Windows hosts.
func TuneChildProcessQoS(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	return nil
}

// TuneProcessTreeQoS returns 1 on valid PID for non-Windows test parity.
func TuneProcessTreeQoS(rootPID int) int {
	if rootPID <= 0 {
		return 0
	}
	return 1
}

// IsProcessAlive reports whether pid is alive on Unix hosts (excluding Linux/POSIX zombies).
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err != nil && err != syscall.EPERM {
		return false
	}
	if data, rerr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); rerr == nil {
		s := string(data)
		if idx := strings.LastIndexByte(s, ')'); idx >= 0 && idx+1 < len(s) {
			rest := strings.TrimSpace(s[idx+1:])
			if len(rest) > 0 && (rest[0] == 'Z' || rest[0] == 'X' || rest[0] == 'x') {
				return false
			}
		}
	}
	var status syscall.WaitStatus
	wpid, werr := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
	if werr == nil && wpid == pid {
		return false
	}
	return true
}
