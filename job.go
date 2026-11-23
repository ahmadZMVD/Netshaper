package main

import "os/exec"

// ProcessJob abstracts OS-level process-tree containment (Win32 Job Object / Unix process group)
// so tearing down a tunnel worker kills gh.exe + ssh.exe atomically with zero orphans.
type ProcessJob interface {
	Assign(pid int) error
	Close() error
}

// ConfigureChildCmd applies platform-specific process group and priority attributes before cmd.Start().
func ConfigureChildCmd(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	configureChildCmdPlatform(cmd)
}
