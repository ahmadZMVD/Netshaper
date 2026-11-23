//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ABOVE_NORMAL_PRIORITY_CLASS     = 0x00008000
	CREATE_NO_WINDOW                = 0x08000000
	processPowerThrottlingInfoClass = 4
	processPowerThrottlingVersion   = 1
	processPowerThrottlingEcoQoS    = 0x1
	stillActiveExitCode             = 259
)

type processPowerThrottlingState struct {
	Version     uint32
	ControlMask uint32
	StateMask   uint32
}

var (
	modKernel32Power          = windows.NewLazySystemDLL("kernel32.dll")
	procSetProcessInformation = modKernel32Power.NewProc("SetProcessInformation")
)

// WindowsJobObject wraps a Win32 Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
type WindowsJobObject struct {
	mu     sync.Mutex
	handle windows.Handle
	closed bool
}

// NewProcessJob creates a Windows Job Object that atomically kills all assigned processes on Close().
func NewProcessJob() (ProcessJob, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return &WindowsJobObject{handle: h}, nil
}

// Assign attaches pid (and all future child processes it spawns) to this Job Object.
func (j *WindowsJobObject) Assign(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.handle == 0 {
		return fmt.Errorf("job object already closed")
	}
	hProc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	if err := windows.AssignProcessToJobObject(j.handle, hProc); err != nil {
		return fmt.Errorf("AssignProcessToJobObject(%d): %w", pid, err)
	}
	return nil
}

// Close closes the Job Object handle, atomically terminating every process in the job tree.
func (j *WindowsJobObject) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.handle == 0 {
		return nil
	}
	j.closed = true
	h := j.handle
	j.handle = 0
	return windows.CloseHandle(h)
}

func configureChildCmdPlatform(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP | ABOVE_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW
	cmd.SysProcAttr.HideWindow = true
}

func disableEcoQoSHandle(h windows.Handle) error {
	if err := procSetProcessInformation.Find(); err != nil {
		return err
	}
	state := processPowerThrottlingState{
		Version:     processPowerThrottlingVersion,
		ControlMask: processPowerThrottlingEcoQoS,
		StateMask:   0, // Explicitly disable Windows 11 Efficiency Mode / EcoQoS throttling
	}
	r1, _, callErr := procSetProcessInformation.Call(
		uintptr(h),
		uintptr(processPowerThrottlingInfoClass),
		uintptr(unsafe.Pointer(&state)),
		uintptr(unsafe.Sizeof(state)),
	)
	if r1 == 0 {
		return callErr
	}
	return nil
}

// DisableEcoQoS elevates NetShaper itself to ABOVE_NORMAL_PRIORITY_CLASS and disables Win11 EcoQoS.
func DisableEcoQoS() error {
	self := windows.CurrentProcess()
	_ = windows.SetPriorityClass(self, ABOVE_NORMAL_PRIORITY_CLASS)
	return disableEcoQoSHandle(self)
}

// TuneChildProcessQoS elevates a supervised child PID to ABOVE_NORMAL_PRIORITY_CLASS and disables EcoQoS.
func TuneChildProcessQoS(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_INFORMATION, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	_ = windows.SetPriorityClass(h, ABOVE_NORMAL_PRIORITY_CLASS)
	return disableEcoQoSHandle(h)
}

// collectProcessTreePIDs walks the Win32 Toolhelp32 snapshot to return rootPID and all descendants (gh.exe + ssh.exe).
func collectProcessTreePIDs(rootPID uint32) []uint32 {
	if rootPID == 0 {
		return nil
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return []uint32{rootPID}
	}
	defer windows.CloseHandle(snap)

	children := make(map[uint32][]uint32)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err == nil {
		for {
			children[entry.ParentProcessID] = append(children[entry.ParentProcessID], entry.ProcessID)
			if err := windows.Process32Next(snap, &entry); err != nil {
				break
			}
		}
	}

	visited := map[uint32]bool{rootPID: true}
	queue := []uint32{rootPID}
	out := []uint32{rootPID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, child := range children[cur] {
			if !visited[child] {
				visited[child] = true
				out = append(out, child)
				queue = append(queue, child)
			}
		}
	}
	return out
}

// TuneProcessTreeQoS disables EcoQoS and sets ABOVE_NORMAL priority across rootPID and all descendants.
func TuneProcessTreeQoS(rootPID int) int {
	if rootPID <= 0 {
		return 0
	}
	pids := collectProcessTreePIDs(uint32(rootPID))
	tuned := 0
	for _, pid := range pids {
		if err := TuneChildProcessQoS(int(pid)); err == nil {
			tuned++
		}
	}
	return tuned
}

// IsProcessAlive reports whether pid is currently running on Windows.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActiveExitCode
}
