//go:build windows

package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet                      = 2
	afInet6                     = 23
	tcpTableOwnerPIDListener    = 3
	tcpTableOwnerPIDConnections = 4
	mibTCPStateEstab            = 5
	errInsufficientBuffer       = 122
)

var (
	modIPHlpAPI             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHlpAPI.NewProc("GetExtendedTcpTable")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

func ntohsFromDWORD(raw uint32) uint16 {
	return uint16(raw&0xff)<<8 | uint16((raw>>8)&0xff)
}

// WindowsPortInspector uses Win32 iphlpapi.dll + kernel32.dll with zero cmd.exe spawns.
type WindowsPortInspector struct{}

// NewPlatformPortInspector returns the native Windows TCP table inspector.
func NewPlatformPortInspector() PortInspector {
	return &WindowsPortInspector{}
}

func (w *WindowsPortInspector) ListListeners() ([]TCPListenerEntry, error) {
	v4, err4 := queryExtendedTCPTable(afInet)
	v6, err6 := queryExtendedTCPTable(afInet6)
	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("GetExtendedTcpTable IPv4=%v IPv6=%v", err4, err6)
	}
	out := make([]TCPListenerEntry, 0, len(v4)+len(v6))
	out = append(out, v4...)
	out = append(out, v6...)
	return out, nil
}

func queryExtendedTCPTableRaw(family uint32, tableClass uint32) ([]byte, error) {
	if err := procGetExtendedTCPTable.Find(); err != nil {
		return nil, err
	}

	var size uint32
	for attempt := 0; attempt < 4; attempt++ {
		var buf []byte
		var ptr uintptr
		if size > 0 {
			buf = make([]byte, size)
			ptr = uintptr(unsafe.Pointer(&buf[0]))
		}
		r1, _, _ := procGetExtendedTCPTable.Call(
			ptr,
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(family),
			uintptr(tableClass),
			0,
		)
		if r1 == errInsufficientBuffer {
			continue
		}
		if r1 != 0 {
			return nil, windows.Errno(r1)
		}
		return buf, nil
	}
	return nil, fmt.Errorf("GetExtendedTcpTable(%d, class=%d): buffer size did not stabilize", family, tableClass)
}

func queryExtendedTCPTable(family uint32) ([]TCPListenerEntry, error) {
	buf, err := queryExtendedTCPTableRaw(family, tcpTableOwnerPIDListener)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numEntries == 0 {
		return nil, nil
	}

	entries := make([]TCPListenerEntry, 0, numEntries)
	if family == afInet {
		rowSize := uint32(unsafe.Sizeof(mibTCPRowOwnerPID{}))
		for i := uint32(0); i < numEntries; i++ {
			off := 4 + i*rowSize
			if int(off+rowSize) > len(buf) {
				break
			}
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[off]))
			entries = append(entries, TCPListenerEntry{
				Port:   ntohsFromDWORD(row.LocalPort),
				PID:    row.OwningPID,
				Family: "tcp4",
			})
		}
	} else {
		rowSize := uint32(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
		for i := uint32(0); i < numEntries; i++ {
			off := 4 + i*rowSize
			if int(off+rowSize) > len(buf) {
				break
			}
			row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[off]))
			entries = append(entries, TCPListenerEntry{
				Port:   ntohsFromDWORD(row.LocalPort),
				PID:    row.OwningPID,
				Family: "tcp6",
			})
		}
	}
	return entries, nil
}

func isGitHubAPIRange(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 140 && ip4[1] == 82 && (ip4[2]&0xf0) == 112
}

// LookupProcessWANRemote inspects kernel TCP connections across pid and descendants,
// preferring Azure Dev Tunnels Relay endpoints over lingering api.github.com connections.
func LookupProcessWANRemote(pid uint32) string {
	remotes := LookupProcessTreeWANRemotes(pid)
	if len(remotes) == 0 {
		return ""
	}
	return remotes[0]
}

// LookupProcessTreeWANRemotes returns all deduplicated ESTABLISHED non-loopback remote IP:Port
// endpoints across pid and its descendant process tree, ordered with Azure Relay IPs first.
func LookupProcessTreeWANRemotes(pid uint32) []string {
	if pid == 0 {
		return nil
	}
	pids := collectProcessTreePIDs(pid)
	pidSet := make(map[uint32]bool, len(pids))
	for _, p := range pids {
		pidSet[p] = true
	}

	var primary []string
	var secondary []string
	seen := make(map[string]bool)

	addEndpoint := func(ip net.IP, port uint16) {
		if port == 0 || ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return
		}
		ep := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		if seen[ep] {
			return
		}
		seen[ep] = true
		if isGitHubAPIRange(ip) {
			secondary = append(secondary, ep)
		} else {
			primary = append(primary, ep)
		}
	}

	collectWANRemotesFamily(pidSet, afInet, addEndpoint)
	collectWANRemotesFamily(pidSet, afInet6, addEndpoint)

	if len(primary) == 0 && len(secondary) == 0 {
		return nil
	}
	return append(primary, secondary...)
}

func collectWANRemotesFamily(pidSet map[uint32]bool, family uint32, emit func(net.IP, uint16)) {
	buf, err := queryExtendedTCPTableRaw(family, tcpTableOwnerPIDConnections)
	if err != nil || len(buf) < 4 {
		return
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numEntries == 0 {
		return
	}

	if family == afInet {
		rowSize := uint32(unsafe.Sizeof(mibTCPRowOwnerPID{}))
		for i := uint32(0); i < numEntries; i++ {
			off := 4 + i*rowSize
			if int(off+rowSize) > len(buf) {
				break
			}
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[off]))
			if !pidSet[row.OwningPID] || row.State != mibTCPStateEstab {
				continue
			}
			ip := net.IPv4(
				byte(row.RemoteAddr),
				byte(row.RemoteAddr>>8),
				byte(row.RemoteAddr>>16),
				byte(row.RemoteAddr>>24),
			)
			emit(ip, ntohsFromDWORD(row.RemotePort))
		}
		return
	}

	rowSize := uint32(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
	for i := uint32(0); i < numEntries; i++ {
		off := 4 + i*rowSize
		if int(off+rowSize) > len(buf) {
			break
		}
		row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[off]))
		if !pidSet[row.OwningPID] || row.State != mibTCPStateEstab {
			continue
		}
		ip := make(net.IP, 16)
		copy(ip, row.RemoteAddr[:])
		emit(ip, ntohsFromDWORD(row.RemotePort))
	}
}

func (w *WindowsPortInspector) ProcessImageName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH*2)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return filepath.Base(windows.UTF16ToString(buf[:size])), nil
}

func (w *WindowsPortInspector) TerminatePID(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}
