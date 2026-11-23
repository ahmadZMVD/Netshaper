//go:build windows

package main

import (
	"errors"
	"fmt"
	"math"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	CREATE_NEW_CONSOLE = 0x00000010

	uiBaseWidth  = 360
	uiBaseHeight = 492

	uiWindowClassName = "NetShaperV7MainWnd"
	uiWindowTitle     = "NetShaper v7.0"
	uiMutexName       = "Local\\NetShaperV7_SingleInstance"

	timerIDUI      = 1
	uiTimerCadence = 250 // ms coalesced repaint timer (<= 4 Hz, never PostMessage per log line)

	wmNull             = 0x0000
	wmCreate           = 0x0001
	wmDestroy          = 0x0002
	wmSize             = 0x0005
	wmPaint            = 0x000F
	wmClose            = 0x0010
	wmQueryEndSession  = 0x0011
	wmEraseBkgnd       = 0x0014
	wmEndSession       = 0x0016
	wmSetFont          = 0x0030
	wmSetIcon          = 0x0080
	wmKeyDown          = 0x0100
	wmCommand          = 0x0111
	wmSysCommand       = 0x0112
	wmTimer            = 0x0113
	wmCtlColorEdit     = 0x0133
	wmCtlColorStatic   = 0x0138
	wmMouseMove        = 0x0200
	wmLButtonDown      = 0x0201
	wmLButtonUp        = 0x0202
	wmLButtonDblClk    = 0x0203
	wmRButtonUp        = 0x0205
	wmMouseWheel       = 0x020A
	wmMouseHWheel      = 0x020E
	wmCaptureChanged   = 0x0215
	wmDpiChanged       = 0x02E0
	wmAppTrayCallback  = 0x8001
	wmAppShowExisting  = 0x8002
	wmAppTraySyncState = 0x8003

	vkPrior = 0x21
	vkNext  = 0x22
	vkEnd   = 0x23
	vkHome  = 0x24
	vkLeft  = 0x25
	vkUp    = 0x26
	vkRight = 0x27
	vkDown  = 0x28

	mkShift = 0x0004

	sizeMinimized = 1
	scMinimize    = 0xF020

	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsClipChildren = 0x02000000
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsTabStop      = 0x00010000
	esAutoHScroll  = 0x0080
	emSetReadOnly  = 0x00CF
	emSetMargins   = 0x00D3
	ecLeftMargin   = 0x0001
	ecRightMargin  = 0x0002
	enChange       = 0x0300

	csHRedraw = 0x0002
	csVRedraw = 0x0001

	swHide           = 0
	swShowNoActivate = 4
	swShow           = 5
	swRestore        = 9

	pmRemove      = 0x0001
	gwlStyle      = ^uintptr(15) // GWL_STYLE (-16)
	grGdiObjects  = 0
	grUserObjects = 1

	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010
	swpNoMove     = 0x0002

	smCxScreen = 0
	smCyScreen = 1

	idcArrow = 32512

	dpiAwarenessPerMonitorV2 = ^uintptr(3) // (DPI_AWARENESS_CONTEXT)-4

	dwmwaUseImmersiveDarkMode   = 20
	dwmwaWindowCornerPreference = 33
	dwmwaSystemBackdropType     = 38
	dwmWindowCornerRound        = 2
	dwmsbtMainWindow            = 2 // Mica
	dwmsbtTransientWindow       = 3 // Acrylic frosted glass

	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nimSetVersion = 0x00000004

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	notifyIconVersion4 = 4
	ninSelect          = 0x0400
	ninKeySelect       = 0x0401
	wmContextMenu      = 0x007B

	miimState  = 0x00000001
	miimID     = 0x00000002
	miimFType  = 0x00000100
	miimString = 0x00000040
	mftString  = 0x00000000
	mftSep     = 0x00000800

	tpmLeftAlign   = 0x0000
	tpmBottomAlign = 0x0020
	tpmRightButton = 0x0002

	srccopy          = 0x00CC0020
	cleartypeQuality = 5
	defaultCharSet   = 1
	biRGB            = 0
	dibRGBColors     = 0

	// GDI+ Flat API constants (integer-only ABI — 0 float32/XMM register arguments in positions 1..4).
	gpFillModeAlternate               = 0
	gpSmoothingModeAntiAlias          = 4
	gpPixelOffsetModeHighQuality      = 2
	gpTextRenderingHintAntiAliasGrid  = 3 // Premultiplied-alpha safe on Windows 11 DWM Acrylic/Mica glass
	gpCombineModeReplace              = 0
	gpStringAlignNear                 = 0
	gpStringAlignCenter               = 1
	gpStringAlignFar                  = 2
	gpStringTrimmingNone              = 0
	gpStringTrimmingEllipsisCharacter = 3
	gpStringFormatFlagsNoWrap         = 0x00001000
	gpStringFormatFlagsNoClip         = 0x00004000

	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	idEditCodespace = 101
	idTrayShow      = 201
	idTrayToggle    = 202
	idTrayCopy      = 203
	idTrayExit      = 204
)

// Exact 64-bit Windows AMD64 Win32, DWM & GDI+ ABI structures (verified in verifyWin32ABISizes).
type winPoint struct {
	X int32
	Y int32
}

type winRect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      winPoint
}

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type paintStruct struct {
	Hdc         uintptr
	FErase      int32
	RcPaint     winRect
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type createStructW struct {
	LpCreateParams uintptr
	HInstance      uintptr
	HMenu          uintptr
	HwndParent     uintptr
	Cy             int32
	Cx             int32
	Y              int32
	X              int32
	Style          int32
	LpszName       *uint16
	LpszClass      *uint16
	DwExStyle      uint32
}

type winGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type notifyIconDataW struct {
	CbSize           uint32
	Hwnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         winGUID
	HBalloonIcon     uintptr
}

type menuItemInfoW struct {
	CbSize        uint32
	FMask         uint32
	FType         uint32
	FState        uint32
	WID           uint32
	HSubMenu      uintptr
	HbmpChecked   uintptr
	HbmpUnchecked uintptr
	DwItemData    uintptr
	DwTypeData    *uint16
	Cch           uint32
	HbmpItem      uintptr
}

type tpmParams struct {
	CbSize    uint32
	RcExclude winRect
}

type logFontW struct {
	LfHeight         int32
	LfWidth          int32
	LfEscapement     int32
	LfOrientation    int32
	LfWeight         int32
	LfItalic         byte
	LfUnderline      byte
	LfStrikeOut      byte
	LfCharSet        byte
	LfOutPrecision   byte
	LfClipPrecision  byte
	LfQuality        byte
	LfPitchAndFamily byte
	LfFaceName       [32]uint16
}

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
	BmiColors [1]uint32
}

type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

type dwmMargins struct {
	CxLeftWidth    int32
	CxRightWidth   int32
	CyTopHeight    int32
	CyBottomHeight int32
}

type gdiplusStartupInput struct {
	GdiplusVersion           uint32
	DebugEventCallback       uintptr
	SuppressBackgroundThread int32
	SuppressExternalCodecs   int32
}

type gpRectF struct {
	X      float32
	Y      float32
	Width  float32
	Height float32
}

var (
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modGdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modGdiplus  = windows.NewLazySystemDLL("gdiplus.dll")
	modShell32  = windows.NewLazySystemDLL("shell32.dll")
	modDwmAPI   = windows.NewLazySystemDLL("dwmapi.dll")
	modKernelUI = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW              = modUser32.NewProc("RegisterClassExW")
	procUnregisterClassW              = modUser32.NewProc("UnregisterClassW")
	procCreateWindowExW               = modUser32.NewProc("CreateWindowExW")
	procDestroyWindow                 = modUser32.NewProc("DestroyWindow")
	procDefWindowProcW                = modUser32.NewProc("DefWindowProcW")
	procGetMessageW                   = modUser32.NewProc("GetMessageW")
	procPeekMessageW                  = modUser32.NewProc("PeekMessageW")
	procTranslateMessage              = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW              = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage               = modUser32.NewProc("PostQuitMessage")
	procPostMessageW                  = modUser32.NewProc("PostMessageW")
	procSendMessageW                  = modUser32.NewProc("SendMessageW")
	procShowWindow                    = modUser32.NewProc("ShowWindow")
	procUpdateWindow                  = modUser32.NewProc("UpdateWindow")
	procSetForegroundWindow           = modUser32.NewProc("SetForegroundWindow")
	procSetFocus                      = modUser32.NewProc("SetFocus")
	procSetCapture                    = modUser32.NewProc("SetCapture")
	procReleaseCapture                = modUser32.NewProc("ReleaseCapture")
	procFindWindowW                   = modUser32.NewProc("FindWindowW")
	procSetTimer                      = modUser32.NewProc("SetTimer")
	procKillTimer                     = modUser32.NewProc("KillTimer")
	procInvalidateRect                = modUser32.NewProc("InvalidateRect")
	procBeginPaint                    = modUser32.NewProc("BeginPaint")
	procEndPaint                      = modUser32.NewProc("EndPaint")
	procGetDC                         = modUser32.NewProc("GetDC")
	procReleaseDC                     = modUser32.NewProc("ReleaseDC")
	procGetClientRect                 = modUser32.NewProc("GetClientRect")
	procAdjustWindowRectEx            = modUser32.NewProc("AdjustWindowRectEx")
	procAdjustWindowRectExForDpi      = modUser32.NewProc("AdjustWindowRectExForDpi")
	procSetWindowPos                  = modUser32.NewProc("SetWindowPos")
	procMoveWindow                    = modUser32.NewProc("MoveWindow")
	procGetCursorPos                  = modUser32.NewProc("GetCursorPos")
	procTrackPopupMenuEx              = modUser32.NewProc("TrackPopupMenuEx")
	procCreatePopupMenu               = modUser32.NewProc("CreatePopupMenu")
	procInsertMenuItemW               = modUser32.NewProc("InsertMenuItemW")
	procDestroyMenu                   = modUser32.NewProc("DestroyMenu")
	procLoadCursorW                   = modUser32.NewProc("LoadCursorW")
	procDestroyIcon                   = modUser32.NewProc("DestroyIcon")
	procCreateIconIndirect            = modUser32.NewProc("CreateIconIndirect")
	procRegisterWindowMessageW        = modUser32.NewProc("RegisterWindowMessageW")
	procSetProcessDpiAwarenessContext = modUser32.NewProc("SetProcessDpiAwarenessContext")
	procGetDpiForWindow               = modUser32.NewProc("GetDpiForWindow")
	procGetSystemMetrics              = modUser32.NewProc("GetSystemMetrics")
	procOpenClipboard                 = modUser32.NewProc("OpenClipboard")
	procEmptyClipboard                = modUser32.NewProc("EmptyClipboard")
	procSetClipboardData              = modUser32.NewProc("SetClipboardData")
	procCloseClipboard                = modUser32.NewProc("CloseClipboard")
	procGetWindowTextLengthW          = modUser32.NewProc("GetWindowTextLengthW")
	procGetWindowTextW                = modUser32.NewProc("GetWindowTextW")
	procSetWindowTextW                = modUser32.NewProc("SetWindowTextW")
	procGetGuiResources               = modUser32.NewProc("GetGuiResources")
	procGetWindowLongPtrW             = modUser32.NewProc("GetWindowLongPtrW")

	procCreateFontIndirectW = modGdi32.NewProc("CreateFontIndirectW")
	procCreateSolidBrush    = modGdi32.NewProc("CreateSolidBrush")
	procCreateCompatibleDC  = modGdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection    = modGdi32.NewProc("CreateDIBSection")
	procCreateBitmap        = modGdi32.NewProc("CreateBitmap")
	procDeleteDC            = modGdi32.NewProc("DeleteDC")
	procDeleteObject        = modGdi32.NewProc("DeleteObject")
	procSelectObject        = modGdi32.NewProc("SelectObject")
	procBitBlt              = modGdi32.NewProc("BitBlt")
	procSetBkColor          = modGdi32.NewProc("SetBkColor")
	procSetTextColor        = modGdi32.NewProc("SetTextColor")

	// GDI+ Flat API procs (100% integer/pointer in args 1..4 — zero Win64 XMM register bugs).
	procGdiplusStartup             = modGdiplus.NewProc("GdiplusStartup")
	procGdiplusShutdown            = modGdiplus.NewProc("GdiplusShutdown")
	procGdipCreateFromHDC          = modGdiplus.NewProc("GdipCreateFromHDC")
	procGdipDeleteGraphics         = modGdiplus.NewProc("GdipDeleteGraphics")
	procGdipSetSmoothingMode       = modGdiplus.NewProc("GdipSetSmoothingMode")
	procGdipSetPixelOffsetMode     = modGdiplus.NewProc("GdipSetPixelOffsetMode")
	procGdipSetTextRenderingHint   = modGdiplus.NewProc("GdipSetTextRenderingHint")
	procGdipGraphicsClear          = modGdiplus.NewProc("GdipGraphicsClear")
	procGdipSetClipRectI           = modGdiplus.NewProc("GdipSetClipRectI")
	procGdipResetClip              = modGdiplus.NewProc("GdipResetClip")
	procGdipCreateSolidFill        = modGdiplus.NewProc("GdipCreateSolidFill")
	procGdipDeleteBrush            = modGdiplus.NewProc("GdipDeleteBrush")
	procGdipCreateFontFromLogfontW = modGdiplus.NewProc("GdipCreateFontFromLogfontW")
	procGdipDeleteFont             = modGdiplus.NewProc("GdipDeleteFont")
	procGdipCreateStringFormat     = modGdiplus.NewProc("GdipCreateStringFormat")
	procGdipDeleteStringFormat     = modGdiplus.NewProc("GdipDeleteStringFormat")
	procGdipSetStringFormatAlign   = modGdiplus.NewProc("GdipSetStringFormatAlign")
	procGdipSetStringFormatLineAl  = modGdiplus.NewProc("GdipSetStringFormatLineAlign")
	procGdipSetStringFormatTrim    = modGdiplus.NewProc("GdipSetStringFormatTrimming")
	procGdipDrawString             = modGdiplus.NewProc("GdipDrawString")
	procGdipMeasureString          = modGdiplus.NewProc("GdipMeasureString")
	procGdipCreatePath             = modGdiplus.NewProc("GdipCreatePath")
	procGdipDeletePath             = modGdiplus.NewProc("GdipDeletePath")
	procGdipStartPathFigure        = modGdiplus.NewProc("GdipStartPathFigure")
	procGdipClosePathFigure        = modGdiplus.NewProc("GdipClosePathFigure")
	procGdipAddPathArcI            = modGdiplus.NewProc("GdipAddPathArcI")
	procGdipAddPathEllipseI        = modGdiplus.NewProc("GdipAddPathEllipseI")
	procGdipFillPath               = modGdiplus.NewProc("GdipFillPath")
	procGdipFillEllipseI           = modGdiplus.NewProc("GdipFillEllipseI")
	procGdipFillRectangleI         = modGdiplus.NewProc("GdipFillRectangleI")

	procShellNotifyIconW            = modShell32.NewProc("Shell_NotifyIconW")
	procDwmSetWindowAttribute       = modDwmAPI.NewProc("DwmSetWindowAttribute")
	procDwmExtendFrameIntoClientArea = modDwmAPI.NewProc("DwmExtendFrameIntoClientArea")

	procGetModuleHandleW = modKernelUI.NewProc("GetModuleHandleW")
	procMulDiv           = modKernelUI.NewProc("MulDiv")
	procGlobalAlloc      = modKernelUI.NewProc("GlobalAlloc")
	procGlobalLock       = modKernelUI.NewProc("GlobalLock")
	procGlobalUnlock     = modKernelUI.NewProc("GlobalUnlock")
	procGlobalFree       = modKernelUI.NewProc("GlobalFree")
	procRtlMoveMemory    = modKernelUI.NewProc("RtlMoveMemory")

	// Single package-level WndProc callback allocated once per process (never leaked inside loops).
	globalWndProcCB = windows.NewCallback(winMainWndProc)

	// Owned strictly by the pinned Win32 UI thread T0 (avoids unsafe.Pointer <-> GWLP_USERDATA casts).
	activeWinUI *winUI
)

// verifyWin32ABISizes validates exact 64-bit Windows ABI struct sizes before any Win32/DWM/GDI+ call.
func verifyWin32ABISizes() error {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil
	}
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"POINT", unsafe.Sizeof(winPoint{}), 8},
		{"RECT", unsafe.Sizeof(winRect{}), 16},
		{"MSG", unsafe.Sizeof(winMsg{}), 48},
		{"WNDCLASSEXW", unsafe.Sizeof(wndClassExW{}), 80},
		{"PAINTSTRUCT", unsafe.Sizeof(paintStruct{}), 72},
		{"CREATESTRUCTW", unsafe.Sizeof(createStructW{}), 80},
		{"NOTIFYICONDATAW", unsafe.Sizeof(notifyIconDataW{}), 976},
		{"MENUITEMINFOW", unsafe.Sizeof(menuItemInfoW{}), 80},
		{"TPMPARAMS", unsafe.Sizeof(tpmParams{}), 20},
		{"LOGFONTW", unsafe.Sizeof(logFontW{}), 92},
		{"BITMAPINFO", unsafe.Sizeof(bitmapInfo{}), 44},
		{"ICONINFO", unsafe.Sizeof(iconInfo{}), 32},
		{"MARGINS", unsafe.Sizeof(dwmMargins{}), 16},
		{"GdiplusStartupInput", unsafe.Sizeof(gdiplusStartupInput{}), 24},
		{"RectF", unsafe.Sizeof(gpRectF{}), 16},
	}
	for _, c := range checks {
		if c.got != c.want {
			return fmt.Errorf("win32 ABI mismatch for %s: got %d bytes, want %d", c.name, c.got, c.want)
		}
	}
	return nil
}

// configureHiddenCmd enforces CREATE_NO_WINDOW + HideWindow on background gh/netsh spawns under -H=windowsgui.
func configureHiddenCmd(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= CREATE_NO_WINDOW
	cmd.SysProcAttr.HideWindow = true
}

// configureInteractiveConsoleCmd spawns gh.exe with its own dedicated interactive console window
// (CREATE_NEW_CONSOLE, never AllocConsole inside NetShaper.exe) so browser OAuth / stdin works cleanly.
func configureInteractiveConsoleCmd(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags &^= CREATE_NO_WINDOW
	cmd.SysProcAttr.CreationFlags |= CREATE_NEW_CONSOLE | windows.CREATE_NEW_PROCESS_GROUP
	cmd.SysProcAttr.HideWindow = false
}

type clipboardOps struct {
	open   func(hwnd uintptr) (uintptr, error)
	empty  func() (uintptr, error)
	alloc  func(flags, bytes uintptr) (uintptr, error)
	lock   func(hMem uintptr) (uintptr, error)
	copy   func(dst uintptr, src *uint16, bytes uintptr)
	unlock func(hMem uintptr)
	set    func(format, hMem uintptr) (uintptr, error)
	free   func(hMem uintptr)
	close  func()
}

func win32ClipboardOps() clipboardOps {
	return clipboardOps{
		open:   func(hwnd uintptr) (uintptr, error) { r, _, e := procOpenClipboard.Call(hwnd); return r, e },
		empty:  func() (uintptr, error) { r, _, e := procEmptyClipboard.Call(); return r, e },
		alloc:  func(flags, bytes uintptr) (uintptr, error) { r, _, e := procGlobalAlloc.Call(flags, bytes); return r, e },
		lock:   func(hMem uintptr) (uintptr, error) { r, _, e := procGlobalLock.Call(hMem); return r, e },
		copy:   func(dst uintptr, src *uint16, bytes uintptr) { _, _, _ = procRtlMoveMemory.Call(dst, uintptr(unsafe.Pointer(src)), bytes) },
		unlock: func(hMem uintptr) { _, _, _ = procGlobalUnlock.Call(hMem) },
		set:    func(format, hMem uintptr) (uintptr, error) { r, _, e := procSetClipboardData.Call(format, hMem); return r, e },
		free:   func(hMem uintptr) { _, _, _ = procGlobalFree.Call(hMem) },
		close:  func() { _, _, _ = procCloseClipboard.Call() },
	}
}

// copyTextToClipboard copies UTF-16 text to the Windows clipboard using an owned HWND
// (falling back to 0 only when called without a window) with 0 unsafe.Pointer(uintptr) casts.
func copyTextToClipboard(hwnd uintptr, text string) error {
	return copyTextToClipboardWithOps(hwnd, text, win32ClipboardOps())
}

func copyTextToClipboardWithOps(hwnd uintptr, text string, ops clipboardOps) error {
	u16, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	byteLen := uintptr(len(u16) * 2)

	var opened bool
	var openErr error
	for attempt := 0; attempt < 3; attempt++ {
		var rOpen uintptr
		rOpen, openErr = ops.open(hwnd)
		if rOpen != 0 {
			opened = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !opened {
		return fmt.Errorf("OpenClipboard: %w", openErr)
	}
	defer ops.close()

	if rEmpty, emptyErr := ops.empty(); rEmpty == 0 {
		return fmt.Errorf("EmptyClipboard: %w", emptyErr)
	}
	hMem, allocErr := ops.alloc(gmemMoveable, byteLen)
	if hMem == 0 {
		return fmt.Errorf("GlobalAlloc: %w", allocErr)
	}
	dstPtr, lockErr := ops.lock(hMem)
	if dstPtr == 0 {
		ops.free(hMem)
		return fmt.Errorf("GlobalLock: %w", lockErr)
	}
	ops.copy(dstPtr, &u16[0], byteLen)
	runtime.KeepAlive(u16)
	ops.unlock(hMem)

	rSet, setErr := ops.set(cfUnicodeText, hMem)
	if rSet == 0 {
		ops.free(hMem)
		return fmt.Errorf("SetClipboardData: %w", setErr)
	}
	// Ownership of hMem transferred to the OS clipboard on success; MUST NOT call GlobalFree.
	return nil
}

// -----------------------------------------------------------------------------
// Apple-Grade Glassmorphism Palette & Zero-Leak Cached GDI+ Theme
// -----------------------------------------------------------------------------

func argb(a, r, g, b byte) uint32 {
	return uint32(a)<<24 | uint32(r)<<16 | uint32(g)<<8 | uint32(b)
}

func rgbGDI(r, g, b byte) uint32 {
	return uint32(r) | uint32(g)<<8 | uint32(b)<<16
}

var (
	// DWM glass canvas & translucent obsidian glass layers (premultiplied by GDI+ onto 32bpp DIB).
	colCanvasOpaque  = argb(255, 11, 15, 22)  // Fallback opaque backdrop on Windows 10
	colCanvasGlass   = argb(82, 10, 14, 22)   // Translucent frosted veil over Win11 Acrylic/Mica
	colGlassCard     = argb(182, 20, 26, 36)  // Frosted dark glass card surface
	colGlassTrack    = argb(156, 15, 20, 29)  // Segmented control & progress track
	colGlassElevated = argb(214, 30, 38, 52)  // Active pill / button fill
	colGlassHover    = argb(232, 42, 52, 70)  // Hovered pill / button fill
	colGlassTermBg   = argb(214, 9, 13, 19)   // Crisp high-contrast dark glass terminal pane
	colGlassHairline  = argb(42, 255, 255, 255) // Apple-style 1px translucent specular hairline border
	colGlassHighlight = argb(24, 255, 255, 255)
	colEditFrameARGB  = argb(255, 26, 33, 45)   // Exact seamless match for native child EDIT control (#1A212D)

	colEditBgGDI    = rgbGDI(26, 33, 45)
	colEditTxtGDI   = rgbGDI(242, 246, 252)
	colEditMutedGDI = rgbGDI(138, 148, 162)

	// High-contrast crisp typography & semantic accents.
	colTxtPrimary = argb(255, 244, 247, 252)
	colTxtSecond  = argb(215, 196, 205, 218)
	colTxtMuted   = argb(185, 142, 153, 170)

	colGreen       = argb(255, 52, 211, 153) // Apple/macOS emerald mint
	colGreenFill   = argb(48, 52, 211, 153)
	colGreenGlow   = argb(26, 52, 211, 153)
	colAmber       = argb(255, 245, 180, 65)
	colAmberFill   = argb(48, 245, 180, 65)
	colAmberGlow   = argb(24, 245, 180, 65)
	colRed         = argb(255, 255, 95, 87)
	colRedFill     = argb(56, 255, 95, 87)
	colBlue        = argb(255, 56, 148, 255)
	colBlueHover   = argb(255, 76, 162, 255)
	colBlueFill    = argb(56, 56, 148, 255)
	colSlateRing   = argb(130, 148, 163, 184)
	colScrollTrack = argb(38, 255, 255, 255)
	colScrollThumb = argb(115, 200, 214, 232)
	colScrollDrag  = argb(185, 230, 240, 252)
	colRowFlash    = argb(58, 56, 148, 255)
	colToastBg     = argb(232, 20, 42, 74)
)

type gdiTheme struct {
	dpi uint32

	// Cached GDI+ GpFonts (created once per DPI via GdipCreateFontFromLogfontW; freed 1:1 on DPI/WM_DESTROY).
	gpFontTitle uintptr
	gpFontSemi  uintptr
	gpFontBody  uintptr
	gpFontSmall uintptr
	gpFontMono  uintptr

	// Monospace character advance width measured once per DPI (0 MeasureString syscalls per paint!).
	monoCharAdvance float32

	// Cached GDI+ GpStringFormats (created once, freed 1:1 on WM_DESTROY).
	fmtLeft        uintptr
	fmtLeftEllip   uintptr
	fmtCenter      uintptr
	fmtCenterEllip uintptr
	fmtRight       uintptr
	fmtWrap        uintptr
	fmtTermNoWrap  uintptr

	// Cached GDI+ GpSolidFill brushes (created once, freed 1:1 on WM_DESTROY).
	brCanvasGlass  uintptr
	brCanvasOpaque uintptr
	brCard         uintptr
	brTrack        uintptr
	brElevated     uintptr
	brHover        uintptr
	brTermBg       uintptr
	brEditFrame    uintptr
	brHairline     uintptr
	brHighlight    uintptr
	brTxtPrimary   uintptr
	brTxtSecond    uintptr
	brTxtMuted     uintptr
	brGreen        uintptr
	brGreenFill    uintptr
	brGreenGlow    uintptr
	brAmber        uintptr
	brAmberFill    uintptr
	brAmberGlow    uintptr
	brRed          uintptr
	brRedFill      uintptr
	brBlue         uintptr
	brBlueHover    uintptr
	brBlueFill     uintptr
	brSlateRing    uintptr
	brScrollTrack  uintptr
	brScrollThumb  uintptr
	brScrollDrag   uintptr
	brRowFlash     uintptr
	brToastBg      uintptr

	// Minimal native GDI handles strictly for the child EDIT control on Account tab.
	editFont uintptr
	brEditBg uintptr

	// Programmatically synthesized 32-bit ARGB tray/window HICONs (0 external .ico files).
	iconStopped  uintptr
	iconStarting uintptr
	iconHealthy  uintptr

	// Persistent 32-bit top-down ARGB DIB backbuffer (released on SW_HIDE, recreated on restore/paint).
	memDC     uintptr
	memBmp    uintptr
	memOldBmp uintptr
	bufW      int32
	bufH      int32
}

func scaleDPI(px int32, dpi uint32) int32 {
	if dpi == 0 {
		dpi = 96
	}
	r, _, _ := procMulDiv.Call(uintptr(px), uintptr(dpi), 96)
	return int32(r)
}

func createGDIFont(face string, ptHeight int32, weight int32, dpi uint32) uintptr {
	var lf logFontW
	lf.LfHeight = -scaleDPI(ptHeight, dpi)
	lf.LfWeight = weight
	lf.LfCharSet = defaultCharSet
	lf.LfQuality = cleartypeQuality
	if u16, err := windows.UTF16FromString(face); err == nil {
		copy(lf.LfFaceName[:], u16)
	}
	h, _, _ := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	runtime.KeepAlive(&lf)
	return h
}

func createGPFont(hdc uintptr, primaryFace, fallbackFace string, pxHeight int32, weight int32, dpi uint32) uintptr {
	tryFace := func(face string) uintptr {
		var lf logFontW
		lf.LfHeight = -scaleDPI(pxHeight, dpi)
		lf.LfWeight = weight
		lf.LfCharSet = defaultCharSet
		lf.LfQuality = cleartypeQuality
		if u16, err := windows.UTF16FromString(face); err == nil {
			copy(lf.LfFaceName[:], u16)
		}
		var font uintptr
		st, _, _ := procGdipCreateFontFromLogfontW.Call(hdc, uintptr(unsafe.Pointer(&lf)), uintptr(unsafe.Pointer(&font)))
		runtime.KeepAlive(&lf)
		if st == 0 && font != 0 {
			return font
		}
		if font != 0 {
			_, _, _ = procGdipDeleteFont.Call(font)
		}
		return 0
	}
	if f := tryFace(primaryFace); f != 0 {
		return f
	}
	return tryFace(fallbackFace)
}

func createGPBrush(color uint32) uintptr {
	var br uintptr
	st, _, _ := procGdipCreateSolidFill.Call(uintptr(color), uintptr(unsafe.Pointer(&br)))
	if st != 0 {
		return 0
	}
	return br
}

func createGPStringFormat(align, lineAlign, trimming, flags int32) uintptr {
	var sf uintptr
	st, _, _ := procGdipCreateStringFormat.Call(uintptr(flags), 0, uintptr(unsafe.Pointer(&sf)))
	if st != 0 || sf == 0 {
		return 0
	}
	_, _, _ = procGdipSetStringFormatAlign.Call(sf, uintptr(align))
	_, _, _ = procGdipSetStringFormatLineAl.Call(sf, uintptr(lineAlign))
	_, _, _ = procGdipSetStringFormatTrim.Call(sf, uintptr(trimming))
	return sf
}

func deleteGDI(h *uintptr) {
	if h != nil && *h != 0 {
		_, _, _ = procDeleteObject.Call(*h)
		*h = 0
	}
}

func deleteGPBrush(h *uintptr) {
	if h != nil && *h != 0 {
		_, _, _ = procGdipDeleteBrush.Call(*h)
		*h = 0
	}
}

func deleteGPFont(h *uintptr) {
	if h != nil && *h != 0 {
		_, _, _ = procGdipDeleteFont.Call(*h)
		*h = 0
	}
}

func deleteGPFormat(h *uintptr) {
	if h != nil && *h != 0 {
		_, _, _ = procGdipDeleteStringFormat.Call(*h)
		*h = 0
	}
}

// createStatusIcon builds a crisp 32x32 ARGB badge icon in memory and frees both intermediate HBITMAPs immediately.
func createStatusIcon(r, g, b byte) uintptr {
	const sz = 32
	pixels := make([]uint32, sz*sz)
	cx, cy := 15.5, 15.5
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			dist := math.Sqrt(dx*dx + dy*dy)
			var px uint32
			if dist <= 14.5 {
				alpha := 1.0
				if dist > 13.5 {
					alpha = 14.5 - dist
				}
				a := byte(math.Round(alpha * 255.0))
				if dist >= 11.2 {
					px = (uint32(a) << 24) | (uint32(20) << 16) | (uint32(26) << 8) | uint32(36)
				} else if dist <= 4.3 {
					px = (uint32(a) << 24) | (uint32(244) << 16) | (uint32(247) << 8) | uint32(252)
				} else {
					px = (uint32(a) << 24) | (uint32(r) << 16) | (uint32(g) << 8) | uint32(b)
				}
			}
			pixels[y*sz+x] = px
		}
	}

	var bi bitmapInfo
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bitmapInfoHeader{}))
	bi.BmiHeader.BiWidth = sz
	bi.BmiHeader.BiHeight = -sz // top-down DIB
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = biRGB

	var bitsPtr uintptr
	hColor, _, _ := procCreateDIBSection.Call(
		0,
		uintptr(unsafe.Pointer(&bi)),
		dibRGBColors,
		uintptr(unsafe.Pointer(&bitsPtr)),
		0,
		0,
	)
	runtime.KeepAlive(&bi)
	if hColor == 0 || bitsPtr == 0 {
		if hColor != 0 {
			_, _, _ = procDeleteObject.Call(hColor)
		}
		return 0
	}
	_, _, _ = procRtlMoveMemory.Call(bitsPtr, uintptr(unsafe.Pointer(&pixels[0])), uintptr(len(pixels)*4))
	runtime.KeepAlive(pixels)

	hMask, _, _ := procCreateBitmap.Call(sz, sz, 1, 1, 0)
	if hMask == 0 {
		_, _, _ = procDeleteObject.Call(hColor)
		return 0
	}

	ii := iconInfo{
		FIcon:    1,
		HbmMask:  hMask,
		HbmColor: hColor,
	}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	runtime.KeepAlive(&ii)
	// CreateIconIndirect copies both bitmaps — immediately release both HBITMAPs (0 GDI leaks).
	_, _, _ = procDeleteObject.Call(hColor)
	_, _, _ = procDeleteObject.Call(hMask)
	return hIcon
}

func (t *gdiTheme) init(dpi uint32) {
	if dpi == 0 {
		dpi = 96
	}
	t.dpi = dpi

	// String formats (cached once per process, freed 1:1 in destroy).
	t.fmtLeft = createGPStringFormat(gpStringAlignNear, gpStringAlignCenter, gpStringTrimmingNone, gpStringFormatFlagsNoWrap)
	t.fmtLeftEllip = createGPStringFormat(gpStringAlignNear, gpStringAlignCenter, gpStringTrimmingEllipsisCharacter, gpStringFormatFlagsNoWrap)
	t.fmtCenter = createGPStringFormat(gpStringAlignCenter, gpStringAlignCenter, gpStringTrimmingNone, gpStringFormatFlagsNoWrap)
	t.fmtCenterEllip = createGPStringFormat(gpStringAlignCenter, gpStringAlignCenter, gpStringTrimmingEllipsisCharacter, gpStringFormatFlagsNoWrap)
	t.fmtRight = createGPStringFormat(gpStringAlignFar, gpStringAlignCenter, gpStringTrimmingNone, gpStringFormatFlagsNoWrap)
	t.fmtWrap = createGPStringFormat(gpStringAlignNear, gpStringAlignNear, gpStringTrimmingEllipsisCharacter, 0)
	t.fmtTermNoWrap = createGPStringFormat(gpStringAlignNear, gpStringAlignCenter, gpStringTrimmingNone, gpStringFormatFlagsNoWrap|gpStringFormatFlagsNoClip)

	// GDI+ solid brushes (cached once, freed 1:1 in destroy).
	t.brCanvasGlass = createGPBrush(colCanvasGlass)
	t.brCanvasOpaque = createGPBrush(colCanvasOpaque)
	t.brCard = createGPBrush(colGlassCard)
	t.brTrack = createGPBrush(colGlassTrack)
	t.brElevated = createGPBrush(colGlassElevated)
	t.brHover = createGPBrush(colGlassHover)
	t.brTermBg = createGPBrush(colGlassTermBg)
	t.brEditFrame = createGPBrush(colEditFrameARGB)
	t.brHairline = createGPBrush(colGlassHairline)
	t.brHighlight = createGPBrush(colGlassHighlight)
	t.brTxtPrimary = createGPBrush(colTxtPrimary)
	t.brTxtSecond = createGPBrush(colTxtSecond)
	t.brTxtMuted = createGPBrush(colTxtMuted)
	t.brGreen = createGPBrush(colGreen)
	t.brGreenFill = createGPBrush(colGreenFill)
	t.brGreenGlow = createGPBrush(colGreenGlow)
	t.brAmber = createGPBrush(colAmber)
	t.brAmberFill = createGPBrush(colAmberFill)
	t.brAmberGlow = createGPBrush(colAmberGlow)
	t.brRed = createGPBrush(colRed)
	t.brRedFill = createGPBrush(colRedFill)
	t.brBlue = createGPBrush(colBlue)
	t.brBlueHover = createGPBrush(colBlueHover)
	t.brBlueFill = createGPBrush(colBlueFill)
	t.brSlateRing = createGPBrush(colSlateRing)
	t.brScrollTrack = createGPBrush(colScrollTrack)
	t.brScrollThumb = createGPBrush(colScrollThumb)
	t.brScrollDrag = createGPBrush(colScrollDrag)
	t.brRowFlash = createGPBrush(colRowFlash)
	t.brToastBg = createGPBrush(colToastBg)

	t.brEditBg, _, _ = procCreateSolidBrush.Call(uintptr(colEditBgGDI))

	t.rebuildFonts(dpi)

	t.iconStopped = createStatusIcon(142, 153, 170)
	t.iconStarting = createStatusIcon(245, 180, 65)
	t.iconHealthy = createStatusIcon(52, 211, 153)
}

func (t *gdiTheme) rebuildFonts(dpi uint32) {
	deleteGPFont(&t.gpFontTitle)
	deleteGPFont(&t.gpFontSemi)
	deleteGPFont(&t.gpFontBody)
	deleteGPFont(&t.gpFontSmall)
	deleteGPFont(&t.gpFontMono)
	deleteGDI(&t.editFont)

	hdc, _, _ := procGetDC.Call(0)
	if hdc != 0 {
		t.gpFontTitle = createGPFont(hdc, "Segoe UI", "Segoe UI", 17, 700, dpi)
		t.gpFontSemi = createGPFont(hdc, "Segoe UI Semibold", "Segoe UI", 13, 600, dpi)
		t.gpFontBody = createGPFont(hdc, "Segoe UI", "Segoe UI", 12, 400, dpi)
		t.gpFontSmall = createGPFont(hdc, "Segoe UI", "Segoe UI", 10, 400, dpi)
		t.gpFontMono = createGPFont(hdc, "Cascadia Mono", "Consolas", 11, 400, dpi)
		t.monoCharAdvance = measureMonoCharAdvance(hdc, t.gpFontMono, t.fmtTermNoWrap, dpi)
		_, _, _ = procReleaseDC.Call(0, hdc)
	}
	t.editFont = createGDIFont("Segoe UI", 12, 400, dpi)
}

// measureMonoCharAdvance computes exact horizontal pixel width per monospace rune once per DPI.
func measureMonoCharAdvance(hdc, font, sf uintptr, dpi uint32) float32 {
	fallback := float32(scaleDPI(7, dpi))
	if hdc == 0 || font == 0 || sf == 0 {
		return fallback
	}
	var g uintptr
	st, _, _ := procGdipCreateFromHDC.Call(hdc, uintptr(unsafe.Pointer(&g)))
	if st != 0 || g == 0 {
		return fallback
	}
	defer procGdipDeleteGraphics.Call(g)

	sample := strings.Repeat("M", 40)
	u16, err := windows.UTF16FromString(sample)
	if err != nil || len(u16) <= 1 {
		return fallback
	}
	layout := gpRectF{X: 0, Y: 0, Width: 8192, Height: 64}
	var bound gpRectF
	st2, _, _ := procGdipMeasureString.Call(
		g,
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(len(u16)-1),
		font,
		uintptr(unsafe.Pointer(&layout)),
		sf,
		uintptr(unsafe.Pointer(&bound)),
		0,
		0,
	)
	runtime.KeepAlive(u16)
	runtime.KeepAlive(&layout)
	if st2 == 0 && bound.Width > 40 {
		return bound.Width / 40.0
	}
	return fallback
}

func (t *gdiTheme) updateDPI(dpi uint32) {
	if dpi == 0 || dpi == t.dpi {
		return
	}
	t.dpi = dpi
	t.rebuildFonts(dpi)
	t.releaseBackBuffer()
}

// ensureBackBuffer allocates a persistent 32-bit top-down ARGB DIB so Windows 11 DWM Acrylic/Mica
// composites translucent glass pixels cleanly with zero per-frame allocations.
func (t *gdiTheme) ensureBackBuffer(hdc uintptr, w, h int32) bool {
	if w <= 0 || h <= 0 {
		return false
	}
	if t.memDC == 0 {
		dc, _, _ := procCreateCompatibleDC.Call(hdc)
		if dc == 0 {
			return false
		}
		t.memDC = dc
	}
	if t.memBmp != 0 && t.bufW == w && t.bufH == h {
		return true
	}
	t.releaseBackBuffer()

	var bi bitmapInfo
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bitmapInfoHeader{}))
	bi.BmiHeader.BiWidth = w
	bi.BmiHeader.BiHeight = -h // top-down 32bpp ARGB DIB
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = biRGB

	var bitsPtr uintptr
	bmp, _, _ := procCreateDIBSection.Call(
		t.memDC,
		uintptr(unsafe.Pointer(&bi)),
		dibRGBColors,
		uintptr(unsafe.Pointer(&bitsPtr)),
		0,
		0,
	)
	runtime.KeepAlive(&bi)
	if bmp == 0 {
		return false
	}
	oldBmp, _, _ := procSelectObject.Call(t.memDC, bmp)
	t.memBmp = bmp
	t.memOldBmp = oldBmp
	t.bufW = w
	t.bufH = h
	return true
}

// releaseBackBuffer frees the offscreen 32bpp DIB (called on SW_HIDE to cut tray RAM and on WM_DESTROY).
func (t *gdiTheme) releaseBackBuffer() {
	if t.memDC != 0 && t.memOldBmp != 0 {
		_, _, _ = procSelectObject.Call(t.memDC, t.memOldBmp)
		t.memOldBmp = 0
	}
	deleteGDI(&t.memBmp)
	t.bufW = 0
	t.bufH = 0
}

// destroy frees EVERY cached GDI+, GDI, and HICON object 1:1 strictly before GdiplusShutdown.
func (t *gdiTheme) destroy() {
	t.releaseBackBuffer()
	if t.memDC != 0 {
		_, _, _ = procDeleteDC.Call(t.memDC)
		t.memDC = 0
	}

	deleteGPFont(&t.gpFontTitle)
	deleteGPFont(&t.gpFontSemi)
	deleteGPFont(&t.gpFontBody)
	deleteGPFont(&t.gpFontSmall)
	deleteGPFont(&t.gpFontMono)
	deleteGDI(&t.editFont)
	deleteGDI(&t.brEditBg)

	deleteGPFormat(&t.fmtLeft)
	deleteGPFormat(&t.fmtLeftEllip)
	deleteGPFormat(&t.fmtCenter)
	deleteGPFormat(&t.fmtCenterEllip)
	deleteGPFormat(&t.fmtRight)
	deleteGPFormat(&t.fmtWrap)
	deleteGPFormat(&t.fmtTermNoWrap)

	deleteGPBrush(&t.brCanvasGlass)
	deleteGPBrush(&t.brCanvasOpaque)
	deleteGPBrush(&t.brCard)
	deleteGPBrush(&t.brTrack)
	deleteGPBrush(&t.brElevated)
	deleteGPBrush(&t.brHover)
	deleteGPBrush(&t.brTermBg)
	deleteGPBrush(&t.brEditFrame)
	deleteGPBrush(&t.brHairline)
	deleteGPBrush(&t.brHighlight)
	deleteGPBrush(&t.brTxtPrimary)
	deleteGPBrush(&t.brTxtSecond)
	deleteGPBrush(&t.brTxtMuted)
	deleteGPBrush(&t.brGreen)
	deleteGPBrush(&t.brGreenFill)
	deleteGPBrush(&t.brGreenGlow)
	deleteGPBrush(&t.brAmber)
	deleteGPBrush(&t.brAmberFill)
	deleteGPBrush(&t.brAmberGlow)
	deleteGPBrush(&t.brRed)
	deleteGPBrush(&t.brRedFill)
	deleteGPBrush(&t.brBlue)
	deleteGPBrush(&t.brBlueHover)
	deleteGPBrush(&t.brBlueFill)
	deleteGPBrush(&t.brSlateRing)
	deleteGPBrush(&t.brScrollTrack)
	deleteGPBrush(&t.brScrollThumb)
	deleteGPBrush(&t.brScrollDrag)
	deleteGPBrush(&t.brRowFlash)
	deleteGPBrush(&t.brToastBg)

	if t.iconStopped != 0 {
		_, _, _ = procDestroyIcon.Call(t.iconStopped)
		t.iconStopped = 0
	}
	if t.iconStarting != 0 {
		_, _, _ = procDestroyIcon.Call(t.iconStarting)
		t.iconStarting = 0
	}
	if t.iconHealthy != 0 {
		_, _, _ = procDestroyIcon.Call(t.iconHealthy)
		t.iconHealthy = 0
	}
}

// -----------------------------------------------------------------------------
// Win32 Application Window & Event Loop (Pinned to OS Thread T0)
// -----------------------------------------------------------------------------

type uiTab int

const (
	tabHome uiTab = iota
	tabTerminal
	tabAccount
)

type hitAction int

const (
	hitNone hitAction = iota
	hitTabHome
	hitTabTerminal
	hitTabAccount
	hitPowerBtn
	hitApplyCodespace
	hitTermClear
	hitTermCopy
	hitTermHScroll
	hitTermViewport
	hitReAuth
	hitCheckQuota
)

type hitBox struct {
	action hitAction
	rect   winRect
}

type winUI struct {
	ctrl  *SessionController
	cfg   Config
	theme gdiTheme

	hwnd             uintptr
	hwndAtomic       atomic.Uintptr
	hwndEdit         uintptr
	hInstance        uintptr
	hMutex           windows.Handle
	wmTaskbarCreated uint32
	dwmGlassActive   bool
	trayAdded        bool
	visible          bool
	timerArmed       bool
	exiting          bool

	activeTab           uiTab
	hoverAction         hitAction
	hitBoxes            []hitBox
	logScratch          []TerminalLine
	termScrollOffset    int   // vertical rows scrolled up from bottom (0 = follow tail)
	termScrollX         int32 // horizontal scroll offset in pixels
	termMaxScrollX      int32 // max horizontal scroll computed from longest buffered line
	termInnerRect       winRect
	termLineHeight      int32
	termStartIdx        int
	termEndIdx          int
	termVisibleRows     int
	termHTrackRect      winRect
	termHThumbRect      winRect
	draggingHScroll     bool
	dragStartMouseX     int32
	dragStartScrollX    int32
	copiedRowSeq        uint64
	copiedRowUntil      time.Time
	editDirty           bool
	suppressEditChange  bool
	lastSyncedCodespace string
	lastEditEditable    bool
	lastTrayState       ControllerState
	toastText           string
	toastUntil          time.Time
}

// RunPlatformUI launches the single-instance Pure-Go Win32 + GDI+ glassmorphic UI on a locked OS thread.
func RunPlatformUI(cfg Config) error {
	if err := verifyWin32ABISizes(); err != nil {
		return err
	}

	// Single-instance guard via named Win32 Mutex.
	// Retries briefly if a previous instance is mid-exit and releasing its mutex/window.
	mutexPtr, err := windows.UTF16PtrFromString(uiMutexName)
	if err != nil {
		return err
	}
	var hMutex windows.Handle
	for attempt := 0; attempt < 6; attempt++ {
		var mErr error
		hMutex, mErr = windows.CreateMutex(nil, false, mutexPtr)
		if !errors.Is(mErr, windows.ERROR_ALREADY_EXISTS) {
			break
		}
		if existing := findWindowW(uiWindowClassName); existing != 0 {
			_, _, _ = procPostMessageW.Call(existing, wmAppShowExisting, 0, 0)
			if hMutex != 0 {
				_ = windows.CloseHandle(hMutex)
			}
			return nil
		}
		if hMutex != 0 {
			_ = windows.CloseHandle(hMutex)
			hMutex = 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	if hMutex == 0 {
		return nil
	}
	defer func() {
		if hMutex != 0 {
			_ = windows.CloseHandle(hMutex)
		}
	}()

	// Pin T0 strictly before ANY Win32/GDI/GDI+ call so HWND thread affinity is never violated.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Initialize GDI+ once per process; defer GdiplusShutdown strictly AFTER WM_DESTROY frees all objects.
	var gpToken uintptr
	gpIn := gdiplusStartupInput{GdiplusVersion: 1}
	gpSt, _, _ := procGdiplusStartup.Call(uintptr(unsafe.Pointer(&gpToken)), uintptr(unsafe.Pointer(&gpIn)), 0)
	runtime.KeepAlive(&gpIn)
	if gpSt != 0 {
		return fmt.Errorf("GdiplusStartup failed with status %d", gpSt)
	}
	defer procGdiplusShutdown.Call(gpToken)

	// Enable Per-Monitor v2 DPI awareness on Windows 10/11.
	_, _, _ = procSetProcessDpiAwarenessContext.Call(dpiAwarenessPerMonitorV2)

	hInst, _, _ := procGetModuleHandleW.Call(0)
	ui := &winUI{
		cfg:              cfg,
		hInstance:        hInst,
		hMutex:           hMutex,
		visible:          true,
		activeTab:        tabHome,
		lastEditEditable: true,
		logScratch:       make([]TerminalLine, 0, TerminalRingCapacity),
	}
	hMutex = 0 // ownership transferred to ui.hMutex
	defer ui.releaseMutex()
	ctrl := NewSessionController(cfg, ControllerDeps{
		OnStateTransition: func(_ ControllerState) {
			// At most 1 message per FSM state transition so hidden tray icon updates immediately (0 per-log PostMessage).
			if hwnd := ui.hwndAtomic.Load(); hwnd != 0 {
				_, _, _ = procPostMessageW.Call(hwnd, wmAppTraySyncState, 0, 0)
			}
		},
	})
	ui.ctrl = ctrl
	ctrl.Start()
	defer ctrl.ShutdownAndWait(exitShutdownTimeout(cfg.StopTimeout, false))

	ui.wmTaskbarCreated = registerWindowMessageW("TaskbarCreated")
	activeWinUI = ui
	defer func() {
		activeWinUI = nil
	}()

	classNamePtr, err := windows.UTF16PtrFromString(uiWindowClassName)
	if err != nil {
		return err
	}
	titlePtr, err := windows.UTF16PtrFromString(uiWindowTitle)
	if err != nil {
		return err
	}

	cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
	wc := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		Style:         csHRedraw | csVRedraw,
		LpfnWndProc:   globalWndProcCB,
		HInstance:     hInst,
		HCursor:       cursor,
		LpszClassName: classNamePtr,
	}
	atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	runtime.KeepAlive(&wc)
	runtime.KeepAlive(classNamePtr)
	if atom == 0 {
		return fmt.Errorf("RegisterClassExW failed: %w", regErr)
	}
	defer func() {
		_, _, _ = procUnregisterClassW.Call(uintptr(unsafe.Pointer(classNamePtr)), hInst)
		runtime.KeepAlive(classNamePtr)
	}()

	style := uint32(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsClipChildren)
	adj := winRect{Left: 0, Top: 0, Right: uiBaseWidth, Bottom: uiBaseHeight}
	_, _, _ = procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&adj)), uintptr(style), 0, 0)
	winW := adj.Right - adj.Left
	winH := adj.Bottom - adj.Top

	scrW, _, _ := procGetSystemMetrics.Call(smCxScreen)
	scrH, _, _ := procGetSystemMetrics.Call(smCyScreen)
	posX := (int32(scrW) - winW) / 2
	posY := (int32(scrH) - winH) / 2
	if posX < 20 {
		posX = 20
	}
	if posY < 20 {
		posY = 20
	}

	hwnd, _, createErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(style),
		uintptr(posX),
		uintptr(posY),
		uintptr(winW),
		uintptr(winH),
		0,
		0,
		hInst,
		0,
	)
	runtime.KeepAlive(classNamePtr)
	runtime.KeepAlive(titlePtr)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %w", createErr)
	}

	// Re-adjust outer frame for the monitor's actual DPI if != 96.
	if dpi := queryWindowDPI(hwnd); dpi != 96 {
		if ui.hwndEdit != 0 {
			_, _, _ = procSendMessageW.Call(ui.hwndEdit, wmSetFont, 0, 0)
		}
		ui.theme.updateDPI(dpi)
		ui.resizeWindowForDPI(dpi)
		if ui.hwndEdit != 0 {
			_, _, _ = procSendMessageW.Call(ui.hwndEdit, wmSetFont, ui.theme.editFont, 1)
		}
		ui.syncEditControlBounds()
	}

	_, _, _ = procShowWindow.Call(hwnd, swShow)
	_, _, _ = procUpdateWindow.Call(hwnd)

	var msg winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return nil
}

func winMainWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	ui := activeWinUI
	if ui == nil {
		r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}
	return ui.handleMessage(hwnd, msg, wParam, lParam)
}

func (u *winUI) handleMessage(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	if u.wmTaskbarCreated != 0 && msg == u.wmTaskbarCreated {
		u.trayAdded = false
		u.addTrayIcon()
		return 0
	}

	switch msg {
	case wmCreate:
		u.hwnd = hwnd
		u.hwndAtomic.Store(hwnd)
		dpi := queryWindowDPI(hwnd)
		u.theme.init(dpi)
		if u.theme.iconHealthy != 0 {
			_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, 0, u.theme.iconHealthy)
			_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, 1, u.theme.iconHealthy)
		}
		u.dwmGlassActive = applyDWMGlassBackdrop(hwnd)
		u.createCodespaceEdit()
		u.addTrayIcon()
		u.armTimer()
		return 0

	case wmEraseBkgnd:
		// Double-buffered 32bpp DIB handles full background fill in WM_PAINT (prevents flicker).
		return 1

	case wmPaint:
		u.onPaint()
		return 0

	case wmTimer:
		if wParam == timerIDUI {
			u.onUITimerTick()
		}
		return 0

	case wmSysCommand:
		if (wParam & 0xFFF0) == scMinimize {
			u.hideToTray()
			return 0
		}

	case wmSize:
		if wParam == sizeMinimized {
			u.hideToTray()
			return 0
		}
		u.syncEditControlBounds()
		return 0

	case wmDpiChanged:
		newDPI := uint32(wParam & 0xFFFF)
		if newDPI >= 72 && newDPI <= 480 {
			if u.hwndEdit != 0 {
				_, _, _ = procSendMessageW.Call(u.hwndEdit, wmSetFont, 0, 0)
			}
			u.theme.updateDPI(newDPI)
			u.resizeWindowForDPI(newDPI)
			if u.hwndEdit != 0 {
				_, _, _ = procSendMessageW.Call(u.hwndEdit, wmSetFont, u.theme.editFont, 1)
				margin := uintptr(u.s(6)) | (uintptr(u.s(6)) << 16)
				_, _, _ = procSendMessageW.Call(u.hwndEdit, emSetMargins, ecLeftMargin|ecRightMargin, margin)
			}
			u.syncEditControlBounds()
			u.invalidate()
		}
		return 0

	case wmCtlColorEdit, wmCtlColorStatic:
		if lParam == u.hwndEdit && u.hwndEdit != 0 {
			hdc := wParam
			if u.lastEditEditable {
				_, _, _ = procSetTextColor.Call(hdc, uintptr(colEditTxtGDI))
			} else {
				_, _, _ = procSetTextColor.Call(hdc, uintptr(colEditMutedGDI))
			}
			_, _, _ = procSetBkColor.Call(hdc, uintptr(colEditBgGDI))
			return u.theme.brEditBg
		}

	case wmCommand:
		cmdID := uint16(wParam & 0xFFFF)
		notifyCode := uint16((wParam >> 16) & 0xFFFF)
		if cmdID == idEditCodespace && notifyCode == enChange {
			if !u.suppressEditChange {
				u.editDirty = true
				u.invalidate()
			}
			return 0
		}
		switch cmdID {
		case idTrayShow:
			if u.visible {
				u.hideToTray()
			} else {
				u.restoreFromTray()
			}
		case idTrayToggle:
			u.ctrl.ToggleStartStop()
			u.syncTrayVisuals(true)
			u.invalidate()
		case idTrayCopy:
			snap := u.ctrl.Snapshot()
			if err := copyTextToClipboard(u.hwnd, snap.LocalAddr); err == nil {
				u.showToast("Copied " + snap.LocalAddr)
			} else {
				u.ctrl.Logs().Append(LogWarn, "[UI] Clipboard copy failed: "+err.Error())
				u.showToast("Clipboard busy — retry copy")
			}
		case idTrayExit:
			u.requestFullExit()
		}
		return 0

	case wmKeyDown:
		if u.activeTab == tabTerminal {
			u.handleTerminalKeyDown(uint32(wParam))
			return 0
		}

	case wmMouseMove:
		x := int32(int16(lParam & 0xFFFF))
		y := int32(int16((lParam >> 16) & 0xFFFF))
		if u.draggingHScroll {
			u.updateHScrollDrag(x)
			return 0
		}
		act := u.hitTest(x, y)
		if act != u.hoverAction {
			u.hoverAction = act
			u.invalidate()
		}
		return 0

	case wmLButtonDown:
		x := int32(int16(lParam & 0xFFFF))
		y := int32(int16((lParam >> 16) & 0xFFFF))
		u.handleClick(u.hitTest(x, y), x, y)
		return 0

	case wmLButtonUp:
		if u.draggingHScroll {
			u.draggingHScroll = false
			_, _, _ = procReleaseCapture.Call()
			u.invalidate()
		}
		return 0

	case wmCaptureChanged:
		if u.draggingHScroll {
			u.draggingHScroll = false
			u.invalidate()
		}
		return 0

	case wmMouseWheel:
		if u.activeTab == tabTerminal {
			keyState := uint16(wParam & 0xFFFF)
			delta := int16((wParam >> 16) & 0xFFFF)
			if keyState&mkShift != 0 {
				// Shift + MouseWheel scrolls horizontally left/right cleanly.
				step := u.s(48)
				if delta > 0 {
					u.scrollTermX(-step)
				} else if delta < 0 {
					u.scrollTermX(step)
				}
			} else {
				if delta > 0 {
					u.termScrollOffset += 3
				} else if delta < 0 {
					u.termScrollOffset -= 3
					if u.termScrollOffset < 0 {
						u.termScrollOffset = 0
					}
				}
			}
			u.invalidate()
		}
		return 0

	case wmMouseHWheel:
		if u.activeTab == tabTerminal {
			delta := int16((wParam >> 16) & 0xFFFF)
			step := u.s(48)
			if delta > 0 {
				u.scrollTermX(step)
			} else if delta < 0 {
				u.scrollTermX(-step)
			}
			u.invalidate()
		}
		return 0

	case wmAppTrayCallback:
		ev := uint32(lParam & 0xFFFF)
		switch ev {
		case wmLButtonUp, wmLButtonDblClk, ninSelect, ninKeySelect:
			u.restoreFromTray()
		case wmRButtonUp, wmContextMenu:
			u.showTrayMenu()
		}
		return 0

	case wmAppShowExisting:
		if !u.exiting {
			u.restoreFromTray()
		}
		return 0

	case wmAppTraySyncState:
		u.syncTrayVisuals(false)
		return 0

	case wmClose:
		// Clicking [X] ALWAYS executes a 100% guaranteed full application exit (stopping Supervisor,
		// TunnelPool, WindowsJobObject children, GDI+, tray icon, and process mutex).
		// Use [_] (Minimize) to hide to the System Tray.
		u.requestFullExit()
		return 0

	case wmQueryEndSession:
		return 1

	case wmEndSession:
		if wParam != 0 {
			u.requestFullExitWithTimeout(exitShutdownTimeout(u.cfg.StopTimeout, true))
		}
		return 0

	case wmDestroy:
		u.hwndAtomic.Store(0)
		u.disarmTimer()
		u.removeTrayIcon()
		if u.hwndEdit != 0 {
			_, _, _ = procSendMessageW.Call(u.hwndEdit, wmSetFont, 0, 0)
			_, _, _ = procDestroyWindow.Call(u.hwndEdit)
			u.hwndEdit = 0
		}
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, 0, 0)
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, 1, 0)
		u.theme.destroy()
		u.hwnd = 0
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return r
}

func (u *winUI) createCodespaceEdit() {
	editClass, err := windows.UTF16PtrFromString("EDIT")
	if err != nil {
		return
	}
	snap := u.ctrl.Snapshot()
	initText, err := windows.UTF16PtrFromString(snap.CodespaceName)
	if err != nil {
		return
	}
	// Hidden initially because default tab is Home; shown strictly on Account tab via syncEditControlBounds.
	style := uint32(wsChild | wsTabStop | esAutoHScroll)
	hEdit, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(editClass)),
		uintptr(unsafe.Pointer(initText)),
		uintptr(style),
		0, 0, 100, 24,
		u.hwnd,
		idEditCodespace,
		u.hInstance,
		0,
	)
	runtime.KeepAlive(editClass)
	runtime.KeepAlive(initText)
	if hEdit != 0 {
		u.hwndEdit = hEdit
		u.lastSyncedCodespace = snap.CodespaceName
		_, _, _ = procSendMessageW.Call(hEdit, wmSetFont, u.theme.editFont, 1)
		margin := uintptr(u.s(6)) | (uintptr(u.s(6)) << 16)
		_, _, _ = procSendMessageW.Call(hEdit, emSetMargins, ecLeftMargin|ecRightMargin, margin)
		u.syncEditControlBounds()
	}
}

func (u *winUI) s(px int32) int32 {
	return scaleDPI(px, u.theme.dpi)
}

func (u *winUI) resizeWindowForDPI(dpi uint32) {
	style := uint32(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsClipChildren)
	adj := winRect{Left: 0, Top: 0, Right: scaleDPI(uiBaseWidth, dpi), Bottom: scaleDPI(uiBaseHeight, dpi)}
	if procAdjustWindowRectExForDpi.Find() == nil {
		_, _, _ = procAdjustWindowRectExForDpi.Call(uintptr(unsafe.Pointer(&adj)), uintptr(style), 0, 0, uintptr(dpi))
	} else {
		_, _, _ = procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&adj)), uintptr(style), 0, 0)
	}
	_, _, _ = procSetWindowPos.Call(
		u.hwnd,
		0,
		0, 0,
		uintptr(adj.Right-adj.Left),
		uintptr(adj.Bottom-adj.Top),
		swpNoMove|swpNoZOrder|swpNoActivate,
	)
}

// syncEditControlBounds positions the native dark EDIT control strictly on the Account tab
// and guarantees it is hidden on Home and Terminal tabs.
func (u *winUI) syncEditControlBounds() {
	if u.hwndEdit == 0 {
		return
	}
	if !u.visible || u.activeTab != tabAccount {
		_, _, _ = procShowWindow.Call(u.hwndEdit, swHide)
		return
	}
	x := u.s(30)
	y := u.s(234)
	w := u.s(232)
	h := u.s(24)
	_, _, _ = procMoveWindow.Call(u.hwndEdit, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 1)
	_, _, _ = procShowWindow.Call(u.hwndEdit, swShow)
}

func (u *winUI) armTimer() {
	if u.hwnd != 0 && !u.timerArmed {
		_, _, _ = procSetTimer.Call(u.hwnd, timerIDUI, uiTimerCadence, 0)
		u.timerArmed = true
	}
}

func (u *winUI) disarmTimer() {
	if u.hwnd != 0 && u.timerArmed {
		_, _, _ = procKillTimer.Call(u.hwnd, timerIDUI)
		u.timerArmed = false
	}
}

func (u *winUI) hideToTray() {
	if u.hwnd == 0 {
		return
	}
	u.visible = false
	if u.draggingHScroll {
		u.draggingHScroll = false
		_, _, _ = procReleaseCapture.Call()
	}
	_, _, _ = procShowWindow.Call(u.hwnd, swHide)
	if u.hwndEdit != 0 {
		_, _, _ = procShowWindow.Call(u.hwndEdit, swHide)
	}
	// Release 32bpp DIB backbuffer and kill 250ms UI timer while hidden in System Tray (0.00% CPU, minimal RAM).
	u.disarmTimer()
	u.theme.releaseBackBuffer()
	u.syncTrayVisuals(false)
}

func (u *winUI) restoreFromTray() {
	if u.exiting || u.hwnd == 0 {
		return
	}
	u.visible = true
	_, _, _ = procShowWindow.Call(u.hwnd, swRestore)
	_, _, _ = procSetForegroundWindow.Call(u.hwnd)
	u.syncEditControlBounds()
	// Re-arm 250ms coalesced timer; 32bpp DIB backbuffer is recreated lazily on the immediate WM_PAINT below.
	u.armTimer()
	u.syncTrayVisuals(true)
	u.invalidate()
}

func (u *winUI) releaseMutex() {
	if u.hMutex != 0 {
		_ = windows.CloseHandle(u.hMutex)
		u.hMutex = 0
	}
}

func (u *winUI) requestFullExit() {
	u.requestFullExitWithTimeout(exitShutdownTimeout(u.cfg.StopTimeout, false))
}

func (u *winUI) requestFullExitWithTimeout(timeout time.Duration) {
	if u.exiting {
		return
	}
	u.exiting = true
	u.visible = false
	if u.draggingHScroll {
		u.draggingHScroll = false
		_, _, _ = procReleaseCapture.Call()
	}
	// Hide window & child EDIT immediately for instant visual exit while bounded teardown completes.
	if u.hwnd != 0 {
		_, _, _ = procShowWindow.Call(u.hwnd, swHide)
	}
	if u.hwndEdit != 0 {
		_, _, _ = procShowWindow.Call(u.hwndEdit, swHide)
	}
	u.disarmTimer()
	u.removeTrayIcon()
	u.hwndAtomic.Store(0)
	// Release single-instance mutex before blocking in bounded WAN teardown so a quick
	// re-launch after clicking [X] creates a clean fresh instance instead of being dropped.
	u.releaseMutex()
	if u.ctrl != nil {
		u.ctrl.ShutdownAndWait(timeout)
	}
	if u.hwnd != 0 {
		_, _, _ = procDestroyWindow.Call(u.hwnd)
	}
}

func (u *winUI) invalidate() {
	if u.hwnd != 0 && u.visible {
		_, _, _ = procInvalidateRect.Call(u.hwnd, 0, 0)
	}
}

func (u *winUI) showToast(msg string) {
	u.toastText = msg
	u.toastUntil = time.Now().Add(2400 * time.Millisecond)
	u.invalidate()
}

func (u *winUI) onUITimerTick() {
	dirty := u.ctrl.ConsumeDirty()
	snap := u.ctrl.Snapshot()

	if u.hwndEdit != 0 {
		if snap.CanEditCodespace != u.lastEditEditable {
			u.lastEditEditable = snap.CanEditCodespace
			ro := uintptr(1)
			if snap.CanEditCodespace {
				ro = 0
			}
			_, _, _ = procSendMessageW.Call(u.hwndEdit, emSetReadOnly, ro, 0)
			dirty |= DirtyConfig
		}
		if !u.editDirty && snap.CodespaceName != u.lastSyncedCodespace {
			u.setEditText(snap.CodespaceName)
			u.lastSyncedCodespace = snap.CodespaceName
		}
	}

	if snap.State != u.lastTrayState {
		u.syncTrayVisuals(false)
		dirty |= DirtyTelemetry
	}

	now := time.Now()
	if u.toastText != "" && now.After(u.toastUntil) {
		u.toastText = ""
		dirty |= DirtyTelemetry
	}
	if u.copiedRowSeq != 0 && now.After(u.copiedRowUntil) {
		u.copiedRowSeq = 0
		dirty |= DirtyLogs
	}

	if dirty != DirtyNone {
		u.invalidate()
	}
}

func (u *winUI) setEditText(s string) {
	if u.hwndEdit == 0 {
		return
	}
	ptr, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return
	}
	u.suppressEditChange = true
	_, _, _ = procSetWindowTextW.Call(u.hwndEdit, uintptr(unsafe.Pointer(ptr)))
	runtime.KeepAlive(ptr)
	u.suppressEditChange = false
}

func (u *winUI) getEditText() string {
	if u.hwndEdit == 0 {
		return ""
	}
	n, _, _ := procGetWindowTextLengthW.Call(u.hwndEdit)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	_, _, _ = procGetWindowTextW.Call(u.hwndEdit, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return strings.TrimSpace(windows.UTF16ToString(buf))
}

// -----------------------------------------------------------------------------
// Terminal Scrolling & Row-Copy Helpers
// -----------------------------------------------------------------------------

func (u *winUI) scrollTermX(deltaPx int32) {
	u.termScrollX += deltaPx
	if u.termScrollX < 0 {
		u.termScrollX = 0
	}
	if u.termScrollX > u.termMaxScrollX {
		u.termScrollX = u.termMaxScrollX
	}
}

func (u *winUI) handleTerminalKeyDown(vk uint32) {
	stepX := u.s(48)
	switch vk {
	case vkLeft:
		u.scrollTermX(-stepX)
	case vkRight:
		u.scrollTermX(stepX)
	case vkHome:
		u.termScrollX = 0
	case vkEnd:
		u.termScrollX = u.termMaxScrollX
	case vkUp:
		u.termScrollOffset++
	case vkDown:
		if u.termScrollOffset > 0 {
			u.termScrollOffset--
		}
	case vkPrior:
		if u.termVisibleRows > 1 {
			u.termScrollOffset += u.termVisibleRows - 1
		}
	case vkNext:
		if u.termVisibleRows > 1 {
			u.termScrollOffset -= u.termVisibleRows - 1
			if u.termScrollOffset < 0 {
				u.termScrollOffset = 0
			}
		}
	default:
		return
	}
	u.invalidate()
}

func (u *winUI) beginHScrollInteraction(x int32) {
	if u.termMaxScrollX <= 0 {
		return
	}
	tr := u.termHTrackRect
	th := u.termHThumbRect
	trackW := tr.Right - tr.Left
	thumbW := th.Right - th.Left
	avail := trackW - thumbW
	if avail <= 0 {
		return
	}
	if x >= th.Left && x <= th.Right {
		u.draggingHScroll = true
		u.dragStartMouseX = x
		u.dragStartScrollX = u.termScrollX
		_, _, _ = procSetCapture.Call(u.hwnd)
		u.invalidate()
		return
	}
	// Click on track outside thumb jumps thumb center smoothly to click position and begins drag.
	targetLeft := x - tr.Left - thumbW/2
	if targetLeft < 0 {
		targetLeft = 0
	}
	if targetLeft > avail {
		targetLeft = avail
	}
	u.termScrollX = int32(float64(targetLeft) / float64(avail) * float64(u.termMaxScrollX))
	u.draggingHScroll = true
	u.dragStartMouseX = x
	u.dragStartScrollX = u.termScrollX
	_, _, _ = procSetCapture.Call(u.hwnd)
	u.invalidate()
}

func (u *winUI) updateHScrollDrag(x int32) {
	if u.termMaxScrollX <= 0 {
		return
	}
	trackW := u.termHTrackRect.Right - u.termHTrackRect.Left
	thumbW := u.termHThumbRect.Right - u.termHThumbRect.Left
	avail := trackW - thumbW
	if avail <= 0 {
		return
	}
	dx := x - u.dragStartMouseX
	next := u.dragStartScrollX + int32(float64(dx)/float64(avail)*float64(u.termMaxScrollX))
	if next < 0 {
		next = 0
	}
	if next > u.termMaxScrollX {
		next = u.termMaxScrollX
	}
	if next != u.termScrollX {
		u.termScrollX = next
		u.invalidate()
	}
}

func (u *winUI) copyClickedTerminalRow(y int32) {
	if u.termLineHeight <= 0 || u.termEndIdx <= u.termStartIdx {
		return
	}
	rowOffset := int((y - u.termInnerRect.Top) / u.termLineHeight)
	idx := u.termStartIdx + rowOffset
	if idx < u.termStartIdx || idx >= u.termEndIdx || idx < 0 || idx >= len(u.logScratch) {
		return
	}
	ln := u.logScratch[idx]
	fullLine := ln.Timestamp + " " + ln.Text
	if err := copyTextToClipboard(u.hwnd, fullLine); err == nil {
		u.copiedRowSeq = ln.Seq
		u.copiedRowUntil = time.Now().Add(900 * time.Millisecond)
		u.showToast("Copied line to clipboard")
	} else {
		u.ctrl.Logs().Append(LogWarn, "[UI] Clipboard copy failed: "+err.Error())
		u.showToast("Clipboard busy — retry copy")
	}
}

// -----------------------------------------------------------------------------
// System Tray (Shell_NotifyIconW + TaskbarCreated + Leak-Free Popup Menu)
// -----------------------------------------------------------------------------

func (u *winUI) trayIconForState(st ControllerState) uintptr {
	switch st {
	case CtrlRunning:
		return u.theme.iconHealthy
	case CtrlStarting, CtrlDegraded, CtrlStopping, CtrlReauthing:
		return u.theme.iconStarting
	default:
		return u.theme.iconStopped
	}
}

func (u *winUI) addTrayIcon() {
	if u.hwnd == 0 {
		return
	}
	snap := u.ctrl.Snapshot()
	var nid notifyIconDataW
	nid.CbSize = uint32(unsafe.Sizeof(notifyIconDataW{}))
	nid.Hwnd = u.hwnd
	nid.UID = 1
	nid.UFlags = nifMessage | nifIcon | nifTip
	nid.UCallbackMessage = wmAppTrayCallback
	nid.HIcon = u.trayIconForState(snap.State)
	copyUTF16Fixed(nid.SzTip[:], fmt.Sprintf("NetShaper v7.0 — %s", snap.State))
	_, _, _ = procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	nid.UVersion = notifyIconVersion4
	_, _, _ = procShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&nid)))
	runtime.KeepAlive(&nid)
	u.trayAdded = true
	u.lastTrayState = snap.State
}

func (u *winUI) syncTrayVisuals(force bool) {
	if !u.trayAdded || u.hwnd == 0 {
		return
	}
	snap := u.ctrl.Snapshot()
	if !force && snap.State == u.lastTrayState {
		return
	}
	var nid notifyIconDataW
	nid.CbSize = uint32(unsafe.Sizeof(notifyIconDataW{}))
	nid.Hwnd = u.hwnd
	nid.UID = 1
	nid.UFlags = nifIcon | nifTip
	nid.HIcon = u.trayIconForState(snap.State)
	tip := fmt.Sprintf("NetShaper v7.0 — %s", snap.State)
	if snap.State == CtrlRunning && snap.LatencyP50MS > 0 {
		tip = fmt.Sprintf("NetShaper v7.0 — %s (%.0fms | %d/%d)", snap.State, snap.LatencyP50MS, snap.HealthyWorkers, snap.PoolSize)
	}
	copyUTF16Fixed(nid.SzTip[:], tip)
	_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
	runtime.KeepAlive(&nid)
	u.lastTrayState = snap.State
}

func (u *winUI) removeTrayIcon() {
	if !u.trayAdded || u.hwnd == 0 {
		return
	}
	var nid notifyIconDataW
	nid.CbSize = uint32(unsafe.Sizeof(notifyIconDataW{}))
	nid.Hwnd = u.hwnd
	nid.UID = 1
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	runtime.KeepAlive(&nid)
	u.trayAdded = false
}

func insertMenuString(hMenu uintptr, pos uint32, id uint32, text string) {
	ptr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	mii := menuItemInfoW{
		CbSize:     uint32(unsafe.Sizeof(menuItemInfoW{})),
		FMask:      miimID | miimString | miimState,
		FType:      mftString,
		WID:        id,
		DwTypeData: ptr,
	}
	_, _, _ = procInsertMenuItemW.Call(hMenu, uintptr(pos), 1, uintptr(unsafe.Pointer(&mii)))
	runtime.KeepAlive(&mii)
	runtime.KeepAlive(ptr)
}

func insertMenuSeparator(hMenu uintptr, pos uint32) {
	mii := menuItemInfoW{
		CbSize: uint32(unsafe.Sizeof(menuItemInfoW{})),
		FMask:  miimFType,
		FType:  mftSep,
	}
	_, _, _ = procInsertMenuItemW.Call(hMenu, uintptr(pos), 1, uintptr(unsafe.Pointer(&mii)))
	runtime.KeepAlive(&mii)
}

func (u *winUI) showTrayMenu() {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	snap := u.ctrl.Snapshot()
	showLabel := "Show NetShaper"
	if u.visible {
		showLabel = "Hide to Tray"
	}
	toggleLabel := "Start Tunnel"
	if snap.State != CtrlStopped {
		toggleLabel = "Stop Tunnel"
	}

	insertMenuString(hMenu, 0, idTrayShow, showLabel)
	insertMenuString(hMenu, 1, idTrayToggle, toggleLabel)
	insertMenuString(hMenu, 2, idTrayCopy, fmt.Sprintf("Copy Proxy (%s)", snap.LocalAddr))
	insertMenuSeparator(hMenu, 3)
	insertMenuString(hMenu, 4, idTrayExit, "Exit NetShaper")

	var pt winPoint
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWindow.Call(u.hwnd)

	tpm := tpmParams{CbSize: uint32(unsafe.Sizeof(tpmParams{}))}
	_, _, _ = procTrackPopupMenuEx.Call(
		hMenu,
		tpmRightButton|tpmBottomAlign|tpmLeftAlign,
		uintptr(pt.X),
		uintptr(pt.Y),
		u.hwnd,
		uintptr(unsafe.Pointer(&tpm)),
	)
	runtime.KeepAlive(&tpm)
	_, _, _ = procPostMessageW.Call(u.hwnd, wmNull, 0, 0)
}

// -----------------------------------------------------------------------------
// Interaction & Hit-Testing
// -----------------------------------------------------------------------------

func (u *winUI) hitTest(x, y int32) hitAction {
	for i := len(u.hitBoxes) - 1; i >= 0; i-- {
		r := u.hitBoxes[i].rect
		if x >= r.Left && x <= r.Right && y >= r.Top && y <= r.Bottom {
			return u.hitBoxes[i].action
		}
	}
	return hitNone
}

func (u *winUI) tryAutoApplyCodespaceOnTabLeave() {
	if u.activeTab != tabAccount || !u.editDirty || u.hwndEdit == 0 {
		return
	}
	snap := u.ctrl.Snapshot()
	if !snap.CanEditCodespace {
		return
	}
	val := u.getEditText()
	if err := ValidateCodespaceName(val); err != nil {
		u.showToast("Unsaved codespace name (invalid)")
		return
	}
	if err := u.ctrl.SetCodespaceName(val); err == nil {
		u.editDirty = false
		u.lastSyncedCodespace = val
		u.showToast("Codespace saved")
	}
}

func (u *winUI) handleClick(act hitAction, x, y int32) {
	switch act {
	case hitTabHome:
		u.tryAutoApplyCodespaceOnTabLeave()
		u.activeTab = tabHome
		u.syncEditControlBounds()
		_, _, _ = procSetFocus.Call(u.hwnd)
		u.invalidate()
	case hitTabTerminal:
		u.tryAutoApplyCodespaceOnTabLeave()
		u.activeTab = tabTerminal
		u.termScrollOffset = 0
		u.syncEditControlBounds()
		_, _, _ = procSetFocus.Call(u.hwnd)
		u.invalidate()
	case hitTabAccount:
		u.activeTab = tabAccount
		u.syncEditControlBounds()
		u.invalidate()
	case hitPowerBtn:
		// If user edited Codespace Name on Account tab and clicked Power while stopped, apply it cleanly first.
		snap := u.ctrl.Snapshot()
		if snap.State == CtrlStopped && u.editDirty {
			val := u.getEditText()
			if err := u.ctrl.SetCodespaceName(val); err != nil {
				u.showToast(err.Error())
				return
			}
			u.editDirty = false
			u.lastSyncedCodespace = val
		}
		u.ctrl.ToggleStartStop()
		u.invalidate()
	case hitApplyCodespace:
		val := u.getEditText()
		if err := u.ctrl.SetCodespaceName(val); err != nil {
			u.showToast(err.Error())
		} else {
			u.editDirty = false
			u.lastSyncedCodespace = val
			u.showToast("Codespace saved")
		}
		u.invalidate()
	case hitTermClear:
		u.ctrl.Logs().Clear()
		u.termScrollOffset = 0
		u.termScrollX = 0
		u.termMaxScrollX = 0
		u.invalidate()
	case hitTermCopy:
		lines := u.ctrl.Logs().SnapshotInto(u.logScratch)
		var b strings.Builder
		for _, ln := range lines {
			b.WriteString(ln.Timestamp)
			b.WriteByte(' ')
			b.WriteString(ln.Text)
			b.WriteString("\r\n")
		}
		if err := copyTextToClipboard(u.hwnd, b.String()); err == nil {
			u.showToast(fmt.Sprintf("Copied %d full lines", len(lines)))
		} else {
			u.ctrl.Logs().Append(LogWarn, "[UI] Clipboard copy failed: "+err.Error())
			u.showToast("Clipboard busy — retry copy")
		}
	case hitTermHScroll:
		_, _, _ = procSetFocus.Call(u.hwnd)
		u.beginHScrollInteraction(x)
	case hitTermViewport:
		_, _, _ = procSetFocus.Call(u.hwnd)
		u.copyClickedTerminalRow(y)
	case hitReAuth:
		if err := u.ctrl.RequestReAuth(); err != nil {
			u.showToast(err.Error())
		} else {
			u.showToast("Opening GitHub CLI auth console...")
		}
		u.invalidate()
	case hitCheckQuota:
		if u.ctrl.RequestQuotaCheck() {
			u.showToast("Checking Codespace quota...")
		}
		u.invalidate()
	}
}

// -----------------------------------------------------------------------------
// Anti-Aliased GDI+ Glassmorphism Painting (0 Cached Resource Leaks / Frame)
// -----------------------------------------------------------------------------

func (u *winUI) onPaint() {
	var ps paintStruct
	hdc, _, _ := procBeginPaint.Call(u.hwnd, uintptr(unsafe.Pointer(&ps)))
	if hdc == 0 {
		return
	}
	defer func() {
		_, _, _ = procEndPaint.Call(u.hwnd, uintptr(unsafe.Pointer(&ps)))
		runtime.KeepAlive(&ps)
	}()

	var rc winRect
	_, _, _ = procGetClientRect.Call(u.hwnd, uintptr(unsafe.Pointer(&rc)))
	w := rc.Right - rc.Left
	h := rc.Bottom - rc.Top
	if !u.theme.ensureBackBuffer(hdc, w, h) {
		return
	}

	var g uintptr
	st, _, _ := procGdipCreateFromHDC.Call(u.theme.memDC, uintptr(unsafe.Pointer(&g)))
	if st != 0 || g == 0 {
		return
	}
	defer procGdipDeleteGraphics.Call(g)

	_, _, _ = procGdipSetSmoothingMode.Call(g, gpSmoothingModeAntiAlias)
	_, _, _ = procGdipSetPixelOffsetMode.Call(g, gpPixelOffsetModeHighQuality)
	_, _, _ = procGdipSetTextRenderingHint.Call(g, gpTextRenderingHintAntiAliasGrid)

	u.hitBoxes = u.hitBoxes[:0]
	snap := u.ctrl.Snapshot()

	// Clear 32bpp DIB: pure transparent glass + subtle frosted dark veil when Win11 DWM Acrylic/Mica is active.
	if u.dwmGlassActive {
		_, _, _ = procGdipGraphicsClear.Call(g, 0x00000000)
		_, _, _ = procGdipFillRectangleI.Call(g, u.theme.brCanvasGlass, 0, 0, uintptr(w), uintptr(h))
	} else {
		_, _, _ = procGdipGraphicsClear.Call(g, uintptr(colCanvasOpaque))
	}

	u.drawHeader(g, w, snap)
	u.drawSegmentedTabs(g, w)

	switch u.activeTab {
	case tabHome:
		u.drawHomeTab(g, w, snap)
	case tabTerminal:
		u.drawTerminalTab(g, w, h)
	case tabAccount:
		u.drawAccountTab(g, w, snap)
	}

	if u.toastText != "" {
		u.drawToast(g, w, h, u.toastText)
	}

	_, _, _ = procBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), u.theme.memDC, 0, 0, srccopy)
}

func (u *winUI) drawHeader(g uintptr, w int32, snap UISnapshot) {
	pad := u.s(16)
	gpDrawText(g, "NetShaper", u.theme.gpFontTitle, u.theme.brTxtPrimary, u.theme.fmtLeft, winRect{pad, u.s(14), u.s(145), u.s(42)})
	gpDrawText(g, "v7.0", u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeft, winRect{u.s(109), u.s(18), u.s(154), u.s(40)})

	dotBr, fillBr, ringBr, txtBr, label := u.stateVisuals(snap.State)
	badgeR := winRect{w - u.s(128), u.s(16), w - pad, u.s(40)}
	gpDrawGlassCard(g, badgeR, u.s(12), fillBr, ringBr, u.s(1))

	// Crisp glowing status dot inside the status pill.
	dotD := u.s(7)
	dotX := badgeR.Left + u.s(12)
	dotY := badgeR.Top + (badgeR.Bottom-badgeR.Top-dotD)/2
	_, _, _ = procGdipFillEllipseI.Call(g, dotBr, uintptr(dotX), uintptr(dotY), uintptr(dotD), uintptr(dotD))

	lblR := winRect{dotX + dotD + u.s(4), badgeR.Top, badgeR.Right - u.s(8), badgeR.Bottom}
	gpDrawText(g, label, u.theme.gpFontSmall, txtBr, u.theme.fmtCenter, lblR)
}

func (u *winUI) drawSegmentedTabs(g uintptr, w int32) {
	pad := u.s(16)
	trackR := winRect{pad, u.s(54), w - pad, u.s(88)}
	gpDrawGlassCard(g, trackR, u.s(11), u.theme.brTrack, u.theme.brHairline, u.s(1))

	inset := u.s(3)
	innerW := (trackR.Right - trackR.Left) - 2*inset
	tabW := innerW / 3

	tabs := []struct {
		id    uiTab
		act   hitAction
		label string
	}{
		{tabHome, hitTabHome, "Home"},
		{tabTerminal, hitTabTerminal, "Terminal"},
		{tabAccount, hitTabAccount, "Account"},
	}

	for i, tb := range tabs {
		x0 := trackR.Left + inset + int32(i)*tabW
		x1 := x0 + tabW
		if i == 2 {
			x1 = trackR.Right - inset
		}
		r := winRect{x0, trackR.Top + inset, x1, trackR.Bottom - inset}
		u.hitBoxes = append(u.hitBoxes, hitBox{action: tb.act, rect: r})

		font := u.theme.gpFontBody
		txtBr := u.theme.brTxtMuted
		if u.activeTab == tb.id {
			gpDrawGlassCard(g, r, u.s(8), u.theme.brElevated, u.theme.brHairline, u.s(1))
			font = u.theme.gpFontSemi
			txtBr = u.theme.brTxtPrimary
		} else if u.hoverAction == tb.act {
			gpDrawGlassCard(g, r, u.s(8), u.theme.brHighlight, 0, 0)
			txtBr = u.theme.brTxtSecond
		}
		gpDrawText(g, tb.label, font, txtBr, u.theme.fmtCenter, r)
	}
}

func (u *winUI) drawHomeTab(g uintptr, w int32, snap UISnapshot) {
	pad := u.s(16)
	borderW := u.s(1)
	if borderW < 1 {
		borderW = 1
	}

	// 1. Spacious Apple-Style Hero Glass Card (NO Codespace Name input on Home!)
	heroR := winRect{pad, u.s(102), w - pad, u.s(296)}
	gpDrawGlassCard(g, heroR, u.s(16), u.theme.brCard, u.theme.brHairline, borderW)

	// Centered Anti-Aliased Power Button (96x96 logical px) + subtle ambient halo glow.
	btnD := u.s(96)
	cx := w / 2
	cy := u.s(168)
	btnR := winRect{cx - btnD/2, cy - btnD/2, cx + btnD/2, cy + btnD/2}
	u.hitBoxes = append(u.hitBoxes, hitBox{action: hitPowerBtn, rect: btnR})

	glowBr, fillBr, ringBr := u.powerButtonVisuals(snap.State, u.hoverAction == hitPowerBtn)
	if glowBr != 0 {
		halo := u.s(12)
		_, _, _ = procGdipFillEllipseI.Call(g, glowBr,
			uintptr(btnR.Left-halo), uintptr(btnR.Top-halo),
			uintptr(btnD+2*halo), uintptr(btnD+2*halo))
		haloInner := u.s(6)
		_, _, _ = procGdipFillEllipseI.Call(g, glowBr,
			uintptr(btnR.Left-haloInner), uintptr(btnR.Top-haloInner),
			uintptr(btnD+2*haloInner), uintptr(btnD+2*haloInner))
	}

	// Button glass body + razor-sharp anti-aliased ring (Even-Odd GpPath, 0 XMM/GpPen).
	_, _, _ = procGdipFillEllipseI.Call(g, fillBr, uintptr(btnR.Left), uintptr(btnR.Top), uintptr(btnD), uintptr(btnD))
	ringThick := u.s(3)
	if ringThick < 2 {
		ringThick = 2
	}
	gpFillEllipseRing(g, btnR, ringThick, ringBr)

	// True IEC Power Symbol: open 280-degree anti-aliased arc + rounded top vertical stem.
	u.drawIECPowerGlyph(g, cx, cy, u.s(19), u.s(3))

	// Primary SOCKS5 status & uptime line
	subText := "Press to start multi-tunnel proxy"
	subBr := u.theme.brTxtMuted
	switch snap.State {
	case CtrlRunning:
		subText = fmt.Sprintf("SOCKS5 %s · %s", snap.LocalAddr, FormatDurationShort(snap.Uptime))
		subBr = u.theme.brGreen
	case CtrlDegraded:
		subText = fmt.Sprintf("Degraded (%s) · %s", snap.SupervisorState, snap.LocalAddr)
		subBr = u.theme.brAmber
	case CtrlStarting:
		if snap.GuardThrottleWaitMS > 0 {
			waitStr := FormatDurationShort(time.Duration(snap.GuardThrottleWaitMS) * time.Millisecond)
			if snap.GuardThrottleReason == "budget_5m_exhausted" || snap.GuardThrottleReason == "budget_hour_exhausted" {
				subText = fmt.Sprintf("API budget %d/%d · retry in %s", snap.GuardCalls5Min, snap.GuardMax5Min, waitStr)
			} else {
				subText = fmt.Sprintf("WAF cooldown · retry in %s", waitStr)
			}
			subBr = u.theme.brAmber
		} else {
			subText = fmt.Sprintf("Booting (%s)...", snap.SupervisorState)
			subBr = u.theme.brAmber
		}
	case CtrlStopping:
		subText = "Ordered shutdown in progress..."
		subBr = u.theme.brAmber
	case CtrlReauthing:
		subText = "Waiting for GitHub CLI auth console..."
		subBr = u.theme.brBlue
	default:
		if snap.LastError != "" {
			subText = truncateUTF8(snap.LastError, 46)
			subBr = u.theme.brRed
		}
	}
	gpDrawText(g, subText, u.theme.gpFontSemi, subBr, u.theme.fmtCenterEllip,
		winRect{heroR.Left + u.s(14), u.s(232), heroR.Right - u.s(14), u.s(258)})

	routeLine := fmt.Sprintf("Pool %d · Max %d SSH ch · PMTU 576 safe", snap.PoolSize, snap.MaxActiveConns)
	if snap.State == CtrlRunning && snap.RoutingMode != "" {
		routeLine = fmt.Sprintf("Route: %s · Underlay %.0f ms", snap.RoutingMode, snap.UnderlayMS)
	} else if snap.State == CtrlStarting && snap.GuardThrottleWaitMS > 0 {
		routeLine = fmt.Sprintf("Throttled (%s) · click Power to cancel", snap.GuardThrottleReason)
	} else if snap.State == CtrlStopped && snap.LastError != "" {
		routeLine = "Open Account tab or Terminal for details"
	} else if snap.State == CtrlStopped && snap.CodespaceName == DefaultCodespaceName {
		routeLine = "Set your Codespace name in Account tab"
	}
	gpDrawText(g, routeLine, u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtCenterEllip,
		winRect{heroR.Left + u.s(14), u.s(260), heroR.Right - u.s(14), u.s(282)})

	// 2. Three-Column Glass Metric Pills (LATENCY | POOL | CHANNELS)
	gap := u.s(10)
	cardW := (w - 2*pad - 2*gap) / 3
	mTop := u.s(308)
	mBot := u.s(380)

	latVal := "--"
	if snap.LatencyP50MS > 0 {
		latVal = fmt.Sprintf("%.0f ms", snap.LatencyP50MS)
	}
	poolVal := fmt.Sprintf("%d / %d", snap.HealthyWorkers, snap.PoolSize)
	chVal := fmt.Sprintf("%d / %d", snap.ActiveConns, snap.MaxActiveConns)

	u.drawMetricCard(g, winRect{pad, mTop, pad + cardW, mBot}, "LATENCY", latVal, u.theme.brTxtPrimary)
	u.drawMetricCard(g, winRect{pad + cardW + gap, mTop, pad + 2*cardW + gap, mBot}, "POOL", poolVal, u.theme.brGreen)
	u.drawMetricCard(g, winRect{pad + 2*(cardW+gap), mTop, w - pad, mBot}, "CHANNELS", chVal, u.theme.brBlue)

	// 3. Compact Transfer & WAF Guard Glass Card
	statR := winRect{pad, u.s(392), w - pad, u.s(472)}
	gpDrawGlassCard(g, statR, u.s(14), u.theme.brCard, u.theme.brHairline, borderW)

	xferLeft := fmt.Sprintf("↑  %s", FormatBytesShort(snap.BytesUp))
	xferRight := fmt.Sprintf("↓  %s", FormatBytesShort(snap.BytesDown))
	gpDrawText(g, xferLeft, u.theme.gpFontSemi, u.theme.brTxtPrimary, u.theme.fmtLeft,
		winRect{statR.Left + u.s(14), statR.Top + u.s(12), statR.Left + u.s(164), statR.Top + u.s(34)})
	gpDrawText(g, xferRight, u.theme.gpFontSemi, u.theme.brGreen, u.theme.fmtRight,
		winRect{statR.Left + u.s(164), statR.Top + u.s(12), statR.Right - u.s(14), statR.Top + u.s(34)})

	guardText := fmt.Sprintf("WAF Guard: %d/%d (5m) · %d/%d (1h)", snap.GuardCalls5Min, snap.GuardMax5Min, snap.GuardCallsHour, snap.GuardMaxHour)
	guardBr := u.theme.brTxtMuted
	if snap.GuardCooldownMS > 0 {
		waitStr := FormatDurationShort(time.Duration(snap.GuardCooldownMS) * time.Millisecond)
		guardText = fmt.Sprintf("WAF Cooldown: %s (%d/%d 5m)", waitStr, snap.GuardCalls5Min, snap.GuardMax5Min)
		guardBr = u.theme.brAmber
	} else if snap.GuardBudgetWaitMS > 0 {
		waitStr := FormatDurationShort(time.Duration(snap.GuardBudgetWaitMS) * time.Millisecond)
		guardText = fmt.Sprintf("API Budget %d/%d (5m) · unlocks in %s", snap.GuardCalls5Min, snap.GuardMax5Min, waitStr)
		guardBr = u.theme.brAmber
	}
	gpDrawText(g, guardText, u.theme.gpFontSmall, guardBr, u.theme.fmtLeftEllip,
		winRect{statR.Left + u.s(14), statR.Top + u.s(38), statR.Right - u.s(14), statR.Top + u.s(56)})

	// Subtle 4px WAF 5-min budget bar
	barTrack := winRect{statR.Left + u.s(14), statR.Bottom - u.s(16), statR.Right - u.s(14), statR.Bottom - u.s(12)}
	gpFillRoundRect(g, barTrack, u.s(2), u.theme.brScrollTrack)
	if snap.GuardMax5Min > 0 && snap.GuardCalls5Min > 0 {
		frac := float64(snap.GuardCalls5Min) / float64(snap.GuardMax5Min)
		if frac > 1.0 {
			frac = 1.0
		}
		fillW := int32(float64(barTrack.Right-barTrack.Left) * frac)
		if fillW < u.s(6) {
			fillW = u.s(6)
		}
		barBr := u.theme.brBlue
		if frac >= 1.0 {
			barBr = u.theme.brRed
		} else if frac >= 0.85 {
			barBr = u.theme.brAmber
		}
		gpFillRoundRect(g, winRect{barTrack.Left, barTrack.Top, barTrack.Left + fillW, barTrack.Bottom}, u.s(2), barBr)
	}
}

func (u *winUI) drawTerminalTab(g uintptr, w, h int32) {
	pad := u.s(16)
	borderW := u.s(1)
	if borderW < 1 {
		borderW = 1
	}

	u.logScratch = u.ctrl.Logs().SnapshotInto(u.logScratch)

	// Top utility bar
	countText := fmt.Sprintf("Ring: %d / %d  ·  Click row to copy", len(u.logScratch), TerminalRingCapacity)
	gpDrawText(g, countText, u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeftEllip,
		winRect{pad, u.s(98), w - u.s(154), u.s(124)})

	clearR := winRect{w - u.s(146), u.s(98), w - u.s(84), u.s(124)}
	copyR := winRect{w - u.s(76), u.s(98), w - pad, u.s(124)}
	u.hitBoxes = append(u.hitBoxes, hitBox{action: hitTermClear, rect: clearR})
	u.hitBoxes = append(u.hitBoxes, hitBox{action: hitTermCopy, rect: copyR})
	u.drawGlassButton(g, clearR, "Clear", u.hoverAction == hitTermClear, false)
	u.drawGlassButton(g, copyR, "Copy", u.hoverAction == hitTermCopy, false)

	// Outer dark glass terminal card
	vp := winRect{pad, u.s(132), w - pad, h - u.s(14)}
	gpDrawGlassCard(g, vp, u.s(12), u.theme.brTermBg, u.theme.brHairline, borderW)

	hBarHeight := u.s(14)
	vBarWidth := u.s(8)
	inner := winRect{
		Left:   vp.Left + u.s(10),
		Top:    vp.Top + u.s(8),
		Right:  vp.Right - vBarWidth - u.s(6),
		Bottom: vp.Bottom - hBarHeight - u.s(4),
	}
	u.termInnerRect = inner
	u.hitBoxes = append(u.hitBoxes, hitBox{action: hitTermViewport, rect: inner})

	lineH := u.s(17)
	if lineH < 13 {
		lineH = 13
	}
	u.termLineHeight = lineH
	visibleRows := int((inner.Bottom - inner.Top) / lineH)
	if visibleRows < 1 {
		visibleRows = 1
	}
	u.termVisibleRows = visibleRows

	total := len(u.logScratch)
	maxScrollV := total - visibleRows
	if maxScrollV < 0 {
		maxScrollV = 0
	}
	if u.termScrollOffset > maxScrollV {
		u.termScrollOffset = maxScrollV
	}
	endIdx := total - u.termScrollOffset
	startIdx := endIdx - visibleRows
	if startIdx < 0 {
		startIdx = 0
	}
	u.termStartIdx = startIdx
	u.termEndIdx = endIdx

	// Compute max line width in O(N) using pre-measured monoCharAdvance (0 GDI+ syscalls!).
	charW := u.theme.monoCharAdvance
	if charW < 4 {
		charW = 7
	}
	maxChars := 0
	for i := 0; i < total; i++ {
		n := len(u.logScratch[i].Timestamp) + 1 + len(u.logScratch[i].Text)
		if n > maxChars {
			maxChars = n
		}
	}
	innerW := inner.Right - inner.Left
	contentW := int32(math.Ceil(float64(maxChars)*float64(charW))) + u.s(20)
	maxScrollX := contentW - innerW
	if maxScrollX < 0 {
		maxScrollX = 0
	}
	u.termMaxScrollX = maxScrollX
	if u.termScrollX > maxScrollX {
		u.termScrollX = maxScrollX
	}
	if u.termScrollX < 0 {
		u.termScrollX = 0
	}

	// Strict inner viewport clip — ZERO ellipsis truncation so horizontal scroll reveals 100% of every line!
	_, _, _ = procGdipSetClipRectI.Call(
		g,
		uintptr(inner.Left),
		uintptr(inner.Top),
		uintptr(inner.Right-inner.Left),
		uintptr(inner.Bottom-inner.Top),
		gpCombineModeReplace,
	)

	y := inner.Top
	for i := startIdx; i < endIdx; i++ {
		ln := u.logScratch[i]
		if u.copiedRowSeq != 0 && ln.Seq == u.copiedRowSeq {
			_, _, _ = procGdipFillRectangleI.Call(g, u.theme.brRowFlash,
				uintptr(inner.Left), uintptr(y), uintptr(innerW), uintptr(lineH))
		}
		br := u.theme.brTxtPrimary
		switch ln.Severity {
		case LogSuccess:
			br = u.theme.brGreen
		case LogWarn:
			br = u.theme.brAmber
		case LogError:
			br = u.theme.brRed
		}
		lineStr := ln.Timestamp + " " + ln.Text
		// Generous layout width beyond contentW so GDI+ never wraps or truncates horizontally.
		rowR := winRect{inner.Left - u.termScrollX, y, inner.Left - u.termScrollX + contentW + u.s(200), y + lineH}
		gpDrawText(g, lineStr, u.theme.gpFontMono, br, u.theme.fmtTermNoWrap, rowR)
		y += lineH
	}
	_, _, _ = procGdipResetClip.Call(g)

	// Slim Vertical Scrollbar Indicator (right inner edge) when lines exceed viewport.
	if maxScrollV > 0 {
		vTrack := winRect{vp.Right - u.s(8), inner.Top + u.s(2), vp.Right - u.s(4), inner.Bottom - u.s(2)}
		gpFillRoundRect(g, vTrack, u.s(2), u.theme.brScrollTrack)
		trackH := vTrack.Bottom - vTrack.Top
		thumbH := int32(float64(visibleRows) / float64(total) * float64(trackH))
		if thumbH < u.s(20) {
			thumbH = u.s(20)
		}
		if thumbH > trackH {
			thumbH = trackH
		}
		fracTop := float64(startIdx) / float64(maxScrollV)
		thumbTop := vTrack.Top + int32(fracTop*float64(trackH-thumbH))
		gpFillRoundRect(g, winRect{vTrack.Left, thumbTop, vTrack.Right, thumbTop + thumbH}, u.s(2), u.theme.brScrollThumb)
	}

	// Interactive Slim Horizontal Scrollbar (clickable track + draggable thumb) at bottom of terminal card.
	hHit := winRect{vp.Left + u.s(8), vp.Bottom - hBarHeight - u.s(2), vp.Right - u.s(8), vp.Bottom - u.s(2)}
	hVis := winRect{vp.Left + u.s(10), vp.Bottom - u.s(9), vp.Right - u.s(10), vp.Bottom - u.s(4)}
	u.termHTrackRect = hVis
	if maxScrollX > 0 {
		u.hitBoxes = append(u.hitBoxes, hitBox{action: hitTermHScroll, rect: hHit})
		gpFillRoundRect(g, hVis, u.s(3), u.theme.brScrollTrack)

		trackW := hVis.Right - hVis.Left
		thumbW := int32(float64(innerW) / float64(contentW) * float64(trackW))
		if thumbW < u.s(28) {
			thumbW = u.s(28)
		}
		if thumbW > trackW {
			thumbW = trackW
		}
		avail := trackW - thumbW
		thumbLeft := hVis.Left
		if avail > 0 {
			thumbLeft = hVis.Left + int32(float64(u.termScrollX)/float64(maxScrollX)*float64(avail))
		}
		thumbR := winRect{thumbLeft, hVis.Top, thumbLeft + thumbW, hVis.Bottom}
		u.termHThumbRect = thumbR
		thumbBr := u.theme.brScrollThumb
		if u.draggingHScroll || u.hoverAction == hitTermHScroll {
			thumbBr = u.theme.brScrollDrag
		}
		gpFillRoundRect(g, thumbR, u.s(3), thumbBr)
	} else {
		u.termHThumbRect = winRect{}
	}
}

func (u *winUI) drawAccountTab(g uintptr, w int32, snap UISnapshot) {
	pad := u.s(16)
	borderW := u.s(1)
	if borderW < 1 {
		borderW = 1
	}

	// 1. GitHub CLI Account Glass Card
	accR := winRect{pad, u.s(100), w - pad, u.s(192)}
	gpDrawGlassCard(g, accR, u.s(14), u.theme.brCard, u.theme.brHairline, borderW)
	gpDrawText(g, "GITHUB CLI ACCOUNT", u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeft,
		winRect{accR.Left + u.s(14), accR.Top + u.s(7), accR.Right - u.s(14), accR.Top + u.s(22)})

	userLabel := "Not detected locally"
	userBr := u.theme.brTxtMuted
	if snap.Auth.Username != "" {
		userLabel = "@" + snap.Auth.Username
		userBr = u.theme.brTxtPrimary
	}
	gpDrawText(g, userLabel, u.theme.gpFontSemi, userBr, u.theme.fmtLeftEllip,
		winRect{accR.Left + u.s(14), accR.Top + u.s(22), accR.Left + u.s(180), accR.Top + u.s(41)})

	authSub := snap.Auth.StatusText
	authSubBr := u.theme.brTxtMuted
	if snap.Auth.Error != "" {
		authSub = snap.Auth.Error
		authSubBr = u.theme.brRed
	}
	gpDrawText(g, authSub, u.theme.gpFontSmall, authSubBr, u.theme.fmtLeftEllip,
		winRect{accR.Left + u.s(14), accR.Top + u.s(40), accR.Right - u.s(14), accR.Top + u.s(55)})

	reauthR := winRect{accR.Left + u.s(14), accR.Top + u.s(58), accR.Right - u.s(14), accR.Bottom - u.s(8)}
	if snap.State != CtrlReauthing {
		u.hitBoxes = append(u.hitBoxes, hitBox{action: hitReAuth, rect: reauthR})
	}
	reauthLabel := "Switch Account / Re-Auth"
	if snap.State == CtrlReauthing {
		reauthLabel = "Re-Auth Running in Console..."
	}
	u.drawGlassButton(g, reauthR, reauthLabel, u.hoverAction == hitReAuth, false)

	// 2. Codespace Name Card (EDIT control shown strictly on Account tab)
	csR := winRect{pad, u.s(200), w - pad, u.s(274)}
	gpDrawGlassCard(g, csR, u.s(14), u.theme.brCard, u.theme.brHairline, borderW)
	gpDrawText(g, "CODESPACE NAME", u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeft,
		winRect{csR.Left + u.s(14), csR.Top + u.s(8), csR.Left + u.s(164), csR.Top + u.s(24)})
	if !snap.CanEditCodespace {
		gpDrawText(g, "LOCKED WHILE ACTIVE", u.theme.gpFontSmall, u.theme.brAmber, u.theme.fmtRight,
			winRect{csR.Right - u.s(154), csR.Top + u.s(8), csR.Right - u.s(14), csR.Top + u.s(24)})
	}

	// Anti-aliased glass input frame matching native dark EDIT control seamlessly (0 seam)
	editFrame := winRect{u.s(24), u.s(230), u.s(266), u.s(262)}
	gpDrawGlassCard(g, editFrame, u.s(8), u.theme.brEditFrame, u.theme.brHairline, borderW)

	// Apply pill button next to EDIT control
	applyR := winRect{u.s(274), u.s(230), csR.Right - u.s(12), u.s(262)}
	if snap.CanEditCodespace {
		u.hitBoxes = append(u.hitBoxes, hitBox{action: hitApplyCodespace, rect: applyR})
	}
	applyFill := u.theme.brElevated
	applyRing := u.theme.brHairline
	applyTxt := u.theme.brTxtMuted
	if snap.CanEditCodespace && u.editDirty {
		applyFill = u.theme.brBlue
		applyRing = u.theme.brBlueHover
		applyTxt = u.theme.brTxtPrimary
	} else if snap.CanEditCodespace && u.hoverAction == hitApplyCodespace {
		applyFill = u.theme.brHover
		applyTxt = u.theme.brTxtPrimary
	} else if snap.CanEditCodespace {
		applyTxt = u.theme.brTxtSecond
	}
	gpDrawGlassCard(g, applyR, u.s(8), applyFill, applyRing, borderW)
	gpDrawText(g, "Apply", u.theme.gpFontSmall, applyTxt, u.theme.fmtCenter, applyR)

	// 3. Strictly On-Demand Quota & Machine Tier Glass Card
	qR := winRect{pad, u.s(282), w - pad, u.s(464)}
	gpDrawGlassCard(g, qR, u.s(14), u.theme.brCard, u.theme.brHairline, borderW)
	gpDrawText(g, "CODESPACE QUOTA (ON-DEMAND ONLY)", u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeft,
		winRect{qR.Left + u.s(14), qR.Top + u.s(8), qR.Right - u.s(14), qR.Top + u.s(22)})

	qBtnR := winRect{qR.Left + u.s(14), qR.Top + u.s(26), qR.Right - u.s(14), qR.Top + u.s(54)}
	if !snap.Quota.Loading {
		u.hitBoxes = append(u.hitBoxes, hitBox{action: hitCheckQuota, rect: qBtnR})
	}
	qBtnLabel := "Check Quota Now (0 Background Calls)"
	if snap.Quota.Loading {
		qBtnLabel = "Querying GitHub API..."
	}
	u.drawGlassButton(g, qBtnR, qBtnLabel, u.hoverAction == hitCheckQuota, true)

	y := qR.Top + u.s(60)
	rowH := u.s(17)
	q := snap.Quota
	if !q.Checked && q.GuardBlocked == "" && q.Error == "" {
		gpDrawText(g, "No API calls issued yet.", u.theme.gpFontBody, u.theme.brTxtMuted, u.theme.fmtLeft,
			winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), y + rowH})
		gpDrawText(g, "Click above to check machine tier & billing.", u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeft,
			winRect{qR.Left + u.s(14), y + rowH, qR.Right - u.s(14), y + 2*rowH})
	} else {
		if q.GuardBlocked != "" {
			gpDrawText(g, q.GuardBlocked, u.theme.gpFontSmall, u.theme.brAmber, u.theme.fmtWrap,
				winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), qR.Bottom - u.s(22)})
		} else if q.Error != "" {
			gpDrawText(g, q.Error, u.theme.gpFontSmall, u.theme.brRed, u.theme.fmtWrap,
				winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), qR.Bottom - u.s(22)})
		} else {
			gpDrawText(g, fmt.Sprintf("VM State: %s", q.CodespaceState), u.theme.gpFontSemi, u.theme.brTxtPrimary, u.theme.fmtLeftEllip,
				winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), y + rowH})
			y += rowH
			gpDrawText(g, fmt.Sprintf("Tier: %s", q.MachineDisplay), u.theme.gpFontBody, u.theme.brTxtSecond, u.theme.fmtLeftEllip,
				winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), y + rowH})
			y += rowH
			gpDrawText(g, fmt.Sprintf("Specs: %d vCPU · %d GB RAM · %d GB Disk", q.CPUs, q.MemoryGB, q.StorageGB), u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeftEllip,
				winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), y + rowH})
			y += rowH
			if q.BillingAvailable {
				gpDrawText(g, fmt.Sprintf("Core-Hours: %.2f / %.0f hr", q.CoreHoursUsed, q.CoreHoursIncluded), u.theme.gpFontSemi, u.theme.brGreen, u.theme.fmtLeftEllip,
					winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), y + rowH})
			} else {
				gpDrawText(g, fmt.Sprintf("Session Timer: %s active", FormatDurationShort(snap.Uptime)), u.theme.gpFontSmall, u.theme.brAmber, u.theme.fmtLeftEllip,
					winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), y + rowH})
			}
			y += rowH
			if q.BillingNote != "" {
				gpDrawText(g, q.BillingNote, u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtWrap,
					winRect{qR.Left + u.s(14), y, qR.Right - u.s(14), qR.Bottom - u.s(22)})
			}
		}
	}

	guardLine := fmt.Sprintf("WAF Budget: %d/%d (5m) · %d/%d (1h) · 429s: %d",
		snap.GuardCalls5Min, snap.GuardMax5Min, snap.GuardCallsHour, snap.GuardMaxHour, snap.GuardRateLimits)
	gpDrawText(g, guardLine, u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtLeftEllip,
		winRect{qR.Left + u.s(14), qR.Bottom - u.s(20), qR.Right - u.s(14), qR.Bottom - u.s(4)})

	// Clean Footer
	gpDrawText(g, "NetShaper v7.0 · Portable Native UI", u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtCenter,
		winRect{pad, u.s(468), w - pad, u.s(486)})
}

func (u *winUI) drawMetricCard(g uintptr, r winRect, label, val string, valBr uintptr) {
	borderW := u.s(1)
	if borderW < 1 {
		borderW = 1
	}
	gpDrawGlassCard(g, r, u.s(14), u.theme.brCard, u.theme.brHairline, borderW)
	gpDrawText(g, label, u.theme.gpFontSmall, u.theme.brTxtMuted, u.theme.fmtCenter,
		winRect{r.Left + u.s(6), r.Top + u.s(12), r.Right - u.s(6), r.Top + u.s(30)})
	gpDrawText(g, val, u.theme.gpFontSemi, valBr, u.theme.fmtCenter,
		winRect{r.Left + u.s(6), r.Top + u.s(32), r.Right - u.s(6), r.Bottom - u.s(10)})
}

func (u *winUI) drawGlassButton(g uintptr, r winRect, text string, hovered bool, primary bool) {
	borderW := u.s(1)
	if borderW < 1 {
		borderW = 1
	}
	fillBr := u.theme.brElevated
	ringBr := u.theme.brHairline
	if primary {
		fillBr = u.theme.brBlue
		ringBr = u.theme.brBlueHover
		if hovered {
			fillBr = u.theme.brBlueHover
		}
	} else if hovered {
		fillBr = u.theme.brHover
	}
	gpDrawGlassCard(g, r, u.s(10), fillBr, ringBr, borderW)
	gpDrawText(g, text, u.theme.gpFontSemi, u.theme.brTxtPrimary, u.theme.fmtCenterEllip, r)
}

func (u *winUI) drawToast(g uintptr, w, h int32, text string) {
	tw := u.s(268)
	th := u.s(30)
	r := winRect{(w - tw) / 2, h - th - u.s(12), (w + tw) / 2, h - u.s(12)}
	gpDrawGlassCard(g, r, u.s(15), u.theme.brToastBg, u.theme.brBlue, u.s(1))
	gpDrawText(g, text, u.theme.gpFontSmall, u.theme.brTxtPrimary, u.theme.fmtCenterEllip, r)
}

func (u *winUI) stateVisuals(st ControllerState) (dotBr, fillBr, ringBr, txtBr uintptr, label string) {
	switch st {
	case CtrlRunning:
		return u.theme.brGreen, u.theme.brGreenFill, u.theme.brGreen, u.theme.brGreen, "CONNECTED"
	case CtrlStarting:
		return u.theme.brAmber, u.theme.brAmberFill, u.theme.brAmber, u.theme.brAmber, "STARTING"
	case CtrlDegraded:
		return u.theme.brAmber, u.theme.brAmberFill, u.theme.brAmber, u.theme.brAmber, "DEGRADED"
	case CtrlStopping:
		return u.theme.brAmber, u.theme.brAmberFill, u.theme.brAmber, u.theme.brAmber, "STOPPING"
	case CtrlReauthing:
		return u.theme.brBlue, u.theme.brBlueFill, u.theme.brBlue, u.theme.brBlue, "RE-AUTH"
	default:
		return u.theme.brSlateRing, u.theme.brElevated, u.theme.brHairline, u.theme.brTxtMuted, "DISCONNECTED"
	}
}

func (u *winUI) powerButtonVisuals(st ControllerState, hovered bool) (glowBr, fillBr, ringBr uintptr) {
	switch st {
	case CtrlRunning:
		if hovered {
			return u.theme.brRedFill, u.theme.brRedFill, u.theme.brRed
		}
		return u.theme.brGreenGlow, u.theme.brGreenFill, u.theme.brGreen
	case CtrlStarting, CtrlDegraded, CtrlStopping:
		return u.theme.brAmberGlow, u.theme.brAmberFill, u.theme.brAmber
	case CtrlReauthing:
		return u.theme.brBlueFill, u.theme.brBlueFill, u.theme.brBlue
	default:
		if hovered {
			return u.theme.brGreenGlow, u.theme.brHover, u.theme.brGreen
		}
		return 0, u.theme.brElevated, u.theme.brSlateRing
	}
}

// drawIECPowerGlyph renders a razor-sharp anti-aliased open 280° IEC power arc + rounded top stem
// using pure GDI+ path fill (0 GpPen / 0 XMM floating-point register args).
func (u *winUI) drawIECPowerGlyph(g uintptr, cx, cy, rad, stroke int32) {
	if stroke < 2 {
		stroke = 2
	}
	innerRad := rad - stroke
	if innerRad < 2 {
		innerRad = 2
	}

	// Open 280° ring path: outer arc from -50° clockwise +280° to +230°, then inner arc back -280°.
	var path uintptr
	st, _, _ := procGdipCreatePath.Call(gpFillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if st == 0 && path != 0 {
		defer procGdipDeletePath.Call(path)
		_, _, _ = procGdipStartPathFigure.Call(path)
		_, _, _ = procGdipAddPathArcI.Call(
			path,
			uintptr(cx-rad), uintptr(cy-rad), uintptr(2*rad), uintptr(2*rad),
			uintptr(math.Float32bits(-50.0)),
			uintptr(math.Float32bits(280.0)),
		)
		_, _, _ = procGdipAddPathArcI.Call(
			path,
			uintptr(cx-innerRad), uintptr(cy-innerRad), uintptr(2*innerRad), uintptr(2*innerRad),
			uintptr(math.Float32bits(230.0)),
			uintptr(math.Float32bits(-280.0)),
		)
		_, _, _ = procGdipClosePathFigure.Call(path)
		_, _, _ = procGdipFillPath.Call(g, u.theme.brTxtPrimary, path)
	}

	// Centered rounded vertical power stem cleanly inside the top 80° opening.
	halfW := stroke / 2
	if halfW < 1 {
		halfW = 1
	}
	stemR := winRect{
		Left:   cx - halfW,
		Top:    cy - rad - u.s(3),
		Right:  cx - halfW + stroke,
		Bottom: cy + u.s(2),
	}
	gpFillRoundRect(g, stemR, halfW, u.theme.brTxtPrimary)
}

// -----------------------------------------------------------------------------
// Low-Level Zero-Leak GDI+ Vector & DWM Helpers (0 XMM Register Arguments)
// -----------------------------------------------------------------------------

func addRoundRectSubpath(path uintptr, r winRect, radius int32) {
	w := r.Right - r.Left
	h := r.Bottom - r.Top
	if w <= 0 || h <= 0 {
		return
	}
	maxR := w / 2
	if h/2 < maxR {
		maxR = h / 2
	}
	if radius > maxR {
		radius = maxR
	}
	if radius < 1 {
		radius = 1
	}
	d := radius * 2
	_, _, _ = procGdipStartPathFigure.Call(path)
	// Top-left, top-right, bottom-right, bottom-left 90° arcs (args 6 & 7 sit cleanly on Win64 stack!).
	_, _, _ = procGdipAddPathArcI.Call(path, uintptr(r.Left), uintptr(r.Top), uintptr(d), uintptr(d), uintptr(math.Float32bits(180)), uintptr(math.Float32bits(90)))
	_, _, _ = procGdipAddPathArcI.Call(path, uintptr(r.Right-d), uintptr(r.Top), uintptr(d), uintptr(d), uintptr(math.Float32bits(270)), uintptr(math.Float32bits(90)))
	_, _, _ = procGdipAddPathArcI.Call(path, uintptr(r.Right-d), uintptr(r.Bottom-d), uintptr(d), uintptr(d), uintptr(math.Float32bits(0)), uintptr(math.Float32bits(90)))
	_, _, _ = procGdipAddPathArcI.Call(path, uintptr(r.Left), uintptr(r.Bottom-d), uintptr(d), uintptr(d), uintptr(math.Float32bits(90)), uintptr(math.Float32bits(90)))
	_, _, _ = procGdipClosePathFigure.Call(path)
}

func gpFillRoundRect(g uintptr, r winRect, radius int32, fillBr uintptr) {
	if fillBr == 0 || r.Right <= r.Left || r.Bottom <= r.Top {
		return
	}
	var path uintptr
	st, _, _ := procGdipCreatePath.Call(gpFillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if st != 0 || path == 0 {
		return
	}
	defer procGdipDeletePath.Call(path)
	addRoundRectSubpath(path, r, radius)
	_, _, _ = procGdipFillPath.Call(g, fillBr, path)
}

// gpDrawGlassCard renders an anti-aliased frosted glass rounded rectangle plus an optional
// 1px translucent hairline border using Even-Odd path fill (zero double-blending in interior!).
func gpDrawGlassCard(g uintptr, r winRect, radius int32, fillBr, borderBr uintptr, borderPx int32) {
	if fillBr != 0 {
		gpFillRoundRect(g, r, radius, fillBr)
	}
	if borderBr == 0 || borderPx <= 0 {
		return
	}
	inner := winRect{r.Left + borderPx, r.Top + borderPx, r.Right - borderPx, r.Bottom - borderPx}
	if inner.Right <= inner.Left || inner.Bottom <= inner.Top {
		return
	}
	var ringPath uintptr
	st, _, _ := procGdipCreatePath.Call(gpFillModeAlternate, uintptr(unsafe.Pointer(&ringPath)))
	if st != 0 || ringPath == 0 {
		return
	}
	defer procGdipDeletePath.Call(ringPath)
	addRoundRectSubpath(ringPath, r, radius)
	innerR := radius - borderPx
	if innerR < 1 {
		innerR = 1
	}
	addRoundRectSubpath(ringPath, inner, innerR)
	_, _, _ = procGdipFillPath.Call(g, borderBr, ringPath)
}

// gpFillEllipseRing renders a razor-sharp anti-aliased circular ring via Even-Odd GpPath.
func gpFillEllipseRing(g uintptr, r winRect, thickness int32, brush uintptr) {
	if brush == 0 || thickness <= 0 {
		return
	}
	w := r.Right - r.Left
	h := r.Bottom - r.Top
	if w <= 2*thickness || h <= 2*thickness {
		return
	}
	var path uintptr
	st, _, _ := procGdipCreatePath.Call(gpFillModeAlternate, uintptr(unsafe.Pointer(&path)))
	if st != 0 || path == 0 {
		return
	}
	defer procGdipDeletePath.Call(path)
	_, _, _ = procGdipAddPathEllipseI.Call(path, uintptr(r.Left), uintptr(r.Top), uintptr(w), uintptr(h))
	_, _, _ = procGdipAddPathEllipseI.Call(path, uintptr(r.Left+thickness), uintptr(r.Top+thickness), uintptr(w-2*thickness), uintptr(h-2*thickness))
	_, _, _ = procGdipFillPath.Call(g, brush, path)
}

func gpDrawText(g uintptr, text string, font, brush, sf uintptr, r winRect) {
	if text == "" || font == 0 || brush == 0 || sf == 0 {
		return
	}
	u16, err := windows.UTF16FromString(text)
	if err != nil || len(u16) <= 1 {
		return
	}
	rf := gpRectF{
		X:      float32(r.Left),
		Y:      float32(r.Top),
		Width:  float32(r.Right - r.Left),
		Height: float32(r.Bottom - r.Top),
	}
	if rf.Width <= 0 || rf.Height <= 0 {
		return
	}
	_, _, _ = procGdipDrawString.Call(
		g,
		uintptr(unsafe.Pointer(&u16[0])),
		uintptr(len(u16)-1),
		font,
		uintptr(unsafe.Pointer(&rf)),
		sf,
		brush,
	)
	runtime.KeepAlive(u16)
	runtime.KeepAlive(&rf)
}

// applyDWMGlassBackdrop enables Win11 dark titlebar, rounded corners, and OS-native Acrylic/Mica glass
// with graceful fallback to opaque dark mode on older Windows 10 builds.
func applyDWMGlassBackdrop(hwnd uintptr) bool {
	if procDwmSetWindowAttribute.Find() != nil {
		return false
	}
	dark := int32(1)
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&dark)), unsafe.Sizeof(dark))
	runtime.KeepAlive(&dark)

	corner := int32(dwmWindowCornerRound)
	_, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaWindowCornerPreference, uintptr(unsafe.Pointer(&corner)), unsafe.Sizeof(corner))
	runtime.KeepAlive(&corner)

	// Prefer Acrylic (DWMSBT_TRANSIENTWINDOW=3) for Apple-style frosted glass; fall back to Mica (2).
	backdrop := int32(dwmsbtTransientWindow)
	hr, _, _ := procDwmSetWindowAttribute.Call(hwnd, dwmwaSystemBackdropType, uintptr(unsafe.Pointer(&backdrop)), unsafe.Sizeof(backdrop))
	runtime.KeepAlive(&backdrop)
	if hr != 0 {
		backdrop = int32(dwmsbtMainWindow)
		hr, _, _ = procDwmSetWindowAttribute.Call(hwnd, dwmwaSystemBackdropType, uintptr(unsafe.Pointer(&backdrop)), unsafe.Sizeof(backdrop))
		runtime.KeepAlive(&backdrop)
	}
	if hr == 0 && procDwmExtendFrameIntoClientArea.Find() == nil {
		margins := dwmMargins{CxLeftWidth: -1, CxRightWidth: -1, CyTopHeight: -1, CyBottomHeight: -1}
		hrExt, _, _ := procDwmExtendFrameIntoClientArea.Call(hwnd, uintptr(unsafe.Pointer(&margins)))
		runtime.KeepAlive(&margins)
		return hrExt == 0
	}
	return false
}

func queryWindowDPI(hwnd uintptr) uint32 {
	if procGetDpiForWindow.Find() == nil && hwnd != 0 {
		if d, _, _ := procGetDpiForWindow.Call(hwnd); d >= 72 && d <= 480 {
			return uint32(d)
		}
	}
	return 96
}

func registerWindowMessageW(name string) uint32 {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(ptr)))
	runtime.KeepAlive(ptr)
	return uint32(r)
}

func findWindowW(className string) uintptr {
	ptr, err := windows.UTF16PtrFromString(className)
	if err != nil {
		return 0
	}
	h, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(ptr)), 0)
	runtime.KeepAlive(ptr)
	return h
}

func copyUTF16Fixed(dst []uint16, s string) {
	if len(dst) == 0 {
		return
	}
	u16, err := windows.UTF16FromString(s)
	if err != nil {
		dst[0] = 0
		return
	}
	n := copy(dst[:len(dst)-1], u16)
	dst[n] = 0
}

// queryProcessGuiResources returns the current process's kernel GDI and USER handle counts via GetGuiResources.
func queryProcessGuiResources() (gdiCount uint32, userCount uint32) {
	hProc := uintptr(windows.CurrentProcess())
	g, _, _ := procGetGuiResources.Call(hProc, grGdiObjects)
	u, _, _ := procGetGuiResources.Call(hProc, grUserObjects)
	return uint32(g), uint32(u)
}

// isWindowStyleVisible reports whether hwnd currently has WS_VISIBLE set on its Win32 window style.
func isWindowStyleVisible(hwnd uintptr) bool {
	if hwnd == 0 {
		return false
	}
	style, _, _ := procGetWindowLongPtrW.Call(hwnd, gwlStyle)
	return (style & wsVisible) != 0
}

// verifyExitReLaunchAndClipboardInvariants exercises BUG-08 & BUG-09 Win32 paths deterministically
// (used by UT-49 without allocating visible windows or touching the interactive desktop clipboard).
func verifyExitReLaunchAndClipboardInvariants() error {
	// 1. Exiting winUI must ignore restoreFromTray() and wmAppShowExisting, and releaseMutex() must free hMutex.
	mName := fmt.Sprintf("Local\\NetShaperV7_UT49_%d", time.Now().UnixNano())
	mPtr, err := windows.UTF16PtrFromString(mName)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}
	h1, mErr := windows.CreateMutex(nil, false, mPtr)
	if mErr != nil || h1 == 0 {
		return fmt.Errorf("CreateMutex #1 failed: h=%v err=%v", h1, mErr)
	}
	u := &winUI{
		exiting: true,
		hwnd:    0x1000,
		hMutex:  h1,
	}
	u.restoreFromTray()
	if u.visible || u.timerArmed {
		u.releaseMutex()
		return fmt.Errorf("restoreFromTray mutated exiting winUI (visible=%v timer=%v)", u.visible, u.timerArmed)
	}
	u.handleMessage(0x1000, wmAppShowExisting, 0, 0)
	if u.visible || u.timerArmed {
		u.releaseMutex()
		return fmt.Errorf("wmAppShowExisting mutated exiting winUI (visible=%v timer=%v)", u.visible, u.timerArmed)
	}
	u.releaseMutex()
	if u.hMutex != 0 {
		return fmt.Errorf("releaseMutex did not clear hMutex")
	}
	h2, mErr2 := windows.CreateMutex(nil, false, mPtr)
	if h2 != 0 {
		_ = windows.CloseHandle(h2)
	}
	if errors.Is(mErr2, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("mutex still held after releaseMutex(): %v", mErr2)
	}

	// 2. Clipboard success path: passes real hwnd, closes clipboard, does NOT GlobalFree transferred hMem.
	var gotHwnd uintptr
	var freedCount, closedCount int
	const wantHwnd uintptr = 0x2468
	const fakeMem uintptr = 0x9001
	okOps := clipboardOps{
		open:   func(hw uintptr) (uintptr, error) { gotHwnd = hw; return 1, nil },
		empty:  func() (uintptr, error) { return 1, nil },
		alloc:  func(flags, bytes uintptr) (uintptr, error) { return fakeMem, nil },
		lock:   func(hm uintptr) (uintptr, error) { return 0x7000, nil },
		copy:   func(dst uintptr, src *uint16, bytes uintptr) {},
		unlock: func(hm uintptr) {},
		set:    func(format, hm uintptr) (uintptr, error) { return hm, nil },
		free:   func(hm uintptr) { freedCount++ },
		close:  func() { closedCount++ },
	}
	if err := copyTextToClipboardWithOps(wantHwnd, "127.0.0.1:1080", okOps); err != nil {
		return fmt.Errorf("clipboard success path errored: %w", err)
	}
	if gotHwnd != wantHwnd || closedCount != 1 || freedCount != 0 {
		return fmt.Errorf("clipboard success invariants violated: hwnd=0x%x closed=%d freed=%d", gotHwnd, closedCount, freedCount)
	}

	// 3. Clipboard SetClipboardData failure path: MUST call GlobalFree(hMem) (0 leak) and CloseClipboard().
	gotHwnd = 0
	freedCount = 0
	closedCount = 0
	var freedHandle uintptr
	failOps := okOps
	failOps.open = func(hw uintptr) (uintptr, error) { gotHwnd = hw; return 1, nil }
	failOps.set = func(format, hm uintptr) (uintptr, error) { return 0, errors.New("clipboard ownership denied") }
	failOps.free = func(hm uintptr) { freedCount++; freedHandle = hm }
	failOps.close = func() { closedCount++ }
	if err := copyTextToClipboardWithOps(wantHwnd, "127.0.0.1:1080", failOps); err == nil {
		return fmt.Errorf("clipboard failure path unexpectedly returned nil error")
	}
	if gotHwnd != wantHwnd || closedCount != 1 || freedCount != 1 || freedHandle != fakeMem {
		return fmt.Errorf("clipboard failure invariants violated: hwnd=0x%x closed=%d freed=%d handle=0x%x",
			gotHwnd, closedCount, freedCount, freedHandle)
	}
	return nil
}

