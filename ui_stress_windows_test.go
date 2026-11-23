//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// UT-40 (v7.0): Real Windows 11 Win32 + GDI+ Apple-Glass handle-leak, DPI, tray,
// TaskbarCreated, Account-tab EDIT visibility, Terminal H-scroll, and [X] full-exit soak test.
func TestUT40_Win32GDIPlusHandleLeakAndHScrollSoak(t *testing.T) {
	if err := verifyWin32ABISizes(); err != nil {
		t.Fatalf("UT-40 verifyWin32ABISizes failed: %v", err)
	}

	// Pin goroutine strictly to one OS thread for Win32 HWND + GDI+ thread affinity.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var gpToken uintptr
	gpIn := gdiplusStartupInput{GdiplusVersion: 1}
	gpSt, _, _ := procGdiplusStartup.Call(uintptr(unsafe.Pointer(&gpToken)), uintptr(unsafe.Pointer(&gpIn)), 0)
	runtime.KeepAlive(&gpIn)
	if gpSt != 0 {
		t.Fatalf("UT-40 GdiplusStartup failed with status %d", gpSt)
	}
	defer func() {
		_, _, _ = procGdiplusShutdown.Call(gpToken)
	}()

	hInst, _, _ := procGetModuleHandleW.Call(0)
	cursor, _, _ := procLoadCursorW.Call(0, idcArrow)

	drainThreadMsgs := func() {
		var msg winMsg
		for i := 0; i < 2048; i++ {
			r, _, _ := procPeekMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, pmRemove)
			if r == 0 {
				break
			}
		}
	}

	createTestWindow := func(className string, dir string) (*winUI, uintptr, *uint16) {
		cfg := DefaultConfig()
		cfg.LocalPort = 0
		cfg.StopTimeout = 1 * time.Second

		ctrl := NewSessionController(cfg, ControllerDeps{
			UIConfigPath:     filepath.Join(dir, "netshaper_ui.json"),
			CachePath:        filepath.Join(dir, "codespace_state_cache.json"),
			SnapshotInterval: 250 * time.Millisecond,
			ReadLocalHostsFn: func() string { return "" },
		})
		ctrl.Start()

		ui := &winUI{
			cfg:              cfg,
			ctrl:             ctrl,
			hInstance:        hInst,
			visible:          true,
			activeTab:        tabHome,
			lastEditEditable: true,
			logScratch:       make([]TerminalLine, 0, TerminalRingCapacity),
			wmTaskbarCreated: registerWindowMessageW("TaskbarCreated"),
		}
		activeWinUI = ui

		clsPtr, err := windows.UTF16PtrFromString(className)
		if err != nil {
			ctrl.ShutdownAndWait(2 * time.Second)
			t.Fatalf("UT-40 UTF16PtrFromString(%q): %v", className, err)
		}
		titlePtr, err := windows.UTF16PtrFromString("NetShaper v7.0 Stress Test")
		if err != nil {
			ctrl.ShutdownAndWait(2 * time.Second)
			t.Fatalf("UT-40 UTF16PtrFromString(title): %v", err)
		}

		wc := wndClassExW{
			CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			Style:         csHRedraw | csVRedraw,
			LpfnWndProc:   globalWndProcCB,
			HInstance:     hInst,
			HCursor:       cursor,
			LpszClassName: clsPtr,
		}
		atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		runtime.KeepAlive(&wc)
		if atom == 0 {
			ctrl.ShutdownAndWait(2 * time.Second)
			t.Fatalf("UT-40 RegisterClassExW(%q) failed: %v", className, regErr)
		}

		style := uint32(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsClipChildren)
		adj := winRect{Left: 0, Top: 0, Right: uiBaseWidth, Bottom: uiBaseHeight}
		_, _, _ = procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&adj)), uintptr(style), 0, 0)
		winW := adj.Right - adj.Left
		winH := adj.Bottom - adj.Top

		// Position far off-screen so 100 tray restore cycles never flash on the interactive desktop.
		hwnd, _, createErr := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(clsPtr)),
			uintptr(unsafe.Pointer(titlePtr)),
			uintptr(style),
			20000,
			20000,
			uintptr(winW),
			uintptr(winH),
			0,
			0,
			hInst,
			0,
		)
		runtime.KeepAlive(titlePtr)
		if hwnd == 0 {
			_, _, _ = procUnregisterClassW.Call(uintptr(unsafe.Pointer(clsPtr)), hInst)
			runtime.KeepAlive(clsPtr)
			ctrl.ShutdownAndWait(2 * time.Second)
			t.Fatalf("UT-40 CreateWindowExW failed: %v", createErr)
		}
		return ui, hwnd, clsPtr
	}

	prevUI := activeWinUI
	defer func() {
		activeWinUI = prevUI
	}()

	// 1. Complete warm-up cycle covering all test DPIs (96/120/144/192), all 3 tabs (including
	//    Terminal monospace rasterization), tray hide/restore, and TaskbarCreated so one-time
	//    process-wide GDI+ internal font-cache handles stabilize before measuring soak deltas.
	dpis := []uint32{144, 192, 120, 96}
	warmDir := t.TempDir()
	warmUI, warmHwnd, warmCls := createTestWindow("NetShaperV7UT40WarmWnd", warmDir)
	for i := 0; i < 8; i++ {
		warmUI.ctrl.Logs().Append(LogInfo, fmt.Sprintf("[UT40-Warm-%02d] %s", i, strings.Repeat("W", 120)))
	}
	for _, dpi := range dpis {
		wParam := uintptr(dpi) | (uintptr(dpi) << 16)
		warmUI.handleMessage(warmHwnd, wmDpiChanged, wParam, 0)
		for _, tab := range []uiTab{tabHome, tabTerminal, tabAccount} {
			warmUI.activeTab = tab
			warmUI.syncEditControlBounds()
			_, _, _ = procInvalidateRect.Call(warmHwnd, 0, 0)
			warmUI.handleMessage(warmHwnd, wmPaint, 0, 0)
		}
	}
	warmUI.hideToTray()
	warmUI.restoreFromTray()
	_, _, _ = procInvalidateRect.Call(warmHwnd, 0, 0)
	warmUI.handleMessage(warmHwnd, wmPaint, 0, 0)
	if warmUI.wmTaskbarCreated != 0 {
		warmUI.handleMessage(warmHwnd, warmUI.wmTaskbarCreated, 0, 0)
	}
	warmUI.handleMessage(warmHwnd, wmClose, 0, 0)
	drainThreadMsgs()
	_, _, _ = procUnregisterClassW.Call(uintptr(unsafe.Pointer(warmCls)), hInst)
	runtime.KeepAlive(warmCls)

	// Record exact kernel GDI & USER object counts before the full soak.
	gdiBefore, userBefore := queryProcessGuiResources()

	// 2. Main soak window.
	soakDir := t.TempDir()
	ui, hwnd, soakCls := createTestWindow("NetShaperV7UT40SoakWnd", soakDir)
	defer func() {
		if ui.hwnd != 0 {
			ui.handleMessage(ui.hwnd, wmClose, 0, 0)
			drainThreadMsgs()
		}
		if soakCls != nil {
			_, _, _ = procUnregisterClassW.Call(uintptr(unsafe.Pointer(soakCls)), hInst)
			runtime.KeepAlive(soakCls)
		}
	}()

	if ui.hwndEdit == 0 {
		t.Fatalf("UT-40 child Codespace EDIT control was not created")
	}

	// Seed 500 wide lines (>220 chars) into TerminalRingBuffer so horizontal scrolling overflows viewport.
	longSuffix := strings.Repeat("abcdefghij0123456789", 11)
	for i := 0; i < TerminalRingCapacity; i++ {
		ui.ctrl.Logs().Append(LogInfo, fmt.Sprintf("[UT40-Line-%03d] %s", i, longSuffix))
	}

	// Verify Account-tab-only visibility of native child EDIT control.
	ui.activeTab = tabHome
	ui.syncEditControlBounds()
	if isWindowStyleVisible(ui.hwndEdit) {
		t.Fatalf("UT-40 Codespace EDIT control must be hidden on Home tab")
	}
	ui.activeTab = tabTerminal
	ui.syncEditControlBounds()
	if isWindowStyleVisible(ui.hwndEdit) {
		t.Fatalf("UT-40 Codespace EDIT control must be hidden on Terminal tab")
	}
	ui.activeTab = tabAccount
	ui.syncEditControlBounds()
	if !isWindowStyleVisible(ui.hwndEdit) {
		t.Fatalf("UT-40 Codespace EDIT control must be visible on Account tab")
	}

	// 3. Execute 10,000 full GDI+ Apple-Glass WM_PAINT frames across Home, Terminal, and Account tabs.
	tabs := []uiTab{tabHome, tabTerminal, tabAccount}
	for frame := 0; frame < 10000; frame++ {
		if frame%333 == 0 {
			ui.activeTab = tabs[(frame/333)%len(tabs)]
			ui.syncEditControlBounds()
		}
		_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		ui.handleMessage(hwnd, wmPaint, 0, 0)
	}

	// 4. Exercise Terminal horizontal scrolling (WM_MOUSEHWHEEL, Shift+WM_MOUSEWHEEL, VK_LEFT/RIGHT/END/HOME).
	ui.activeTab = tabTerminal
	ui.syncEditControlBounds()
	_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
	ui.handleMessage(hwnd, wmPaint, 0, 0)
	if ui.termMaxScrollX <= 0 {
		t.Fatalf("UT-40 expected Terminal termMaxScrollX > 0 for 220-char lines, got %d", ui.termMaxScrollX)
	}

	ui.termScrollX = 0
	// WM_MOUSEHWHEEL right (+120)
	ui.handleMessage(hwnd, wmMouseHWheel, uintptr(uint32(120)<<16), 0)
	afterHWheel := ui.termScrollX
	if afterHWheel <= 0 {
		t.Fatalf("UT-40 WM_MOUSEHWHEEL right did not advance termScrollX (got %d)", afterHWheel)
	}
	// Shift + WM_MOUSEWHEEL down (-120 -> scroll right)
	neg120 := uint16(0xFF88) // int16(-120)
	ui.handleMessage(hwnd, wmMouseWheel, uintptr(uint32(neg120)<<16|mkShift), 0)
	if ui.termScrollX <= afterHWheel && afterHWheel < ui.termMaxScrollX {
		t.Fatalf("UT-40 Shift+WM_MOUSEWHEEL did not advance termScrollX: before=%d after=%d max=%d",
			afterHWheel, ui.termScrollX, ui.termMaxScrollX)
	}
	// VK_END -> max right
	ui.handleMessage(hwnd, wmKeyDown, vkEnd, 0)
	if ui.termScrollX != ui.termMaxScrollX {
		t.Fatalf("UT-40 VK_END expected termScrollX=%d, got %d", ui.termMaxScrollX, ui.termScrollX)
	}
	// VK_LEFT -> scroll left
	ui.handleMessage(hwnd, wmKeyDown, vkLeft, 0)
	if ui.termScrollX >= ui.termMaxScrollX {
		t.Fatalf("UT-40 VK_LEFT did not decrement termScrollX (got %d, max=%d)", ui.termScrollX, ui.termMaxScrollX)
	}
	leftPos := ui.termScrollX
	// VK_RIGHT -> scroll right
	ui.handleMessage(hwnd, wmKeyDown, vkRight, 0)
	if ui.termScrollX <= leftPos {
		t.Fatalf("UT-40 VK_RIGHT did not increment termScrollX (before=%d after=%d)", leftPos, ui.termScrollX)
	}
	// VK_HOME -> reset to 0
	ui.handleMessage(hwnd, wmKeyDown, vkHome, 0)
	if ui.termScrollX != 0 {
		t.Fatalf("UT-40 VK_HOME expected termScrollX=0, got %d", ui.termScrollX)
	}

	// 5. Execute 500 WM_DPICHANGED cycles (96 -> 144 -> 192 -> 120 -> 96) with font + DIB rebuilds.
	for i := 0; i < 500; i++ {
		dpi := dpis[i%len(dpis)]
		wParam := uintptr(dpi) | (uintptr(dpi) << 16)
		ui.handleMessage(hwnd, wmDpiChanged, wParam, 0)
		if i%5 == 0 {
			_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
			ui.handleMessage(hwnd, wmPaint, 0, 0)
		}
	}

	// 6. Execute 100 hideToTray / restoreFromTray cycles verifying backbuffer release & recreation.
	for i := 0; i < 100; i++ {
		ui.hideToTray()
		if ui.theme.memBmp != 0 || ui.timerArmed || ui.visible {
			t.Fatalf("UT-40 hideToTray #%d did not release backbuffer/timer (memBmp=%d timer=%v vis=%v)",
				i, ui.theme.memBmp, ui.timerArmed, ui.visible)
		}
		ui.restoreFromTray()
		if !ui.timerArmed || !ui.visible {
			t.Fatalf("UT-40 restoreFromTray #%d did not re-arm timer/visibility", i)
		}
		_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
		ui.handleMessage(hwnd, wmPaint, 0, 0)
		if ui.theme.memBmp == 0 {
			t.Fatalf("UT-40 restoreFromTray #%d did not recreate DIB backbuffer on paint", i)
		}
	}

	// 6b. Verify native [_] minimize button (WM_SYSCOMMAND -> SC_MINIMIZE) hides cleanly to tray without exiting.
	ui.handleMessage(hwnd, wmSysCommand, scMinimize, 0)
	if ui.exiting || ui.visible || ui.timerArmed || ui.theme.memBmp != 0 {
		t.Fatalf("UT-40 wmSysCommand(scMinimize) did not hide cleanly to tray: exiting=%v vis=%v timer=%v memBmp=%d",
			ui.exiting, ui.visible, ui.timerArmed, ui.theme.memBmp)
	}
	ui.restoreFromTray()
	_, _, _ = procInvalidateRect.Call(hwnd, 0, 0)
	ui.handleMessage(hwnd, wmPaint, 0, 0)

	// 7. Execute 10 Explorer TaskbarCreated broadcasts verifying tray icon recovery without handle leaks.
	if ui.wmTaskbarCreated != 0 {
		for i := 0; i < 10; i++ {
			ui.handleMessage(hwnd, ui.wmTaskbarCreated, 0, 0)
			if !ui.trayAdded {
				t.Fatalf("UT-40 TaskbarCreated #%d failed to re-add tray icon", i)
			}
		}
	}

	// 8. Verify clicking [X] (wmClose) executes full exit + DestroyWindow + 100% resource cleanup.
	ui.handleMessage(hwnd, wmClose, 0, 0)
	drainThreadMsgs()
	if !ui.exiting || ui.hwnd != 0 || ui.hwndEdit != 0 || ui.trayAdded || ui.theme.memDC != 0 || ui.theme.memBmp != 0 {
		t.Fatalf("UT-40 wmClose did not perform complete teardown: exiting=%v hwnd=%d edit=%d tray=%v memDC=%d memBmp=%d",
			ui.exiting, ui.hwnd, ui.hwndEdit, ui.trayAdded, ui.theme.memDC, ui.theme.memBmp)
	}
	_, _, _ = procUnregisterClassW.Call(uintptr(unsafe.Pointer(soakCls)), hInst)
	runtime.KeepAlive(soakCls)
	soakCls = nil // avoid duplicate unregister in defer

	gdiAfterCycle1, userAfterCycle1 := queryProcessGuiResources()
	if gdiAfterCycle1 != gdiBefore {
		t.Fatalf("UT-40 Cycle 1 GDI handle leak after 10,000 GDI+ frames / 500 DPI / 100 tray cycles: before=%d after=%d (delta=%+d)",
			gdiBefore, gdiAfterCycle1, int64(gdiAfterCycle1)-int64(gdiBefore))
	}
	if userAfterCycle1 != userBefore {
		t.Fatalf("UT-40 Cycle 1 USER handle leak after 10,000 GDI+ frames / 500 DPI / 100 tray cycles: before=%d after=%d (delta=%+d)",
			userBefore, userAfterCycle1, int64(userAfterCycle1)-int64(userBefore))
	}

	// 9. Second full create/paint/DPI/tray/close soak cycle proving exact zero drift across repeated lifecycles.
	cycle2Dir := t.TempDir()
	ui2, hwnd2, cls2 := createTestWindow("NetShaperV7UT40Cycle2Wnd", cycle2Dir)
	for i := 0; i < 64; i++ {
		ui2.ctrl.Logs().Append(LogInfo, fmt.Sprintf("[UT40-C2-%02d] %s", i, longSuffix))
	}
	for frame := 0; frame < 2000; frame++ {
		if frame%200 == 0 {
			ui2.activeTab = tabs[(frame/200)%len(tabs)]
			ui2.syncEditControlBounds()
		}
		_, _, _ = procInvalidateRect.Call(hwnd2, 0, 0)
		ui2.handleMessage(hwnd2, wmPaint, 0, 0)
	}
	for i := 0; i < 100; i++ {
		dpi := dpis[i%len(dpis)]
		ui2.handleMessage(hwnd2, wmDpiChanged, uintptr(dpi)|(uintptr(dpi)<<16), 0)
		if i%5 == 0 {
			_, _, _ = procInvalidateRect.Call(hwnd2, 0, 0)
			ui2.handleMessage(hwnd2, wmPaint, 0, 0)
		}
	}
	for i := 0; i < 20; i++ {
		ui2.hideToTray()
		ui2.restoreFromTray()
		_, _, _ = procInvalidateRect.Call(hwnd2, 0, 0)
		ui2.handleMessage(hwnd2, wmPaint, 0, 0)
	}
	if ui2.wmTaskbarCreated != 0 {
		for i := 0; i < 5; i++ {
			ui2.handleMessage(hwnd2, ui2.wmTaskbarCreated, 0, 0)
		}
	}
	ui2.handleMessage(hwnd2, wmClose, 0, 0)
	drainThreadMsgs()
	_, _, _ = procUnregisterClassW.Call(uintptr(unsafe.Pointer(cls2)), hInst)
	runtime.KeepAlive(cls2)

	// 10. Exact kernel handle count audit: 0 GDI handle leaks and 0 USER handle leaks across both cycles.
	gdiAfterCycle2, userAfterCycle2 := queryProcessGuiResources()
	if gdiAfterCycle2 != gdiAfterCycle1 || gdiAfterCycle2 != gdiBefore {
		t.Fatalf("UT-40 Cycle 2 GDI handle drift detected: before=%d afterCycle1=%d afterCycle2=%d (delta=%+d)",
			gdiBefore, gdiAfterCycle1, gdiAfterCycle2, int64(gdiAfterCycle2)-int64(gdiBefore))
	}
	if userAfterCycle2 != userAfterCycle1 || userAfterCycle2 != userBefore {
		t.Fatalf("UT-40 Cycle 2 USER handle drift detected: before=%d afterCycle1=%d afterCycle2=%d (delta=%+d)",
			userBefore, userAfterCycle1, userAfterCycle2, int64(userAfterCycle2)-int64(userBefore))
	}

	t.Logf("UT-40 PASS: 12,000 GDI+ frames + 600 DPI + 120 tray + 15 TaskbarCreated + scMinimize + H-scroll + 2x [X] exit -> GDI delta=0 (%d), USER delta=0 (%d)",
		gdiAfterCycle2, userAfterCycle2)
}
