//go:build windows

package main

import "golang.org/x/sys/windows"

// preinitConsole pre-warms the Windows console I/O subsystem without
// producing a visible window.
//
// AllocConsole + FreeConsole was the original approach but AllocConsole
// briefly allocates a real console window (visible for ~1 frame) before
// FreeConsole tears it down.
//
// AttachConsole(-1) (ATTACH_PARENT_PROCESS) silently fails when there is no
// parent console (which is always the case for a windowsgui binary launched
// by Explorer or a stager), exercising the same kernel init path with zero
// visible side-effects.
func preinitConsole() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	attachConsole := kernel32.NewProc("AttachConsole")
	// 0xFFFFFFFF == ATTACH_PARENT_PROCESS; returns false when no parent console
	// exists — the error is intentional and expected.
	attachConsole.Call(uintptr(0xFFFFFFFF))
}
