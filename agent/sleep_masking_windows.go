//go:build windows

package main

import (
	"time"

	"golang.org/x/sys/windows"
)

var (
	kernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procSleepEx = kernel32.NewProc("SleepEx")
)

// maskedSleep sleeps for the given duration using SleepEx (alertable, APC-compatible).
//
// NOTE: VirtualProtect on Go-heap slices is unsafe — the Go GC scans all heap
// memory concurrently and touching PAGE_NOACCESS bytes causes an access violation
// that kills the process. We therefore keep only the alertable-sleep benefit
// (SleepEx) and skip the page-protection step. If true memory hiding is needed,
// the sensitive data must be allocated via VirtualAlloc (outside the GC heap).
func maskedSleep(duration time.Duration, _ []byte) {
	ms := uint32(duration.Milliseconds())
	if ms == 0 {
		ms = 1
	}
	// SleepEx(dwMilliseconds, bAlertable=TRUE)
	procSleepEx.Call(uintptr(ms), 1)
}
