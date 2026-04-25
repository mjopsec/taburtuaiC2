//go:build windows

package exec

import (
	"time"

	"golang.org/x/sys/windows"
)

var (
	kernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procSleepEx = kernel32.NewProc("SleepEx")
)

// MaskedSleep sleeps using SleepEx (alertable, APC-compatible).
func MaskedSleep(duration time.Duration, _ []byte) {
	ms := uint32(duration.Milliseconds())
	if ms == 0 {
		ms = 1
	}
	procSleepEx.Call(uintptr(ms), 1)
}
