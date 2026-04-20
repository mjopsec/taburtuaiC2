//go:build !windows

package main

import "time"

// maskedSleep on non-Windows platforms falls back to a plain time.Sleep.
// The sensitiveData argument is accepted for API compatibility but unused.
func maskedSleep(duration time.Duration, _ []byte) {
	time.Sleep(duration)
}
