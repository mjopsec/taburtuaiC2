//go:build !windows || !amd64

package winsyscall

import "time"

// SpoofedSleep falls back to plain sleep on non-amd64 or non-Windows platforms.
func SpoofedSleep(d time.Duration) {
	time.Sleep(d)
}
