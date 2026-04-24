//go:build !windows || !amd64

package main

import "time"

// spoofedSleep falls back to plain sleep on non-amd64 or non-Windows platforms.
// Stack spoofing is only implemented for the windows/amd64 target.
func spoofedSleep(d time.Duration) {
	time.Sleep(d)
}
