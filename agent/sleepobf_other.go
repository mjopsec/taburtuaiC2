//go:build !windows

package main

import "time"

func sleepObf(d time.Duration) {
	time.Sleep(d)
}
