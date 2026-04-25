//go:build !windows

package winsyscall

import "time"

func SleepObf(d time.Duration) {
	time.Sleep(d)
}
