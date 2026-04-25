//go:build !windows

package exec

import "time"

func MaskedSleep(duration time.Duration, _ []byte) {
	time.Sleep(duration)
}
