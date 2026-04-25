//go:build !windows

package inject

import "fmt"

func HijackThread(_ uint32, _ []byte) error {
	return fmt.Errorf("thread hijacking is not supported on this platform")
}
