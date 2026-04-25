//go:build !windows

package inject

import "fmt"

func HollowProcess(_ string, _ []byte) error {
	return fmt.Errorf("process hollowing is only supported on Windows")
}
