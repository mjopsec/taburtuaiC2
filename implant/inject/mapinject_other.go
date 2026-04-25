//go:build !windows

package inject

import "fmt"

func MapInjectLocal(_ []byte) error {
	return fmt.Errorf("mapping injection is Windows-only")
}

func MapInjectRemote(_ uint32, _ []byte) error {
	return fmt.Errorf("mapping injection is Windows-only")
}
