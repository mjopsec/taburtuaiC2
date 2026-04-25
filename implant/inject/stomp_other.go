//go:build !windows

package inject

import "fmt"

func StompModule(_ string, _ []byte) error {
	return fmt.Errorf("module stomping is Windows-only")
}
