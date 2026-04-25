//go:build !windows

package inject

import "fmt"

func ThreadlessInject(_ uint32, _, _ string, _ []byte) error {
	return fmt.Errorf("threadless injection is Windows-only")
}
