//go:build !windows

package exec

import "fmt"

func enablePrivilege(name string) error {
	return fmt.Errorf("enablePrivilege is Windows-only")
}
