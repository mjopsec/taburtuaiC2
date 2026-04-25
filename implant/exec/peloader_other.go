//go:build !windows

package exec

import "fmt"

func PeLoad(rawPE []byte) (uintptr, error) {
	return 0, fmt.Errorf("PeLoad is Windows-only")
}
