//go:build !windows

package exec

import "fmt"

func PsRunspace(psScript, bridgePath string) (string, error) {
	return "", fmt.Errorf("PsRunspace is Windows-only")
}
