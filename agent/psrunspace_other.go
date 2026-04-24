//go:build !windows

package main

import "fmt"

func psRunspace(psScript, bridgePath string) (string, error) {
	return "", fmt.Errorf("psRunspace is Windows-only")
}
