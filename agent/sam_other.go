//go:build !windows

package main

import "fmt"

func dumpSAM(outDir string) (string, error) {
	return "", fmt.Errorf("SAM dump is Windows-only")
}
