//go:build !windows

package main

import (
	"fmt"
)

func dumpLSASS(outPath string) error {
	return fmt.Errorf("LSASS dump is Windows-only")
}

func findProcessByName(name string) (uint32, error) {
	return 0, fmt.Errorf("findProcessByName is Windows-only")
}

func lsassDumpViaDup(outPath string) (string, error) {
	return "", fmt.Errorf("lsassDumpViaDup is Windows-only")
}

func lsassDumpViaWER(outPath string) (string, error) {
	return "", fmt.Errorf("lsassDumpViaWER is Windows-only")
}
