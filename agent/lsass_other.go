//go:build !windows

package main

import "fmt"

func dumpLSASS(outPath string) error {
	return fmt.Errorf("LSASS dump is Windows-only")
}

func findProcessByName(name string) (uint32, error) {
	return 0, fmt.Errorf("findProcessByName is Windows-only")
}
