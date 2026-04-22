//go:build !windows

package main

import "fmt"

// RegRead returns an error on non-Windows platforms.
func RegRead(hive, key, value string) (string, error) {
	return "", fmt.Errorf("registry operations are Windows-only")
}

// RegWrite returns an error on non-Windows platforms.
func RegWrite(hive, key, value, data, kind string) error {
	return fmt.Errorf("registry operations are Windows-only")
}

// RegDelete returns an error on non-Windows platforms.
func RegDelete(hive, key, value string) error {
	return fmt.Errorf("registry operations are Windows-only")
}

// RegList returns an error on non-Windows platforms.
func RegList(hive, key string) ([]string, error) {
	return nil, fmt.Errorf("registry operations are Windows-only")
}
