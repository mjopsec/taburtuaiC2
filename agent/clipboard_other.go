//go:build !windows

package main

import "fmt"

func readClipboard() (string, error) {
	return "", fmt.Errorf("clipboard read is Windows-only")
}
