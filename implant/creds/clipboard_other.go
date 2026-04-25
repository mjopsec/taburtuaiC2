//go:build !windows

package creds

import "fmt"

func ReadClipboard() (string, error) {
	return "", fmt.Errorf("clipboard read is Windows-only")
}
