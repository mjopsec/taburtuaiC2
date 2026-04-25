//go:build !windows

package creds

import "fmt"

func DumpSAM(_ string) (string, error) {
	return "", fmt.Errorf("SAM dump is Windows-only")
}
