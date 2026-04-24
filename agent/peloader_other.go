//go:build !windows

package main

import "fmt"

func peLoad(rawPE []byte) (uintptr, error) {
	return 0, fmt.Errorf("peLoad is Windows-only")
}
