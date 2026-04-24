//go:build !windows

package main

import "fmt"

func hollowShellcode(exe string, shellcode []byte) error {
	return fmt.Errorf("process hollowing is Windows-only")
}

func HollowProcess(exe string, payload []byte) error {
	return fmt.Errorf("process hollowing is Windows-only")
}
