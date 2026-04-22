//go:build !windows

package main

import "fmt"

func injectShellcode(targetPID uint32, shellcode []byte, method string) error {
	return fmt.Errorf("process injection is only supported on Windows")
}

func execShellcodeSelf(shellcode []byte) error {
	return fmt.Errorf("in-memory shellcode execution is only supported on Windows")
}
