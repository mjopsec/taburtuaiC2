//go:build !windows

package main

import "fmt"

func mapInjectLocal(shellcode []byte) error {
	return fmt.Errorf("mapping injection is Windows-only")
}

func mapInjectRemote(pid uint32, shellcode []byte) error {
	return fmt.Errorf("mapping injection is Windows-only")
}
