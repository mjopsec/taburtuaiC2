//go:build !windows

package main

import "fmt"

func threadlessInject(pid uint32, dllName, exportName string, shellcode []byte) error {
	return fmt.Errorf("threadlessInject is Windows-only")
}
