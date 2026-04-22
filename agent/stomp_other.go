//go:build !windows

package main

import "fmt"

func stompModule(sacrificialDLL string, shellcode []byte) error {
	return fmt.Errorf("module stomping is Windows-only")
}
