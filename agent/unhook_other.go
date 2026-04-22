//go:build !windows

package main

import "fmt"

func unhookNTDLL() error {
	return fmt.Errorf("NTDLL unhooking is Windows-only")
}
