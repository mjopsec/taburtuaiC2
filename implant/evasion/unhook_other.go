//go:build !windows

package evasion

import "fmt"

func UnhookNTDLL() error { return fmt.Errorf("NTDLL unhooking is Windows-only") }
