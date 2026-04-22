//go:build !windows

package main

import "fmt"

func patchAMSI() error              { return fmt.Errorf("AMSI bypass is Windows-only") }
func patchAMSIRemote(_ uint32) error { return fmt.Errorf("AMSI bypass is Windows-only") }
func patchETW() error               { return fmt.Errorf("ETW bypass is Windows-only") }
func patchETWRemote(_ uint32) error  { return fmt.Errorf("ETW bypass is Windows-only") }
