//go:build !windows

package evasion

import "fmt"

func PatchAMSI() error              { return fmt.Errorf("AMSI bypass is Windows-only") }
func PatchAMSIRemote(_ uint32) error { return fmt.Errorf("AMSI bypass is Windows-only") }
func PatchETW() error               { return fmt.Errorf("ETW bypass is Windows-only") }
func PatchETWRemote(_ uint32) error  { return fmt.Errorf("ETW bypass is Windows-only") }
