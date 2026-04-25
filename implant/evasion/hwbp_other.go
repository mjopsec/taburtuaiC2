//go:build !windows

package evasion

import "fmt"

type HWBPSlot int

func SetHWBP(_ HWBPSlot, _ uintptr, _ func(uintptr)) error {
	return fmt.Errorf("hardware breakpoints are Windows-only")
}
func ClearHWBP(_ HWBPSlot) error   { return fmt.Errorf("hardware breakpoints are Windows-only") }
func BypassAMSIHWBP() error        { return fmt.Errorf("HWBP AMSI bypass is Windows-only") }
func BypassETWHWBP() error         { return fmt.Errorf("HWBP ETW bypass is Windows-only") }
func hwbpClearAll()                {}
