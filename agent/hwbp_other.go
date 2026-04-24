//go:build !windows

package main

import "fmt"

type HWBPSlot uint8

const (
	HWBP_DR0 HWBPSlot = 0
	HWBP_DR1 HWBPSlot = 1
	HWBP_DR2 HWBPSlot = 2
	HWBP_DR3 HWBPSlot = 3
)

func SetHWBP(slot HWBPSlot, addr uintptr, handler func(uintptr)) error {
	return fmt.Errorf("hardware breakpoints are Windows-only")
}

func ClearHWBP(slot HWBPSlot) error {
	return fmt.Errorf("hardware breakpoints are Windows-only")
}

func bypassAMSIHWBP() error {
	return fmt.Errorf("HWBP AMSI bypass is Windows-only")
}

func bypassETWHWBP() error {
	return fmt.Errorf("HWBP ETW bypass is Windows-only")
}

func hwbpClearAll() {}

func hwbpSetManual(drIdx int, addr uintptr) error {
	return fmt.Errorf("hwbpSetManual is Windows-only")
}
