//go:build !windows

package evasion

func IsVM() bool          { return false }
func AntiVMReport() string { return "n/a (non-Windows)" }
