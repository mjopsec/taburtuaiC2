//go:build !windows

package main

func IsVM() bool          { return false }
func AntiVMReport() string { return "n/a (non-Windows)" }
