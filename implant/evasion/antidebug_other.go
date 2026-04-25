//go:build !windows

package evasion

func IsDebugged() bool        { return false }
func AntiDebugReport() string { return "n/a (non-Windows)" }
