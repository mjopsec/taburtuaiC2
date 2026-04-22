//go:build !windows

package main

func IsDebugged() bool       { return false }
func AntiDebugReport() string { return "n/a (non-Windows)" }
