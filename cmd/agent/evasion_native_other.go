//go:build !windows

package main

func nativeDetectVM() bool        { return false }
func nativeDetectDebugger() bool   { return false }
func nativeCheckProcesses(names []string) []string { return nil }
