//go:build !windows

package main

// preinitConsole is a no-op on non-Windows platforms.
func preinitConsole() {}
