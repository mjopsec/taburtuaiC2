//go:build !windows

package main

import "fmt"

func startKeylogger() error  { return fmt.Errorf("keylogger is Windows-only") }
func dumpKeylog() string     { return "" }
func clearKeylog()           {}
func stopKeylogger()         {}
