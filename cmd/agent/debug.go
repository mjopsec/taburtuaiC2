package main

import "fmt"

// dbgf prints a formatted message to stdout only when debugMode == "true".
// In production builds this is a silent no-op — no indicator strings are
// written to any handle, so console-based behavioral detections do not fire.
func dbgf(format string, args ...any) {
	if debugMode == "true" {
		fmt.Printf(format, args...)
	}
}
