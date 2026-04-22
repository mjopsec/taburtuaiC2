//go:build !windows

package main

import "fmt"

func spawnWithPPID(executable, args string, parentPID uint32) (interface{}, error) {
	return nil, fmt.Errorf("PPID spoofing is only supported on Windows")
}

func pidByName(name string) (uint32, error) {
	return 0, fmt.Errorf("pidByName is only supported on Windows")
}
