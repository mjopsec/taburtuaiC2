//go:build !windows

package main

import "fmt"

func hijackThread(_ uint32, _ []byte) error {
	return fmt.Errorf("thread hijacking not supported on this platform")
}
