//go:build !windows

package main

import "fmt"

func execute(payload []byte) error {
	return fmt.Errorf("stager: unsupported platform")
}
