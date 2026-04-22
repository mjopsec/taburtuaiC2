//go:build !windows

package main

import "fmt"

func captureScreen() ([]byte, error) { return nil, fmt.Errorf("screenshot is Windows-only") }
