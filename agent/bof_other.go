//go:build !windows

package main

import "fmt"

type BOFResult struct {
	Output string
	Err    string
}

func RunBOF(coffBytes []byte, args []byte) (*BOFResult, error) {
	return nil, fmt.Errorf("BOF execution is Windows-only")
}
