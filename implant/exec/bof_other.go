//go:build !windows

package exec

import "fmt"

// BOFResult holds the output and error string from a BOF execution.
type BOFResult struct {
	Output string
	Err    string
}

func RunBOF(coffBytes []byte, args []byte) (*BOFResult, error) {
	return nil, fmt.Errorf("BOF execution is Windows-only")
}
