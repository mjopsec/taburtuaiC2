//go:build !windows

package inject

import "fmt"

func InjectShellcode(_ uint32, _ []byte, _ string) error {
	return fmt.Errorf("process injection is only supported on Windows")
}

func ExecShellcodeSelf(_ []byte) error {
	return fmt.Errorf("in-memory shellcode execution is only supported on Windows")
}

func ProcessThreadIDs(_ uint32) ([]uint32, error) {
	return nil, fmt.Errorf("ProcessThreadIDs is only supported on Windows")
}
