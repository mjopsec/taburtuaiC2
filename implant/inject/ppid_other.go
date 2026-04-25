//go:build !windows

package inject

import "fmt"

func SpawnWithPPID(_, _ string, _ uint32) (interface{}, error) {
	return nil, fmt.Errorf("PPID spoofing is only supported on Windows")
}

func PidByName(_ string) (uint32, error) {
	return 0, fmt.Errorf("PidByName is only supported on Windows")
}
