//go:build !windows

package persist

import "fmt"

func RegRead(_, _, _ string) (string, error) {
	return "", fmt.Errorf("registry operations are Windows-only")
}

func RegWrite(_, _, _, _, _ string) error {
	return fmt.Errorf("registry operations are Windows-only")
}

func RegDelete(_, _, _ string) error {
	return fmt.Errorf("registry operations are Windows-only")
}

func RegList(_, _ string) ([]string, error) {
	return nil, fmt.Errorf("registry operations are Windows-only")
}
