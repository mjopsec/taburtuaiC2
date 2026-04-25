//go:build !windows

package recon

import "fmt"

func CaptureScreen() ([]byte, error) {
	return nil, fmt.Errorf("screenshot is Windows-only")
}
