//go:build !windows

package exec

import "fmt"

func AdsWrite(path string, data []byte) error {
	return fmt.Errorf("NTFS ADS is only available on Windows")
}

func AdsRead(path string) ([]byte, error) {
	return nil, fmt.Errorf("NTFS ADS is only available on Windows")
}

func AdsExec(path string) (string, error) {
	return "", fmt.Errorf("NTFS ADS is only available on Windows")
}
