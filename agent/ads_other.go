//go:build !windows

package main

import "fmt"

func adsWrite(path string, data []byte) error {
	return fmt.Errorf("NTFS ADS is only available on Windows")
}

func adsRead(path string) ([]byte, error) {
	return nil, fmt.Errorf("NTFS ADS is only available on Windows")
}

func adsExec(path string) (string, error) {
	return "", fmt.Errorf("NTFS ADS is only available on Windows")
}
