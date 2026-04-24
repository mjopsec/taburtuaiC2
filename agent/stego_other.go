//go:build !windows

package main

import "fmt"

func stegoExtract(imagePath string, key byte) ([]byte, error) {
	return nil, fmt.Errorf("stegoExtract is Windows-only")
}

func stegoExtractAndRun(imagePath string, key byte) error {
	return fmt.Errorf("stegoExtractAndRun is Windows-only")
}

func stegoEncodePNG(carrierPath, outPath string, shellcode []byte, key byte) error {
	return fmt.Errorf("stegoEncodePNG is Windows-only")
}

func stegoEncodeJPEG(carrierPath, outPath string, shellcode []byte, key byte, quality int) error {
	return fmt.Errorf("stegoEncodeJPEG is Windows-only")
}
