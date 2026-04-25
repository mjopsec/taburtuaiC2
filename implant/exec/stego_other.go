//go:build !windows

package exec

import "fmt"

func StegoExtract(imagePath string, key byte) ([]byte, error) {
	return nil, fmt.Errorf("StegoExtract is Windows-only")
}

func StegoExtractAndRun(imagePath string, key byte) error {
	return fmt.Errorf("StegoExtractAndRun is Windows-only")
}

func StegoEncodePNG(carrierPath, outPath string, shellcode []byte, key byte) error {
	return fmt.Errorf("StegoEncodePNG is Windows-only")
}

func StegoEncodeJPEG(carrierPath, outPath string, shellcode []byte, key byte, quality int) error {
	return fmt.Errorf("StegoEncodeJPEG is Windows-only")
}
