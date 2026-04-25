//go:build !windows

package creds

import "fmt"

func DumpLSASS(_ string) error {
	return fmt.Errorf("LSASS dump is Windows-only")
}

func FindProcessByName(_ string) (uint32, error) {
	return 0, fmt.Errorf("FindProcessByName is Windows-only")
}

func LsassDumpViaDup(_ string) (string, error) {
	return "", fmt.Errorf("LsassDumpViaDup is Windows-only")
}

func LsassDumpViaWER(_ string) (string, error) {
	return "", fmt.Errorf("LsassDumpViaWER is Windows-only")
}
