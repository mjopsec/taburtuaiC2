//go:build !windows

package main

import "fmt"

// lolbinFetch is not supported on non-Windows platforms.
// Windows LOLBins (certutil, bitsadmin, curl.exe) are not available here.
func lolbinFetch(url, localPath, method string) error {
	return fmt.Errorf("lolbin_fetch is only supported on Windows (got method=%q)", method)
}
