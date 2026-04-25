//go:build windows

package main

import (
	"strings"
	"unsafe"

	implantevasion "github.com/mjopsec/taburtuaiC2/implant/evasion"
	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
	"golang.org/x/sys/windows"
)

func nativeDetectVM() bool {
	return implantevasion.IsVM()
}

func nativeDetectDebugger() bool {
	return implantevasion.IsDebugged()
}

// nativeCheckProcesses enumerates running processes via Toolhelp32 and returns
// any names from the given list that are currently running.
func nativeCheckProcesses(names []string) []string {
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

	hSnap, _, _ := winsyscall.ProcCreateToolhelp32Snapshot.Call(uintptr(winsyscall.Th32csSnapProcess), 0)
	if hSnap == ^uintptr(0) {
		return nil
	}
	defer windows.CloseHandle(windows.Handle(hSnap))

	pe := PROCESSENTRY32W{dwSize: uint32(unsafe.Sizeof(PROCESSENTRY32W{}))}
	winsyscall.ProcProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe)))

	lower := make([]string, len(names))
	for i, n := range names {
		lower[i] = strings.ToLower(n)
	}

	found := map[string]struct{}{}
	for {
		exeName := strings.ToLower(utf16PtrToString(pe.szExeFile[:]))
		for _, n := range lower {
			if strings.Contains(exeName, n) {
				found[n] = struct{}{}
			}
		}
		r, _, _ := winsyscall.ProcProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}

	result := make([]string, 0, len(found))
	for k := range found {
		result = append(result, k)
	}
	return result
}

func utf16PtrToString(u16 []uint16) string {
	end := len(u16)
	for i, c := range u16 {
		if c == 0 {
			end = i
			break
		}
	}
	runes := make([]rune, end)
	for i, c := range u16[:end] {
		runes[i] = rune(c)
	}
	return string(runes)
}
