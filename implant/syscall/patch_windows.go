//go:build windows

package winsyscall

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PatchBytes changes the protection of addr, writes patch bytes, then restores protection.
func PatchBytes(addr uintptr, patch []byte) error {
	size := uintptr(len(patch))
	var old uint32
	r, _, e := ProcVirtualProtect.Call(addr, size, windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return fmt.Errorf("VirtualProtect(RWX): %v", e)
	}
	p := unsafe.Pointer(addr) //nolint:unsafeptr
	for i, b := range patch {
		*(*byte)(unsafe.Add(p, i)) = b
	}
	ProcVirtualProtect.Call(addr, size, uintptr(old), uintptr(unsafe.Pointer(&old)))
	return nil
}

// PatchBytesRemote writes patch into a remote process at addr using WriteProcessMemory.
func PatchBytesRemote(hProc windows.Handle, addr uintptr, patch []byte) error {
	var old uint32
	ProcVirtualProtect.Call(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&old)))

	var written uintptr
	r, _, e := ProcWriteProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&patch[0])),
		uintptr(len(patch)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		return fmt.Errorf("WriteProcessMemory: %v", e)
	}
	return nil
}
