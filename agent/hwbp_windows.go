//go:build windows

package main

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CONTEXT flag constants (already defined as contextAll in hollow_windows.go)
// DR register offsets in x64 CONTEXT:
//   Dr0 at offset 24, Dr1 at 32, Dr2 at 40, Dr3 at 48 — but wait, those are the
//   debug register fields in the actual CONTEXT struct.
//
// In CONTEXT_AMD64:
//   Offset  0: P1Home (8)
//   ...
//   Offset 96: Dr0 (8)
//   Offset 104: Dr1 (8)
//   Offset 112: Dr2 (8)
//   Offset 120: Dr3 (8)
//   Offset 128: Dr6 (8)
//   Offset 136: Dr7 (8)
const (
	dr0Off = 96
	dr1Off = 104
	dr2Off = 112
	dr3Off = 120
	dr6Off = 128
	dr7Off = 136
)

// HWBPSlot represents a single hardware breakpoint register (DR0-DR3).
type HWBPSlot uint8

const (
	HWBP_DR0 HWBPSlot = 0
	HWBP_DR1 HWBPSlot = 1
	HWBP_DR2 HWBPSlot = 2
	HWBP_DR3 HWBPSlot = 3
)

type hwbpEntry struct {
	slot    HWBPSlot
	addr    uintptr
	handler func(addr uintptr) // called on hit
}

var (
	hwbpMu      sync.Mutex
	hwbpEntries []hwbpEntry
	hwbpVEH     uintptr
)

// EXCEPTION_POINTERS / EXCEPTION_RECORD constants
const (
	exceptionSingleStep   uintptr = 0x80000004
	exceptionAccessViolation uintptr = 0xC0000005
)

// setDR sets a debug register in ctx (our x64Context wrapper).
func setDR(ctx *x64Context, slot HWBPSlot, addr uintptr) {
	off := [4]uintptr{dr0Off, dr1Off, dr2Off, dr3Off}
	*(*uintptr)(unsafe.Pointer(ctx.ptr + off[slot])) = addr
}

// getDR7 / setDR7 manipulate the debug control register.
func getDR7(ctx *x64Context) uint64 {
	return *(*uint64)(unsafe.Pointer(ctx.ptr + dr7Off))
}
func setDR7(ctx *x64Context, v uint64) {
	*(*uint64)(unsafe.Pointer(ctx.ptr + dr7Off)) = v
}

// dr7Enable sets the local enable bit and condition for a slot.
// condition: 00=execute, 01=write, 11=read/write
// size:      00=1-byte, 01=2-byte, 10=8-byte, 11=4-byte
func dr7Enable(dr7 uint64, slot HWBPSlot, condition, size uint64) uint64 {
	s := uint64(slot)
	dr7 |= (1 << (s * 2))                      // local enable (L0..L3 at bits 0,2,4,6)
	dr7 &^= (0xF << (16 + s*4))                // clear condition+size bits
	dr7 |= ((condition | (size << 2)) << (16 + s*4))
	return dr7
}

func dr7Disable(dr7 uint64, slot HWBPSlot) uint64 {
	s := uint64(slot)
	dr7 &^= (3 << (s * 2))   // clear L+G bits
	dr7 &^= (0xF << (16 + s*4))
	return dr7
}

func hwbpVEHCallback(ep uintptr) uintptr {
	// ep points to EXCEPTION_POINTERS{*EXCEPTION_RECORD, *CONTEXT}
	// EXCEPTION_RECORD.ExceptionCode is at offset 0
	exCode := *(*uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(ep))))
	if exCode != exceptionSingleStep {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}

	ctxPtr := *(*uintptr)(unsafe.Pointer(ep + unsafe.Sizeof(uintptr(0))))
	// Read Dr6 to identify which BP fired
	dr6 := *(*uint64)(unsafe.Pointer(ctxPtr + dr6Off))

	hwbpMu.Lock()
	entries := make([]hwbpEntry, len(hwbpEntries))
	copy(entries, hwbpEntries)
	hwbpMu.Unlock()

	for _, e := range entries {
		bit := uint64(1) << e.slot
		if dr6&bit != 0 {
			if e.handler != nil {
				e.handler(e.addr)
			}
			// Clear Dr6 to prevent re-trigger
			*(*uint64)(unsafe.Pointer(ctxPtr + dr6Off)) = 0
			return ^uintptr(0) // EXCEPTION_CONTINUE_EXECUTION (-1)
		}
	}
	return 0
}

// SetHWBP installs a hardware execute-breakpoint at addr in slot DR{slot}.
// handler is called synchronously in the VEH when the BP fires.
func SetHWBP(slot HWBPSlot, addr uintptr, handler func(uintptr)) error {
	if slot > HWBP_DR3 {
		return fmt.Errorf("invalid slot %d (must be 0-3)", slot)
	}

	hwbpMu.Lock()
	defer hwbpMu.Unlock()

	// Install VEH if not yet installed
	if hwbpVEH == 0 {
		// We need a C-callable trampoline — use syscall trick
		// For simplicity: use a go func as the VEH stub via windows callback
		cb := windows.NewCallback(func(ep uintptr) uintptr {
			return hwbpVEHCallback(ep)
		})
		r, _, e := procAddVectoredExceptionHandler.Call(1, cb)
		if r == 0 {
			return fmt.Errorf("AddVectoredExceptionHandler: %v", e)
		}
		hwbpVEH = r
	}

	// Set DR register in all threads of this process via thread context
	tids, err := processThreadIDs(uint32(windows.GetCurrentProcessId()))
	if err != nil {
		return fmt.Errorf("processThreadIDs: %w", err)
	}

	for _, tid := range tids {
		if err := setDRForThread(tid, slot, addr); err != nil {
			return fmt.Errorf("thread %d: %w", tid, err)
		}
	}

	// Record entry
	for i, e := range hwbpEntries {
		if e.slot == slot {
			hwbpEntries[i] = hwbpEntry{slot: slot, addr: addr, handler: handler}
			return nil
		}
	}
	hwbpEntries = append(hwbpEntries, hwbpEntry{slot: slot, addr: addr, handler: handler})
	return nil
}

// ClearHWBP removes the hardware breakpoint in slot.
func ClearHWBP(slot HWBPSlot) error {
	hwbpMu.Lock()
	defer hwbpMu.Unlock()

	tids, err := processThreadIDs(uint32(windows.GetCurrentProcessId()))
	if err != nil {
		return err
	}
	for _, tid := range tids {
		if err := clearDRForThread(tid, slot); err != nil {
			return err
		}
	}
	for i, e := range hwbpEntries {
		if e.slot == slot {
			hwbpEntries = append(hwbpEntries[:i], hwbpEntries[i+1:]...)
			break
		}
	}
	return nil
}

func setDRForThread(tid uint32, slot HWBPSlot, addr uintptr) error {
	hThread, _, e := procOpenThread.Call(uintptr(threadAllAccess), 0, uintptr(tid))
	if hThread == 0 {
		return fmt.Errorf("OpenThread: %v", e)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	procSuspendThread.Call(hThread)
	defer procResumeThread.Call(hThread)

	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e := procGetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		return fmt.Errorf("GetThreadContext: %v", e)
	}

	setDR(ctx, slot, addr)
	dr7 := getDR7(ctx)
	dr7 = dr7Enable(dr7, slot, 0, 0) // execute, 1-byte
	setDR7(ctx, dr7)

	r, _, e = procSetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		return fmt.Errorf("SetThreadContext: %v", e)
	}
	return nil
}

func clearDRForThread(tid uint32, slot HWBPSlot) error {
	hThread, _, e := procOpenThread.Call(uintptr(threadAllAccess), 0, uintptr(tid))
	if hThread == 0 {
		return fmt.Errorf("OpenThread: %v", e)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	procSuspendThread.Call(hThread)
	defer procResumeThread.Call(hThread)

	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e := procGetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		return fmt.Errorf("GetThreadContext: %v", e)
	}

	setDR(ctx, slot, 0)
	dr7 := getDR7(ctx)
	dr7 = dr7Disable(dr7, slot)
	setDR7(ctx, dr7)

	r, _, e = procSetThreadContext.Call(hThread, ctx.raw())
	if r == 0 {
		return fmt.Errorf("SetThreadContext: %v", e)
	}
	return nil
}
