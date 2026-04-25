/*
 * utils.c — memory, random, string, JSON, and UUID helpers.
 *
 * No CRT dependency: HeapAlloc/HeapFree via kernel32, BCryptGenRandom via
 * the already-loaded bcrypt handle from crypto.c.
 */
#include "../include/implant.h"
#include <string.h>
#include <stdarg.h>

/* ── Memory helpers ──────────────────────────────────────────────────────── */

void *ImplantAlloc(SIZE_T n) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}

void ImplantFree(void *p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

char *ImplantStrDup(const char *s) {
    if (!s) return NULL;
    SIZE_T n = strlen(s) + 1;
    char *out = (char *)ImplantAlloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

/* ── Randomness ──────────────────────────────────────────────────────────── */

void RandBytes(BYTE *buf, DWORD len) {
    /* BCryptGenRandom — pBCryptOpenAlgorithmProvider already called in CryptoInit */
    typedef NTSTATUS (WINAPI *pfnBCryptGenRandom)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
    static pfnBCryptGenRandom pFn = NULL;
    if (!pFn) {
        HMODULE h = GetModuleHandleA("bcrypt.dll");
        if (!h) h = LoadLibraryA("bcrypt.dll");
        if (h) pFn = (pfnBCryptGenRandom)(FARPROC)GetProcAddress(h, "BCryptGenRandom");
    }
    if (pFn && pFn(NULL, buf, len, 2 /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */) == 0)
        return;
    /* Fallback: mix RDTSC + heap address */
    for (DWORD i = 0; i < len; i++) {
        ULONGLONG t;
#if defined(__GNUC__)
        __asm__ volatile("rdtsc" : "=A"(t));
#else
        t = __rdtsc();
#endif
        buf[i] = (BYTE)(t ^ (ULONG_PTR)buf ^ i);
    }
}

DWORD RandDword(void) {
    DWORD v = 0;
    RandBytes((BYTE *)&v, sizeof(v));
    return v;
}

/* ── Wide ↔ narrow string ──────────────────────────────────────────────── */

void WstrToStr(WCHAR *w, char *out, int outCap) {
    int i = 0;
    while (i < outCap - 1 && w[i]) {
        out[i] = (char)(w[i] & 0xFF);
        i++;
    }
    out[i] = '\0';
}

void StrToWstr(const char *s, WCHAR *out, int outCap) {
    int i = 0;
    while (i < outCap - 1 && s[i]) {
        out[i] = (WCHAR)(unsigned char)s[i];
        i++;
    }
    out[i] = L'\0';
}

/* ── Minimal printf-style formatter (no CRT sprintf) ─────────────────────
 *
 * Supported: %s %d %u %x %02x %ld %lu %lld %llu
 * Returns bytes written (not including NUL), or -1 if truncated.
 */
static void _append(char *buf, int cap, int *pos, const char *s, int slen) {
    for (int i = 0; i < slen && *pos < cap - 1; i++)
        buf[(*pos)++] = s[i];
    buf[*pos] = '\0';
}

static void _append_uint(char *buf, int cap, int *pos,
                          unsigned long long v, int base, int minWidth, char pad) {
    char tmp[32];
    int  len = 0;
    if (v == 0) { tmp[len++] = '0'; }
    else {
        const char *digits = "0123456789abcdef";
        while (v) { tmp[len++] = digits[v % base]; v /= base; }
        /* reverse */
        for (int i = 0, j = len-1; i < j; i++, j--) {
            char c = tmp[i]; tmp[i] = tmp[j]; tmp[j] = c;
        }
    }
    while (len < minWidth) {
        /* prepend pad by shifting — simpler: just write pad chars first */
        char padded[32];
        int extra = minWidth - len;
        for (int i = 0; i < extra; i++) padded[i] = pad;
        memcpy(padded + extra, tmp, len);
        len += extra;
        memcpy(tmp, padded, len);
        break;
    }
    _append(buf, cap, pos, tmp, len);
}

int xsnprintf(char *buf, int cap, const char *fmt, ...) {
    if (cap <= 0) return -1;
    va_list ap;
    va_start(ap, fmt);
    int pos = 0;
    buf[0] = '\0';

    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            if (pos < cap - 1) buf[pos++] = *p;
            buf[pos] = '\0';
            continue;
        }
        p++;
        int minWidth = 0;
        char padChar = ' ';
        if (*p == '0') { padChar = '0'; p++; }
        while (*p >= '0' && *p <= '9') { minWidth = minWidth * 10 + (*p - '0'); p++; }

        int isLong = 0, isLongLong = 0;
        if (*p == 'l') { isLong = 1; p++; }
        if (*p == 'l') { isLongLong = 1; p++; }

        switch (*p) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            _append(buf, cap, &pos, s, (int)strlen(s));
            break;
        }
        case 'd': case 'i': {
            long long v;
            if (isLongLong)     v = va_arg(ap, long long);
            else if (isLong)    v = va_arg(ap, long);
            else                v = va_arg(ap, int);
            if (v < 0) {
                if (pos < cap - 1) buf[pos++] = '-';
                buf[pos] = '\0';
                v = -v;
            }
            _append_uint(buf, cap, &pos, (unsigned long long)v, 10, minWidth, padChar);
            break;
        }
        case 'u': {
            unsigned long long v;
            if (isLongLong)     v = va_arg(ap, unsigned long long);
            else if (isLong)    v = va_arg(ap, unsigned long);
            else                v = va_arg(ap, unsigned int);
            _append_uint(buf, cap, &pos, v, 10, minWidth, padChar);
            break;
        }
        case 'x': case 'X': {
            unsigned long long v;
            if (isLongLong)     v = va_arg(ap, unsigned long long);
            else if (isLong)    v = va_arg(ap, unsigned long);
            else                v = va_arg(ap, unsigned int);
            _append_uint(buf, cap, &pos, v, 16, minWidth, padChar);
            break;
        }
        case 'c': {
            char c = (char)va_arg(ap, int);
            if (pos < cap - 1) buf[pos++] = c;
            buf[pos] = '\0';
            break;
        }
        case '%':
            if (pos < cap - 1) buf[pos++] = '%';
            buf[pos] = '\0';
            break;
        default:
            /* unknown specifier — pass through */
            if (pos < cap - 1) buf[pos++] = '%';
            if (pos < cap - 1) buf[pos++] = *p;
            buf[pos] = '\0';
            break;
        }
    }
    va_end(ap);
    buf[pos] = '\0';
    return pos;
}

/* ── UUID generation — SHA-256(seed) → RFC-4122 v4 format ───────────────── */

void GenUUID(const char *seed, char out[UUID_STR_LEN]) {
    BYTE hash[SHA256_LEN];
    Sha256((const BYTE *)seed, (SIZE_T)strlen(seed), hash);

    /* Force version 4 and variant bits */
    hash[6] = (hash[6] & 0x0F) | 0x40;
    hash[8] = (hash[8] & 0x3F) | 0x80;

    xsnprintf(out, UUID_STR_LEN,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        hash[0],  hash[1],  hash[2],  hash[3],
        hash[4],  hash[5],
        hash[6],  hash[7],
        hash[8],  hash[9],
        hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);
}

/* ── JSON builder helpers ────────────────────────────────────────────────── */
/*
 * All JsonXxx functions write into buf[cap], starting at byte offset pos,
 * and return the new pos after writing.  The caller manages the opening/
 * closing braces separately.  The first key in an object should use pos
 * immediately after the '{'; subsequent keys use the returned pos directly
 * (a comma is prepended when pos > 1 && buf[pos-1] != '{').
 */

static int _json_sep(char *buf, int cap, int pos) {
    /* Add comma separator if we're past the opening brace */
    if (pos > 0 && buf[pos-1] != '{' && buf[pos-1] != '[') {
        if (pos < cap - 1) buf[pos++] = ',';
        buf[pos] = '\0';
    }
    return pos;
}

static int _json_key(char *buf, int cap, int pos, const char *key) {
    pos = _json_sep(buf, cap, pos);
    /* "key": */
    if (pos < cap - 1) buf[pos++] = '"';
    for (const char *k = key; *k && pos < cap - 1; k++) buf[pos++] = *k;
    if (pos < cap - 2) { buf[pos++] = '"'; buf[pos++] = ':'; }
    buf[pos] = '\0';
    return pos;
}

/* Escape a string value into JSON (handles \n \r \t \\ \") */
static int _json_str_val(char *buf, int cap, int pos, const char *val) {
    if (pos < cap - 1) buf[pos++] = '"';
    for (const char *v = val; *v && pos < cap - 2; v++) {
        switch (*v) {
        case '"':  buf[pos++] = '\\'; if (pos < cap-1) buf[pos++] = '"';  break;
        case '\\': buf[pos++] = '\\'; if (pos < cap-1) buf[pos++] = '\\'; break;
        case '\n': buf[pos++] = '\\'; if (pos < cap-1) buf[pos++] = 'n';  break;
        case '\r': buf[pos++] = '\\'; if (pos < cap-1) buf[pos++] = 'r';  break;
        case '\t': buf[pos++] = '\\'; if (pos < cap-1) buf[pos++] = 't';  break;
        default:   buf[pos++] = *v;  break;
        }
    }
    if (pos < cap - 1) buf[pos++] = '"';
    buf[pos] = '\0';
    return pos;
}

int JsonStr(char *buf, int cap, int pos, const char *key, const char *val) {
    pos = _json_key(buf, cap, pos, key);
    return _json_str_val(buf, cap, pos, val ? val : "");
}

int JsonInt(char *buf, int cap, int pos, const char *key, int val) {
    pos = _json_key(buf, cap, pos, key);
    char tmp[24];
    xsnprintf(tmp, sizeof(tmp), "%d", val);
    _append(buf, cap, &pos, tmp, (int)strlen(tmp));
    return pos;
}

int JsonBool(char *buf, int cap, int pos, const char *key, int val) {
    pos = _json_key(buf, cap, pos, key);
    const char *lit = val ? "true" : "false";
    _append(buf, cap, &pos, lit, (int)strlen(lit));
    return pos;
}

int JsonRaw(char *buf, int cap, int pos, const char *key, const char *raw) {
    pos = _json_key(buf, cap, pos, key);
    _append(buf, cap, &pos, raw, (int)strlen(raw));
    return pos;
}

/* ── JSON extractor ──────────────────────────────────────────────────────── */
/*
 * JsonGetStr — find "key":"value" or "key": value in flat JSON and return
 * heap-allocated copy of the value string (unescaped).  Caller must free.
 * Returns NULL if key not found.
 *
 * This is deliberately simple: it scans for `"key":` and reads the next
 * string value.  It does not handle nested objects for the key name.
 */
char *JsonGetStr(const char *json, const char *key) {
    if (!json || !key) return NULL;

    /* Build search pattern: "key": */
    char pat[128];
    xsnprintf(pat, sizeof(pat), "\"%s\"", key);
    int patLen = (int)strlen(pat);

    const char *p = json;
    while (*p) {
        /* find "key" */
        const char *found = NULL;
        while (*p) {
            if (*p == pat[0]) {
                int match = 1;
                for (int i = 1; i < patLen; i++) {
                    if (p[i] != pat[i]) { match = 0; break; }
                }
                if (match) { found = p; break; }
            }
            p++;
        }
        if (!found) return NULL;
        p = found + patLen;

        /* skip whitespace and colon */
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') continue;
        p++;
        while (*p == ' ' || *p == '\t') p++;

        if (*p == '"') {
            /* string value */
            p++;
            char *out = (char *)ImplantAlloc(4096);
            if (!out) return NULL;
            int oi = 0;
            while (*p && *p != '"' && oi < 4095) {
                if (*p == '\\' && *(p+1)) {
                    p++;
                    switch (*p) {
                    case '"':  out[oi++] = '"';  break;
                    case '\\': out[oi++] = '\\'; break;
                    case 'n':  out[oi++] = '\n'; break;
                    case 'r':  out[oi++] = '\r'; break;
                    case 't':  out[oi++] = '\t'; break;
                    default:   out[oi++] = *p;   break;
                    }
                } else {
                    out[oi++] = *p;
                }
                p++;
            }
            out[oi] = '\0';
            return out;
        } else {
            /* number / bool / null — return raw token */
            const char *start = p;
            while (*p && *p != ',' && *p != '}' && *p != ']' &&
                   *p != ' ' && *p != '\n' && *p != '\r') p++;
            int len = (int)(p - start);
            if (len <= 0) return NULL;
            char *out = (char *)ImplantAlloc(len + 1);
            if (!out) return NULL;
            memcpy(out, start, len);
            out[len] = '\0';
            return out;
        }
    }
    return NULL;
}

/*
 * JsonGetPath — dot-separated key path, e.g. "args.pid".
 * Iteratively extracts each segment.  Caller must free result.
 */
char *JsonGetPath(const char *json, const char *path) {
    if (!json || !path) return NULL;

    char seg[128];
    const char *p = path;
    char *cur = ImplantStrDup(json);
    if (!cur) return NULL;

    while (*p) {
        /* extract next segment */
        int si = 0;
        while (*p && *p != '.' && si < (int)sizeof(seg) - 1) seg[si++] = *p++;
        seg[si] = '\0';
        if (*p == '.') p++;

        char *val = JsonGetStr(cur, seg);
        ImplantFree(cur);
        if (!val) return NULL;
        cur = val;
    }
    return cur;
}
