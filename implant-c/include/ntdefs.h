#pragma once
/*
 * ntdefs.h — NT native API type definitions for the C implant.
 * Uses hard-coded x64 offsets to avoid struct-packing surprises.
 */

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <winternl.h>

/* ── NTSTATUS / helpers ───────────────────────────────────────────────────── */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif
#define STATUS_SUCCESS     ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

/* ── PEB / LDR offsets (x64, all Windows 10/11 versions) ─────────────────── */
#define PEB_OFFSET_BEING_DEBUGGED  0x02
#define PEB_OFFSET_LDR             0x18
#define LDR_OFFSET_INLOAD_LIST     0x10
#define LDR_ENTRY_OFFSET_DLLBASE   0x30
#define LDR_ENTRY_OFFSET_FULLNAME  0x48   /* UNICODE_STRING FullDllName  (full path) */
#define LDR_ENTRY_OFFSET_BASENAME  0x58   /* UNICODE_STRING BaseDllName  (filename only) */
#define USTR_OFFSET_LENGTH         0x00
#define USTR_OFFSET_BUFFER         0x08

/* ── NT object-attribute flags ────────────────────────────────────────────── */
#define OBJ_INHERIT            0x00000002L
#define OBJ_CASE_INSENSITIVE   0x00000040L

typedef struct _NT_OBJECT_ATTRIBUTES {
    ULONG     Length;
    HANDLE    RootDirectory;
    PVOID     ObjectName;   /* PUNICODE_STRING — NULL for process open */
    ULONG     Attributes;
    PVOID     SecurityDescriptor;
    PVOID     SecurityQualityOfService;
} NT_OBJECT_ATTRIBUTES;

typedef struct _NT_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} NT_CLIENT_ID;

/* ── NT_UNICODE_STRING (used for NtCreateFile path) ──────────────────────── */
typedef struct _NT_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NT_UNICODE_STRING;

/* ── NT_IO_STATUS_BLOCK ───────────────────────────────────────────────────── */
typedef struct _NT_IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} NT_IO_STATUS_BLOCK;

/* NtCreateFile / NtCreateSection / NtMapViewOfSection constants */
#define NT_FILE_READ_DATA          0x0001
#define NT_FILE_SHARE_READ         0x0001
#define NT_FILE_OPEN               0x00000001
#define NT_FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define NT_FILE_NON_DIRECTORY_FILE 0x00000040
#define NT_SECTION_MAP_READ        0x0004
#define NT_PAGE_READONLY           0x02
#define NT_SEC_IMAGE               0x1000000
#define NT_SEC_COMMIT              0x8000000
#define NT_VIEW_SHARE              1

/* ── PROCESS_BASIC_INFORMATION (ProcessInformationClass 0) ───────────────── */
typedef struct _NT_PROCESS_BASIC_INFO {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} NT_PROCESS_BASIC_INFO;

/* ── Memory constants ─────────────────────────────────────────────────────── */
#define NT_MEM_COMMIT_RESERVE  ((ULONG_PTR)0x3000)
#define NT_MEM_RELEASE         ((ULONG_PTR)0x8000)

/* ── Page protection constants (not always in MinGW headers) ─────────────── */
#ifndef PAGE_NOACCESS
#define PAGE_NOACCESS          0x01
#endif
#ifndef PAGE_EXECUTE_READ
#define PAGE_EXECUTE_READ      0x20
#endif

/* ── Thread creation flags ────────────────────────────────────────────────── */
#define THREAD_CREATE_FLAGS_HIDE_DEBUGGER 0x04

/* ── Process access ───────────────────────────────────────────────────────── */
#define NT_PROCESS_ALL_ACCESS  0x1FFFFF

/* ── Image PE helpers ─────────────────────────────────────────────────────── */
typedef struct _NT_EXPORT_DIR {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} NT_EXPORT_DIR;

/* ── AMSI result codes ────────────────────────────────────────────────────── */
#define AMSI_RESULT_CLEAN 0

/* ── BCrypt forward types (resolved dynamically) ─────────────────────────── */
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;

#define BCRYPT_AES_ALGORITHM        L"AES"
#define BCRYPT_CHAIN_MODE_GCM       L"ChainingModeGCM"
#define BCRYPT_CHAINING_MODE        L"ChainingMode"
#define BCRYPT_AUTH_TAG_LENGTH      L"AuthTagLength"

typedef struct _BCRYPT_AUTH_TAG_LENGTHS_STRUCT {
    ULONG dwMinLength;
    ULONG dwMaxLength;
    ULONG dwIncrement;
} BCRYPT_AUTH_TAG_LENGTHS_STRUCT;

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG  cbNonce;
    PUCHAR pbAuthData;
    ULONG  cbAuthData;
    PUCHAR pbTag;
    ULONG  cbTag;
    PUCHAR pbMacContext;
    ULONG  cbMacContext;
    ULONG  cbAAD;
    ULONGLONG cbData;
    ULONG  dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

#define BCRYPT_AUTH_MODE_INFO_VERSION 1
#define BCRYPT_INIT_AUTH_MODE_INFO(x) \
    RtlZeroMemory(&(x), sizeof(x)); \
    (x).cbSize = sizeof(x); \
    (x).dwInfoVersion = BCRYPT_AUTH_MODE_INFO_VERSION

/* BCrypt function pointer types */
typedef NTSTATUS (WINAPI *pfnBCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptSetProperty)(BCRYPT_ALG_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *pfnBCryptEncrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *pfnBCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);

/* WinHTTP function pointer types */
typedef HINTERNET (WINAPI *pfnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pfnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pfnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pfnWinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI *pfnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pfnWinHttpCloseHandle)(HINTERNET);
typedef BOOL (WINAPI *pfnWinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *pfnWinHttpQueryOption)(HINTERNET, DWORD, LPVOID, LPDWORD);
typedef BOOL (WINAPI *pfnWinHttpAddRequestHeaders)(HINTERNET, LPCWSTR, DWORD, DWORD);
typedef BOOL (WINAPI *pfnWinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY  0
#define WINHTTP_NO_PROXY_NAME   NULL
#define WINHTTP_NO_PROXY_BYPASS NULL
#define WINHTTP_FLAG_SECURE     0x00800000
#define WINHTTP_OPTION_SECURITY_FLAGS         31
#define WINHTTP_OPTION_SERVER_CERT_CONTEXT    78
#define WINHTTP_ADDREQS_FLAG_REPLACE          0x80000000
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS  0x3300

#ifndef INTERNET_DEFAULT_HTTPS_PORT
#define INTERNET_DEFAULT_HTTPS_PORT 443
#endif
#ifndef INTERNET_DEFAULT_HTTP_PORT
#define INTERNET_DEFAULT_HTTP_PORT 80
#endif
