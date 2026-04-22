//go:build windows

package main

import (
	"strings"
	"unsafe"
)

// IsDebugged returns true if any debugger is detected via multiple methods.
func IsDebugged() bool {
	return checkIsDebuggerPresent() ||
		checkRemoteDebuggerPresent() ||
		checkNtQueryDebugPort() ||
		checkHeapFlag() ||
		checkTimingAnomaly()
}

// checkIsDebuggerPresent: kernel32!IsDebuggerPresent
func checkIsDebuggerPresent() bool {
	r, _, _ := procIsDebuggerPresent.Call()
	return r != 0
}

// checkRemoteDebuggerPresent: kernel32!CheckRemoteDebuggerPresent on own process
func checkRemoteDebuggerPresent() bool {
	var present uint32
	procCheckRemoteDebuggerPresent.Call(^uintptr(0)-1, uintptr(unsafe.Pointer(&present)))
	return present != 0
}

// checkNtQueryDebugPort: NtQueryInformationProcess(ProcessDebugPort = 7)
func checkNtQueryDebugPort() bool {
	var debugPort uintptr
	status, _, _ := procNtQueryInformationProcess.Call(
		^uintptr(0)-1, // NtCurrentProcess
		7,             // ProcessDebugPort
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	return status == 0 && debugPort != 0
}

// checkHeapFlag: look for debug heap flags at the PEB
// PEB at GS:[0x60] on x64; HeapForceFlags at offset 0x74 in the first HEAP header.
func checkHeapFlag() bool {
	// Safe fallback: OutputDebugString timing trick
	// SendOutputDebugString — if a debugger is attached it consumes the string,
	// otherwise SetLastError is called. We rely on the other checks above.
	return false
}

// checkTimingAnomaly: uses GetTickCount64 delta — debuggers slow execution.
func checkTimingAnomaly() bool {
	t1, _, _ := procGetTickCount64.Call()
	// Do some busy work
	sum := uint64(0)
	for i := uint64(0); i < 1_000_000; i++ {
		sum += i
	}
	_ = sum
	t2, _, _ := procGetTickCount64.Call()
	return (t2 - t1) > 500 // >500ms for 1M iterations is suspicious
}

// AntiDebugReport returns a descriptive string of detected debugger artifacts.
func AntiDebugReport() string {
	var findings []string
	if checkIsDebuggerPresent() {
		findings = append(findings, "IsDebuggerPresent=TRUE")
	}
	if checkRemoteDebuggerPresent() {
		findings = append(findings, "CheckRemoteDebuggerPresent=TRUE")
	}
	if checkNtQueryDebugPort() {
		findings = append(findings, "NtQueryInformationProcess(DebugPort)!=0")
	}
	if checkTimingAnomaly() {
		findings = append(findings, "TimingAnomaly(>500ms)")
	}
	if len(findings) == 0 {
		return "clean"
	}
	return strings.Join(findings, ", ")
}
