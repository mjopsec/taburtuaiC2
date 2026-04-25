//go:build windows

package evasion

import (
	"strings"
	"unsafe"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// IsDebugged returns true if any debugger is detected.
func IsDebugged() bool {
	return checkIsDebuggerPresent() ||
		checkRemoteDebuggerPresent() ||
		checkNtQueryDebugPort() ||
		checkTimingAnomaly()
}

func checkIsDebuggerPresent() bool {
	r, _, _ := winsyscall.ProcIsDebuggerPresent.Call()
	return r != 0
}

func checkRemoteDebuggerPresent() bool {
	var present uint32
	winsyscall.ProcCheckRemoteDebuggerPresent.Call(^uintptr(0)-1, uintptr(unsafe.Pointer(&present)))
	return present != 0
}

func checkNtQueryDebugPort() bool {
	var debugPort uintptr
	status, _, _ := winsyscall.ProcNtQueryInformationProcess.Call(
		^uintptr(0)-1,
		7,
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	return status == 0 && debugPort != 0
}

func checkTimingAnomaly() bool {
	t1, _, _ := winsyscall.ProcGetTickCount64.Call()
	sum := uint64(0)
	for i := uint64(0); i < 1_000_000; i++ {
		sum += i
	}
	_ = sum
	t2, _, _ := winsyscall.ProcGetTickCount64.Call()
	return (t2 - t1) > 500
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
