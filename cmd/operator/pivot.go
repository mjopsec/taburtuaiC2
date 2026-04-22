package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func pivotPost(agentID, endpoint string, payload interface{}, desc string, wait bool, timeout int) {
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

// ── netscan ───────────────────────────────────────────────────────────────────

var netscanCmd = &cobra.Command{
	Use:   "netscan <agent-id>",
	Short: "TCP port scan via agent",
	Long: `Run a concurrent TCP port scan from the agent's network position.
Useful for internal network discovery during lateral movement.

Examples:
  netscan 7d019eb7 --targets 192.168.1.0/24 --ports 22,80,443,3389 --wait
  netscanCmd 7d019eb7 -t 10.0.0.1 -t 10.0.0.2 -p 80 -p 443 --banners --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		targets, _ := cmd.Flags().GetStringArray("targets")
		portsStr, _ := cmd.Flags().GetStringArray("ports")
		timeoutSec, _ := cmd.Flags().GetInt("scan-timeout")
		workers, _ := cmd.Flags().GetInt("workers")
		banners, _ := cmd.Flags().GetBool("banners")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if len(targets) == 0 {
			printError("--targets is required")
			os.Exit(1)
		}

		// Parse ports — accept "22,80,443" or multiple --ports flags
		var ports []int
		for _, ps := range portsStr {
			for _, p := range strings.Split(ps, ",") {
				p = strings.TrimSpace(p)
				if n, err := strconv.Atoi(p); err == nil {
					ports = append(ports, n)
				}
			}
		}

		pivotPost(agentID, "pivot/netscan", map[string]interface{}{
			"targets":      targets,
			"ports":        ports,
			"timeout":      timeoutSec,
			"workers":      workers,
			"grab_banners": banners,
		}, "Net scan", wait, timeout)
	},
}

var arpscanCmd = &cobra.Command{
	Use:   "arpscan <agent-id>",
	Short: "Dump ARP table from agent",
	Long: `Retrieve the ARP cache from the agent to enumerate live hosts
on the local subnet without sending any probe packets.

Examples:
  arpscan 7d019eb7 --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		pivotPost(agentID, "pivot/arpscan", nil, "ARP scan", wait, timeout)
	},
}

// ── registry ──────────────────────────────────────────────────────────────────

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Windows registry operations (read / write / delete / list)",
}

var regReadCmd = &cobra.Command{
	Use:   "read <agent-id>",
	Short: "Read a registry value",
	Long: `Read a single registry value from the agent (Windows only).

Examples:
  registry read 7d019eb7 --hive HKLM --key "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" --value ProductName --wait
  registry read 7d019eb7 -H HKCU -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run" -V MyApp --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		hive, _ := cmd.Flags().GetString("hive")
		key, _ := cmd.Flags().GetString("key")
		value, _ := cmd.Flags().GetString("value")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if hive == "" || key == "" || value == "" {
			printError("--hive, --key, and --value are required")
			os.Exit(1)
		}
		pivotPost(agentID, "registry/read", map[string]interface{}{
			"hive": hive, "key": key, "value": value,
		}, "Registry read", wait, timeout)
	},
}

var regWriteCmd = &cobra.Command{
	Use:   "write <agent-id>",
	Short: "Write a registry value",
	Long: `Write a registry value on the agent (Windows only).
Supported types: sz, expand_sz, multi_sz, dword, qword, binary.

Examples:
  registry write 7d019eb7 --hive HKCU --key "Software\\Test" --value MyKey --data "hello" --type sz --wait
  registry write 7d019eb7 -H HKLM -K "SYSTEM\\CurrentControlSet\\Services\\MyApp" -V Start --data 2 --type dword --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		hive, _ := cmd.Flags().GetString("hive")
		key, _ := cmd.Flags().GetString("key")
		value, _ := cmd.Flags().GetString("value")
		data, _ := cmd.Flags().GetString("data")
		regType, _ := cmd.Flags().GetString("type")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if hive == "" || key == "" || value == "" || data == "" {
			printError("--hive, --key, --value, and --data are required")
			os.Exit(1)
		}
		pivotPost(agentID, "registry/write", map[string]interface{}{
			"hive": hive, "key": key, "value": value, "data": data, "type": regType,
		}, "Registry write", wait, timeout)
	},
}

var regDeleteCmd = &cobra.Command{
	Use:   "delete <agent-id>",
	Short: "Delete a registry key or value",
	Long: `Delete a registry value (or entire key if --value is omitted) on the agent.

Examples:
  registry delete 7d019eb7 --hive HKCU --key "Software\\Test" --value MyKey --wait
  registry delete 7d019eb7 --hive HKCU --key "Software\\Test" --wait  (deletes entire key)`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		hive, _ := cmd.Flags().GetString("hive")
		key, _ := cmd.Flags().GetString("key")
		value, _ := cmd.Flags().GetString("value")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if hive == "" || key == "" {
			printError("--hive and --key are required")
			os.Exit(1)
		}
		pivotPost(agentID, "registry/delete", map[string]interface{}{
			"hive": hive, "key": key, "value": value,
		}, "Registry delete", wait, timeout)
	},
}

var regListCmd = &cobra.Command{
	Use:   "list <agent-id>",
	Short: "List subkeys and values of a registry key",
	Long: `Enumerate all subkeys and values under a registry key on the agent.

Examples:
  registry list 7d019eb7 --hive HKLM --key "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" --wait
  registry list 7d019eb7 -H HKCU -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run" --wait`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		hive, _ := cmd.Flags().GetString("hive")
		key, _ := cmd.Flags().GetString("key")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if hive == "" || key == "" {
			printError("--hive and --key are required")
			os.Exit(1)
		}
		pivotPost(agentID, "registry/list", map[string]interface{}{
			"hive": hive, "key": key,
		}, "Registry list", wait, timeout)
	},
}

// ── SOCKS5 proxy pivot ────────────────────────────────────────────────────────

var socks5Cmd = &cobra.Command{
	Use:   "socks5",
	Short: "SOCKS5 proxy pivot (start / stop / status)",
}

var socks5StartCmd = &cobra.Command{
	Use:   "start <agent-id>",
	Short: "Start in-process SOCKS5 listener on the agent",
	Long: `Start an in-process SOCKS5 proxy on the agent. Once running, you can
configure proxychains or your tool's proxy setting to route traffic through
the agent's network position.

Examples:
  socks5 start 7d019eb7 --addr 0.0.0.0:1080 --wait
  socks5 start 7d019eb7 --wait  (default: 127.0.0.1:1080)`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		addr, _ := cmd.Flags().GetString("addr")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		pivotPost(agentID, "pivot/socks5/start", map[string]interface{}{
			"addr": addr,
		}, fmt.Sprintf("SOCKS5 start (%s)", addr), wait, timeout)
	},
}

var socks5StopCmd = &cobra.Command{
	Use:   "stop <agent-id>",
	Short: "Stop the SOCKS5 listener on the agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		pivotPost(agentID, "pivot/socks5/stop", nil, "SOCKS5 stop", wait, timeout)
	},
}

var socks5StatusCmd = &cobra.Command{
	Use:   "status <agent-id>",
	Short: "Query SOCKS5 proxy status on the agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")
		pivotPost(agentID, "pivot/socks5/status", nil, "SOCKS5 status", wait, timeout)
	},
}

// ── flag registration (called from main) ─────────────────────────────────────

func initPivotFlags() {
	// netscan
	netscanCmd.Flags().StringArrayP("targets", "t", nil, "Target IPs, CIDRs, or ranges (repeatable)")
	netscanCmd.Flags().StringArrayP("ports", "p", nil, "Ports to scan: 22,80,443 or repeatable")
	netscanCmd.Flags().Int("scan-timeout", 2, "Per-connection timeout (seconds)")
	netscanCmd.Flags().Int("workers", 50, "Concurrent goroutines")
	netscanCmd.Flags().Bool("banners", false, "Grab service banners")
	netscanCmd.Flags().Bool("wait", false, "Wait for result")
	netscanCmd.Flags().Int("timeout", 300, "Wait timeout (seconds)")

	// arpscan
	arpscanCmd.Flags().Bool("wait", false, "Wait for result")
	arpscanCmd.Flags().Int("timeout", 30, "Wait timeout (seconds)")

	// registry shared flags
	for _, c := range []*cobra.Command{regReadCmd, regWriteCmd, regDeleteCmd, regListCmd} {
		c.Flags().StringP("hive", "H", "", "Registry hive (HKLM, HKCU, HKCR, HKU, HKCC)")
		c.Flags().StringP("key", "K", "", "Registry key path")
		c.Flags().Bool("wait", false, "Wait for result")
		c.Flags().Int("timeout", 30, "Wait timeout (seconds)")
	}
	regReadCmd.Flags().StringP("value", "V", "", "Value name to read")
	regWriteCmd.Flags().StringP("value", "V", "", "Value name to write")
	regWriteCmd.Flags().StringP("data", "d", "", "Data to write")
	regWriteCmd.Flags().StringP("type", "T", "sz", "Value type: sz|expand_sz|multi_sz|dword|qword|binary")
	regDeleteCmd.Flags().StringP("value", "V", "", "Value name (omit to delete entire key)")

	// socks5
	socks5StartCmd.Flags().String("addr", "127.0.0.1:1080", "Listen address (host:port)")
	for _, c := range []*cobra.Command{socks5StartCmd, socks5StopCmd, socks5StatusCmd} {
		c.Flags().Bool("wait", false, "Wait for result")
		c.Flags().Int("timeout", 15, "Wait timeout (seconds)")
	}
}
