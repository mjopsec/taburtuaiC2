package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// teamEvent mirrors services.TeamEvent for JSON decoding.
type teamEvent struct {
	Type    string `json:"type"`
	AgentID string `json:"agent_id,omitempty"`
	OpName  string `json:"op_name,omitempty"`
	Payload string `json:"payload,omitempty"`
	Time    string `json:"time"`
}

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Multi-operator team server — join, claim agents, broadcast notes",
}

// team subscribe <operator-name>
// Opens an SSE stream and prints events in real time.
var teamSubscribeCmd = &cobra.Command{
	Use:   "subscribe <operator-name>",
	Short: "Connect to the team server event stream (real-time agent events)",
	Long: `Opens a live Server-Sent Events stream from the C2 server.
All agent checkins, command results, and operator activity are shown.

Examples:
  team subscribe alice
  team subscribe bob --server https://c2.example.com`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		opName := args[0]
		url := config.ServerURL + "/api/v1/team/events?name=" + opName

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			printError(fmt.Sprintf("Subscribe failed: %v", err))
			os.Exit(1)
		}
		req.Header.Set("Accept", "text/event-stream")
		if config.APIKey != "" {
			req.Header.Set("X-API-Key", config.APIKey)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			printError(fmt.Sprintf("Connect failed: %v", err))
			os.Exit(1)
		}
		defer resp.Body.Close()

		sessionID := resp.Header.Get("X-Session-ID")
		printSuccess(fmt.Sprintf("Connected to team server as \033[1m%s\033[0m (session: %s)", opName, sessionID))
		printInfo("Press Ctrl+C to disconnect\n")

		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					printInfo("Server closed the connection.")
				} else {
					printError(fmt.Sprintf("Stream error: %v", err))
				}
				return
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")

			var ev teamEvent
			if err := json.Unmarshal([]byte(data), &ev); err != nil {
				continue
			}
			printTeamEvent(ev)
		}
	},
}

// team operators
var teamOperatorsCmd = &cobra.Command{
	Use:   "operators",
	Short: "List currently connected operators",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		body, err := makeAPIRequestWithMethod("GET", "/api/v1/team/operators", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("List operators failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError("Failed to list operators")
			os.Exit(1)
		}
		dataMap, _ := resp.Data.(map[string]interface{})
		ops, _ := dataMap["operators"].([]interface{})
		count, _ := dataMap["count"].(float64)

		if len(ops) == 0 {
			printInfo("No operators connected")
			return
		}
		fmt.Printf("\n  %-36s  %-16s  %s\n", "SESSION ID", "NAME", "JOINED")
		fmt.Printf("  %s\n", strings.Repeat("─", 72))
		for _, o := range ops {
			op, _ := o.(map[string]interface{})
			id, _ := op["id"].(string)
			name, _ := op["name"].(string)
			joined, _ := op["joined_at"].(string)
			if t, err := time.Parse(time.RFC3339, joined); err == nil {
				joined = t.Format("15:04:05")
			}
			fmt.Printf("  %-36s  %-16s  %s\n", id, name, joined)
		}
		fmt.Printf("\n  %s%d operator(s) connected%s\n\n", ColorGreen, int(count), ColorReset)
	},
}

// team claim <agent-id>  --session <session-id>
var teamClaimCmd = &cobra.Command{
	Use:   "claim <agent-id>",
	Short: "Claim exclusive write access to an agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		sessionID, _ := cmd.Flags().GetString("session")
		if sessionID == "" {
			printError("--session is required (get it from 'team subscribe' or 'team register')")
			os.Exit(1)
		}

		req, _ := http.NewRequest("POST",
			config.ServerURL+"/api/v1/team/agent/"+agentID+"/claim", nil)
		req.Header.Set("X-Session-ID", sessionID)
		if config.APIKey != "" {
			req.Header.Set("X-API-Key", config.APIKey)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			printError(fmt.Sprintf("Claim failed: %v", err))
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var apiResp APIResponse
		json.Unmarshal(body, &apiResp)
		if !apiResp.Success {
			printError(fmt.Sprintf("Claim failed: %s", apiResp.Error))
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("Agent %s claimed", agentID[:8]))
	},
}

// team release <agent-id>  --session <session-id>
var teamReleaseCmd = &cobra.Command{
	Use:   "release <agent-id>",
	Short: "Release your claim on an agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID, err := resolveAgentID(args[0])
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}
		sessionID, _ := cmd.Flags().GetString("session")
		if sessionID == "" {
			printError("--session is required")
			os.Exit(1)
		}

		req, _ := http.NewRequest("POST",
			config.ServerURL+"/api/v1/team/agent/"+agentID+"/release", nil)
		req.Header.Set("X-Session-ID", sessionID)
		if config.APIKey != "" {
			req.Header.Set("X-API-Key", config.APIKey)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			printError(fmt.Sprintf("Release failed: %v", err))
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var apiResp APIResponse
		json.Unmarshal(body, &apiResp)
		if !apiResp.Success {
			printError(fmt.Sprintf("Release failed: %s", apiResp.Error))
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("Agent %s released", agentID[:8]))
	},
}

// team broadcast --session <id> --message "text"
var teamBroadcastCmd = &cobra.Command{
	Use:   "broadcast",
	Short: "Send a note to all connected operators",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		sessionID, _ := cmd.Flags().GetString("session")
		message, _ := cmd.Flags().GetString("message")
		if message == "" {
			printError("--message is required")
			os.Exit(1)
		}

		payload, _ := json.Marshal(map[string]string{
			"type":    "note",
			"payload": message,
		})
		req, _ := http.NewRequest("POST",
			config.ServerURL+"/api/v1/team/broadcast",
			bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session-ID", sessionID)
		if config.APIKey != "" {
			req.Header.Set("X-API-Key", config.APIKey)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			printError(fmt.Sprintf("Broadcast failed: %v", err))
			os.Exit(1)
		}
		defer resp.Body.Close()
		printSuccess("Note broadcast to all operators")
	},
}

// ── private helpers ───────────────────────────────────────────────────────────

func printTeamEvent(ev teamEvent) {
	t := ev.Time
	if parsed, err := time.Parse(time.RFC3339, t); err == nil {
		t = parsed.Format("15:04:05")
	}

	var icon, color string
	switch ev.Type {
	case "agent_checkin":
		icon = "[+]"
		color = ColorGreen
	case "agent_offline":
		icon = "[-]"
		color = "\033[31m"
	case "result_ready":
		icon = "[=]"
		color = ColorCyan
	case "command_queued":
		icon = "[>]"
		color = ColorBlue
	case "operator_joined":
		icon = "[*]"
		color = ColorGreen
	case "operator_left":
		icon = "[*]"
		color = "\033[33m"
	case "agent_claimed":
		icon = "[L]"
		color = "\033[35m"
	case "agent_released":
		icon = "[U]"
		color = "\033[35m"
	case "note":
		icon = "[!]"
		color = "\033[33m"
	case "ping":
		return // suppress keepalive pings from display
	default:
		icon = "[?]"
		color = ColorReset
	}

	agentTag := ""
	if ev.AgentID != "" {
		tag := ev.AgentID
		if len(tag) > 8 {
			tag = tag[:8]
		}
		agentTag = fmt.Sprintf(" \033[2m[%s]\033[0m", tag)
	}
	opTag := ""
	if ev.OpName != "" && ev.OpName != "unknown" {
		opTag = fmt.Sprintf(" \033[2m<%s>\033[0m", ev.OpName)
	}

	fmt.Printf("  %s%s %s%s%s%s  %s\033[0m\n",
		color, icon, ColorReset,
		"\033[2m", t, "\033[0m",
		color+agentTag+opTag+" "+ev.Payload)
}
