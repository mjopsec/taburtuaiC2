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

// Color codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// Global variables
var (
	config = &CLIConfig{
		ServerURL: os.Getenv("TABURTUAI_SERVER"),
		APIKey:    os.Getenv("TABURTUAI_API_KEY"),
		Timeout:   30,
	}
	httpClient = &http.Client{Timeout: 30 * time.Second}
	verbose    bool
)

// CLIConfig holds configuration for the CLI
type CLIConfig struct {
	ServerURL string
	APIKey    string
	Timeout   int
}

// APIResponse represents standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Root command
var rootCmd = &cobra.Command{
	Use:   "taburtuai-cli",
	Short: "Taburtuai C2 Command Line Interface",
	Long: `Taburtuai C2 CLI - Enhanced Command & Control Interface
	
This CLI provides full control over the Taburtuai C2 server, allowing you to:
- Manage and monitor agents
- Execute commands remotely
- Transfer files
- View logs and statistics`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if config.ServerURL == "" {
			printError("TABURTUAI_SERVER environment variable not set")
			fmt.Println("Please set: export TABURTUAI_SERVER=http://localhost:8080")
			os.Exit(1)
		}
	},
}

// Agent commands
var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage agents",
	Long:  "List, view, and manage connected agents",
}

var agentsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all agents",
	Run: func(cmd *cobra.Command, args []string) {
		printInfo("Fetching agent list...")

		body, err := makeAPIRequest("/api/v1/agents")
		if err != nil {
			printError(fmt.Sprintf("Failed to fetch agents: %v", err))
			os.Exit(1)
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Server error: %s", response.Error))
			os.Exit(1)
		}

		data := response.Data.(map[string]interface{})
		agents := data["agents"].([]interface{})

		if len(agents) == 0 {
			printWarning("No agents found")
			return
		}

		printSuccess(fmt.Sprintf("Found %d agent(s)", len(agents)))
		fmt.Println()

		// Print table header
		fmt.Printf("%s%-36s %-20s %-15s %-10s %-20s%s\n",
			ColorBlue, "AGENT ID", "HOSTNAME", "USERNAME", "STATUS", "LAST SEEN", ColorReset)
		fmt.Println(strings.Repeat("-", 100))

		for _, agent := range agents {
			a := agent.(map[string]interface{})

			agentID := a["id"].(string)
			if len(agentID) > 8 {
				agentID = agentID[:8] + "..."
			}

			hostname := a["hostname"].(string)
			username := a["username"].(string)
			status := a["status"].(string)

			var statusColor string
			switch status {
			case "online":
				statusColor = ColorGreen
			case "offline":
				statusColor = ColorRed
			case "dormant":
				statusColor = ColorYellow
			default:
				statusColor = ColorWhite
			}

			lastSeen := "Unknown"
			if a["last_seen"] != nil {
				t, _ := time.Parse(time.RFC3339, a["last_seen"].(string))
				lastSeen = t.Format("2006-01-02 15:04:05")
			}

			fmt.Printf("%-36s %-20s %-15s %s%-10s%s %-20s\n",
				agentID, hostname, username, statusColor, status, ColorReset, lastSeen)
		}
	},
}

var agentsInfoCmd = &cobra.Command{
	Use:   "info <agent-id>",
	Short: "Show detailed agent information",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		printInfo(fmt.Sprintf("Fetching information for agent: %s", agentID))

		body, err := makeAPIRequest(fmt.Sprintf("/api/v1/agents/%s", agentID))
		if err != nil {
			printError(fmt.Sprintf("Failed to fetch agent info: %v", err))
			os.Exit(1)
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error: %s", response.Error))
			os.Exit(1)
		}

		agent := response.Data.(map[string]interface{})

		fmt.Printf("\n%sAgent Information:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 50))

		fmt.Printf("%sID:%s %s\n", ColorCyan, ColorReset, agent["id"])
		fmt.Printf("%sHostname:%s %s\n", ColorCyan, ColorReset, agent["hostname"])
		fmt.Printf("%sUsername:%s %s\n", ColorCyan, ColorReset, agent["username"])
		fmt.Printf("%sOS:%s %s\n", ColorCyan, ColorReset, agent["os"])
		fmt.Printf("%sStatus:%s %s\n", ColorCyan, ColorReset, agent["status"])

		if agent["last_seen"] != nil {
			t, _ := time.Parse(time.RFC3339, agent["last_seen"].(string))
			fmt.Printf("%sLast Seen:%s %s\n", ColorCyan, ColorReset, t.Format("2006-01-02 15:04:05"))
		}
	},
}

// Command execution command
var cmdCmd = &cobra.Command{
	Use:   "cmd <agent-id> <command>",
	Short: "Execute command on agent",
	Long:  "Execute a command on the specified agent and wait for results",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		command := args[1]

		// Optional flags
		timeout, _ := cmd.Flags().GetInt("timeout")
		workDir, _ := cmd.Flags().GetString("workdir")
		background, _ := cmd.Flags().GetBool("background")

		printInfo(fmt.Sprintf("Executing command on agent %s", agentID[:8]))
		printVerbose(fmt.Sprintf("Command: %s", command))

		// Prepare request
		reqBody := map[string]interface{}{
			"agent_id": agentID,
			"command":  command,
			"timeout":  timeout,
		}

		if workDir != "" {
			reqBody["working_dir"] = workDir
		}

		// Send command
		reqJSON, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", config.ServerURL+"/api/v1/command", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		if config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+config.APIKey)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			printError(fmt.Sprintf("Failed to send command: %v", err))
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Command failed: %s", response.Error))
			os.Exit(1)
		}

		// Extract command ID
		data := response.Data.(map[string]interface{})
		commandID := data["command_id"].(string)

		printSuccess(fmt.Sprintf("Command queued with ID: %s", commandID))

		if background {
			printInfo("Background mode - use 'status' command to check results")
			fmt.Printf("\nCheck status with: %staburtuai-cli status %s%s\n",
				ColorCyan, commandID, ColorReset)
			return
		}

		// Wait for results
		printInfo("Waiting for command execution...")

		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		spinIdx := 0

		startTime := time.Now()
		for {
			// Check command status
			statusResp, err := makeAPIRequest(fmt.Sprintf("/api/v1/command/%s/status", commandID))
			if err != nil {
				printError(fmt.Sprintf("Failed to check status: %v", err))
				os.Exit(1)
			}

			var statusResponse APIResponse
			if err := json.Unmarshal(statusResp, &statusResponse); err != nil {
				printError("Failed to parse status response")
				os.Exit(1)
			}

			if statusResponse.Success {
				cmdData := statusResponse.Data.(map[string]interface{})
				status := cmdData["status"].(string)

				switch status {
				case "completed", "failed", "timeout":
					// Command finished
					fmt.Print("\r") // Clear spinner

					// Safe parsing with nil checks
					exitCode := 0
					if cmdData["exit_code"] != nil {
						exitCode = int(cmdData["exit_code"].(float64))
					}

					output := ""
					if cmdData["output"] != nil {
						output = cmdData["output"].(string)
					}

					errorMsg := ""
					if cmdData["error"] != nil {
						errorMsg = cmdData["error"].(string)
					}

					duration := time.Since(startTime)

					// Display results
					fmt.Printf("\n%s═══════════════════════════════════════════════════════════════%s\n",
						ColorBlue, ColorReset)

					if status == "completed" && exitCode == 0 {
						printSuccess(fmt.Sprintf("Command completed successfully (%.2fs)", duration.Seconds()))
					} else if status == "timeout" {
						printError(fmt.Sprintf("Command timed out after %d seconds", timeout))
					} else {
						printError(fmt.Sprintf("Command failed with exit code %d", exitCode))
					}

					fmt.Printf("%sCommand:%s %s\n", ColorCyan, ColorReset, command)
					fmt.Printf("%sAgent:%s %s\n", ColorCyan, ColorReset, agentID[:8])
					fmt.Printf("%sDuration:%s %.2f seconds\n", ColorCyan, ColorReset, duration.Seconds())
					fmt.Printf("%sExit Code:%s %d\n", ColorCyan, ColorReset, exitCode)

					if output != "" {
						fmt.Printf("\n%sOutput:%s\n", ColorGreen, ColorReset)
						fmt.Println(output)
					}

					if errorMsg != "" {
						fmt.Printf("\n%sError:%s\n", ColorRed, ColorReset)
						fmt.Println(errorMsg)
					}

					fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n",
						ColorBlue, ColorReset)

					if exitCode != 0 {
						os.Exit(exitCode)
					}
					return

				case "executing":
					// Still running - show spinner
					fmt.Printf("\r%s Executing... %s", spinner[spinIdx], strings.Repeat(" ", 20))
					spinIdx = (spinIdx + 1) % len(spinner)
				}
			}

			time.Sleep(200 * time.Millisecond)
		}
	},
}

// Interactive shell command
var shellCmd = &cobra.Command{
	Use:   "shell <agent-id>",
	Short: "Start interactive shell session",
	Long:  "Start an interactive shell session with the specified agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]

		printInfo(fmt.Sprintf("Starting interactive shell with agent %s", agentID[:8]))
		printWarning("Type 'exit' or press Ctrl+C to quit")
		fmt.Println()

		reader := bufio.NewReader(os.Stdin)

		for {
			// Show prompt
			fmt.Printf("%s[%s]%s $ ", ColorGreen, agentID[:8], ColorReset)

			// Read command
			input, err := reader.ReadString('\n')
			if err != nil {
				break
			}

			command := strings.TrimSpace(input)
			if command == "" {
				continue
			}

			if command == "exit" || command == "quit" {
				printInfo("Exiting shell session")
				break
			}

			// Execute command
			executeShellCommand(agentID, command)
		}
	},
}

// Helper function for shell command execution
func executeShellCommand(agentID, command string) {
	reqBody := map[string]interface{}{
		"agent_id": agentID,
		"command":  command,
		"timeout":  30, // 30 seconds for shell commands
	}

	reqJSON, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", config.ServerURL+"/api/v1/command", bytes.NewBuffer(reqJSON))
	req.Header.Set("Content-Type", "application/json")
	if config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", ColorRed, err, ColorReset)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var response APIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Printf("%sError: Failed to parse response%s\n", ColorRed, ColorReset)
		return
	}

	if !response.Success {
		fmt.Printf("%sError: %s%s\n", ColorRed, response.Error, ColorReset)
		return
	}

	// Get command ID and wait for result
	data := response.Data.(map[string]interface{})
	commandID := data["command_id"].(string)

	// Poll for results
	for i := 0; i < 60; i++ { // Max 30 seconds
		time.Sleep(500 * time.Millisecond)

		statusResp, err := makeAPIRequest(fmt.Sprintf("/api/v1/command/%s/status", commandID))
		if err != nil {
			continue
		}

		var statusResponse APIResponse
		if err := json.Unmarshal(statusResp, &statusResponse); err != nil {
			continue
		}

		if statusResponse.Success {
			cmdData := statusResponse.Data.(map[string]interface{})
			status := cmdData["status"].(string)

			if status == "completed" || status == "failed" || status == "timeout" {
				output := ""
				if cmdData["output"] != nil {
					output = cmdData["output"].(string)
				}
				errorMsg := ""
				if cmdData["error"] != nil {
					errorMsg = cmdData["error"].(string)
				}

				if output != "" {
					fmt.Print(output)
					if !strings.HasSuffix(output, "\n") {
						fmt.Println()
					}
				}

				if errorMsg != "" {
					fmt.Printf("%s%s%s\n", ColorRed, errorMsg, ColorReset)
				}

				break
			}
		}
	}
}

// Command status command
var statusCmd = &cobra.Command{
	Use:   "status <command-id>",
	Short: "Check command execution status",
	Long:  "Check the status of a previously executed command",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		commandID := args[0]

		printInfo(fmt.Sprintf("Checking status for command: %s", commandID))

		body, err := makeAPIRequest(fmt.Sprintf("/api/v1/command/%s/status", commandID))
		if err != nil {
			printError(fmt.Sprintf("Failed to get command status: %v", err))
			os.Exit(1)
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error: %s", response.Error))
			os.Exit(1)
		}

		// Display command details
		cmdData := response.Data.(map[string]interface{})

		fmt.Printf("\n%sCommand Details:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 60))

		fmt.Printf("%sCommand ID:%s %s\n", ColorCyan, ColorReset, cmdData["command_id"])
		fmt.Printf("%sAgent ID:%s %s\n", ColorCyan, ColorReset, cmdData["agent_id"])
		fmt.Printf("%sCommand:%s %s\n", ColorCyan, ColorReset, cmdData["command"])
		fmt.Printf("%sStatus:%s ", ColorCyan, ColorReset)

		status := cmdData["status"].(string)
		switch status {
		case "pending":
			fmt.Printf("%s%s%s\n", ColorYellow, status, ColorReset)
		case "executing":
			fmt.Printf("%s%s%s\n", ColorBlue, status, ColorReset)
		case "completed":
			fmt.Printf("%s%s%s\n", ColorGreen, status, ColorReset)
		case "failed", "timeout":
			fmt.Printf("%s%s%s\n", ColorRed, status, ColorReset)
		default:
			fmt.Println(status)
		}

		if cmdData["created_at"] != nil {
			created, _ := time.Parse(time.RFC3339, cmdData["created_at"].(string))
			fmt.Printf("%sCreated:%s %s\n", ColorCyan, ColorReset, created.Format("2006-01-02 15:04:05"))
		}

		if cmdData["executed_at"] != nil && cmdData["executed_at"] != "" {
			executed, _ := time.Parse(time.RFC3339, cmdData["executed_at"].(string))
			fmt.Printf("%sExecuted:%s %s\n", ColorCyan, ColorReset, executed.Format("2006-01-02 15:04:05"))
		}

		if cmdData["completed_at"] != nil && cmdData["completed_at"] != "" {
			completed, _ := time.Parse(time.RFC3339, cmdData["completed_at"].(string))
			fmt.Printf("%sCompleted:%s %s\n", ColorCyan, ColorReset, completed.Format("2006-01-02 15:04:05"))
		}

		if cmdData["exit_code"] != nil {
			exitCode := int(cmdData["exit_code"].(float64))
			fmt.Printf("%sExit Code:%s %d\n", ColorCyan, ColorReset, exitCode)
		}

		if cmdData["output"] != nil && cmdData["output"] != "" {
			fmt.Printf("\n%sOutput:%s\n", ColorGreen, ColorReset)
			fmt.Println(cmdData["output"].(string))
		}

		if cmdData["error"] != nil && cmdData["error"] != "" {
			fmt.Printf("\n%sError:%s\n", ColorRed, ColorReset)
			fmt.Println(cmdData["error"].(string))
		}

		fmt.Println()
	},
}

// History command
var historyCmd = &cobra.Command{
	Use:   "history <agent-id>",
	Short: "Show agent command history",
	Long:  "Display the command execution history for the specified agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		limit, _ := cmd.Flags().GetInt("limit")
		statusFilter, _ := cmd.Flags().GetString("status")

		printInfo(fmt.Sprintf("Fetching command history for agent: %s", agentID[:8]))

		endpoint := fmt.Sprintf("/api/v1/agent/%s/commands?limit=%d", agentID, limit)
		if statusFilter != "" {
			endpoint += "&status=" + statusFilter
		}

		body, err := makeAPIRequest(endpoint)
		if err != nil {
			printError(fmt.Sprintf("Failed to get command history: %v", err))
			os.Exit(1)
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error: %s", response.Error))
			os.Exit(1)
		}

		data := response.Data.(map[string]interface{})
		commands := data["commands"].([]interface{})

		if len(commands) == 0 {
			printWarning("No command history found for this agent")
			return
		}

		printSuccess(fmt.Sprintf("Found %d command(s) in history", len(commands)))
		fmt.Println()

		// Table header
		fmt.Printf("%s%-36s %-20s %-10s %-8s %-30s%s\n",
			ColorBlue, "COMMAND ID", "TIMESTAMP", "STATUS", "EXIT", "COMMAND", ColorReset)
		fmt.Println(strings.Repeat("-", 110))

		for _, item := range commands {
			cmd := item.(map[string]interface{})

			cmdID := cmd["id"].(string)
			if len(cmdID) > 8 {
				cmdID = cmdID[:8] + "..."
			}

			timestamp := "N/A"
			if cmd["executed_at"] != nil && cmd["executed_at"] != "" {
				t, _ := time.Parse(time.RFC3339, cmd["executed_at"].(string))
				timestamp = t.Format("2006-01-02 15:04:05")
			} else if cmd["created_at"] != nil {
				t, _ := time.Parse(time.RFC3339, cmd["created_at"].(string))
				timestamp = t.Format("2006-01-02 15:04:05")
			}

			status := cmd["status"].(string)
			var statusColor string
			switch status {
			case "completed":
				statusColor = ColorGreen
			case "failed", "timeout":
				statusColor = ColorRed
			case "executing":
				statusColor = ColorBlue
			case "pending":
				statusColor = ColorYellow
			default:
				statusColor = ColorWhite
			}

			exitCode := "-"
			if cmd["exit_code"] != nil {
				exitCode = fmt.Sprintf("%d", int(cmd["exit_code"].(float64)))
			}

			command := cmd["command"].(string)
			if len(command) > 30 {
				command = command[:27] + "..."
			}

			fmt.Printf("%-36s %-20s %s%-10s%s %-8s %-30s\n",
				cmdID,
				timestamp,
				statusColor,
				status,
				ColorReset,
				exitCode,
				command)
		}

		fmt.Println()
		fmt.Printf("%sUse 'taburtuai-cli status <command-id>' for detailed information%s\n",
			ColorCyan, ColorReset)
	},
}

// Queue management command
var queueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Manage command queues",
	Long:  "View and manage command queues for agents",
}

var queueStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show queue statistics",
	Run: func(cmd *cobra.Command, args []string) {
		printInfo("Fetching queue statistics...")

		body, err := makeAPIRequest("/api/v1/queue/stats")
		if err != nil {
			printError(fmt.Sprintf("Failed to get queue stats: %v", err))
			os.Exit(1)
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error: %s", response.Error))
			os.Exit(1)
		}

		stats := response.Data.(map[string]interface{})

		fmt.Printf("\n%sQueue Statistics:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 50))
		fmt.Printf("%sTotal Queued:%s %d\n", ColorCyan, ColorReset, int(stats["total_queued"].(float64)))
		fmt.Printf("%sTotal Active:%s %d\n", ColorCyan, ColorReset, int(stats["total_active"].(float64)))
		fmt.Printf("%sTotal Completed:%s %d\n", ColorCyan, ColorReset, int(stats["total_completed"].(float64)))

		if byAgent, ok := stats["by_agent"].(map[string]interface{}); ok && len(byAgent) > 0 {
			fmt.Printf("\n%sBy Agent:%s\n", ColorBlue, ColorReset)
			fmt.Println(strings.Repeat("-", 50))

			for agentID, agentStats := range byAgent {
				as := agentStats.(map[string]interface{})
				fmt.Printf("  %s%s%s:\n", ColorYellow, agentID[:8], ColorReset)
				fmt.Printf("    Queued: %d, Active: %d, Completed: %d\n",
					int(as["queued"].(float64)),
					int(as["active"].(float64)),
					int(as["completed"].(float64)))
			}
		}

		fmt.Println()
	},
}

var queueClearCmd = &cobra.Command{
	Use:   "clear <agent-id>",
	Short: "Clear pending commands for an agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]

		printWarning(fmt.Sprintf("Clearing command queue for agent %s", agentID[:8]))

		req, _ := http.NewRequest("DELETE",
			config.ServerURL+"/api/v1/agent/"+agentID+"/queue", nil)
		if config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+config.APIKey)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			printError(fmt.Sprintf("Failed to clear queue: %v", err))
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if response.Success {
			printSuccess(response.Message)
		} else {
			printError(fmt.Sprintf("Error: %s", response.Error))
		}
	},
}

// Files command (placeholder)
var filesCmd = &cobra.Command{
	Use:   "files",
	Short: "File operations",
	Long:  "Upload, download, and manage files",
}

var filesUploadCmd = &cobra.Command{
	Use:   "upload <agent-id> <local-file> <remote-path>",
	Short: "Upload file to agent",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		printWarning("File upload not yet implemented in Phase 2A")
		printInfo("This feature will be available in Phase 2C")
	},
}

var filesDownloadCmd = &cobra.Command{
	Use:   "download <agent-id> <remote-file> <local-path>",
	Short: "Download file from agent",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		printWarning("File download not yet implemented in Phase 2A")
		printInfo("This feature will be available in Phase 2C")
	},
}

// Logs command
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show server logs",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")

		printInfo(fmt.Sprintf("Fetching last %d log entries...", limit))

		body, err := makeAPIRequest(fmt.Sprintf("/api/v1/logs?limit=%d", limit))
		if err != nil {
			printError(fmt.Sprintf("Failed to fetch logs: %v", err))
			os.Exit(1)
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error: %s", response.Error))
			os.Exit(1)
		}

		logs := response.Data.([]interface{})
		if len(logs) == 0 {
			printWarning("No logs found")
			return
		}

		printSuccess(fmt.Sprintf("Showing %d log entries", len(logs)))
		fmt.Println()

		for _, log := range logs {
			entry := log.(map[string]interface{})

			timestamp := entry["timestamp"].(string)
			level := entry["level"].(string)
			category := entry["category"].(string)
			message := entry["message"].(string)

			var levelColor string
			switch level {
			case "INFO":
				levelColor = ColorBlue
			case "WARN":
				levelColor = ColorYellow
			case "ERROR", "CRITICAL":
				levelColor = ColorRed
			default:
				levelColor = ColorWhite
			}

			fmt.Printf("%s[%s]%s [%s] %s - %s\n",
				levelColor, level, ColorReset,
				timestamp, category, message)
		}
	},
}

// Stats command
var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show server statistics",
	Run: func(cmd *cobra.Command, args []string) {
		printInfo("Fetching server statistics...")

		body, err := makeAPIRequest("/api/v1/stats")
		if err != nil {
			printError(fmt.Sprintf("Failed to fetch stats: %v", err))
			os.Exit(1)
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError("Failed to parse response")
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error: %s", response.Error))
			os.Exit(1)
		}

		stats := response.Data.(map[string]interface{})

		fmt.Printf("\n%sServer Statistics:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 50))

		if agentStats, ok := stats["agents"].(map[string]interface{}); ok {
			fmt.Printf("%sAgent Statistics:%s\n", ColorCyan, ColorReset)
			fmt.Printf("  Total Agents: %d\n", int(agentStats["total_agents"].(float64)))
			fmt.Printf("  Online: %s%d%s\n", ColorGreen, int(agentStats["online_agents"].(float64)), ColorReset)
			fmt.Printf("  Offline: %s%d%s\n", ColorRed, int(agentStats["offline_agents"].(float64)), ColorReset)
			fmt.Printf("  Total Commands: %d\n", int(agentStats["total_commands"].(float64)))
		}

		if serverInfo, ok := stats["server"].(map[string]interface{}); ok {
			fmt.Printf("\n%sServer Information:%s\n", ColorCyan, ColorReset)
			fmt.Printf("  Version: %s\n", serverInfo["version"])
			fmt.Printf("  Uptime: %s\n", serverInfo["uptime"])
		}

		fmt.Println()
	},
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show CLI version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%sTaburtuai CLI%s\n", ColorGreen, ColorReset)
		fmt.Println("Version: 2.0 - Phase 2A")
		fmt.Println("Features: Enhanced Command Execution")
		fmt.Printf("Server: %s\n", config.ServerURL)

		if config.APIKey != "" {
			fmt.Println("API Key: Configured")
		} else {
			fmt.Println("API Key: Not configured")
		}
	},
}

// Helper functions
func makeAPIRequest(endpoint string) ([]byte, error) {
	url := config.ServerURL + endpoint

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return body, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return body, nil
}

func printInfo(msg string) {
	fmt.Printf("%s[INFO]%s %s\n", ColorBlue, ColorReset, msg)
}

func printSuccess(msg string) {
	fmt.Printf("%s[SUCCESS]%s %s\n", ColorGreen, ColorReset, msg)
}

func printWarning(msg string) {
	fmt.Printf("%s[WARNING]%s %s\n", ColorYellow, ColorReset, msg)
}

func printError(msg string) {
	fmt.Printf("%s[ERROR]%s %s\n", ColorRed, ColorReset, msg)
}

func printVerbose(msg string) {
	if verbose {
		fmt.Printf("%s[DEBUG]%s %s\n", ColorPurple, ColorReset, msg)
	}
}

// Initialize commands
func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&config.ServerURL, "server", "s", config.ServerURL, "C2 server URL")
	rootCmd.PersistentFlags().StringVarP(&config.APIKey, "api-key", "k", config.APIKey, "API key for authentication")
	rootCmd.PersistentFlags().IntVarP(&config.Timeout, "timeout", "t", 30, "Request timeout in seconds")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add commands to root
	rootCmd.AddCommand(agentsCmd)
	rootCmd.AddCommand(cmdCmd)
	rootCmd.AddCommand(shellCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(queueCmd)
	rootCmd.AddCommand(filesCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(versionCmd)

	// Add subcommands to agents
	agentsCmd.AddCommand(agentsListCmd)
	agentsCmd.AddCommand(agentsInfoCmd)

	// Add subcommands to queue
	queueCmd.AddCommand(queueStatsCmd)
	queueCmd.AddCommand(queueClearCmd)

	// Add subcommands to files
	filesCmd.AddCommand(filesUploadCmd)
	filesCmd.AddCommand(filesDownloadCmd)

	// Command flags
	cmdCmd.Flags().IntP("timeout", "", 300, "Command timeout in seconds")
	cmdCmd.Flags().StringP("workdir", "w", "", "Working directory for command")
	cmdCmd.Flags().BoolP("background", "b", false, "Run command in background")

	historyCmd.Flags().IntP("limit", "l", 50, "Number of commands to show")
	historyCmd.Flags().StringP("status", "", "", "Filter by status (completed, failed, etc)")

	logsCmd.Flags().IntP("limit", "l", 100, "Number of log entries to show")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		printError(fmt.Sprintf("Failed to execute: %v", err))
		os.Exit(1)
	}
}
