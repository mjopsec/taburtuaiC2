package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// CLI Configuration
type CLIConfig struct {
	ServerURL string
	APIKey    string
	Timeout   time.Duration
	Verbose   bool
}

// Agent represents an agent in the system
type Agent struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	Username     string    `json:"username"`
	OS           string    `json:"os"`
	Architecture string    `json:"architecture"`
	ProcessID    int       `json:"process_id"`
	LastSeen     time.Time `json:"last_seen"`
	Status       string    `json:"status"`
	IPAddress    string    `json:"ip_address,omitempty"`
}

// ServerStatus represents server status
type ServerStatus struct {
	Status      string    `json:"status"`
	Version     string    `json:"version"`
	Uptime      string    `json:"uptime"`
	AgentCount  int       `json:"agent_count"`
	LastCheckin time.Time `json:"last_checkin"`
}

var config CLIConfig

// Colors for output
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

// HTTP Client with timeout
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// Print colored output functions
func printSuccess(msg string) {
	fmt.Printf("%s[SUCCESS]%s %s\n", ColorGreen, ColorReset, msg)
}

func printError(msg string) {
	fmt.Printf("%s[ERROR]%s %s\n", ColorRed, ColorReset, msg)
}

func printWarning(msg string) {
	fmt.Printf("%s[WARNING]%s %s\n", ColorYellow, ColorReset, msg)
}

func printInfo(msg string) {
	fmt.Printf("%s[INFO]%s %s\n", ColorBlue, ColorReset, msg)
}

func printVerbose(msg string) {
	if config.Verbose {
		fmt.Printf("%s[DEBUG]%s %s\n", ColorPurple, ColorReset, msg)
	}
}

// Make API request
func makeAPIRequest(endpoint string) ([]byte, error) {
	url := config.ServerURL + endpoint
	printVerbose(fmt.Sprintf("Making request to: %s", url))
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("User-Agent", "Taburtuai-CLI/2.0")
	req.Header.Set("Accept", "application/json")
	
	if config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
	}
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	printVerbose(fmt.Sprintf("Response status: %d", resp.StatusCode))
	printVerbose(fmt.Sprintf("Response body: %s", string(body)))
	
	if resp.StatusCode != 200 {
		return body, fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	
	return body, nil
}

// Helper functions
func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt(data map[string]interface{}, key string) int {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return 0
}

func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

// Root command
var rootCmd = &cobra.Command{
	Use:   "taburtuai-cli",
	Short: "Taburtuai C2 Command Line Interface",
	Long: `Taburtuai CLI - Command and control interface for the Taburtuai C2 framework.
	
This tool allows you to interact with your Taburtuai C2 server to manage agents,
view system status, and execute commands.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if config.ServerURL == "" {
			config.ServerURL = "http://localhost:8080"
		}
		if config.Timeout == 0 {
			config.Timeout = 30 * time.Second
		}
		httpClient.Timeout = config.Timeout
	},
}

// Status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show server status",
	Long:  "Display the current status of the Taburtuai C2 server",
	Run: func(cmd *cobra.Command, args []string) {
		printInfo("Checking server status...")
		
		body, err := makeAPIRequest("/api/v1/health")
		if err != nil {
			printError(fmt.Sprintf("Failed to get server status: %v", err))
			os.Exit(1)
		}
		
		var status ServerStatus
		if err := json.Unmarshal(body, &status); err != nil {
			var apiResp map[string]interface{}
			if err := json.Unmarshal(body, &apiResp); err != nil {
				printError(fmt.Sprintf("Failed to parse response: %v", err))
				printVerbose(fmt.Sprintf("Raw response: %s", string(body)))
				os.Exit(1)
			}
			
			if success, ok := apiResp["success"].(bool); ok && success {
				printSuccess("Server is online and responding")
				fmt.Printf("  Server URL: %s%s%s\n", ColorCyan, config.ServerURL, ColorReset)
				if message, ok := apiResp["message"].(string); ok {
					fmt.Printf("  Response: %s\n", message)
				}
				return
			}
		}
		
		printSuccess("Server is online")
		fmt.Printf("  %sServer URL:%s %s\n", ColorBlue, ColorReset, config.ServerURL)
		fmt.Printf("  %sStatus:%s %s\n", ColorBlue, ColorReset, status.Status)
		if status.Version != "" {
			fmt.Printf("  %sVersion:%s %s\n", ColorBlue, ColorReset, status.Version)
		}
		if status.Uptime != "" {
			fmt.Printf("  %sUptime:%s %s\n", ColorBlue, ColorReset, status.Uptime)
		}
		fmt.Printf("  %sAgent Count:%s %d\n", ColorBlue, ColorReset, status.AgentCount)
		if !status.LastCheckin.IsZero() {
			fmt.Printf("  %sLast Checkin:%s %s\n", ColorBlue, ColorReset, status.LastCheckin.Format("2006-01-02 15:04:05"))
		}
	},
}

// Stats command
var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show server statistics",
	Long:  "Display detailed server statistics and metrics",
	Run: func(cmd *cobra.Command, args []string) {
		printInfo("Fetching server statistics...")
		
		body, err := makeAPIRequest("/api/v1/stats")
		if err != nil {
			printError(fmt.Sprintf("Failed to get server stats: %v", err))
			os.Exit(1)
		}
		
		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse stats response: %v", err))
			os.Exit(1)
		}
		
		if data, ok := response["data"].(map[string]interface{}); ok {
			fmt.Printf("\n%sServer Statistics:%s\n", ColorBlue, ColorReset)
			fmt.Println(strings.Repeat("=", 50))
			fmt.Printf("  %sServer Version:%s %s\n", ColorCyan, ColorReset, getString(data, "server_version"))
			fmt.Printf("  %sUptime:%s %s\n", ColorCyan, ColorReset, getString(data, "server_uptime"))
			fmt.Printf("  %sTotal Agents:%s %d\n", ColorCyan, ColorReset, getInt(data, "total_agents"))
			fmt.Printf("  %sOnline Agents:%s %s%d%s\n", ColorCyan, ColorReset, ColorGreen, getInt(data, "online_agents"), ColorReset)
			fmt.Printf("  %sDormant Agents:%s %s%d%s\n", ColorCyan, ColorReset, ColorYellow, getInt(data, "dormant_agents"), ColorReset)
			fmt.Printf("  %sOffline Agents:%s %s%d%s\n", ColorCyan, ColorReset, ColorRed, getInt(data, "offline_agents"), ColorReset)
			fmt.Printf("  %sActive Sessions:%s %d\n", ColorCyan, ColorReset, getInt(data, "active_sessions"))
			fmt.Println()
		}
	},
}

// Agents command group
var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage agents",
	Long:  "Commands to list, interact with, and manage connected agents",
}

// Agents list command
var agentsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all agents",
	Long:  "Display a list of all connected and recently seen agents",
	Run: func(cmd *cobra.Command, args []string) {
		printInfo("Fetching agents list...")
		
		body, err := makeAPIRequest("/api/v1/agents")
		if err != nil {
			printError(fmt.Sprintf("Failed to get agents: %v", err))
			os.Exit(1)
		}
		
		var responseData map[string]interface{}
		if err := json.Unmarshal(body, &responseData); err != nil {
			printError(fmt.Sprintf("Failed to parse response: %v", err))
			printVerbose(fmt.Sprintf("Raw response: %s", string(body)))
			os.Exit(1)
		}
		
		var agents []Agent
		
		// Handle nested format: {"success":true,"data":{"agents":[...],"total":2}}
		if data, ok := responseData["data"].(map[string]interface{}); ok {
			if agentsArray, ok := data["agents"].([]interface{}); ok {
				for _, item := range agentsArray {
					if agentData, ok := item.(map[string]interface{}); ok {
						agent := Agent{
							ID:           getString(agentData, "id"),
							Hostname:     getString(agentData, "hostname"),
							Username:     getString(agentData, "username"),
							OS:           getString(agentData, "os"),
							Architecture: getString(agentData, "architecture"),
							ProcessID:    getInt(agentData, "process_id"),
							Status:       getString(agentData, "status"),
							IPAddress:    getString(agentData, "ip_address"),
						}
						
						if lastSeenStr := getString(agentData, "last_seen"); lastSeenStr != "" {
							if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
								agent.LastSeen = t
							}
						}
						
						agents = append(agents, agent)
					}
				}
			}
		} else {
			// Try direct array format
			var agentsArray []interface{}
			if directArray, ok := responseData["data"].([]interface{}); ok {
				agentsArray = directArray
			} else {
				if err := json.Unmarshal(body, &agentsArray); err != nil {
					printError("Unable to parse agents data in any expected format")
					printVerbose(fmt.Sprintf("Response structure: %+v", responseData))
					os.Exit(1)
				}
			}
			
			for _, item := range agentsArray {
				if agentData, ok := item.(map[string]interface{}); ok {
					agent := Agent{
						ID:           getString(agentData, "id"),
						Hostname:     getString(agentData, "hostname"),
						Username:     getString(agentData, "username"),
						OS:           getString(agentData, "os"),
						Architecture: getString(agentData, "architecture"),
						ProcessID:    getInt(agentData, "process_id"),
						Status:       getString(agentData, "status"),
						IPAddress:    getString(agentData, "ip_address"),
					}
					
					if lastSeenStr := getString(agentData, "last_seen"); lastSeenStr != "" {
						if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
							agent.LastSeen = t
						}
					}
					
					agents = append(agents, agent)
				}
			}
		}
		
		if len(agents) == 0 {
			printWarning("No agents found")
			printInfo("Agents will appear here once they connect to the server")
			printVerbose(fmt.Sprintf("Full response: %s", string(body)))
			return
		}
		
		printSuccess(fmt.Sprintf("Found %d agent(s)", len(agents)))
		fmt.Println()
		
		// Header
		fmt.Printf("%s%-32s %-15s %-12s %-8s %-10s %-8s %-12s%s\n",
			ColorBlue, "AGENT ID", "HOSTNAME", "USERNAME", "OS", "STATUS", "PID", "LAST SEEN", ColorReset)
		fmt.Println(strings.Repeat("-", 110))
		
		// Agent rows
		for _, agent := range agents {
			lastSeen := "Never"
			if !agent.LastSeen.IsZero() {
				if time.Since(agent.LastSeen) < time.Minute {
					lastSeen = "Just now"
				} else if time.Since(agent.LastSeen) < time.Hour {
					lastSeen = fmt.Sprintf("%dm ago", int(time.Since(agent.LastSeen).Minutes()))
				} else {
					lastSeen = agent.LastSeen.Format("15:04:05")
				}
			}
			
			var statusColor string
			switch strings.ToLower(agent.Status) {
			case "online", "active":
				statusColor = ColorGreen
			case "offline":
				statusColor = ColorRed
			case "dormant":
				statusColor = ColorYellow
			default:
				statusColor = ColorWhite
			}
			
			shortID := agent.ID
			if len(shortID) > 8 && strings.Contains(shortID, "-") {
				shortID = shortID[:8] + "..."
			}
			
			fmt.Printf("%-32s %-15s %-12s %-8s %s%-10s%s %-8d %-12s\n",
				shortID,
				truncateString(agent.Hostname, 15),
				truncateString(agent.Username, 12),
				agent.OS,
				statusColor,
				agent.Status,
				ColorReset,
				agent.ProcessID,
				lastSeen)
		}
		
		fmt.Println()
		printInfo(fmt.Sprintf("Use '%staburtuai-cli agents show <id>%s' for detailed agent information", ColorCyan, ColorReset))
		printInfo(fmt.Sprintf("Total active sessions: %s%d%s", ColorGreen, len(agents), ColorReset))
	},
}

// Agents show command
var agentsShowCmd = &cobra.Command{
	Use:   "show <agent-id>",
	Short: "Show detailed agent information",
	Long:  "Display detailed information about a specific agent",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		printInfo(fmt.Sprintf("Fetching agent details for: %s", agentID))
		
		body, err := makeAPIRequest(fmt.Sprintf("/api/v1/agents/%s", agentID))
		if err != nil {
			printError(fmt.Sprintf("Failed to get agent details: %v", err))
			os.Exit(1)
		}
		
		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse agent details: %v", err))
			printVerbose(fmt.Sprintf("Raw response: %s", string(body)))
			os.Exit(1)
		}
		
		if success, ok := response["success"].(bool); !ok || !success {
			if message, ok := response["message"].(string); ok {
				printError(fmt.Sprintf("API Error: %s", message))
			} else {
				printError("Failed to fetch agent details")
			}
			os.Exit(1)
		}
		
		var agent Agent
		if data, ok := response["data"].(map[string]interface{}); ok {
			agent = Agent{
				ID:           getString(data, "id"),
				Hostname:     getString(data, "hostname"),
				Username:     getString(data, "username"),
				OS:           getString(data, "os"),
				Architecture: getString(data, "architecture"),
				ProcessID:    getInt(data, "process_id"),
				Status:       getString(data, "status"),
				IPAddress:    getString(data, "ip_address"),
			}
			
			if lastSeenStr := getString(data, "last_seen"); lastSeenStr != "" {
				if t, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
					agent.LastSeen = t
				}
			}
		} else {
			printError("Invalid response format")
			os.Exit(1)
		}
		
		fmt.Printf("\n%sAgent Details:%s\n", ColorBlue, ColorReset)
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("  %sAgent ID:%s %s\n", ColorCyan, ColorReset, agent.ID)
		fmt.Printf("  %sHostname:%s %s\n", ColorCyan, ColorReset, agent.Hostname)
		fmt.Printf("  %sUsername:%s %s\n", ColorCyan, ColorReset, agent.Username)
		fmt.Printf("  %sOperating System:%s %s\n", ColorCyan, ColorReset, agent.OS)
		fmt.Printf("  %sArchitecture:%s %s\n", ColorCyan, ColorReset, agent.Architecture)
		fmt.Printf("  %sProcess ID:%s %d\n", ColorCyan, ColorReset, agent.ProcessID)
		
		var statusColor string
		switch strings.ToLower(agent.Status) {
		case "online":
			statusColor = ColorGreen
		case "dormant":
			statusColor = ColorYellow
		case "offline":
			statusColor = ColorRed
		default:
			statusColor = ColorWhite
		}
		fmt.Printf("  %sStatus:%s %s%s%s\n", ColorCyan, ColorReset, statusColor, agent.Status, ColorReset)
		
		if agent.IPAddress != "" {
			fmt.Printf("  %sIP Address:%s %s\n", ColorCyan, ColorReset, agent.IPAddress)
		}
		if !agent.LastSeen.IsZero() {
			fmt.Printf("  %sLast Seen:%s %s\n", ColorCyan, ColorReset, agent.LastSeen.Format("2006-01-02 15:04:05"))
			fmt.Printf("  %sLast Activity:%s %s ago\n", ColorCyan, ColorReset, time.Since(agent.LastSeen).Round(time.Second))
		}
		fmt.Println()
		
		fmt.Printf("%sAvailable Commands:%s\n", ColorBlue, ColorReset)
		fmt.Printf("  %staburtuai-cli cmd %s \"<command>\"%s - Execute command\n", ColorGreen, agent.ID, ColorReset)
		fmt.Printf("  %staburtuai-cli history %s%s - View command history\n", ColorGreen, agent.ID, ColorReset)
		fmt.Println()
	},
}

// Command execution command
var cmdCmd = &cobra.Command{
	Use:   "cmd <agent-id> <command>",
	Short: "Execute command on agent",
	Long:  "Execute a command on the specified agent",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		agentID := args[0]
		command := args[1]
		
		printInfo(fmt.Sprintf("Executing command on agent %s: %s", agentID[:8], command))
		
		printWarning("Command execution feature is not yet implemented")
		fmt.Printf("  Agent ID: %s\n", agentID)
		fmt.Printf("  Command: %s\n", command)
		fmt.Printf("  Status: %sPending Implementation%s\n", ColorYellow, ColorReset)
		
		printInfo("This feature will be available in the next phase")
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
		printInfo(fmt.Sprintf("Fetching command history for agent: %s", agentID[:8]))
		
		body, err := makeAPIRequest(fmt.Sprintf("/api/v1/history/%s", agentID))
		if err != nil {
			printError(fmt.Sprintf("Failed to get agent history: %v", err))
			os.Exit(1)
		}
		
		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse history response: %v", err))
			os.Exit(1)
		}
		
		if data, ok := response["data"].([]interface{}); ok {
			if len(data) == 0 {
				printWarning("No command history found for this agent")
				return
			}
			
			printSuccess(fmt.Sprintf("Found %d command(s) in history", len(data)))
			fmt.Println()
			
			fmt.Printf("%s%-20s %-20s %-12s %-10s %-30s%s\n",
				ColorBlue, "TIMESTAMP", "COMMAND", "STATUS", "DURATION", "RESULT", ColorReset)
			fmt.Println(strings.Repeat("-", 95))
			
			for _, item := range data {
				if histData, ok := item.(map[string]interface{}); ok {
					timestamp := getString(histData, "timestamp")
					command := getString(histData, "command")
					status := getString(histData, "status")
					duration := getString(histData, "duration")
					result := getString(histData, "result")
					
					if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
						timestamp = t.Format("15:04:05 Jan 02")
					}
					
					var statusColor string
					switch strings.ToLower(status) {
					case "completed":
						statusColor = ColorGreen
					case "failed":
						statusColor = ColorRed
					case "pending":
						statusColor = ColorYellow
					default:
						statusColor = ColorWhite
					}
					
					fmt.Printf("%-20s %-20s %s%-12s%s %-10s %-30s\n",
						timestamp,
						truncateString(command, 20),
						statusColor,
						status,
						ColorReset,
						duration,
						truncateString(result, 30))
				}
			}
			fmt.Println()
		}
	},
}

// Logs command
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show recent server logs",
	Long:  "Display recent server logs and activities",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt("limit")
		printInfo(fmt.Sprintf("Fetching last %d log entries...", limit))
		
		endpoint := fmt.Sprintf("/api/v1/logs?limit=%d", limit)
		body, err := makeAPIRequest(endpoint)
		if err != nil {
			printError(fmt.Sprintf("Failed to get server logs: %v", err))
			os.Exit(1)
		}
		
		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			printError(fmt.Sprintf("Failed to parse logs response: %v", err))
			os.Exit(1)
		}
		
		if data, ok := response["data"].([]interface{}); ok {
			if len(data) == 0 {
				printWarning("No recent logs found")
				return
			}
			
			printSuccess(fmt.Sprintf("Showing %d recent log entries", len(data)))
			fmt.Println()
			
			for _, item := range data {
				if logData, ok := item.(map[string]interface{}); ok {
					timestamp := getString(logData, "timestamp")
					level := getString(logData, "level")
					component := getString(logData, "component")
					message := getString(logData, "message")
					agentID := getString(logData, "agent_id")
					
					if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
						timestamp = t.Format("15:04:05")
					}
					
					var levelColor string
					switch strings.ToUpper(level) {
					case "INFO":
						levelColor = ColorBlue
					case "WARNING":
						levelColor = ColorYellow
					case "ERROR":
						levelColor = ColorRed
					default:
						levelColor = ColorWhite
					}
					
					fmt.Printf("%s[%s]%s %s[%s]%s %s - %s",
						levelColor, level, ColorReset,
						ColorCyan, timestamp, ColorReset,
						component, message)
					
					if agentID != "" {
						fmt.Printf(" (Agent: %s)", agentID[:8])
					}
					fmt.Println()
				}
			}
			fmt.Println()
		}
	},
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show CLI version",
	Long:  "Display the version information for the Taburtuai CLI",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%sTaburtuai CLI%s v2.0-phase1\n", ColorGreen, ColorReset)
		fmt.Printf("Build: Enhanced Agent Management\n")
		fmt.Printf("Compatible with: Taburtuai C2 Server v2.0+\n")
		fmt.Printf("API Endpoints: /api/v1/*\n")
		fmt.Printf("Features: Agent management, Command execution, File operations\n")
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&config.ServerURL, "server", "s", "http://localhost:8080", "C2 server URL")
	rootCmd.PersistentFlags().StringVarP(&config.APIKey, "api-key", "k", "", "API key for authentication")
	rootCmd.PersistentFlags().DurationVarP(&config.Timeout, "timeout", "t", 30*time.Second, "Request timeout")
	rootCmd.PersistentFlags().BoolVarP(&config.Verbose, "verbose", "v", false, "Enable verbose output")
	
	// Add main commands
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(agentsCmd)
	rootCmd.AddCommand(cmdCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(logsCmd)
	rootCmd.AddCommand(versionCmd)
	
	// Add agents subcommands
	agentsCmd.AddCommand(agentsListCmd)
	agentsCmd.AddCommand(agentsShowCmd)
	
	// Add flags for specific commands
	logsCmd.Flags().IntP("limit", "l", 50, "Number of log entries to show")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		printError(fmt.Sprintf("CLI error: %v", err))
		os.Exit(1)
	}
}