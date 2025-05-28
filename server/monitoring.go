package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentStatus represents the current status of an agent
type AgentStatus string

const (
	StatusOnline    AgentStatus = "online"
	StatusOffline   AgentStatus = "offline"
	StatusDormant   AgentStatus = "dormant"
	StatusError     AgentStatus = "error"
	StatusSuspected AgentStatus = "suspected"
)

// AgentHealth contains health information about an agent
type AgentHealth struct {
	ID               string                 `json:"id"`
	Hostname         string                 `json:"hostname"`
	Username         string                 `json:"username"`
	OS               string                 `json:"os"`
	Architecture     string                 `json:"architecture"`
	ProcessID        int                    `json:"process_id"`
	ParentProcessID  int                    `json:"parent_process_id"`
	Status           AgentStatus            `json:"status"`
	LastSeen         time.Time              `json:"last_seen"`
	LastHeartbeat    time.Time              `json:"last_heartbeat"`
	FirstContact     time.Time              `json:"first_contact"`
	TotalConnections int                    `json:"total_connections"`
	CommandsExecuted int                    `json:"commands_executed"`
	FilesTransferred int                    `json:"files_transferred"`
	Privileges       string                 `json:"privileges"`
	NetworkInfo      NetworkInfo            `json:"network_info"`
	SystemInfo       SystemInfo             `json:"system_info"`
	SecurityInfo     SecurityInfo           `json:"security_info"`
	Performance      PerformanceMetrics     `json:"performance"`
	Metadata         map[string]interface{} `json:"metadata"`
	Errors           []ErrorInfo            `json:"errors"`
}

// NetworkInfo contains network-related information
type NetworkInfo struct {
	InternalIP    string   `json:"internal_ip"`
	ExternalIP    string   `json:"external_ip"`
	MACAddress    string   `json:"mac_address"`
	Gateway       string   `json:"gateway"`
	DNSServers    []string `json:"dns_servers"`
	OpenPorts     []int    `json:"open_ports"`
	NetworkShares []string `json:"network_shares"`
}

// SystemInfo contains system information
type SystemInfo struct {
	CPUCount        int               `json:"cpu_count"`
	CPUUsage        float64           `json:"cpu_usage"`
	MemoryTotal     uint64            `json:"memory_total"`
	MemoryUsed      uint64            `json:"memory_used"`
	DiskSpace       uint64            `json:"disk_space"`
	DiskUsed        uint64            `json:"disk_used"`
	Uptime          int64             `json:"uptime"`
	InstalledSoft   []string          `json:"installed_software"`
	RunningProcs    []string          `json:"running_processes"`
	Services        []string          `json:"services"`
	EnvironmentVars map[string]string `json:"environment_vars"`
}

// SecurityInfo contains security-related information
type SecurityInfo struct {
	AntivirusStatus    string   `json:"antivirus_status"`
	FirewallStatus     string   `json:"firewall_status"`
	UAC                bool     `json:"uac_enabled"`
	DefenderStatus     string   `json:"defender_status"`
	RunningEDR         []string `json:"running_edr"`
	SecurityPatches    []string `json:"security_patches"`
	AppLockerStatus    string   `json:"applocker_status"`
	PowerShellLogging  bool     `json:"powershell_logging"`
	ScriptBlockLogging bool     `json:"script_block_logging"`
}

// PerformanceMetrics contains performance data
type PerformanceMetrics struct {
	ResponseTime     time.Duration `json:"response_time"`
	LastCommandTime  time.Duration `json:"last_command_time"`
	AverageLatency   time.Duration `json:"average_latency"`
	DataTransferRate float64       `json:"data_transfer_rate"`
	ErrorRate        float64       `json:"error_rate"`
	SuccessRate      float64       `json:"success_rate"`
}

// ErrorInfo represents an error that occurred
type ErrorInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Message     string    `json:"message"`
	Command     string    `json:"command,omitempty"`
	Severity    string    `json:"severity"`
	Recoverable bool      `json:"recoverable"`
}

// AgentMonitor manages agent health monitoring
type AgentMonitor struct {
	agents          map[string]*AgentHealth
	mutex           sync.RWMutex
	heartbeatWindow time.Duration
	offlineWindow   time.Duration
	checkInterval   time.Duration
	callbacks       map[string]func(*AgentHealth)
	running         bool
	stopChan        chan struct{}
}

// NewAgentMonitor creates a new agent monitor
func NewAgentMonitor(heartbeatWindow, offlineWindow, checkInterval time.Duration) *AgentMonitor {
	return &AgentMonitor{
		agents:          make(map[string]*AgentHealth),
		heartbeatWindow: heartbeatWindow,
		offlineWindow:   offlineWindow,
		checkInterval:   checkInterval,
		callbacks:       make(map[string]func(*AgentHealth)),
		stopChan:        make(chan struct{}),
	}
}

// Start begins the monitoring process
func (am *AgentMonitor) Start() {
	am.mutex.Lock()
	if am.running {
		am.mutex.Unlock()
		return
	}
	am.running = true
	am.mutex.Unlock()

	go am.monitorLoop()
	LogInfo(SYSTEM, "Agent monitor started", "")
}

// Stop stops the monitoring process
func (am *AgentMonitor) Stop() {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if !am.running {
		return
	}

	am.running = false
	close(am.stopChan)
	LogInfo(SYSTEM, "Agent monitor stopped", "")
}

// RegisterAgent registers a new agent or updates existing one
func (am *AgentMonitor) RegisterAgent(agentData map[string]interface{}) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// --- MODIFIKASI UNTUK VALIDASI ID ---
	idInterface, idExists := agentData["id"]
	if !idExists {
		LogError(SYSTEM, "Agent registration failed: 'id' field is missing in agentData.", "") //
		// Anda bisa mengembalikan error atau hanya keluar dari fungsi
		// tergantung bagaimana Anda ingin menangani agent tanpa ID.
		// Untuk saat ini, kita akan keluar.
		return
	}

	agentID, ok := idInterface.(string)
	if !ok || agentID == "" {
		LogError(SYSTEM, fmt.Sprintf("Agent registration failed: 'id' field is not a valid non-empty string. Received type: %T, value: %v", idInterface, idInterface), "") //
		return
	}
	// --- AKHIR MODIFIKASI VALIDASI ID ---

	now := time.Now()

	agent, exists := am.agents[agentID]
	if !exists {
		agent = &AgentHealth{ //
			ID:           agentID,
			Status:       StatusOnline, //
			FirstContact: now,
			Metadata:     make(map[string]interface{}),
			Errors:       make([]ErrorInfo, 0), //
		}
		am.agents[agentID] = agent
		LogAgentActivity(agentID, "first_contact", "")                                       //
		LogInfo(AGENT_CONNECTION, fmt.Sprintf("New agent registered: %s", agentID), agentID) //
	} else {
		LogInfo(AGENT_CONNECTION, fmt.Sprintf("Agent re-registered or updated: %s", agentID), agentID) //
	}

	// Update basic info
	// Tambahkan pengecekan tipe data yang lebih aman di sini juga
	if hostnameVal, okHostname := agentData["hostname"]; okHostname {
		if hostname, typeOk := hostnameVal.(string); typeOk {
			agent.Hostname = hostname
		}
	}
	if usernameVal, okUsername := agentData["username"]; okUsername {
		if username, typeOk := usernameVal.(string); typeOk {
			agent.Username = username
		}
	}
	// Lakukan hal yang sama untuk field lain seperti os, architecture, process_id, dll.
	// Contoh untuk OS:
	if osVal, okOS := agentData["os"]; okOS {
		if osStr, typeOk := osVal.(string); typeOk {
			agent.OS = osStr
		}
	}
	// Contoh untuk ProcessID (int):
	if pidVal, okPID := agentData["process_id"]; okPID {
		// JSON number unmarshal menjadi float64 secara default ke interface{}
		if pidFloat, typeOk := pidVal.(float64); typeOk {
			agent.ProcessID = int(pidFloat)
		} else if pidInt, typeOk := pidVal.(int); typeOk { // Jika sudah int
			agent.ProcessID = pidInt
		}
	}
	// ... dan seterusnya untuk field lain ...
	if arch, ok := agentData["architecture"].(string); ok { //
		agent.Architecture = arch //
	}
	if ppidVal, okPPID := agentData["parent_process_id"]; okPPID { //
		if ppidFloat, typeOk := ppidVal.(float64); typeOk {
			agent.ParentProcessID = int(ppidFloat) //
		} else if ppidInt, typeOk := ppidVal.(int); typeOk {
			agent.ParentProcessID = ppidInt //
		}
	}
	if privileges, ok := agentData["privileges"].(string); ok { //
		agent.Privileges = privileges //
	}

	agent.LastSeen = now
	agent.LastHeartbeat = now // Anggap checkin juga sebagai heartbeat
	agent.TotalConnections++

	// Update status to online if it was offline or error
	if agent.Status == StatusOffline || agent.Status == StatusError || agent.Status == StatusDormant { //
		oldStatus := agent.Status
		agent.Status = StatusOnline                                                                                                //
		LogInfo(AGENT_CONNECTION, fmt.Sprintf("Agent %s status changed from %s to %s", agentID, oldStatus, agent.Status), agentID) //
		am.triggerCallback("agent_reconnected", agent)
	} else if agent.Status != StatusOnline { // Jika statusnya belum online (misal baru pertama kali)
		agent.Status = StatusOnline //
	}

	LogAgentActivity(agentID, "heartbeat_via_checkin", "") //
}

// UpdateAgentSystemInfo updates system information for an agent
func (am *AgentMonitor) UpdateAgentSystemInfo(agentID string, sysInfo SystemInfo) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		agent.SystemInfo = sysInfo
		agent.LastSeen = time.Now()
	}
}

// UpdateAgentNetworkInfo updates network information for an agent
func (am *AgentMonitor) UpdateAgentNetworkInfo(agentID string, netInfo NetworkInfo) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		agent.NetworkInfo = netInfo
		agent.LastSeen = time.Now()
	}
}

// UpdateAgentSecurityInfo updates security information for an agent
func (am *AgentMonitor) UpdateAgentSecurityInfo(agentID string, secInfo SecurityInfo) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		agent.SecurityInfo = secInfo
		agent.LastSeen = time.Now()

		// Check for security concerns
		am.checkSecurityConcerns(agent)
	}
}

// UpdateAgentPerformance updates performance metrics
func (am *AgentMonitor) UpdateAgentPerformance(agentID string, perf PerformanceMetrics) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		agent.Performance = perf
		agent.LastSeen = time.Now()
	}
}

// RecordCommand records a command execution
func (am *AgentMonitor) RecordCommand(agentID, command string, success bool, duration time.Duration) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		agent.CommandsExecuted++
		agent.Performance.LastCommandTime = duration

		// Update average latency (simple moving average)
		if agent.Performance.AverageLatency == 0 {
			agent.Performance.AverageLatency = duration
		} else {
			agent.Performance.AverageLatency = (agent.Performance.AverageLatency + duration) / 2
		}

		// Update success rate
		totalCommands := float64(agent.CommandsExecuted)
		if success {
			agent.Performance.SuccessRate = ((agent.Performance.SuccessRate * (totalCommands - 1)) + 1) / totalCommands
		} else {
			agent.Performance.SuccessRate = (agent.Performance.SuccessRate * (totalCommands - 1)) / totalCommands
		}

		agent.Performance.ErrorRate = 1 - agent.Performance.SuccessRate
		agent.LastSeen = time.Now()
	}
}

// RecordError records an error for an agent
func (am *AgentMonitor) RecordError(agentID, errorType, message, command, severity string, recoverable bool) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		errorInfo := ErrorInfo{
			Timestamp:   time.Now(),
			Type:        errorType,
			Message:     message,
			Command:     command,
			Severity:    severity,
			Recoverable: recoverable,
		}

		agent.Errors = append(agent.Errors, errorInfo)

		// Keep only last 50 errors
		if len(agent.Errors) > 50 {
			agent.Errors = agent.Errors[len(agent.Errors)-50:]
		}

		// Check if agent should be marked as suspected
		if severity == "critical" || !recoverable {
			agent.Status = StatusError
			am.triggerCallback("agent_error", agent)
		}

		agent.LastSeen = time.Now()
	}
}

// RecordFileTransfer records a file transfer operation
func (am *AgentMonitor) RecordFileTransfer(agentID string, success bool, size int64) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		if success {
			agent.FilesTransferred++
		}

		// Update data transfer rate (bytes per second)
		if size > 0 && agent.Performance.LastCommandTime > 0 {
			rate := float64(size) / agent.Performance.LastCommandTime.Seconds()
			if agent.Performance.DataTransferRate == 0 {
				agent.Performance.DataTransferRate = rate
			} else {
				agent.Performance.DataTransferRate = (agent.Performance.DataTransferRate + rate) / 2
			}
		}

		agent.LastSeen = time.Now()
	}
}

// GetAgent returns agent information
func (am *AgentMonitor) GetAgent(agentID string) (*AgentHealth, bool) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	agent, exists := am.agents[agentID]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid race conditions
	agentCopy := *agent
	return &agentCopy, true
}

// GetAllAgents returns all agents
func (am *AgentMonitor) GetAllAgents() map[string]*AgentHealth {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	result := make(map[string]*AgentHealth)
	for id, agent := range am.agents {
		agentCopy := *agent
		result[id] = &agentCopy
	}

	return result
}

// GetAgentsByStatus returns agents with specific status
func (am *AgentMonitor) GetAgentsByStatus(status AgentStatus) []*AgentHealth {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	var result []*AgentHealth
	for _, agent := range am.agents {
		if agent.Status == status {
			agentCopy := *agent
			result = append(result, &agentCopy)
		}
	}

	return result
}

// GetStats returns monitoring statistics
func (am *AgentMonitor) GetStats() map[string]interface{} {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_agents":     len(am.agents),
		"online_agents":    0,
		"offline_agents":   0,
		"error_agents":     0,
		"suspected_agents": 0,
		"total_commands":   0,
		"total_transfers":  0,
		"average_uptime":   0.0,
	}

	var totalUptime float64
	for _, agent := range am.agents {
		switch agent.Status {
		case StatusOnline:
			stats["online_agents"] = stats["online_agents"].(int) + 1
		case StatusOffline:
			stats["offline_agents"] = stats["offline_agents"].(int) + 1
		case StatusError:
			stats["error_agents"] = stats["error_agents"].(int) + 1
		case StatusSuspected:
			stats["suspected_agents"] = stats["suspected_agents"].(int) + 1
		}

		stats["total_commands"] = stats["total_commands"].(int) + agent.CommandsExecuted
		stats["total_transfers"] = stats["total_transfers"].(int) + agent.FilesTransferred

		uptime := time.Since(agent.FirstContact).Hours()
		totalUptime += uptime
	}

	if len(am.agents) > 0 {
		stats["average_uptime"] = totalUptime / float64(len(am.agents))
	}

	return stats
}

// RegisterCallback registers a callback for specific events
func (am *AgentMonitor) RegisterCallback(event string, callback func(*AgentHealth)) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	am.callbacks[event] = callback
}

// triggerCallback triggers a registered callback
func (am *AgentMonitor) triggerCallback(event string, agent *AgentHealth) {
	if callback, exists := am.callbacks[event]; exists {
		go callback(agent) // Run callback in goroutine to avoid blocking
	}
}

// monitorLoop runs the main monitoring loop
func (am *AgentMonitor) monitorLoop() {
	ticker := time.NewTicker(am.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.checkAgentStatuses()
		case <-am.stopChan:
			return
		}
	}
}

// checkAgentStatuses checks and updates agent statuses
func (am *AgentMonitor) checkAgentStatuses() {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	now := time.Now()

	for _, agent := range am.agents {
		timeSinceLastSeen := now.Sub(agent.LastSeen)

		oldStatus := agent.Status

		switch {
		case timeSinceLastSeen > am.offlineWindow:
			agent.Status = StatusOffline
		case timeSinceLastSeen > am.heartbeatWindow:
			if agent.Status == StatusOnline {
				agent.Status = StatusDormant
			}
		case timeSinceLastSeen <= am.heartbeatWindow:
			if agent.Status == StatusOffline || agent.Status == StatusDormant {
				agent.Status = StatusOnline
			}
		}

		// Trigger callbacks for status changes
		if oldStatus != agent.Status {
			switch agent.Status {
			case StatusOffline:
				am.triggerCallback("agent_offline", agent)
				LogAgentActivity(agent.ID, "went_offline", "")
			case StatusOnline:
				if oldStatus == StatusOffline {
					am.triggerCallback("agent_reconnected", agent)
					LogAgentActivity(agent.ID, "reconnected", "")
				}
			case StatusDormant:
				am.triggerCallback("agent_dormant", agent)
				LogAgentActivity(agent.ID, "dormant", "")
			}
		}
	}
}

// checkSecurityConcerns checks for security-related concerns
func (am *AgentMonitor) checkSecurityConcerns(agent *AgentHealth) {
	concerns := []string{}

	// Check for EDR/AV
	if len(agent.SecurityInfo.RunningEDR) > 0 {
		concerns = append(concerns, "EDR detected")
	}

	if agent.SecurityInfo.AntivirusStatus == "active" {
		concerns = append(concerns, "Active antivirus")
	}

	if agent.SecurityInfo.PowerShellLogging {
		concerns = append(concerns, "PowerShell logging enabled")
	}

	if agent.SecurityInfo.ScriptBlockLogging {
		concerns = append(concerns, "Script block logging enabled")
	}

	if len(concerns) > 0 {
		agent.Status = StatusSuspected
		agent.Metadata["security_concerns"] = concerns
		am.triggerCallback("security_concern", agent)

		LogError(AUDIT, fmt.Sprintf("Security concerns detected: %v", concerns), agent.ID)
	}
}

// RemoveAgent removes an agent from monitoring
func (am *AgentMonitor) RemoveAgent(agentID string) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if agent, exists := am.agents[agentID]; exists {
		delete(am.agents, agentID)
		am.triggerCallback("agent_removed", agent)
		LogAgentActivity(agentID, "removed", "")
	}
}

// ExportAgentData exports agent data for backup/analysis
func (am *AgentMonitor) ExportAgentData() ([]byte, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	return json.MarshalIndent(am.agents, "", "  ")
}

// ImportAgentData imports agent data from backup
func (am *AgentMonitor) ImportAgentData(data []byte) error {
	var agents map[string]*AgentHealth
	if err := json.Unmarshal(data, &agents); err != nil {
		return err
	}

	am.mutex.Lock()
	defer am.mutex.Unlock()

	for id, agent := range agents {
		am.agents[id] = agent
	}

	return nil
}

// GetAgentHistory returns command history for an agent
func (am *AgentMonitor) GetAgentHistory(agentID string, limit int) []ErrorInfo {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	if agent, exists := am.agents[agentID]; exists {
		errors := agent.Errors
		if len(errors) > limit {
			return errors[len(errors)-limit:]
		}
		return errors
	}

	return nil
}

// GetHighRiskAgents returns agents that might be at risk
func (am *AgentMonitor) GetHighRiskAgents() []*AgentHealth {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	var riskAgents []*AgentHealth

	for _, agent := range am.agents {
		isHighRisk := false

		// Check error rate
		if agent.Performance.ErrorRate > 0.3 {
			isHighRisk = true
		}

		// Check recent errors
		recentErrors := 0
		oneHourAgo := time.Now().Add(-time.Hour)
		for _, err := range agent.Errors {
			if err.Timestamp.After(oneHourAgo) && err.Severity == "critical" {
				recentErrors++
			}
		}
		if recentErrors > 3 {
			isHighRisk = true
		}

		// Check security status
		if agent.Status == StatusSuspected || agent.Status == StatusError {
			isHighRisk = true
		}

		if isHighRisk {
			agentCopy := *agent
			riskAgents = append(riskAgents, &agentCopy)
		}
	}

	return riskAgents
}

// GetPerformanceReport generates a performance report
func (am *AgentMonitor) GetPerformanceReport() map[string]interface{} {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	report := map[string]interface{}{
		"timestamp": time.Now(),
		"agents":    make([]map[string]interface{}, 0),
	}

	for _, agent := range am.agents {
		agentReport := map[string]interface{}{
			"id":                agent.ID,
			"hostname":          agent.Hostname,
			"status":            agent.Status,
			"uptime_hours":      time.Since(agent.FirstContact).Hours(),
			"commands_executed": agent.CommandsExecuted,
			"files_transferred": agent.FilesTransferred,
			"error_rate":        agent.Performance.ErrorRate,
			"success_rate":      agent.Performance.SuccessRate,
			"avg_latency_ms":    agent.Performance.AverageLatency.Milliseconds(),
			"transfer_rate_bps": agent.Performance.DataTransferRate,
			"recent_errors":     len(agent.Errors),
		}

		report["agents"] = append(report["agents"].([]map[string]interface{}), agentReport)
	}

	return report
}

// Global monitor instance
var GlobalMonitor *AgentMonitor

// InitAgentMonitor initializes the global agent monitor
func InitAgentMonitor() {
	GlobalMonitor = NewAgentMonitor(
		30*time.Second, // heartbeat window
		5*time.Minute,  // offline window
		10*time.Second, // check interval
	)

	// Register default callbacks
	GlobalMonitor.RegisterCallback("agent_offline", func(agent *AgentHealth) {
		LogAgentActivity(agent.ID, "offline_detected", "")
	})

	GlobalMonitor.RegisterCallback("agent_reconnected", func(agent *AgentHealth) {
		LogAgentActivity(agent.ID, "reconnected_detected", "")
	})

	GlobalMonitor.RegisterCallback("security_concern", func(agent *AgentHealth) {
		LogError(AUDIT, "Security concern detected", agent.ID)
	})

	GlobalMonitor.Start()
}
