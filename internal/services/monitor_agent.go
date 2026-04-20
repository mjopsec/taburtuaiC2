package services

import (
	"encoding/json"
	"fmt"
	"time"
)

// RegisterAgent adds a new agent or updates an existing one from checkin data
func (am *AgentMonitor) RegisterAgent(data map[string]interface{}) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if data == nil {
		return fmt.Errorf("agent data cannot be nil")
	}

	agentID, ok := data["id"].(string)
	if !ok || agentID == "" {
		return fmt.Errorf("agent ID must be a non-empty string")
	}
	if !isValidAgentUUID(agentID) {
		return fmt.Errorf("agent ID must be a valid UUID")
	}
	if err := validateAgentData(data); err != nil {
		return err
	}

	now := time.Now()
	agent, exists := am.agents[agentID]
	if !exists {
		agent = &AgentHealth{
			ID:           agentID,
			Status:       StatusOnline,
			FirstContact: now,
			Metadata:     make(map[string]interface{}),
			Errors:       make([]ErrorInfo, 0),
		}
		am.agents[agentID] = agent
		LogAgentActivity(agentID, "first_contact", "")
	} else {
		LogInfo(AGENT_CONNECTION, fmt.Sprintf("Agent re-registered: %s", agentID), agentID)
	}

	if v, ok := getString(data, "hostname"); ok {
		agent.Hostname = v
	}
	if v, ok := getString(data, "username"); ok {
		agent.Username = v
	}
	if v, ok := getString(data, "os"); ok {
		agent.OS = v
	}
	if v, ok := getString(data, "architecture"); ok {
		agent.Architecture = v
	}
	if v, ok := getInt(data, "process_id"); ok {
		agent.ProcessID = v
	}
	if v, ok := getInt(data, "parent_process_id"); ok {
		agent.ParentProcessID = v
	}
	if v, ok := getString(data, "privileges"); ok {
		agent.Privileges = v
	}

	agent.LastSeen = now
	agent.LastHeartbeat = now
	agent.TotalConnections++

	if agent.Status != StatusOnline {
		agent.Status = StatusOnline
		am.triggerCallback("agent_reconnected", agent)
	}
	return nil
}

// RemoveAgent deregisters an agent
func (am *AgentMonitor) RemoveAgent(agentID string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if agent, ok := am.agents[agentID]; ok {
		delete(am.agents, agentID)
		am.triggerCallback("agent_removed", agent)
		LogAgentActivity(agentID, "removed", "")
	}
}

// UpdateAgentSystemInfo replaces system info for an agent
func (am *AgentMonitor) UpdateAgentSystemInfo(agentID string, info SystemInfo) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if a, ok := am.agents[agentID]; ok {
		a.SystemInfo = info
		a.LastSeen = time.Now()
	}
}

// UpdateAgentNetworkInfo replaces network info for an agent
func (am *AgentMonitor) UpdateAgentNetworkInfo(agentID string, info NetworkInfo) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if a, ok := am.agents[agentID]; ok {
		a.NetworkInfo = info
		a.LastSeen = time.Now()
	}
}

// UpdateAgentSecurityInfo replaces security info and checks for concerns
func (am *AgentMonitor) UpdateAgentSecurityInfo(agentID string, info SecurityInfo) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if a, ok := am.agents[agentID]; ok {
		a.SecurityInfo = info
		a.LastSeen = time.Now()
		am.checkSecurityConcerns(a)
	}
}

// UpdateAgentPerformance replaces performance metrics for an agent
func (am *AgentMonitor) UpdateAgentPerformance(agentID string, perf PerformanceMetrics) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if a, ok := am.agents[agentID]; ok {
		a.Performance = perf
		a.LastSeen = time.Now()
	}
}

// RecordCommand updates execution statistics for an agent
func (am *AgentMonitor) RecordCommand(agentID, command string, success bool, duration time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	a, ok := am.agents[agentID]
	if !ok {
		return
	}
	a.CommandsExecuted++
	a.Performance.LastCommandTime = duration

	if a.Performance.AverageLatency == 0 {
		a.Performance.AverageLatency = duration
	} else {
		a.Performance.AverageLatency = (a.Performance.AverageLatency + duration) / 2
	}

	total := float64(a.CommandsExecuted)
	if success {
		a.Performance.SuccessRate = ((a.Performance.SuccessRate * (total - 1)) + 1) / total
	} else {
		a.Performance.SuccessRate = (a.Performance.SuccessRate * (total - 1)) / total
	}
	a.Performance.ErrorRate = 1 - a.Performance.SuccessRate
	a.LastSeen = time.Now()
}

// RecordError appends an error entry for an agent
func (am *AgentMonitor) RecordError(agentID, errType, message, command, severity string, recoverable bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	a, ok := am.agents[agentID]
	if !ok {
		return
	}
	a.Errors = append(a.Errors, ErrorInfo{
		Timestamp:   time.Now(),
		Type:        errType,
		Message:     message,
		Command:     command,
		Severity:    severity,
		Recoverable: recoverable,
	})
	if len(a.Errors) > 50 {
		a.Errors = a.Errors[len(a.Errors)-50:]
	}
	if severity == "critical" || !recoverable {
		a.Status = StatusError
		am.triggerCallback("agent_error", a)
	}
	a.LastSeen = time.Now()
}

// RecordFileTransfer updates file transfer counters
func (am *AgentMonitor) RecordFileTransfer(agentID string, success bool, size int64) {
	am.mu.Lock()
	defer am.mu.Unlock()
	a, ok := am.agents[agentID]
	if !ok {
		return
	}
	if success {
		a.FilesTransferred++
	}
	if size > 0 && a.Performance.LastCommandTime > 0 {
		rate := float64(size) / a.Performance.LastCommandTime.Seconds()
		if a.Performance.DataTransferRate == 0 {
			a.Performance.DataTransferRate = rate
		} else {
			a.Performance.DataTransferRate = (a.Performance.DataTransferRate + rate) / 2
		}
	}
	a.LastSeen = time.Now()
}

// ExportAgentData serialises all agent records to JSON
func (am *AgentMonitor) ExportAgentData() ([]byte, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return json.MarshalIndent(am.agents, "", "  ")
}

// ImportAgentData restores agent records from JSON
func (am *AgentMonitor) ImportAgentData(data []byte) error {
	var agents map[string]*AgentHealth
	if err := json.Unmarshal(data, &agents); err != nil {
		return err
	}
	am.mu.Lock()
	defer am.mu.Unlock()
	for id, a := range agents {
		am.agents[id] = a
	}
	return nil
}
