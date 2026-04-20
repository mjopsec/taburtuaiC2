package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/storage"
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

	am.persistAgent(agent)
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
		if am.store != nil {
			_ = am.store.DeleteAgent(agentID)
		}
	}
}

// UpdateAgentSystemInfo replaces system info for an agent
func (am *AgentMonitor) UpdateAgentSystemInfo(agentID string, info SystemInfo) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if a, ok := am.agents[agentID]; ok {
		a.SystemInfo = info
		a.LastSeen = time.Now()
		am.persistAgent(a)
	}
}

// UpdateAgentNetworkInfo replaces network info for an agent
func (am *AgentMonitor) UpdateAgentNetworkInfo(agentID string, info NetworkInfo) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if a, ok := am.agents[agentID]; ok {
		a.NetworkInfo = info
		a.LastSeen = time.Now()
		am.persistAgent(a)
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
		am.persistAgent(a)
	}
}

// UpdateAgentPerformance replaces performance metrics for an agent
func (am *AgentMonitor) UpdateAgentPerformance(agentID string, perf PerformanceMetrics) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if a, ok := am.agents[agentID]; ok {
		a.Performance = perf
		a.LastSeen = time.Now()
		am.persistAgent(a)
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
	am.persistAgent(a)
}

// RecordError appends an error entry for an agent
func (am *AgentMonitor) RecordError(agentID, errType, message, command, severity string, recoverable bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	a, ok := am.agents[agentID]
	if !ok {
		return
	}
	now := time.Now()
	a.Errors = append(a.Errors, ErrorInfo{
		Timestamp:   now,
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
	a.LastSeen = now

	if am.store != nil {
		_ = am.store.AppendAgentError(storage.AgentErrorRow{
			AgentID:     agentID,
			ErrorType:   errType,
			Message:     message,
			Command:     command,
			Severity:    severity,
			Recoverable: recoverable,
			OccurredAt:  now.Unix(),
		})
		_ = am.store.PruneAgentErrors(agentID, 50)
		am.persistAgent(a)
	}
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
	am.persistAgent(a)
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
		am.persistAgent(a)
	}
	return nil
}

// ── persistence helpers ───────────────────────────────────────────────────────

// persistAgent writes an agent to SQLite. Must be called with am.mu held.
func (am *AgentMonitor) persistAgent(a *AgentHealth) {
	if am.store == nil {
		return
	}
	row, err := agentToRow(a)
	if err != nil {
		return
	}
	_ = am.store.UpsertAgent(row)
}

// loadFromDB restores all agents from SQLite into the in-memory map
func (am *AgentMonitor) loadFromDB() {
	rows, err := am.store.GetAllAgents()
	if err != nil {
		return
	}
	for _, r := range rows {
		a := agentFromRow(r)
		am.agents[a.ID] = a
	}
}

// agentToRow converts an AgentHealth to a flat storage row
func agentToRow(a *AgentHealth) (storage.AgentRow, error) {
	netJSON, _ := json.Marshal(a.NetworkInfo)
	sysJSON, _ := json.Marshal(a.SystemInfo)
	secJSON, _ := json.Marshal(a.SecurityInfo)
	perfJSON, _ := json.Marshal(a.Performance)
	metaJSON, _ := json.Marshal(a.Metadata)

	return storage.AgentRow{
		ID:               a.ID,
		Hostname:         a.Hostname,
		Username:         a.Username,
		OS:               a.OS,
		Architecture:     a.Architecture,
		ProcessID:        a.ProcessID,
		ParentProcessID:  a.ParentProcessID,
		Privileges:       a.Privileges,
		Status:           string(a.Status),
		LastSeen:         a.LastSeen.Unix(),
		LastHeartbeat:    a.LastHeartbeat.Unix(),
		FirstContact:     a.FirstContact.Unix(),
		TotalConnections: a.TotalConnections,
		CmdsExecuted:     a.CommandsExecuted,
		FilesTransferred: a.FilesTransferred,
		NetworkInfoJSON:  string(netJSON),
		SystemInfoJSON:   string(sysJSON),
		SecurityInfoJSON: string(secJSON),
		PerformanceJSON:  string(perfJSON),
		MetadataJSON:     string(metaJSON),
	}, nil
}

// agentFromRow converts a flat storage row to an AgentHealth
func agentFromRow(r storage.AgentRow) *AgentHealth {
	a := &AgentHealth{
		ID:               r.ID,
		Hostname:         r.Hostname,
		Username:         r.Username,
		OS:               r.OS,
		Architecture:     r.Architecture,
		ProcessID:        r.ProcessID,
		ParentProcessID:  r.ParentProcessID,
		Privileges:       r.Privileges,
		Status:           AgentStatus(r.Status),
		LastSeen:         time.Unix(r.LastSeen, 0),
		LastHeartbeat:    time.Unix(r.LastHeartbeat, 0),
		FirstContact:     time.Unix(r.FirstContact, 0),
		TotalConnections: r.TotalConnections,
		CommandsExecuted: r.CmdsExecuted,
		FilesTransferred: r.FilesTransferred,
		Metadata:         make(map[string]interface{}),
		Errors:           make([]ErrorInfo, 0),
	}
	_ = json.Unmarshal([]byte(r.NetworkInfoJSON), &a.NetworkInfo)
	_ = json.Unmarshal([]byte(r.SystemInfoJSON), &a.SystemInfo)
	_ = json.Unmarshal([]byte(r.SecurityInfoJSON), &a.SecurityInfo)
	_ = json.Unmarshal([]byte(r.PerformanceJSON), &a.Performance)
	_ = json.Unmarshal([]byte(r.MetadataJSON), &a.Metadata)
	return a
}
