package services

import (
	"fmt"
	"time"
)

// RegisterCallback registers a function to be called when an event fires
func (am *AgentMonitor) RegisterCallback(event string, fn func(*AgentHealth)) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.callbacks[event] = fn
}

// triggerCallback calls the registered handler for an event in a goroutine
func (am *AgentMonitor) triggerCallback(event string, agent *AgentHealth) {
	if fn, ok := am.callbacks[event]; ok {
		go fn(agent)
	}
}

// monitorLoop runs the periodic status-check ticker
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

// checkAgentStatuses evaluates each agent's last-seen time and updates status
func (am *AgentMonitor) checkAgentStatuses() {
	am.mu.Lock()
	defer am.mu.Unlock()
	now := time.Now()
	for _, a := range am.agents {
		old := a.Status
		elapsed := now.Sub(a.LastSeen)

		switch {
		case elapsed > am.offlineWindow:
			a.Status = StatusOffline
		case elapsed > am.heartbeatWindow:
			if a.Status == StatusOnline {
				a.Status = StatusDormant
			}
		default:
			if a.Status == StatusOffline || a.Status == StatusDormant {
				a.Status = StatusOnline
			}
		}

		if old != a.Status {
			switch a.Status {
			case StatusOffline:
				am.triggerCallback("agent_offline", a)
				LogAgentActivity(a.ID, "went_offline", "")
			case StatusOnline:
				am.triggerCallback("agent_reconnected", a)
				LogAgentActivity(a.ID, "reconnected", "")
			case StatusDormant:
				am.triggerCallback("agent_dormant", a)
				LogAgentActivity(a.ID, "dormant", "")
			}
		}
	}
}

// checkSecurityConcerns marks an agent as suspected if defensive tools are detected
func (am *AgentMonitor) checkSecurityConcerns(a *AgentHealth) {
	var concerns []string
	if len(a.SecurityInfo.RunningEDR) > 0 {
		concerns = append(concerns, "EDR detected")
	}
	if a.SecurityInfo.AntivirusStatus == "active" {
		concerns = append(concerns, "Active antivirus")
	}
	if a.SecurityInfo.PowerShellLogging {
		concerns = append(concerns, "PowerShell logging enabled")
	}
	if a.SecurityInfo.ScriptBlockLogging {
		concerns = append(concerns, "Script block logging enabled")
	}
	if len(concerns) > 0 {
		a.Status = StatusSuspected
		a.Metadata["security_concerns"] = concerns
		am.triggerCallback("security_concern", a)
		LogError(AUDIT, fmt.Sprintf("Security concerns detected: %v", concerns), a.ID)
	}
}
