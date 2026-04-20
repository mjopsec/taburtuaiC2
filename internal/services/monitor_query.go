package services

import "time"

// GetAgent returns a copy of an agent's health record
func (am *AgentMonitor) GetAgent(agentID string) (*AgentHealth, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	a, ok := am.agents[agentID]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// GetAllAgents returns copies of all registered agents
func (am *AgentMonitor) GetAllAgents() map[string]*AgentHealth {
	am.mu.RLock()
	defer am.mu.RUnlock()
	out := make(map[string]*AgentHealth, len(am.agents))
	for id, a := range am.agents {
		cp := *a
		out[id] = &cp
	}
	return out
}

// GetAgentsByStatus returns agents with the given status
func (am *AgentMonitor) GetAgentsByStatus(status AgentStatus) []*AgentHealth {
	am.mu.RLock()
	defer am.mu.RUnlock()
	var out []*AgentHealth
	for _, a := range am.agents {
		if a.Status == status {
			cp := *a
			out = append(out, &cp)
		}
	}
	return out
}

// GetStats returns aggregate counts across all agents
func (am *AgentMonitor) GetStats() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()

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
	for _, a := range am.agents {
		switch a.Status {
		case StatusOnline:
			stats["online_agents"] = stats["online_agents"].(int) + 1
		case StatusOffline:
			stats["offline_agents"] = stats["offline_agents"].(int) + 1
		case StatusError:
			stats["error_agents"] = stats["error_agents"].(int) + 1
		case StatusSuspected:
			stats["suspected_agents"] = stats["suspected_agents"].(int) + 1
		}
		stats["total_commands"] = stats["total_commands"].(int) + a.CommandsExecuted
		stats["total_transfers"] = stats["total_transfers"].(int) + a.FilesTransferred
		totalUptime += time.Since(a.FirstContact).Hours()
	}
	if len(am.agents) > 0 {
		stats["average_uptime"] = totalUptime / float64(len(am.agents))
	}
	return stats
}

// GetAgentHistory returns the error log for an agent, newest last
func (am *AgentMonitor) GetAgentHistory(agentID string, limit int) []ErrorInfo {
	am.mu.RLock()
	defer am.mu.RUnlock()
	a, ok := am.agents[agentID]
	if !ok {
		return nil
	}
	errs := a.Errors
	if len(errs) > limit {
		return errs[len(errs)-limit:]
	}
	return errs
}

// GetHighRiskAgents returns agents with elevated error rates or adverse status
func (am *AgentMonitor) GetHighRiskAgents() []*AgentHealth {
	am.mu.RLock()
	defer am.mu.RUnlock()
	var out []*AgentHealth
	oneHourAgo := time.Now().Add(-time.Hour)
	for _, a := range am.agents {
		risk := a.Performance.ErrorRate > 0.3 ||
			a.Status == StatusSuspected ||
			a.Status == StatusError

		if !risk {
			for _, e := range a.Errors {
				if e.Timestamp.After(oneHourAgo) && e.Severity == "critical" {
					risk = true
					break
				}
			}
		}
		if risk {
			cp := *a
			out = append(out, &cp)
		}
	}
	return out
}

// GetPerformanceReport returns a per-agent performance summary
func (am *AgentMonitor) GetPerformanceReport() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()

	agents := make([]map[string]interface{}, 0, len(am.agents))
	for _, a := range am.agents {
		agents = append(agents, map[string]interface{}{
			"id":                a.ID,
			"hostname":          a.Hostname,
			"status":            a.Status,
			"uptime_hours":      time.Since(a.FirstContact).Hours(),
			"commands_executed": a.CommandsExecuted,
			"files_transferred": a.FilesTransferred,
			"error_rate":        a.Performance.ErrorRate,
			"success_rate":      a.Performance.SuccessRate,
			"avg_latency_ms":    a.Performance.AverageLatency.Milliseconds(),
			"transfer_rate_bps": a.Performance.DataTransferRate,
			"recent_errors":     len(a.Errors),
		})
	}
	return map[string]interface{}{
		"timestamp": time.Now(),
		"agents":    agents,
	}
}
