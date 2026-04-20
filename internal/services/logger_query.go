package services

import "time"

// GetRecentLogs returns the last n log entries
func (l *Logger) GetRecentLogs(n int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n > len(l.entries) {
		n = len(l.entries)
	}
	out := make([]LogEntry, n)
	copy(out, l.entries[len(l.entries)-n:])
	return out
}

// GetSecurityEvents returns the last n security events
func (l *Logger) GetSecurityEvents(n int) []SecurityEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n > len(l.secEvents) {
		n = len(l.secEvents)
	}
	out := make([]SecurityEvent, n)
	copy(out, l.secEvents[len(l.secEvents)-n:])
	return out
}

// GetLogsByAgent returns the last n entries for a specific agent
func (l *Logger) GetLogsByAgent(agentID string, n int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []LogEntry
	for i := len(l.entries) - 1; i >= 0 && len(out) < n; i-- {
		if l.entries[i].AgentID == agentID {
			out = append([]LogEntry{l.entries[i]}, out...)
		}
	}
	return out
}

// GetLogsByCategory returns the last n entries for a log category
func (l *Logger) GetLogsByCategory(category LogCategory, n int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []LogEntry
	for i := len(l.entries) - 1; i >= 0 && len(out) < n; i-- {
		if l.entries[i].Category == string(category) {
			out = append([]LogEntry{l.entries[i]}, out...)
		}
	}
	return out
}

// GetCommandHistory returns command execution entries for an agent
func (l *Logger) GetCommandHistory(agentID string, n int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []LogEntry
	for i := len(l.entries) - 1; i >= 0 && len(out) < n; i-- {
		e := l.entries[i]
		if e.AgentID == agentID && e.Category == string(COMMAND_EXEC) {
			out = append([]LogEntry{e}, out...)
		}
	}
	return out
}

// GetStats returns aggregate log statistics
func (l *Logger) GetStats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	categories := make(map[string]int)
	levels := make(map[string]int)
	agents := make(map[string]int)
	for _, e := range l.entries {
		categories[e.Category]++
		levels[e.Level]++
		if e.AgentID != "" {
			agents[e.AgentID]++
		}
	}

	secSummary := make(map[string]int)
	for _, se := range l.secEvents {
		secSummary[se.ThreatLevel]++
	}

	return map[string]interface{}{
		"total_entries":    len(l.entries),
		"security_events":  len(l.secEvents),
		"categories":       categories,
		"levels":           levels,
		"agents":           agents,
		"security_summary": secSummary,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	}
}
