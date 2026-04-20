package services

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LogAgentConnection records agent checkin / status change events
func (l *Logger) LogAgentConnection(agentID, action, clientIP string) {
	l.Info(AGENT_CONNECTION, fmt.Sprintf("Agent %s: %s", agentID, action), agentID, "", map[string]string{
		"client_ip": clientIP,
		"action":    action,
	})

	severityMap := map[string]int{
		"first_contact": 3,
		"reconnected":   2,
		"went_offline":  4,
		"removed":       5,
	}
	if sev, ok := severityMap[action]; ok {
		l.LogSecurityEvent("AGENT_"+strings.ToUpper(action),
			fmt.Sprintf("Agent %s: %s", agentID, action), agentID, clientIP, sev)
	}
}

// LogCommandExecution records command execution and flags dangerous patterns
func (l *Logger) LogCommandExecution(agentID, command, result string, success bool) {
	level := INFO
	if !success {
		level = ERROR
	}

	dangerous := []string{"rm -rf", "del /s", "format", "shutdown", "reboot", "useradd", "passwd", "sudo", "net user", "reg add"}
	cmdLower := strings.ToLower(command)
	for _, p := range dangerous {
		if strings.Contains(cmdLower, p) {
			l.LogSecurityEvent("DANGEROUS_COMMAND",
				fmt.Sprintf("Dangerous command executed: %s", command), agentID, "", 6)
			break
		}
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Category:  string(COMMAND_EXEC),
		Message:   fmt.Sprintf("Command executed: %s", command),
		AgentID:   agentID,
		Command:   command,
		Result:    result,
		Success:   success,
		EventID:   generateEventID(),
		Hostname:  l.hostname,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxSize {
		l.entries = l.entries[len(l.entries)-l.maxSize:]
	}

	if l.logFile != nil {
		line := fmt.Sprintf("[%s] [%s] [%s] [%s] %s | Agent: %s | Result: %s\n",
			entry.Timestamp, entry.Level, entry.Category, entry.EventID,
			entry.Message, agentID, truncate(result, 100))
		_, _ = l.logFile.WriteString(line)
		_ = l.logFile.Sync()
	}
	if l.jsonFile != nil {
		b, _ := json.Marshal(entry)
		_, _ = l.jsonFile.WriteString(string(b) + "\n")
		_ = l.jsonFile.Sync()
	}
}

// LogFileTransfer records file upload/download operations
func (l *Logger) LogFileTransfer(agentID, operation, filename, size string, success bool) {
	level := INFO
	if !success {
		level = ERROR
	}

	l.Log(level, FILE_TRANSFER,
		fmt.Sprintf("File %s: %s (%s bytes)", operation, filename, size),
		agentID, "", map[string]string{
			"operation": operation,
			"filename":  filename,
			"size":      size,
			"success":   fmt.Sprintf("%v", success),
		})

	if sizeInt, err := strconv.Atoi(size); err == nil && sizeInt > 50*1024*1024 {
		l.LogSecurityEvent("LARGE_FILE_TRANSFER",
			fmt.Sprintf("Large file %s: %s (%s bytes)", operation, filename, size), agentID, "", 4)
	}

	suspicious := []string{".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr"}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, s := range suspicious {
		if ext == s {
			l.LogSecurityEvent("SUSPICIOUS_FILE_TRANSFER",
				fmt.Sprintf("Transfer of %s file: %s", ext, filename), agentID, "", 5)
			break
		}
	}
}

// LogAuthentication records auth attempts and always logs as a security event
func (l *Logger) LogAuthentication(user, action, clientIP string, success bool) {
	level := INFO
	severity := 2
	if !success {
		level = WARN
		severity = 5
	}

	msg := fmt.Sprintf("Auth %s for user %s from %s", action, user, clientIP)
	l.Log(level, AUTHENTICATION, msg, "", "", map[string]string{
		"user":      user,
		"action":    action,
		"client_ip": clientIP,
		"success":   fmt.Sprintf("%v", success),
	})

	eventType := "AUTH_SUCCESS"
	if !success {
		eventType = "AUTH_FAILURE"
	}
	l.LogSecurityEvent(eventType, msg, "", clientIP, severity)
}

// LogSecurityEvent writes a threat-classified security event
func (l *Logger) LogSecurityEvent(event, description, agentID, clientIP string, severity int) {
	threatLevel := "LOW"
	switch {
	case severity >= 8:
		threatLevel = "CRITICAL"
	case severity >= 6:
		threatLevel = "HIGH"
	case severity >= 4:
		threatLevel = "MEDIUM"
	}

	var logLevel LogLevel
	switch {
	case severity <= 2:
		logLevel = INFO
	case severity <= 4:
		logLevel = WARN
	case severity <= 6:
		logLevel = ERROR
	default:
		logLevel = CRITICAL
	}

	eventID := generateEventID()
	msg := fmt.Sprintf("SECURITY EVENT: %s - %s", event, description)

	secEvent := SecurityEvent{
		LogEntry: LogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     logLevel.String(),
			Category:  string(SECURITY),
			Message:   msg,
			AgentID:   agentID,
			EventID:   eventID,
			Hostname:  l.hostname,
		},
		Severity:    severity,
		ClientIP:    clientIP,
		EventType:   event,
		ThreatLevel: threatLevel,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.secEvents = append(l.secEvents, secEvent)
	if len(l.secEvents) > l.maxSize {
		l.secEvents = l.secEvents[len(l.secEvents)-l.maxSize:]
	}

	if l.securityFile != nil {
		line := fmt.Sprintf("[%s] [SEV:%d] [%s] [%s] %s", secEvent.Timestamp, severity, threatLevel, eventID, msg)
		if clientIP != "" {
			line += " | IP: " + clientIP
		}
		if agentID != "" {
			line += " | Agent: " + agentID
		}
		_, _ = l.securityFile.WriteString(line + "\n")
		_ = l.securityFile.Sync()

		b, _ := json.Marshal(secEvent)
		_, _ = l.securityFile.WriteString(string(b) + "\n")
		_ = l.securityFile.Sync()
	}

	// Mirror to main log (without holding mu again — already held above)
	entry := secEvent.LogEntry
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxSize {
		l.entries = l.entries[len(l.entries)-l.maxSize:]
	}
}
