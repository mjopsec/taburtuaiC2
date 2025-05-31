package services

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LogLevel represents different log levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	CRITICAL
)

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case CRITICAL:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp string            `json:"timestamp"`
	Level     string            `json:"level"`
	Category  string            `json:"category"`
	Message   string            `json:"message"`
	AgentID   string            `json:"agent_id,omitempty"`
	Command   string            `json:"command,omitempty"`
	Result    string            `json:"result,omitempty"`
	Success   bool              `json:"success,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	EventID   string            `json:"event_id,omitempty"`
	Hostname  string            `json:"hostname,omitempty"`
}

// SecurityEvent represents a security-specific log entry
type SecurityEvent struct {
	LogEntry
	Severity    int    `json:"severity"`
	ClientIP    string `json:"client_ip"`
	UserAgent   string `json:"user_agent,omitempty"`
	EventType   string `json:"event_type"`
	ThreatLevel string `json:"threat_level"`
}

// LogCategory represents different categories of logs
type LogCategory string

const (
	AGENT_CONNECTION LogCategory = "AGENT_CONNECTION"
	COMMAND_EXEC     LogCategory = "COMMAND_EXECUTION"
	FILE_TRANSFER    LogCategory = "FILE_TRANSFER"
	AUTHENTICATION   LogCategory = "AUTHENTICATION"
	SYSTEM           LogCategory = "SYSTEM"
	ERROR_LOG        LogCategory = "ERROR"
	AUDIT            LogCategory = "AUDIT"
	SECURITY         LogCategory = "SECURITY"
)

// Logger is the main logging structure
type Logger struct {
	level        LogLevel
	logFile      *os.File
	jsonFile     *os.File
	securityFile *os.File
	mutex        sync.RWMutex
	entries      []LogEntry
	secEvents    []SecurityEvent
	maxSize      int // Maximum number of entries to keep in memory
	hostname     string
	version      string
}

// Global logger instance
var GlobalLogger *Logger

// InitLogger initializes the global logger
func InitLogger(logLevel LogLevel, logDir string) error {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log files
	logFile, err := os.OpenFile(
		filepath.Join(logDir, "taburtuai.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	jsonFile, err := os.OpenFile(
		filepath.Join(logDir, "taburtuai.json"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		logFile.Close()
		return fmt.Errorf("failed to open JSON log file: %v", err)
	}

	securityFile, err := os.OpenFile(
		filepath.Join(logDir, "security.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		logFile.Close()
		jsonFile.Close()
		return fmt.Errorf("failed to open security log file: %v", err)
	}

	hostname, _ := os.Hostname()

	GlobalLogger = &Logger{
		level:        logLevel,
		logFile:      logFile,
		jsonFile:     jsonFile,
		securityFile: securityFile,
		entries:      make([]LogEntry, 0),
		secEvents:    make([]SecurityEvent, 0),
		maxSize:      1000, // Keep last 1000 entries in memory
		hostname:     hostname,
		version:      "2.0.0",
	}

	// Log initialization
	GlobalLogger.Info(SYSTEM, "Logger initialized", "", "", nil)
	return nil
}

// Close closes the logger files
func (l *Logger) Close() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.logFile != nil {
		l.logFile.Close()
	}
	if l.jsonFile != nil {
		l.jsonFile.Close()
	}
	if l.securityFile != nil {
		l.securityFile.Close()
	}
}

// Log writes a log entry with enhanced metadata
func (l *Logger) Log(level LogLevel, category LogCategory, message, agentID, command string, metadata map[string]string) {
	if level < l.level {
		return
	}

	// Enhanced metadata
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["hostname"] = l.hostname
	metadata["version"] = l.version
	metadata["pid"] = fmt.Sprintf("%d", os.Getpid())

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Category:  string(category),
		Message:   message,
		AgentID:   agentID,
		Command:   command,
		Metadata:  metadata,
		EventID:   generateEventID(),
		Hostname:  l.hostname,
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Add to memory buffer
	l.entries = append(l.entries, entry)

	// Trim if too many entries
	if len(l.entries) > l.maxSize {
		l.entries = l.entries[len(l.entries)-l.maxSize:]
	}

	// Write to text log file
	if l.logFile != nil {
		logLine := fmt.Sprintf("[%s] [%s] [%s] [%s] %s",
			entry.Timestamp, entry.Level, entry.Category, entry.EventID, entry.Message)

		if entry.AgentID != "" {
			logLine += fmt.Sprintf(" | Agent: %s", entry.AgentID)
		}
		if entry.Command != "" {
			logLine += fmt.Sprintf(" | Command: %s", entry.Command)
		}

		// Add important metadata to log line
		if clientIP, ok := metadata["client_ip"]; ok && clientIP != "" {
			logLine += fmt.Sprintf(" | IP: %s", clientIP)
		}

		logLine += "\n"
		l.logFile.WriteString(logLine)
		l.logFile.Sync()
	}

	// Write to JSON log file
	if l.jsonFile != nil {
		jsonData, _ := json.Marshal(entry)
		l.jsonFile.WriteString(string(jsonData) + "\n")
		l.jsonFile.Sync()
	}

	// Also log to standard logger for console output
	if level >= WARN {
		log.Printf("[%s] [%s] [%s] %s", entry.Level, entry.Category, entry.EventID, entry.Message)
	}
}

// LogSecurityEvent logs security-related events with enhanced details
func (l *Logger) LogSecurityEvent(event, description, agentID, clientIP string, severity int) {
	if l == nil {
		return
	}

	// Determine threat level based on severity
	threatLevel := "LOW"
	switch {
	case severity >= 8:
		threatLevel = "CRITICAL"
	case severity >= 6:
		threatLevel = "HIGH"
	case severity >= 4:
		threatLevel = "MEDIUM"
	}

	metadata := map[string]string{
		"event_type":    "security",
		"hostname":      l.hostname,
		"version":       l.version,
		"client_ip":     clientIP,
		"severity":      fmt.Sprintf("%d", severity),
		"timestamp_utc": time.Now().UTC().Format(time.RFC3339),
		"event_id":      generateEventID(),
		"threat_level":  threatLevel,
	}

	message := fmt.Sprintf("SECURITY EVENT: %s - %s", event, description)

	var logLevel LogLevel
	switch severity {
	case 1, 2:
		logLevel = INFO
	case 3, 4:
		logLevel = WARN
	case 5, 6:
		logLevel = ERROR
	default:
		logLevel = CRITICAL
	}

	// Create security event
	secEvent := SecurityEvent{
		LogEntry: LogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     logLevel.String(),
			Category:  string(SECURITY),
			Message:   message,
			AgentID:   agentID,
			Metadata:  metadata,
			EventID:   metadata["event_id"],
			Hostname:  l.hostname,
		},
		Severity:    severity,
		ClientIP:    clientIP,
		EventType:   event,
		ThreatLevel: threatLevel,
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Add to security events buffer
	l.secEvents = append(l.secEvents, secEvent)
	if len(l.secEvents) > l.maxSize {
		l.secEvents = l.secEvents[len(l.secEvents)-l.maxSize:]
	}

	// Write to security log file
	if l.securityFile != nil {
		secLogLine := fmt.Sprintf("[%s] [SEVERITY:%d] [%s] [%s] %s",
			secEvent.Timestamp, severity, threatLevel, secEvent.EventID, message)

		if clientIP != "" {
			secLogLine += fmt.Sprintf(" | IP: %s", clientIP)
		}
		if agentID != "" {
			secLogLine += fmt.Sprintf(" | Agent: %s", agentID)
		}

		secLogLine += "\n"
		l.securityFile.WriteString(secLogLine)
		l.securityFile.Sync()

		// Also write JSON format to security file
		secJSON, _ := json.Marshal(secEvent)
		l.securityFile.WriteString(string(secJSON) + "\n")
		l.securityFile.Sync()
	}

	// Log using regular logging system as well
	l.Log(logLevel, AUDIT, message, agentID, "", metadata)
}

// Convenience methods
func (l *Logger) Debug(category LogCategory, message, agentID, command string, metadata map[string]string) {
	l.Log(DEBUG, category, message, agentID, command, metadata)
}

func (l *Logger) Info(category LogCategory, message, agentID, command string, metadata map[string]string) {
	l.Log(INFO, category, message, agentID, command, metadata)
}

func (l *Logger) Warn(category LogCategory, message, agentID, command string, metadata map[string]string) {
	l.Log(WARN, category, message, agentID, command, metadata)
}

func (l *Logger) Error(category LogCategory, message, agentID, command string, metadata map[string]string) {
	l.Log(ERROR, category, message, agentID, command, metadata)
}

func (l *Logger) Critical(category LogCategory, message, agentID, command string, metadata map[string]string) {
	l.Log(CRITICAL, category, message, agentID, command, metadata)
}

// LogAgentConnection logs agent connection events with enhanced details
func (l *Logger) LogAgentConnection(agentID, action, clientIP string) {
	metadata := map[string]string{
		"client_ip": clientIP,
		"action":    action,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	message := fmt.Sprintf("Agent %s: %s", agentID, action)
	l.Info(AGENT_CONNECTION, message, agentID, "", metadata)

	// Log as security event for certain actions
	securityActions := map[string]int{
		"first_contact": 3,
		"reconnected":   2,
		"went_offline":  4,
		"removed":       5,
	}

	if severity, isSecurityEvent := securityActions[action]; isSecurityEvent {
		l.LogSecurityEvent("AGENT_"+strings.ToUpper(action), message, agentID, clientIP, severity)
	}
}

// LogCommandExecution logs command execution with enhanced security tracking
func (l *Logger) LogCommandExecution(agentID, command, result string, success bool) {
	level := INFO
	if !success {
		level = ERROR
	}

	metadata := map[string]string{
		"success":   fmt.Sprintf("%v", success),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Check for potentially dangerous commands and log as security events
	dangerousPatterns := []string{
		"rm -rf", "del /s", "format", "shutdown", "reboot",
		"useradd", "passwd", "sudo", "net user", "reg add",
	}

	commandLower := strings.ToLower(command)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(commandLower, pattern) {
			l.LogSecurityEvent("DANGEROUS_COMMAND",
				fmt.Sprintf("Potentially dangerous command executed: %s", command),
				agentID, "", 6)
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
		Metadata:  metadata,
		EventID:   generateEventID(),
		Hostname:  l.hostname,
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Add to memory buffer
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxSize {
		l.entries = l.entries[len(l.entries)-l.maxSize:]
	}

	// Write to files
	if l.logFile != nil {
		logLine := fmt.Sprintf("[%s] [%s] [%s] [%s] %s | Agent: %s | Result: %s\n",
			entry.Timestamp, entry.Level, entry.Category, entry.EventID, entry.Message,
			entry.AgentID, truncate(entry.Result, 100))
		l.logFile.WriteString(logLine)
		l.logFile.Sync()
	}

	if l.jsonFile != nil {
		jsonData, _ := json.Marshal(entry)
		l.jsonFile.WriteString(string(jsonData) + "\n")
		l.jsonFile.Sync()
	}
}

// LogFileTransfer logs file transfer operations with security monitoring
func (l *Logger) LogFileTransfer(agentID, operation, filename, size string, success bool) {
	level := INFO
	if !success {
		level = ERROR
	}

	metadata := map[string]string{
		"operation": operation,
		"filename":  filename,
		"size":      size,
		"success":   fmt.Sprintf("%v", success),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	message := fmt.Sprintf("File %s: %s (%s bytes)", operation, filename, size)
	l.Log(level, FILE_TRANSFER, message, agentID, "", metadata)

	// Log large file transfers as security events
	if sizeInt, err := strconv.Atoi(size); err == nil && sizeInt > 50*1024*1024 { // 50MB
		l.LogSecurityEvent("LARGE_FILE_TRANSFER",
			fmt.Sprintf("Large file %s: %s (%s bytes)", operation, filename, size),
			agentID, "", 4)
	}

	// Log suspicious file extensions
	suspiciousExts := []string{".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr"}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, suspExt := range suspiciousExts {
		if ext == suspExt {
			l.LogSecurityEvent("SUSPICIOUS_FILE_TRANSFER",
				fmt.Sprintf("Transfer of %s file: %s", ext, filename),
				agentID, "", 5)
			break
		}
	}
}

// LogAuthentication logs authentication events
func (l *Logger) LogAuthentication(user, action, clientIP string, success bool) {
	level := INFO
	severity := 2
	if !success {
		level = WARN
		severity = 5
	}

	metadata := map[string]string{
		"user":      user,
		"action":    action,
		"client_ip": clientIP,
		"success":   fmt.Sprintf("%v", success),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	message := fmt.Sprintf("Authentication %s for user %s from %s", action, user, clientIP)
	l.Log(level, AUTHENTICATION, message, "", "", metadata)

	// Always log authentication events as security events
	eventType := "AUTH_SUCCESS"
	if !success {
		eventType = "AUTH_FAILURE"
	}

	l.LogSecurityEvent(eventType, message, "", clientIP, severity)
}

// GetRecentLogs returns recent log entries
func (l *Logger) GetRecentLogs(count int) []LogEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if count > len(l.entries) {
		count = len(l.entries)
	}

	start := len(l.entries) - count
	result := make([]LogEntry, count)
	copy(result, l.entries[start:])
	return result
}

// GetSecurityEvents returns recent security events
func (l *Logger) GetSecurityEvents(count int) []SecurityEvent {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	if count > len(l.secEvents) {
		count = len(l.secEvents)
	}

	start := len(l.secEvents) - count
	result := make([]SecurityEvent, count)
	copy(result, l.secEvents[start:])
	return result
}

// GetLogsByAgent returns logs for a specific agent
func (l *Logger) GetLogsByAgent(agentID string, count int) []LogEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	var result []LogEntry
	for i := len(l.entries) - 1; i >= 0 && len(result) < count; i-- {
		if l.entries[i].AgentID == agentID {
			result = append([]LogEntry{l.entries[i]}, result...)
		}
	}
	return result
}

// GetLogsByCategory returns logs by category
func (l *Logger) GetLogsByCategory(category LogCategory, count int) []LogEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	var result []LogEntry
	for i := len(l.entries) - 1; i >= 0 && len(result) < count; i-- {
		if l.entries[i].Category == string(category) {
			result = append([]LogEntry{l.entries[i]}, result...)
		}
	}
	return result
}

// GetCommandHistory returns command execution history for an agent
func (l *Logger) GetCommandHistory(agentID string, count int) []LogEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	var result []LogEntry
	for i := len(l.entries) - 1; i >= 0 && len(result) < count; i-- {
		entry := l.entries[i]
		if entry.AgentID == agentID && entry.Category == string(COMMAND_EXEC) {
			result = append([]LogEntry{entry}, result...)
		}
	}
	return result
}

// GetStats returns enhanced logging statistics
func (l *Logger) GetStats() map[string]interface{} {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_entries":    len(l.entries),
		"security_events":  len(l.secEvents),
		"categories":       make(map[string]int),
		"levels":           make(map[string]int),
		"agents":           make(map[string]int),
		"security_summary": make(map[string]int),
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	}

	for _, entry := range l.entries {
		// Count by category
		if count, ok := stats["categories"].(map[string]int)[entry.Category]; ok {
			stats["categories"].(map[string]int)[entry.Category] = count + 1
		} else {
			stats["categories"].(map[string]int)[entry.Category] = 1
		}

		// Count by level
		if count, ok := stats["levels"].(map[string]int)[entry.Level]; ok {
			stats["levels"].(map[string]int)[entry.Level] = count + 1
		} else {
			stats["levels"].(map[string]int)[entry.Level] = 1
		}

		// Count by agent
		if entry.AgentID != "" {
			if count, ok := stats["agents"].(map[string]int)[entry.AgentID]; ok {
				stats["agents"].(map[string]int)[entry.AgentID] = count + 1
			} else {
				stats["agents"].(map[string]int)[entry.AgentID] = 1
			}
		}
	}

	// Security events summary
	for _, secEvent := range l.secEvents {
		if count, ok := stats["security_summary"].(map[string]int)[secEvent.ThreatLevel]; ok {
			stats["security_summary"].(map[string]int)[secEvent.ThreatLevel] = count + 1
		} else {
			stats["security_summary"].(map[string]int)[secEvent.ThreatLevel] = 1
		}
	}

	return stats
}

// Helper function to truncate long strings
func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

// generateEventID generates a unique event ID
func generateEventID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("EVT_%d_%x", time.Now().Unix(), b)
}

// Enhanced global convenience functions
func LogInfo(category LogCategory, message, agentID string) {
	if GlobalLogger != nil {
		GlobalLogger.Info(category, message, agentID, "", nil)
	}
}

func LogError(category LogCategory, message, agentID string) {
	if GlobalLogger != nil {
		GlobalLogger.Error(category, message, agentID, "", nil)
	}
}

func LogAgentActivity(agentID, action, clientIP string) {
	if GlobalLogger != nil {
		GlobalLogger.LogAgentConnection(agentID, action, clientIP)
	}
}

func LogCommand(agentID, command, result string, success bool) {
	if GlobalLogger != nil {
		GlobalLogger.LogCommandExecution(agentID, command, result, success)
	}
}

func LogFileOp(agentID, operation, filename, size string, success bool) {
	if GlobalLogger != nil {
		GlobalLogger.LogFileTransfer(agentID, operation, filename, size, success)
	}
}

func LogWarn(category LogCategory, message, agentID string) {
	if GlobalLogger != nil {
		GlobalLogger.Warn(category, message, agentID, "", nil)
	}
}

// LogSecurityEvent - global convenience function
func LogSecurityEvent(event, description, agentID, clientIP string, severity int) {
	if GlobalLogger != nil {
		GlobalLogger.LogSecurityEvent(event, description, agentID, clientIP, severity)
	}
}

// NewLogger creates a new logger instance
func NewLogger(logLevel LogLevel, logDir string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log files
	logFile, err := os.OpenFile(
		filepath.Join(logDir, "taburtuai.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	jsonFile, err := os.OpenFile(
		filepath.Join(logDir, "taburtuai.json"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		logFile.Close()
		return nil, fmt.Errorf("failed to open JSON log file: %v", err)
	}

	securityFile, err := os.OpenFile(
		filepath.Join(logDir, "security.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		logFile.Close()
		jsonFile.Close()
		return nil, fmt.Errorf("failed to open security log file: %v", err)
	}

	hostname, _ := os.Hostname()

	logger := &Logger{
		level:        logLevel,
		logFile:      logFile,
		jsonFile:     jsonFile,
		securityFile: securityFile,
		entries:      make([]LogEntry, 0),
		secEvents:    make([]SecurityEvent, 0),
		maxSize:      1000,
		hostname:     hostname,
		version:      "2.0.0",
	}

	logger.Info(SYSTEM, "Logger initialized", "", "", nil)
	return logger, nil
}
