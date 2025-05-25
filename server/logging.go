package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
)

// Logger is the main logging structure
type Logger struct {
	level    LogLevel
	logFile  *os.File
	jsonFile *os.File
	mutex    sync.RWMutex
	entries  []LogEntry
	maxSize  int // Maximum number of entries to keep in memory
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

	GlobalLogger = &Logger{
		level:    logLevel,
		logFile:  logFile,
		jsonFile: jsonFile,
		entries:  make([]LogEntry, 0),
		maxSize:  1000, // Keep last 1000 entries in memory
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
}

// Log writes a log entry
func (l *Logger) Log(level LogLevel, category LogCategory, message, agentID, command string, metadata map[string]string) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Level:     level.String(),
		Category:  string(category),
		Message:   message,
		AgentID:   agentID,
		Command:   command,
		Metadata:  metadata,
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
		logLine := fmt.Sprintf("[%s] [%s] [%s] %s",
			entry.Timestamp, entry.Level, entry.Category, entry.Message)
		
		if entry.AgentID != "" {
			logLine += fmt.Sprintf(" | Agent: %s", entry.AgentID)
		}
		if entry.Command != "" {
			logLine += fmt.Sprintf(" | Command: %s", entry.Command)
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
		log.Printf("[%s] [%s] %s", entry.Level, entry.Category, entry.Message)
	}
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

// LogAgentConnection logs agent connection events
func (l *Logger) LogAgentConnection(agentID, action, clientIP string) {
	metadata := map[string]string{
		"client_ip": clientIP,
		"action":    action,
	}
	message := fmt.Sprintf("Agent %s: %s", agentID, action)
	l.Info(AGENT_CONNECTION, message, agentID, "", metadata)
}

// LogCommandExecution logs command execution
func (l *Logger) LogCommandExecution(agentID, command, result string, success bool) {
	level := INFO
	if !success {
		level = ERROR
	}

	metadata := map[string]string{
		"success": fmt.Sprintf("%v", success),
	}

	entry := LogEntry{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Level:     level.String(),
		Category:  string(COMMAND_EXEC),
		Message:   fmt.Sprintf("Command executed: %s", command),
		AgentID:   agentID,
		Command:   command,
		Result:    result,
		Success:   success,
		Metadata:  metadata,
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
		logLine := fmt.Sprintf("[%s] [%s] [%s] %s | Agent: %s | Result: %s\n",
			entry.Timestamp, entry.Level, entry.Category, entry.Message,
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

// LogFileTransfer logs file transfer operations
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
	}

	message := fmt.Sprintf("File %s: %s (%s bytes)", operation, filename, size)
	l.Log(level, FILE_TRANSFER, message, agentID, "", metadata)
}

// LogAuthentication logs authentication events
func (l *Logger) LogAuthentication(user, action, clientIP string, success bool) {
	level := INFO
	if !success {
		level = WARN
	}

	metadata := map[string]string{
		"user":      user,
		"action":    action,
		"client_ip": clientIP,
		"success":   fmt.Sprintf("%v", success),
	}

	message := fmt.Sprintf("Authentication %s for user %s from %s", action, user, clientIP)
	l.Log(level, AUTHENTICATION, message, "", "", metadata)
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

// GetStats returns logging statistics
func (l *Logger) GetStats() map[string]interface{} {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_entries": len(l.entries),
		"categories":    make(map[string]int),
		"levels":       make(map[string]int),
		"agents":       make(map[string]int),
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

	return stats
}

// Helper function to truncate long strings
func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

// Global convenience functions
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
