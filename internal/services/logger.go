package services

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger writes structured logs to text, JSON, and security files
type Logger struct {
	level        LogLevel
	logFile      *os.File
	jsonFile     *os.File
	securityFile *os.File
	mu           sync.RWMutex
	entries      []LogEntry
	secEvents    []SecurityEvent
	maxSize      int
	hostname     string
}

// NewLogger creates and initialises a Logger instance
func NewLogger(level LogLevel, logDir string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log dir: %v", err)
	}

	open := func(name string) (*os.File, error) {
		return os.OpenFile(filepath.Join(logDir, name),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	}

	lf, err := open("taburtuai.log")
	if err != nil {
		return nil, err
	}
	jf, err := open("taburtuai.json")
	if err != nil {
		lf.Close()
		return nil, err
	}
	sf, err := open("security.log")
	if err != nil {
		lf.Close()
		jf.Close()
		return nil, err
	}

	hostname, _ := os.Hostname()
	l := &Logger{
		level:        level,
		logFile:      lf,
		jsonFile:     jf,
		securityFile: sf,
		entries:      make([]LogEntry, 0, 256),
		secEvents:    make([]SecurityEvent, 0, 64),
		maxSize:      1000,
		hostname:     hostname,
	}
	l.Info(SYSTEM, "Logger initialised", "", "", nil)
	return l, nil
}

// Close flushes and closes all open log files
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, f := range []*os.File{l.logFile, l.jsonFile, l.securityFile} {
		if f != nil {
			f.Close()
		}
	}
}

// Log writes an entry at the given level
func (l *Logger) Log(level LogLevel, category LogCategory, message, agentID, command string, metadata map[string]string) {
	if level < l.level {
		return
	}

	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["hostname"] = l.hostname

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

	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxSize {
		l.entries = l.entries[len(l.entries)-l.maxSize:]
	}

	line := fmt.Sprintf("[%s] [%s] [%s] [%s] %s", entry.Timestamp, entry.Level, entry.Category, entry.EventID, entry.Message)
	if agentID != "" {
		line += " | Agent: " + agentID
	}
	if ip := metadata["client_ip"]; ip != "" {
		line += " | IP: " + ip
	}
	line += "\n"

	if l.logFile != nil {
		_, _ = l.logFile.WriteString(line)
		_ = l.logFile.Sync()
	}
	if l.jsonFile != nil {
		b, _ := json.Marshal(entry)
		_, _ = l.jsonFile.WriteString(string(b) + "\n")
		_ = l.jsonFile.Sync()
	}
	if level >= WARN {
		log.Printf("[%s] [%s] %s", entry.Level, entry.Category, entry.Message)
	}
}

// Convenience level methods
func (l *Logger) Debug(cat LogCategory, msg, agentID, cmd string, meta map[string]string) {
	l.Log(DEBUG, cat, msg, agentID, cmd, meta)
}
func (l *Logger) Info(cat LogCategory, msg, agentID, cmd string, meta map[string]string) {
	l.Log(INFO, cat, msg, agentID, cmd, meta)
}
func (l *Logger) Warn(cat LogCategory, msg, agentID, cmd string, meta map[string]string) {
	l.Log(WARN, cat, msg, agentID, cmd, meta)
}
func (l *Logger) Error(cat LogCategory, msg, agentID, cmd string, meta map[string]string) {
	l.Log(ERROR, cat, msg, agentID, cmd, meta)
}
func (l *Logger) Critical(cat LogCategory, msg, agentID, cmd string, meta map[string]string) {
	l.Log(CRITICAL, cat, msg, agentID, cmd, meta)
}

// generateEventID produces a short unique event identifier
func generateEventID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("EVT_%d_%x", time.Now().Unix(), b)
}

// truncate shortens s to at most n characters, appending "..." if cut
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
