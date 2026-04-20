package services

// LogLevel represents log severity
type LogLevel int

const (
	DEBUG    LogLevel = iota
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

// LogCategory groups log entries by subsystem
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

// LogEntry is a single structured log record
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

// SecurityEvent extends LogEntry with threat classification
type SecurityEvent struct {
	LogEntry
	Severity    int    `json:"severity"`
	ClientIP    string `json:"client_ip"`
	UserAgent   string `json:"user_agent,omitempty"`
	EventType   string `json:"event_type"`
	ThreatLevel string `json:"threat_level"`
}
