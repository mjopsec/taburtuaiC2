package listener

import (
	"context"
	"time"
)

// Type defines the transport protocol for a listener
type Type string

const (
	TypeHTTP      Type = "http"
	TypeHTTPS     Type = "https"
	TypeDNS       Type = "dns"
	TypeSMB       Type = "smb"
	TypeWebSocket Type = "websocket"
	TypeTCP       Type = "tcp"
)

// Status represents listener operational state
type Status string

const (
	StatusStarting Status = "starting"
	StatusRunning  Status = "running"
	StatusStopped  Status = "stopped"
	StatusError    Status = "error"
)

// Config holds common configuration for all listener types
type Config struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        Type              `json:"type"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Enabled     bool              `json:"enabled"`
	Options     map[string]string `json:"options,omitempty"`

	// OPSEC options
	Profile     string `json:"profile,omitempty"`   // malleable profile name
	Jitter      int    `json:"jitter,omitempty"`    // beacon jitter %
	Sleep       int    `json:"sleep,omitempty"`     // sleep interval seconds
	KillDate    string `json:"kill_date,omitempty"` // auto-kill date YYYY-MM-DD
}

// CheckinData holds agent check-in payload
type CheckinData struct {
	AgentID   string            `json:"agent_id"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	PID       int               `json:"pid"`
	Privs     string            `json:"privs"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Encrypted bool              `json:"encrypted"`
	Payload   string            `json:"payload,omitempty"`
}

// Listener is the core interface all transports must implement
type Listener interface {
	// Start begins accepting connections
	Start(ctx context.Context) error

	// Stop shuts down the listener gracefully
	Stop() error

	// GetConfig returns the listener's configuration
	GetConfig() *Config

	// GetStatus returns current operational status
	GetStatus() Status

	// GetStats returns listener statistics
	GetStats() *Stats
}

// Stats holds listener runtime statistics
type Stats struct {
	ListenerID    string    `json:"listener_id"`
	StartedAt     time.Time `json:"started_at"`
	TotalCheckins int64     `json:"total_checkins"`
	ActiveAgents  int       `json:"active_agents"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	LastCheckin   time.Time `json:"last_checkin"`
	Errors        int64     `json:"errors"`
}

// Handler is the callback interface for processing agent messages
type Handler interface {
	OnCheckin(data *CheckinData) (interface{}, error)
	OnPoll(agentID string) (interface{}, error)
	OnResult(agentID string, payload []byte) error
}
