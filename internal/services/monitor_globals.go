package services

import (
	"os"
	"strconv"
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/storage"
)

// GlobalMonitor is the shared monitor instance used across the server
var GlobalMonitor *AgentMonitor

// InitAgentMonitor initialises and starts the global agent monitor.
// Thresholds can be tuned via env vars:
//   AGENT_DORMANT_SEC  — seconds without beacon before agent goes dormant (default 600)
//   AGENT_OFFLINE_SEC  — seconds without beacon before agent goes offline  (default 1800)
func InitAgentMonitor(store *storage.Store) {
	dormantSec := envInt("AGENT_DORMANT_SEC", 600)
	offlineSec := envInt("AGENT_OFFLINE_SEC", 1800)

	GlobalMonitor = NewAgentMonitor(
		time.Duration(dormantSec)*time.Second,
		time.Duration(offlineSec)*time.Second,
		15*time.Second,
		store,
	)

	GlobalMonitor.RegisterCallback("agent_offline", func(a *AgentHealth) {
		LogAgentActivity(a.ID, "offline_detected", "")
	})
	GlobalMonitor.RegisterCallback("agent_reconnected", func(a *AgentHealth) {
		LogAgentActivity(a.ID, "reconnected_detected", "")
	})
	GlobalMonitor.RegisterCallback("security_concern", func(a *AgentHealth) {
		LogError(AUDIT, "Security concern detected", a.ID)
	})

	GlobalMonitor.Start()
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
