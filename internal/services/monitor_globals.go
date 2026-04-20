package services

import (
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/storage"
)

// GlobalMonitor is the shared monitor instance used across the server
var GlobalMonitor *AgentMonitor

// InitAgentMonitor initialises and starts the global agent monitor
func InitAgentMonitor(store *storage.Store) {
	GlobalMonitor = NewAgentMonitor(
		30*time.Second,
		5*time.Minute,
		10*time.Second,
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
