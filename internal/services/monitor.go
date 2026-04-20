package services

import (
	"sync"
	"time"
)

// AgentMonitor tracks agent health and status in real time
type AgentMonitor struct {
	agents          map[string]*AgentHealth
	mu              sync.RWMutex
	heartbeatWindow time.Duration
	offlineWindow   time.Duration
	checkInterval   time.Duration
	callbacks       map[string]func(*AgentHealth)
	running         bool
	stopChan        chan struct{}
}

// NewAgentMonitor creates a monitor with the given timing windows
func NewAgentMonitor(heartbeatWindow, offlineWindow, checkInterval time.Duration) *AgentMonitor {
	return &AgentMonitor{
		agents:          make(map[string]*AgentHealth),
		heartbeatWindow: heartbeatWindow,
		offlineWindow:   offlineWindow,
		checkInterval:   checkInterval,
		callbacks:       make(map[string]func(*AgentHealth)),
		stopChan:        make(chan struct{}),
	}
}

// Start begins the background monitoring loop
func (am *AgentMonitor) Start() {
	am.mu.Lock()
	if am.running {
		am.mu.Unlock()
		return
	}
	am.running = true
	am.mu.Unlock()
	go am.monitorLoop()
	LogInfo(SYSTEM, "Agent monitor started", "")
}

// Stop halts the monitoring loop
func (am *AgentMonitor) Stop() {
	am.mu.Lock()
	defer am.mu.Unlock()
	if !am.running {
		return
	}
	am.running = false
	close(am.stopChan)
	LogInfo(SYSTEM, "Agent monitor stopped", "")
}
