package listener

import (
	"context"
	"fmt"
	"sync"
)

// Manager orchestrates multiple listeners across different protocols
type Manager struct {
	listeners map[string]Listener
	handler   Handler
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewManager creates a new listener manager
func NewManager(handler Handler) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		listeners: make(map[string]Listener),
		handler:   handler,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Add registers a listener (does not start it)
func (m *Manager) Add(l Listener) error {
	cfg := l.GetConfig()
	if cfg.ID == "" {
		return fmt.Errorf("listener ID cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[cfg.ID]; exists {
		return fmt.Errorf("listener %s already registered", cfg.ID)
	}

	m.listeners[cfg.ID] = l
	return nil
}

// Start starts a registered listener by ID
func (m *Manager) Start(id string) error {
	m.mu.RLock()
	l, exists := m.listeners[id]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("listener %s not found", id)
	}

	go func() {
		if err := l.Start(m.ctx); err != nil {
			// TODO: propagate error through event channel
			_ = err
		}
	}()

	return nil
}

// Stop stops a listener by ID
func (m *Manager) Stop(id string) error {
	m.mu.RLock()
	l, exists := m.listeners[id]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("listener %s not found", id)
	}

	return l.Stop()
}

// StopAll stops all running listeners
func (m *Manager) StopAll() {
	m.cancel()
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, l := range m.listeners {
		_ = l.Stop()
	}
}

// Get returns a listener by ID
func (m *Manager) Get(id string) (Listener, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.listeners[id]
	return l, ok
}

// List returns all registered listener configs and their status
func (m *Manager) List() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(m.listeners))
	for _, l := range m.listeners {
		cfg := l.GetConfig()
		result = append(result, map[string]interface{}{
			"id":     cfg.ID,
			"name":   cfg.Name,
			"type":   cfg.Type,
			"host":   cfg.Host,
			"port":   cfg.Port,
			"status": l.GetStatus(),
			"stats":  l.GetStats(),
		})
	}
	return result
}
