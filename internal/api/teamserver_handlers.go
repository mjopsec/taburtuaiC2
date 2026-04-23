package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/services"
)

// ── Operator registration ─────────────────────────────────────────────────────

// RegisterOperator creates a new operator session.
// POST /api/v1/team/register
// Body: { "name": "op1" }
// Returns: { "session_id": "...", "name": "op1" }
func (h *Handlers) RegisterOperator(c *gin.Context) {
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "name is required")
		return
	}

	sess := h.server.TeamHub.RegisterOperator(req.Name)
	h.APIResponse(c, true, "Operator registered", map[string]interface{}{
		"session_id": sess.ID,
		"name":       sess.Name,
		"joined_at":  sess.JoinedAt,
	}, "")
}

// ListOperators returns all currently connected operators.
// GET /api/v1/team/operators
func (h *Handlers) ListOperators(c *gin.Context) {
	ops := h.server.TeamHub.ListOperators()
	h.APIResponse(c, true, "", map[string]interface{}{
		"operators": ops,
		"count":     len(ops),
	}, "")
}

// ── Agent claiming ────────────────────────────────────────────────────────────

// ClaimAgent gives an operator exclusive write access to an agent.
// POST /api/v1/team/agent/:id/claim
// Header: X-Session-ID: <session_id>
func (h *Handlers) ClaimAgent(c *gin.Context) {
	agentID, err := resolveAgentFromParam(h, c)
	if err != nil {
		return
	}
	sessionID := c.GetHeader("X-Session-ID")
	if sessionID == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "X-Session-ID header required")
		return
	}
	if err := h.server.TeamHub.ClaimAgent(agentID, sessionID); err != nil {
		c.Status(http.StatusConflict)
		h.APIResponse(c, false, "", nil, err.Error())
		return
	}
	h.APIResponse(c, true, fmt.Sprintf("Agent %s claimed", agentID[:8]), nil, "")
}

// ReleaseAgent removes an operator's claim on an agent.
// POST /api/v1/team/agent/:id/release
// Header: X-Session-ID: <session_id>
func (h *Handlers) ReleaseAgent(c *gin.Context) {
	agentID, err := resolveAgentFromParam(h, c)
	if err != nil {
		return
	}
	sessionID := c.GetHeader("X-Session-ID")
	if sessionID == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "X-Session-ID header required")
		return
	}
	h.server.TeamHub.ReleaseAgent(agentID, sessionID)
	h.APIResponse(c, true, fmt.Sprintf("Agent %s released", agentID[:8]), nil, "")
}

// AgentClaimStatus returns who (if anyone) has claimed an agent.
// GET /api/v1/team/agent/:id/claim
func (h *Handlers) AgentClaimStatus(c *gin.Context) {
	agentID, err := resolveAgentFromParam(h, c)
	if err != nil {
		return
	}
	sid, opName, claimed := h.server.TeamHub.AgentClaim(agentID)
	h.APIResponse(c, true, "", map[string]interface{}{
		"agent_id": agentID,
		"claimed":  claimed,
		"op_name":  opName,
		"session":  sid,
	}, "")
}

// ── SSE event stream ──────────────────────────────────────────────────────────

// EventStream opens an SSE stream for an operator.
// GET /api/v1/team/events
// Query: name=<operatorName>  (or use existing session via X-Session-ID header)
//
// The client receives a stream of JSON events:
//   data: {"type":"agent_checkin","agent_id":"...","payload":"...","time":"..."}
//
// The connection stays open until the client disconnects or the server stops.
func (h *Handlers) EventStream(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		name = c.GetHeader("X-Session-ID")
	}
	if name == "" {
		name = "anonymous"
	}

	sess := h.server.TeamHub.RegisterOperator(name)
	defer h.server.TeamHub.RemoveOperator(sess.ID)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Session-ID", sess.ID)

	// Send session info as first event
	h.writeSSEEvent(c, services.TeamEvent{
		Type:    "session_start",
		OpName:  name,
		Payload: fmt.Sprintf("session_id=%s", sess.ID),
		Time:    time.Now().Format(time.RFC3339),
	})
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()
	for {
		select {
		case <-clientGone:
			return
		case ev, ok := <-sess.Events:
			if !ok {
				return
			}
			h.writeSSEEvent(c, ev)
			c.Writer.Flush()
		}
	}
}

// BroadcastEvent allows the operator to send a custom event to all peers.
// POST /api/v1/team/broadcast
// Header: X-Session-ID: <session_id>
// Body: { "type": "note", "payload": "starting lsass dump on dc01" }
func (h *Handlers) BroadcastEvent(c *gin.Context) {
	sessionID := c.GetHeader("X-Session-ID")
	var req struct {
		Type    string `json:"type"`
		Payload string `json:"payload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Payload == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "payload is required")
		return
	}
	h.server.TeamHub.Broadcast(services.TeamEvent{
		Type:    req.Type,
		OpName:  sessionID,
		Payload: req.Payload,
		Time:    time.Now().Format(time.RFC3339),
	})
	h.APIResponse(c, true, "Broadcast sent", nil, "")
}

// ── private helpers ───────────────────────────────────────────────────────────

func (h *Handlers) writeSSEEvent(c *gin.Context, ev services.TeamEvent) {
	b, _ := json.Marshal(ev)
	fmt.Fprintf(c.Writer, "data: %s\n\n", string(b))
}

func resolveAgentFromParam(h *Handlers, c *gin.Context) (string, error) {
	agentID := c.Param("id")
	if _, exists := h.server.Monitor.GetAgent(agentID); !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return "", fmt.Errorf("not found")
	}
	return agentID, nil
}
