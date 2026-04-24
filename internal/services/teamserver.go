// Package services — teamserver.go
// Multi-operator team server hub.
//
// Architecture:
//   • Each operator registers with a name and gets a session ID.
//   • A SSE (Server-Sent Events) stream is opened per operator via
//     GET /api/v1/events.  The hub broadcasts agent events to all streams.
//   • Operators can "claim" exclusive write access to an agent.  Other
//     operators can observe but cannot queue commands for a claimed agent.
//   • No new dependencies: SSE is plain HTTP chunked-transfer.
package services

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TeamEvent is broadcast to all connected operator sessions.
type TeamEvent struct {
	Type    string `json:"type"`    // "agent_checkin" | "agent_offline" | "command_queued" | "result_ready" | "operator_joined" | "operator_left" | "agent_claimed" | "agent_released"
	AgentID string `json:"agent_id,omitempty"`
	OpName  string `json:"op_name,omitempty"`
	Payload string `json:"payload,omitempty"` // human-readable detail
	Time    string `json:"time"`
}

// Role represents an operator's permission level.
type Role string

const (
	RoleAdmin    Role = "admin"    // full access — manage operators, all agents
	RoleOperator Role = "operator" // queue commands, claim agents
	RoleViewer   Role = "viewer"   // read-only — list agents, view results, SSE
)

// RoleWeight returns a numeric weight for role comparison (higher = more access).
func RoleWeight(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// OperatorSession represents a connected operator.
type OperatorSession struct {
	ID       string
	Name     string
	Role     Role
	JoinedAt time.Time
	// Events is the channel the SSE handler drains. Closed when the HTTP
	// connection drops (detected by ctx.Done in the handler).
	Events chan TeamEvent
}

// TeamHub manages operator sessions, claimed agents, and event broadcasting.
type TeamHub struct {
	mu        sync.RWMutex
	operators map[string]*OperatorSession // session ID → session
	claims    map[string]string           // agent ID → operator session ID
	adminKey  string                      // secret required to register as admin
}

// NewTeamHub creates an idle hub.  Call Start() to enable periodic pings.
// adminKey is the secret operators must supply to register with role=admin.
// An empty adminKey disables admin-role promotion (all register as operator).
func NewTeamHub(adminKey string) *TeamHub {
	return &TeamHub{
		operators: make(map[string]*OperatorSession),
		claims:    make(map[string]string),
		adminKey:  adminKey,
	}
}

// Start launches background goroutines (keepalive ping, stale session GC).
func (h *TeamHub) Start() {
	go h.pingLoop()
}

// RegisterOperator adds a new operator session and returns its ID.
// role defaults to RoleOperator unless the supplied adminKey matches the hub's
// configured admin key, in which case RoleAdmin is granted.
// Pass role=RoleViewer explicitly to create a read-only session.
func (h *TeamHub) RegisterOperator(name string, role Role, adminKey string) *OperatorSession {
	// Validate requested role.
	switch role {
	case RoleAdmin:
		if h.adminKey == "" || adminKey != h.adminKey {
			role = RoleOperator // downgrade — key mismatch
		}
	case RoleViewer:
		// Always allowed.
	default:
		role = RoleOperator // unknown role → default
	}

	sess := &OperatorSession{
		ID:       uuid.New().String(),
		Name:     name,
		Role:     role,
		JoinedAt: time.Now(),
		Events:   make(chan TeamEvent, 64),
	}
	h.mu.Lock()
	h.operators[sess.ID] = sess
	h.mu.Unlock()

	h.Broadcast(TeamEvent{
		Type:    "operator_joined",
		OpName:  name,
		Payload: fmt.Sprintf("%s joined the team server", name),
		Time:    time.Now().Format(time.RFC3339),
	})
	return sess
}

// RemoveOperator removes a session and releases any claims it holds.
func (h *TeamHub) RemoveOperator(sessionID string) {
	h.mu.Lock()
	sess, ok := h.operators[sessionID]
	if !ok {
		h.mu.Unlock()
		return
	}
	// Release all agent claims held by this operator
	for agentID, claimant := range h.claims {
		if claimant == sessionID {
			delete(h.claims, agentID)
		}
	}
	delete(h.operators, sessionID)
	close(sess.Events)
	name := sess.Name
	h.mu.Unlock()

	h.Broadcast(TeamEvent{
		Type:    "operator_left",
		OpName:  name,
		Payload: fmt.Sprintf("%s disconnected", name),
		Time:    time.Now().Format(time.RFC3339),
	})
}

// ClaimAgent grants exclusive write access to agentID for sessionID.
// Returns an error if the agent is already claimed by another operator.
func (h *TeamHub) ClaimAgent(agentID, sessionID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if existing, ok := h.claims[agentID]; ok && existing != sessionID {
		op := h.operators[existing]
		name := "unknown"
		if op != nil {
			name = op.Name
		}
		return fmt.Errorf("agent %s is already claimed by %s", agentID, name)
	}
	h.claims[agentID] = sessionID

	sess := h.operators[sessionID]
	opName := "unknown"
	if sess != nil {
		opName = sess.Name
	}
	// Broadcast without holding the lock to avoid deadlock
	go h.Broadcast(TeamEvent{
		Type:    "agent_claimed",
		AgentID: agentID,
		OpName:  opName,
		Payload: fmt.Sprintf("%s claimed agent %s", opName, agentID[:8]),
		Time:    time.Now().Format(time.RFC3339),
	})
	return nil
}

// ReleaseAgent removes the claim on agentID if held by sessionID.
func (h *TeamHub) ReleaseAgent(agentID, sessionID string) {
	h.mu.Lock()
	if h.claims[agentID] == sessionID {
		delete(h.claims, agentID)
	}
	sess := h.operators[sessionID]
	opName := "unknown"
	if sess != nil {
		opName = sess.Name
	}
	h.mu.Unlock()

	h.Broadcast(TeamEvent{
		Type:    "agent_released",
		AgentID: agentID,
		OpName:  opName,
		Payload: fmt.Sprintf("%s released agent %s", opName, agentID[:8]),
		Time:    time.Now().Format(time.RFC3339),
	})
}

// CanWrite returns true if sessionID may queue commands for agentID.
// An unclaimed agent is writable by anyone.
func (h *TeamHub) CanWrite(agentID, sessionID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	claimant, claimed := h.claims[agentID]
	if !claimed {
		return true
	}
	return claimant == sessionID
}

// Broadcast sends ev to all connected operator sessions.
// Drops the event for sessions whose channel is full (non-blocking).
func (h *TeamHub) Broadcast(ev TeamEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, sess := range h.operators {
		select {
		case sess.Events <- ev:
		default:
			// Drop rather than block — slow operators get skipped
		}
	}
}

// ListOperators returns a snapshot of all connected operators.
func (h *TeamHub) ListOperators() []OperatorInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]OperatorInfo, 0, len(h.operators))
	for _, sess := range h.operators {
		claimed := h.operatorClaims(sess.ID)
		out = append(out, OperatorInfo{
			ID:            sess.ID,
			Name:          sess.Name,
			Role:          sess.Role,
			JoinedAt:      sess.JoinedAt,
			ClaimedAgents: claimed,
		})
	}
	return out
}

// GetRole returns the role of the operator identified by sessionID.
// Returns RoleViewer and false if the session does not exist.
func (h *TeamHub) GetRole(sessionID string) (Role, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sess, ok := h.operators[sessionID]
	if !ok {
		return RoleViewer, false
	}
	return sess.Role, true
}

// HasRole returns true when the session's role is at least minRole.
func (h *TeamHub) HasRole(sessionID string, minRole Role) bool {
	role, ok := h.GetRole(sessionID)
	if !ok {
		return false
	}
	return RoleWeight(role) >= RoleWeight(minRole)
}

// PromoteOperator changes an operator's role.  Only admin sessions may call this.
func (h *TeamHub) PromoteOperator(callerSessionID, targetSessionID string, newRole Role) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	caller, ok := h.operators[callerSessionID]
	if !ok || caller.Role != RoleAdmin {
		return fmt.Errorf("only admins may change operator roles")
	}
	target, ok := h.operators[targetSessionID]
	if !ok {
		return fmt.Errorf("target operator session not found")
	}
	target.Role = newRole
	return nil
}

// AgentClaim returns who (if anyone) has claimed agentID.
func (h *TeamHub) AgentClaim(agentID string) (sessionID, opName string, claimed bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	sid, ok := h.claims[agentID]
	if !ok {
		return "", "", false
	}
	name := "unknown"
	if sess, exists := h.operators[sid]; exists {
		name = sess.Name
	}
	return sid, name, true
}

// OperatorInfo is the external representation of a connected operator.
type OperatorInfo struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Role          Role      `json:"role"`
	JoinedAt      time.Time `json:"joined_at"`
	ClaimedAgents []string  `json:"claimed_agents,omitempty"`
}

// ── private ───────────────────────────────────────────────────────────────────

func (h *TeamHub) operatorClaims(sessionID string) []string {
	// caller holds RLock
	var agents []string
	for agentID, claimant := range h.claims {
		if claimant == sessionID {
			agents = append(agents, agentID)
		}
	}
	return agents
}

func (h *TeamHub) pingLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for range tick.C {
		h.Broadcast(TeamEvent{
			Type:    "ping",
			Payload: "keepalive",
			Time:    time.Now().Format(time.RFC3339),
		})
	}
}
