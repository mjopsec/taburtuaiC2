package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/server/services"
)

// ListAgents returns all registered agents
func (h *Handlers) ListAgents(c *gin.Context) {
	agents := h.server.Monitor.GetAllAgents()

	var agentList []map[string]interface{}
	for _, agent := range agents {
		agentList = append(agentList, map[string]interface{}{
			"id":        agent.ID,
			"hostname":  agent.Hostname,
			"username":  agent.Username,
			"os":        agent.OS,
			"status":    agent.Status,
			"last_seen": agent.LastSeen,
		})
	}

	response := map[string]interface{}{
		"agents": agentList,
		"total":  len(agentList),
	}

	h.APIResponse(c, true, "", response, "")
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

	message := fmt.Sprintf("Agent %s removed", agentID)
	h.APIResponse(c, true, message, nil, "")
}

// AgentCheckin handles agent check-in
func (h *Handlers) AgentCheckin(c *gin.Context) {
	var checkinData map[string]interface{}
	if err := c.ShouldBindJSON(&checkinData); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid checkin data: "+err.Error())
		return
	}

	// Handle encrypted payload
	if encryptedPayload, ok := checkinData["encrypted_payload"].(string); ok && h.server.CryptoMgr != nil {
		decrypted, err := h.server.CryptoMgr.DecryptData(encryptedPayload)
		if err != nil {
			h.server.Logger.Error(services.SYSTEM, "Failed to decrypt checkin data: "+err.Error(), "", "", nil)
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, "Failed to decrypt checkin data")
			return
		}

		var decryptedData map[string]interface{}
		if err := json.Unmarshal(decrypted, &decryptedData); err != nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, "Failed to parse decrypted data")
			return
		}
		checkinData = decryptedData
	}

	// Register agent
	h.server.Monitor.RegisterAgent(checkinData)

	agentID := ""
	if id, ok := checkinData["id"].(string); ok {
		agentID = id
	}

	h.server.Logger.LogAgentConnection(agentID, "checkin", c.ClientIP())

	response := map[string]interface{}{
		"status": "ok",
		"config": map[string]interface{}{
			"interval": 30,
			"jitter":   0.3,
		},
	}

	h.APIResponse(c, true, "Checkin successful", response, "")
}
