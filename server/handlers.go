package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Command represents a command to be executed
type Command struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id"`
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Timeout     int               `json:"timeout,omitempty"` // seconds
	CreatedAt   time.Time         `json:"created_at"`
	ExecutedAt  time.Time         `json:"executed_at,omitempty"`
	CompletedAt time.Time         `json:"completed_at,omitempty"`
	Status      string            `json:"status"` // pending, executing, completed, failed, timeout
	ExitCode    int               `json:"exit_code,omitempty"`
	Output      string            `json:"output,omitempty"`
	Error       string            `json:"error,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CommandQueue manages commands for agents
type CommandQueue struct {
	queues  map[string][]*Command // agentID -> commands
	active  map[string]*Command   // agentID -> currently executing command
	results map[string]*Command   // commandID -> completed command
	mutex   sync.RWMutex
}

// Global command queue
var commandQueue = &CommandQueue{
	queues:  make(map[string][]*Command),
	active:  make(map[string]*Command),
	results: make(map[string]*Command),
}

// Enhanced API handlers for Phase 2

// executeCommand - POST /api/v1/command
func (s *TaburtuaiServer) executeCommand(c *gin.Context) {
	var req struct {
		AgentID    string            `json:"agent_id" binding:"required"`
		Command    string            `json:"command" binding:"required"`
		Args       []string          `json:"args,omitempty"`
		WorkingDir string            `json:"working_dir,omitempty"`
		Timeout    int               `json:"timeout,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, APIResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Check if agent exists and is online
	agent, exists := s.monitor.GetAgent(req.AgentID)
	if !exists {
		c.JSON(404, APIResponse{
			Success: false,
			Error:   "Agent not found",
		})
		return
	}

	if agent.Status != StatusOnline {
		c.JSON(400, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Agent is %s", agent.Status),
		})
		return
	}

	// Create command
	cmd := &Command{
		ID:         uuid.New().String(),
		AgentID:    req.AgentID,
		Command:    req.Command,
		Args:       req.Args,
		WorkingDir: req.WorkingDir,
		Timeout:    req.Timeout,
		CreatedAt:  time.Now(),
		Status:     "pending",
		Metadata:   req.Metadata,
	}

	if cmd.Timeout == 0 {
		cmd.Timeout = 300 // Default 5 minutes
	}

	// Add to queue
	commandQueue.mutex.Lock()
	commandQueue.queues[req.AgentID] = append(commandQueue.queues[req.AgentID], cmd)
	commandQueue.mutex.Unlock()

	// Log command
	LogCommand(req.AgentID, req.Command, "Queued", true)

	c.JSON(200, APIResponse{
		Success: true,
		Message: "Command queued successfully",
		Data: map[string]interface{}{
			"command_id": cmd.ID,
			"status":     cmd.Status,
			"position":   len(commandQueue.queues[req.AgentID]),
		},
	})
}

func (s *TaburtuaiServer) getNextCommand(c *gin.Context) {
	agentID := c.Param("id")

	// Verify agent
	if _, exists := s.monitor.GetAgent(agentID); !exists {
		c.JSON(404, APIResponse{
			Success: false,
			Error:   "Agent not found",
		})
		return
	}

	commandQueue.mutex.Lock()
	defer commandQueue.mutex.Unlock()

	// Check if agent has active command
	if active, exists := commandQueue.active[agentID]; exists {
		// Check for timeout
		if active.Timeout > 0 && time.Since(active.ExecutedAt) > time.Duration(active.Timeout)*time.Second {
			active.Status = "timeout"
			active.CompletedAt = time.Now()
			active.Error = "Command execution timeout"
			commandQueue.results[active.ID] = active
			delete(commandQueue.active, agentID)

			LogCommand(agentID, active.Command, "Timeout", false)
		} else {
			// TEMPORARY: Send unencrypted
			LogInfo(SYSTEM, fmt.Sprintf("Sending unencrypted active command to agent %s", agentID), "")
			c.JSON(200, APIResponse{
				Success: true,
				Data:    active, // Send unencrypted
			})
			return
		}
	}

	// Get next command from queue
	// Get next command from queue
	if queue, exists := commandQueue.queues[agentID]; exists && len(queue) > 0 {
		cmd := queue[0]
		commandQueue.queues[agentID] = queue[1:]

		// Mark as executing
		cmd.Status = "executing"
		cmd.ExecutedAt = time.Now()
		commandQueue.active[agentID] = cmd

		// Try encryption with debug
		var responseData interface{}

		if s.crypto != nil {
			cmdJSON, err := json.Marshal(cmd)
			if err != nil {
				LogError(SYSTEM, fmt.Sprintf("Failed to marshal command: %v", err), "")
				responseData = cmd
			} else {
				LogInfo(SYSTEM, fmt.Sprintf("Encrypting command for agent %s", agentID), "")

				encrypted, err := s.crypto.EncryptData(cmdJSON)
				if err != nil {
					LogError(SYSTEM, fmt.Sprintf("Failed to encrypt command: %v", err), "")
					responseData = cmd
				} else {
					LogInfo(SYSTEM, fmt.Sprintf("Encryption successful"), "")

					responseData = map[string]string{
						"encrypted": encrypted,
					}
				}
			}
		} else {
			LogInfo(SYSTEM, "No crypto manager available", "")
			responseData = cmd
		}

		c.JSON(200, APIResponse{
			Success: true,
			Data:    responseData,
		})
		return
	}
}

// submitCommandResult - POST /api/v1/command/result
func (s *TaburtuaiServer) submitCommandResult(c *gin.Context) {
	var req struct {
		CommandID string `json:"command_id" binding:"required"`
		ExitCode  int    `json:"exit_code"`
		Output    string `json:"output"`
		Error     string `json:"error"`
		Encrypted bool   `json:"encrypted"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, APIResponse{
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Decrypt if needed
	if req.Encrypted && s.crypto != nil {
		LogInfo(SYSTEM, "Decrypting command result", "")

		if req.Output != "" {
			if decrypted, err := s.crypto.DecryptData(req.Output); err == nil {
				req.Output = string(decrypted)
				LogInfo(SYSTEM, fmt.Sprintf("Output decrypted: %d bytes", len(decrypted)), "")
			} else {
				LogError(SYSTEM, fmt.Sprintf("Failed to decrypt output: %v", err), "")
			}
		}

		if req.Error != "" {
			if decrypted, err := s.crypto.DecryptData(req.Error); err == nil {
				req.Error = string(decrypted)
			}
		}
	}

	commandQueue.mutex.Lock()
	defer commandQueue.mutex.Unlock()

	// Find active command
	var cmd *Command
	for agentID, active := range commandQueue.active {
		if active.ID == req.CommandID {
			cmd = active
			delete(commandQueue.active, agentID)
			break
		}
	}

	if cmd == nil {
		c.JSON(404, APIResponse{
			Success: false,
			Error:   "Command not found or already completed",
		})
		return
	}

	// Update command with results
	cmd.CompletedAt = time.Now()
	cmd.ExitCode = req.ExitCode
	cmd.Output = req.Output
	cmd.Error = req.Error

	if req.ExitCode == 0 {
		cmd.Status = "completed"
	} else {
		cmd.Status = "failed"
	}

	// Store result
	commandQueue.results[cmd.ID] = cmd

	// Log execution
	success := cmd.ExitCode == 0
	result := cmd.Output
	if len(result) > 100 {
		result = result[:100] + "..."
	}
	if cmd.Error != "" {
		result = "Error: " + cmd.Error
	}

	LogCommand(cmd.AgentID, cmd.Command, result, success)

	// Update agent metrics
	duration := cmd.CompletedAt.Sub(cmd.ExecutedAt)
	s.monitor.RecordCommand(cmd.AgentID, cmd.Command, success, duration)

	c.JSON(200, APIResponse{
		Success: true,
		Message: "Command result submitted",
		Data: map[string]interface{}{
			"command_id": cmd.ID,
			"status":     cmd.Status,
			"duration":   duration.String(),
		},
	})
}

// getCommandStatus - GET /api/v1/command/:id/status
func (s *TaburtuaiServer) getCommandStatus(c *gin.Context) {
	commandID := c.Param("id")

	commandQueue.mutex.RLock()
	defer commandQueue.mutex.RUnlock()

	// Check results first
	if cmd, exists := commandQueue.results[commandID]; exists {
		c.JSON(200, APIResponse{
			Success: true,
			Data:    cmd,
		})
		return
	}

	// Check active commands
	for _, cmd := range commandQueue.active {
		if cmd.ID == commandID {
			c.JSON(200, APIResponse{
				Success: true,
				Data:    cmd,
			})
			return
		}
	}

	// Check queued commands
	for _, queue := range commandQueue.queues {
		for _, cmd := range queue {
			if cmd.ID == commandID {
				c.JSON(200, APIResponse{
					Success: true,
					Data:    cmd,
				})
				return
			}
		}
	}

	c.JSON(404, APIResponse{
		Success: false,
		Error:   "Command not found",
	})
}

// getAgentCommands - GET /api/v1/agent/:id/commands
func (s *TaburtuaiServer) getAgentCommands(c *gin.Context) {
	agentID := c.Param("id")
	status := c.Query("status") // filter by status
	limit := 50

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	commandQueue.mutex.RLock()
	defer commandQueue.mutex.RUnlock()

	var commands []*Command

	// Get all commands for agent
	for _, cmd := range commandQueue.results {
		if cmd.AgentID == agentID {
			if status == "" || cmd.Status == status {
				commands = append(commands, cmd)
			}
		}
	}

	// Add active command
	if active, exists := commandQueue.active[agentID]; exists {
		if status == "" || active.Status == status {
			commands = append(commands, active)
		}
	}

	// Add queued commands
	if queue, exists := commandQueue.queues[agentID]; exists {
		for _, cmd := range queue {
			if status == "" || cmd.Status == status {
				commands = append(commands, cmd)
			}
		}
	}

	// Sort by creation time (newest first)
	sort.Slice(commands, func(i, j int) bool {
		return commands[i].CreatedAt.After(commands[j].CreatedAt)
	})

	// Limit results
	if len(commands) > limit {
		commands = commands[:limit]
	}

	c.JSON(200, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"commands": commands,
			"count":    len(commands),
		},
	})
}

// clearAgentQueue - DELETE /api/v1/agent/:id/queue
func (s *TaburtuaiServer) clearAgentQueue(c *gin.Context) {
	agentID := c.Param("id")

	commandQueue.mutex.Lock()
	defer commandQueue.mutex.Unlock()

	count := 0
	if queue, exists := commandQueue.queues[agentID]; exists {
		count = len(queue)
		delete(commandQueue.queues, agentID)
	}

	c.JSON(200, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Cleared %d pending commands", count),
	})
}

// getQueueStats - GET /api/v1/queue/stats
func (s *TaburtuaiServer) getQueueStats(c *gin.Context) {
	commandQueue.mutex.RLock()
	defer commandQueue.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_queued":    0,
		"total_active":    len(commandQueue.active),
		"total_completed": len(commandQueue.results),
		"by_agent":        make(map[string]map[string]int),
	}

	// Count queued commands
	for agentID, queue := range commandQueue.queues {
		stats["total_queued"] = stats["total_queued"].(int) + len(queue)

		if _, exists := stats["by_agent"].(map[string]map[string]int)[agentID]; !exists {
			stats["by_agent"].(map[string]map[string]int)[agentID] = map[string]int{
				"queued":    0,
				"active":    0,
				"completed": 0,
			}
		}
		stats["by_agent"].(map[string]map[string]int)[agentID]["queued"] = len(queue)
	}

	// Count active commands
	for agentID := range commandQueue.active {
		if _, exists := stats["by_agent"].(map[string]map[string]int)[agentID]; !exists {
			stats["by_agent"].(map[string]map[string]int)[agentID] = map[string]int{
				"queued":    0,
				"active":    0,
				"completed": 0,
			}
		}
		stats["by_agent"].(map[string]map[string]int)[agentID]["active"] = 1
	}

	// Count completed commands
	for _, cmd := range commandQueue.results {
		if _, exists := stats["by_agent"].(map[string]map[string]int)[cmd.AgentID]; !exists {
			stats["by_agent"].(map[string]map[string]int)[cmd.AgentID] = map[string]int{
				"queued":    0,
				"active":    0,
				"completed": 0,
			}
		}
		stats["by_agent"].(map[string]map[string]int)[cmd.AgentID]["completed"]++
	}

	c.JSON(200, APIResponse{
		Success: true,
		Data:    stats,
	})
}

// Helper function to clean old results periodically
func (cq *CommandQueue) cleanOldResults(maxAge time.Duration) {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, cmd := range cq.results {
		if cmd.CompletedAt.Before(cutoff) {
			delete(cq.results, id)
		}
	}
}

// Start cleanup routine
func startCommandQueueCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			commandQueue.cleanOldResults(24 * time.Hour) // Keep results for 24 hours
		}
	}()
}
