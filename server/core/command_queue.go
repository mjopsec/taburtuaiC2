package core

import (
	"fmt"
	"sync"
	"time"

	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// CommandQueue manages commands for agents
type CommandQueue struct {
	queues  map[string][]*types.Command
	active  map[string]*types.Command
	results map[string]*types.Command
	mutex   sync.RWMutex
}

// NewCommandQueue creates a new command queue
func NewCommandQueue() *CommandQueue {
	return &CommandQueue{
		queues:  make(map[string][]*types.Command),
		active:  make(map[string]*types.Command),
		results: make(map[string]*types.Command),
	}
}

// Add adds a command to agent's queue with enhanced validation
func (cq *CommandQueue) Add(agentID string, cmd *types.Command) error {
	if cmd == nil {
		return fmt.Errorf("command cannot be nil")
	}

	if agentID == "" {
		return fmt.Errorf("agent ID cannot be empty")
	}

	if cmd.ID == "" {
		return fmt.Errorf("command ID cannot be empty")
	}

	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	// Check queue size limits
	const maxQueueSize = 1000
	if queue := cq.queues[agentID]; len(queue) >= maxQueueSize {
		return fmt.Errorf("command queue full for agent %s (max %d commands)", agentID, maxQueueSize)
	}

	// Validate command fields
	if err := validateCommandForQueue(cmd); err != nil {
		return fmt.Errorf("command validation failed: %v", err)
	}

	// Initialize queue if doesn't exist
	if cq.queues[agentID] == nil {
		cq.queues[agentID] = make([]*types.Command, 0)
	}

	cq.queues[agentID] = append(cq.queues[agentID], cmd)

	fmt.Printf("[DEBUG] Added command to queue for agent %s: ID=%s, Command=%s, Type=%s\n",
		agentID, cmd.ID, cmd.Command, cmd.OperationType)
	fmt.Printf("[DEBUG] Queue size for agent %s: %d\n", agentID, len(cq.queues[agentID]))

	return nil
}

// GetNext returns the next command for an agent with enhanced error handling
func (cq *CommandQueue) GetNext(agentID string) *types.Command {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	if agentID == "" {
		return nil
	}

	// Check if agent has active command
	if active, exists := cq.active[agentID]; exists {
		// Check for timeout
		if active.Timeout > 0 && time.Since(active.ExecutedAt) > time.Duration(active.Timeout)*time.Second {
			active.Status = "timeout"
			active.CompletedAt = time.Now()
			active.Error = fmt.Sprintf("Command execution timeout after %d seconds", active.Timeout)
			cq.results[active.ID] = active
			delete(cq.active, agentID)
			fmt.Printf("[DEBUG] Command %s timed out for agent %s\n", active.ID, agentID)
		} else {
			fmt.Printf("[DEBUG] Agent %s has active command %s (status: %s)\n", agentID, active.ID, active.Status)
			return active
		}
	}

	// Get next command from queue
	if queue, exists := cq.queues[agentID]; exists && len(queue) > 0 {
		cmd := queue[0]
		cq.queues[agentID] = queue[1:]

		// Mark as executing
		cmd.Status = "executing"
		cmd.ExecutedAt = time.Now()
		cq.active[agentID] = cmd

		fmt.Printf("[DEBUG] Dispatching command to agent %s: ID=%s, Command=%s, Type=%s\n",
			agentID, cmd.ID, cmd.Command, cmd.OperationType)

		return cmd
	}

	fmt.Printf("[DEBUG] No commands in queue for agent %s\n", agentID)
	return nil
}

// CompleteCommand marks a command as completed with enhanced validation
func (cq *CommandQueue) CompleteCommand(commandID string, result *types.CommandResult) (*types.Command, error) {
	if commandID == "" {
		return nil, fmt.Errorf("command ID cannot be empty")
	}

	if result == nil {
		return nil, fmt.Errorf("command result cannot be nil")
	}

	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	var cmd *types.Command
	var agentID string

	// Find command in active commands
	for aid, active := range cq.active {
		if active.ID == commandID {
			cmd = active
			agentID = aid
			delete(cq.active, agentID)
			break
		}
	}

	if cmd == nil {
		// Check if already in results
		if existingResult, exists := cq.results[commandID]; exists {
			return existingResult, nil
		}
		return nil, fmt.Errorf("command not found: %s", commandID)
	}

	// Update command with result
	cmd.CompletedAt = time.Now()
	cmd.ExitCode = result.ExitCode

	// Sanitize output and error (limit size)
	if len(result.Output) > 1000000 { // 1MB limit
		cmd.Output = result.Output[:1000000] + "\n[Output truncated - too large]"
	} else {
		cmd.Output = result.Output
	}

	if len(result.Error) > 10000 { // 10KB limit for errors
		cmd.Error = result.Error[:10000] + "\n[Error message truncated - too large]"
	} else {
		cmd.Error = result.Error
	}

	// Determine status based on exit code and error
	if result.ExitCode == 0 && cmd.Error == "" {
		cmd.Status = "completed"
	} else {
		cmd.Status = "failed"
	}

	cq.results[cmd.ID] = cmd
	return cmd, nil
}

// GetCommand returns a specific command
func (cq *CommandQueue) GetCommand(commandID string) *types.Command {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	if commandID == "" {
		return nil
	}

	// Check results first
	if cmd, exists := cq.results[commandID]; exists {
		return cmd
	}

	// Check active commands
	for _, cmd := range cq.active {
		if cmd.ID == commandID {
			return cmd
		}
	}

	// Check queued commands
	for _, queue := range cq.queues {
		for _, cmd := range queue {
			if cmd.ID == commandID {
				return cmd
			}
		}
	}

	return nil
}

// GetAgentCommands returns all commands for an agent with enhanced filtering
func (cq *CommandQueue) GetAgentCommands(agentID string, status string, limit int) []*types.Command {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	if agentID == "" {
		return []*types.Command{}
	}

	// Validate and sanitize limit
	if limit <= 0 || limit > 1000 {
		limit = 50 // Default limit
	}

	var commands []*types.Command

	// Collect all commands for the agent
	for _, cmd := range cq.results {
		if cmd.AgentID == agentID && (status == "" || cmd.Status == status) {
			commands = append(commands, cmd)
		}
	}

	// Add active command if exists
	if active, exists := cq.active[agentID]; exists {
		if status == "" || active.Status == status {
			commands = append(commands, active)
		}
	}

	// Add queued commands
	if queue, exists := cq.queues[agentID]; exists {
		for _, cmd := range queue {
			if status == "" || cmd.Status == status {
				commands = append(commands, cmd)
			}
		}
	}

	// Sort by creation time (newest first)
	// Note: For production, consider using sort.Slice for proper sorting

	// Apply limit
	if len(commands) > limit {
		commands = commands[:limit]
	}

	return commands
}

// ClearQueue clears pending commands for an agent
func (cq *CommandQueue) ClearQueue(agentID string) int {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	if agentID == "" {
		return 0
	}

	count := 0
	if queue, exists := cq.queues[agentID]; exists {
		count = len(queue)
		delete(cq.queues, agentID)
	}

	return count
}

// GetStats returns queue statistics with enhanced metrics
func (cq *CommandQueue) GetStats() map[string]interface{} {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	totalQueued := 0
	totalActive := len(cq.active)
	totalCompleted := len(cq.results)

	agentStats := make(map[string]map[string]int)

	// Count queued commands per agent
	for agentID, queue := range cq.queues {
		queueCount := len(queue)
		totalQueued += queueCount

		agentStats[agentID] = map[string]int{
			"queued":    queueCount,
			"active":    0,
			"completed": 0,
		}
	}

	// Count active commands per agent
	for agentID := range cq.active {
		if _, exists := agentStats[agentID]; !exists {
			agentStats[agentID] = map[string]int{
				"queued": 0, "active": 0, "completed": 0,
			}
		}
		agentStats[agentID]["active"] = 1
	}

	// Count completed commands per agent
	for _, cmd := range cq.results {
		agentID := cmd.AgentID
		if _, exists := agentStats[agentID]; !exists {
			agentStats[agentID] = map[string]int{
				"queued": 0, "active": 0, "completed": 0,
			}
		}
		agentStats[agentID]["completed"]++
	}

	stats := map[string]interface{}{
		"total_queued":    totalQueued,
		"total_active":    totalActive,
		"total_completed": totalCompleted,
		"by_agent":        agentStats,
		"timestamp":       time.Now().Format(time.RFC3339),
		"total_agents":    len(agentStats),
	}

	return stats
}

// CleanOldResults removes old command results with enhanced cleanup
func (cq *CommandQueue) CleanOldResults(maxAge time.Duration) int {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	if maxAge <= 0 {
		return 0
	}

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	for id, cmd := range cq.results {
		if cmd.CompletedAt.Before(cutoff) {
			delete(cq.results, id)
			cleaned++
		}
	}

	return cleaned
}

// GetQueueSize returns the current queue size for an agent
func (cq *CommandQueue) GetQueueSize(agentID string) int {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	if agentID == "" {
		return 0
	}

	if queue, exists := cq.queues[agentID]; exists {
		return len(queue)
	}

	return 0
}

// HasActiveCommand checks if an agent has an active command
func (cq *CommandQueue) HasActiveCommand(agentID string) bool {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	if agentID == "" {
		return false
	}

	_, exists := cq.active[agentID]
	return exists
}

// GetActiveCommand returns the active command for an agent
func (cq *CommandQueue) GetActiveCommand(agentID string) *types.Command {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	if agentID == "" {
		return nil
	}

	if cmd, exists := cq.active[agentID]; exists {
		return cmd
	}

	return nil
}

// CancelCommand cancels a pending or active command
func (cq *CommandQueue) CancelCommand(commandID string) error {
	if commandID == "" {
		return fmt.Errorf("command ID cannot be empty")
	}

	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	// Check if command is active
	for agentID, active := range cq.active {
		if active.ID == commandID {
			active.Status = "cancelled"
			active.CompletedAt = time.Now()
			active.Error = "Command cancelled by user"
			cq.results[active.ID] = active
			delete(cq.active, agentID)
			return nil
		}
	}

	// Check if command is queued
	for agentID, queue := range cq.queues {
		for i, cmd := range queue {
			if cmd.ID == commandID {
				// Remove from queue
				cq.queues[agentID] = append(queue[:i], queue[i+1:]...)

				// Add to results as cancelled
				cmd.Status = "cancelled"
				cmd.CompletedAt = time.Now()
				cmd.Error = "Command cancelled before execution"
				cq.results[cmd.ID] = cmd

				return nil
			}
		}
	}

	// Check if already completed
	if _, exists := cq.results[commandID]; exists {
		return fmt.Errorf("command already completed, cannot cancel")
	}

	return fmt.Errorf("command not found: %s", commandID)
}

// validateCommandForQueue validates command fields before adding to queue
func validateCommandForQueue(cmd *types.Command) error {
	if cmd.Command == "" {
		return fmt.Errorf("command text cannot be empty")
	}

	if len(cmd.Command) > 10000 {
		return fmt.Errorf("command too long (max 10000 characters)")
	}

	if cmd.Timeout < 0 || cmd.Timeout > 3600 {
		return fmt.Errorf("invalid timeout value (must be 0-3600 seconds)")
	}

	if cmd.AgentID == "" {
		return fmt.Errorf("agent ID cannot be empty")
	}

	// Validate operation type
	validOperations := map[string]bool{
		"":        true, // empty is valid for backwards compatibility
		"execute": true, "upload": true, "download": true,
		"process_list": true, "process_kill": true, "process_start": true,
		"persist_setup": true, "persist_remove": true,
	}

	if !validOperations[cmd.OperationType] {
		return fmt.Errorf("invalid operation type: %s", cmd.OperationType)
	}

	// Validate file operations
	if cmd.OperationType == "upload" || cmd.OperationType == "download" {
		if cmd.OperationType == "upload" && cmd.DestinationPath == "" {
			return fmt.Errorf("destination path required for upload operation")
		}
		if cmd.OperationType == "download" && cmd.SourcePath == "" {
			return fmt.Errorf("source path required for download operation")
		}
	}

	// Validate file content size for uploads
	if cmd.OperationType == "upload" && len(cmd.FileContent) > 100*1024*1024 {
		return fmt.Errorf("file content too large (max 100MB)")
	}

	return nil
}
