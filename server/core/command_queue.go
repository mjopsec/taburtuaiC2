package core

import (
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

// Add adds a command to agent's queue
func (cq *CommandQueue) Add(agentID string, cmd *types.Command) {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()
	cq.queues[agentID] = append(cq.queues[agentID], cmd)
}

// GetNext returns the next command for an agent
func (cq *CommandQueue) GetNext(agentID string) *types.Command {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	// Check if agent has active command
	if active, exists := cq.active[agentID]; exists {
		// Check for timeout
		if active.Timeout > 0 && time.Since(active.ExecutedAt) > time.Duration(active.Timeout)*time.Second {
			active.Status = "timeout"
			active.CompletedAt = time.Now()
			active.Error = "Command execution timeout"
			cq.results[active.ID] = active
			delete(cq.active, agentID)
		} else {
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

		return cmd
	}

	return nil
}

// CompleteCommand marks a command as completed
func (cq *CommandQueue) CompleteCommand(commandID string, result *types.CommandResult) (*types.Command, error) {
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
			cmd = existingResult
		} else {
			return nil, nil
		}
	}

	// Update command with result
	cmd.CompletedAt = time.Now()
	cmd.ExitCode = result.ExitCode
	cmd.Output = result.Output
	cmd.Error = result.Error

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

// GetAgentCommands returns all commands for an agent
func (cq *CommandQueue) GetAgentCommands(agentID string, status string, limit int) []*types.Command {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	var commands []*types.Command

	// Collect all commands
	for _, cmd := range cq.results {
		if cmd.AgentID == agentID && (status == "" || cmd.Status == status) {
			commands = append(commands, cmd)
		}
	}

	if active, exists := cq.active[agentID]; exists {
		if status == "" || active.Status == status {
			commands = append(commands, active)
		}
	}

	if queue, exists := cq.queues[agentID]; exists {
		for _, cmd := range queue {
			if status == "" || cmd.Status == status {
				commands = append(commands, cmd)
			}
		}
	}

	// Sort and limit
	if len(commands) > limit && limit > 0 {
		commands = commands[:limit]
	}

	return commands
}

// ClearQueue clears pending commands for an agent
func (cq *CommandQueue) ClearQueue(agentID string) int {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	count := 0
	if queue, exists := cq.queues[agentID]; exists {
		count = len(queue)
		delete(cq.queues, agentID)
	}

	return count
}

// GetStats returns queue statistics
func (cq *CommandQueue) GetStats() map[string]interface{} {
	cq.mutex.RLock()
	defer cq.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_queued":    0,
		"total_active":    len(cq.active),
		"total_completed": len(cq.results),
		"by_agent":        make(map[string]map[string]int),
	}

	totalQueued := 0
	for agentID, queue := range cq.queues {
		queueCount := len(queue)
		totalQueued += queueCount

		if _, ok := stats["by_agent"].(map[string]map[string]int)[agentID]; !ok {
			stats["by_agent"].(map[string]map[string]int)[agentID] = map[string]int{
				"queued":    0,
				"active":    0,
				"completed": 0,
			}
		}
		stats["by_agent"].(map[string]map[string]int)[agentID]["queued"] = queueCount
	}
	stats["total_queued"] = totalQueued

	return stats
}

// CleanOldResults removes old command results
func (cq *CommandQueue) CleanOldResults(maxAge time.Duration) {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, cmd := range cq.results {
		if cmd.CompletedAt.Before(cutoff) {
			delete(cq.results, id)
		}
	}
}
