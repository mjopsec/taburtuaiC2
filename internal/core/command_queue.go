package core

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/storage"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// CommandQueue persists and dispatches commands via SQLite
type CommandQueue struct {
	store *storage.Store
	mu    sync.Mutex // serialises GetNext to prevent double-dispatch
}

// NewCommandQueue creates a queue backed by store
func NewCommandQueue(store *storage.Store) *CommandQueue {
	return &CommandQueue{store: store}
}

// Add validates and persists a command as 'pending'
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
	if err := validateCommandForQueue(cmd); err != nil {
		return fmt.Errorf("command validation failed: %v", err)
	}

	const maxQueueSize = 1000
	size, err := cq.store.GetAgentQueueSize(agentID)
	if err != nil {
		return fmt.Errorf("queue size check: %w", err)
	}
	if size >= maxQueueSize {
		return fmt.Errorf("command queue full for agent %s (max %d commands)", agentID, maxQueueSize)
	}

	row, err := cmdToRow(cmd)
	if err != nil {
		return fmt.Errorf("encode command: %w", err)
	}
	return cq.store.InsertCommand(row)
}

// GetNext returns the next command the agent should execute.
// If a command is already executing it is returned (unless it timed out).
// If timed out the command is marked and the next pending command is dispatched.
func (cq *CommandQueue) GetNext(agentID string) *types.Command {
	if agentID == "" {
		return nil
	}
	cq.mu.Lock()
	defer cq.mu.Unlock()

	// Check for active command
	active, hasActive, err := cq.store.GetAgentExecutingCommand(agentID)
	if err == nil && hasActive {
		cmd := rowToCmd(active)
		if cmd.Timeout > 0 && time.Since(cmd.ExecutedAt) > time.Duration(cmd.Timeout)*time.Second {
			// Timeout — mark it and fall through to next pending
			active.Status = "timeout"
			active.CompletedAt = time.Now().Unix()
			active.Error = fmt.Sprintf("Command execution timeout after %d seconds", cmd.Timeout)
			_ = cq.store.UpdateCommandStatus(active)
		} else {
			return cmd
		}
	}

	// Dispatch next pending
	pending, hasPending, err := cq.store.GetAgentNextPending(agentID)
	if err != nil || !hasPending {
		return nil
	}
	pending.Status = "executing"
	pending.ExecutedAt = time.Now().Unix()
	if err := cq.store.UpdateCommandStatus(pending); err != nil {
		return nil
	}
	return rowToCmd(pending)
}

// CompleteCommand records the result of a finished command
func (cq *CommandQueue) CompleteCommand(commandID string, result *types.CommandResult) (*types.Command, error) {
	if commandID == "" {
		return nil, fmt.Errorf("command ID cannot be empty")
	}
	if result == nil {
		return nil, fmt.Errorf("command result cannot be nil")
	}

	row, found, err := cq.store.GetCommand(commandID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("command not found: %s", commandID)
	}
	// Already completed — return as-is
	if row.Status != "executing" && row.Status != "pending" {
		return rowToCmd(row), nil
	}

	row.CompletedAt = time.Now().Unix()
	row.ExitCode = result.ExitCode

	if len(result.Output) > 1000000 {
		row.Output = result.Output[:1000000] + "\n[Output truncated - too large]"
	} else {
		row.Output = result.Output
	}
	if len(result.Error) > 10000 {
		row.Error = result.Error[:10000] + "\n[Error message truncated - too large]"
	} else {
		row.Error = result.Error
	}

	if result.ExitCode == 0 && row.Error == "" {
		row.Status = "completed"
	} else {
		row.Status = "failed"
	}

	if err := cq.store.UpdateCommandStatus(row); err != nil {
		return nil, err
	}
	return rowToCmd(row), nil
}

// GetCommand returns a command by ID regardless of status
func (cq *CommandQueue) GetCommand(commandID string) *types.Command {
	if commandID == "" {
		return nil
	}
	row, found, err := cq.store.GetCommand(commandID)
	if err != nil || !found {
		return nil
	}
	return rowToCmd(row)
}

// GetAgentCommands returns commands for an agent with optional status filter
func (cq *CommandQueue) GetAgentCommands(agentID string, status string, limit int) []*types.Command {
	if agentID == "" {
		return []*types.Command{}
	}
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := cq.store.GetAgentCommands(agentID, status, limit)
	if err != nil {
		return []*types.Command{}
	}
	cmds := make([]*types.Command, 0, len(rows))
	for _, r := range rows {
		cmds = append(cmds, rowToCmd(r))
	}
	return cmds
}

// ClearQueue cancels all pending commands for an agent and returns how many were cleared
func (cq *CommandQueue) ClearQueue(agentID string) int {
	if agentID == "" {
		return 0
	}
	n, _ := cq.store.CancelAgentPendingCommands(agentID)
	return n
}

// GetStats returns aggregate command queue statistics
func (cq *CommandQueue) GetStats() map[string]any {
	stats, err := cq.store.GetCommandStats()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return stats
}

// CleanOldResults removes completed commands older than maxAge
func (cq *CommandQueue) CleanOldResults(maxAge time.Duration) int {
	if maxAge <= 0 {
		return 0
	}
	n, _ := cq.store.CleanOldCommands(maxAge)
	return n
}

// GetQueueSize returns the pending command count for an agent
func (cq *CommandQueue) GetQueueSize(agentID string) int {
	if agentID == "" {
		return 0
	}
	n, _ := cq.store.GetAgentQueueSize(agentID)
	return n
}

// HasActiveCommand reports whether an agent has an executing command
func (cq *CommandQueue) HasActiveCommand(agentID string) bool {
	if agentID == "" {
		return false
	}
	_, has, _ := cq.store.GetAgentExecutingCommand(agentID)
	return has
}

// GetActiveCommand returns the executing command for an agent, or nil
func (cq *CommandQueue) GetActiveCommand(agentID string) *types.Command {
	if agentID == "" {
		return nil
	}
	row, has, err := cq.store.GetAgentExecutingCommand(agentID)
	if err != nil || !has {
		return nil
	}
	return rowToCmd(row)
}

// CancelCommand cancels a pending or executing command by ID
func (cq *CommandQueue) CancelCommand(commandID string) error {
	if commandID == "" {
		return fmt.Errorf("command ID cannot be empty")
	}
	row, found, err := cq.store.GetCommand(commandID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("command not found: %s", commandID)
	}
	if row.Status != "pending" && row.Status != "executing" {
		return fmt.Errorf("command already completed, cannot cancel")
	}
	row.Status = "cancelled"
	row.CompletedAt = time.Now().Unix()
	row.Error = "Command cancelled by user"
	return cq.store.UpdateCommandStatus(row)
}

// ── conversion helpers ────────────────────────────────────────────────────────

func cmdToRow(cmd *types.Command) (storage.CommandRow, error) {
	argsJSON, err := json.Marshal(cmd.Args)
	if err != nil {
		return storage.CommandRow{}, err
	}
	metaJSON, err := json.Marshal(cmd.Metadata)
	if err != nil {
		return storage.CommandRow{}, err
	}
	procArgsJSON, err := json.Marshal(cmd.ProcessArgs)
	if err != nil {
		return storage.CommandRow{}, err
	}

	var execAt, compAt int64
	if !cmd.ExecutedAt.IsZero() {
		execAt = cmd.ExecutedAt.Unix()
	}
	if !cmd.CompletedAt.IsZero() {
		compAt = cmd.CompletedAt.Unix()
	}

	return storage.CommandRow{
		ID:              cmd.ID,
		AgentID:         cmd.AgentID,
		Command:         cmd.Command,
		ArgsJSON:        string(argsJSON),
		WorkingDir:      cmd.WorkingDir,
		Timeout:         cmd.Timeout,
		Status:          cmd.Status,
		ExitCode:        cmd.ExitCode,
		Output:          cmd.Output,
		Error:           cmd.Error,
		MetadataJSON:    string(metaJSON),
		OperationType:   cmd.OperationType,
		SourcePath:      cmd.SourcePath,
		DestinationPath: cmd.DestinationPath,
		FileContent:     cmd.FileContent,
		IsEncrypted:     cmd.IsEncrypted,
		ProcessName:     cmd.ProcessName,
		ProcessID:       cmd.ProcessID,
		ProcessPath:     cmd.ProcessPath,
		ProcessArgsJSON: string(procArgsJSON),
		PersistMethod:   cmd.PersistMethod,
		PersistName:     cmd.PersistName,
		CreatedAt:       cmd.CreatedAt.Unix(),
		ExecutedAt:      execAt,
		CompletedAt:     compAt,
	}, nil
}

func rowToCmd(r storage.CommandRow) *types.Command {
	cmd := &types.Command{
		ID:              r.ID,
		AgentID:         r.AgentID,
		Command:         r.Command,
		WorkingDir:      r.WorkingDir,
		Timeout:         r.Timeout,
		Status:          r.Status,
		ExitCode:        r.ExitCode,
		Output:          r.Output,
		Error:           r.Error,
		OperationType:   r.OperationType,
		SourcePath:      r.SourcePath,
		DestinationPath: r.DestinationPath,
		FileContent:     r.FileContent,
		IsEncrypted:     r.IsEncrypted,
		ProcessName:     r.ProcessName,
		ProcessID:       r.ProcessID,
		ProcessPath:     r.ProcessPath,
		PersistMethod:   r.PersistMethod,
		PersistName:     r.PersistName,
		CreatedAt:       time.Unix(r.CreatedAt, 0),
	}
	if r.ExecutedAt > 0 {
		cmd.ExecutedAt = time.Unix(r.ExecutedAt, 0)
	}
	if r.CompletedAt > 0 {
		cmd.CompletedAt = time.Unix(r.CompletedAt, 0)
	}

	_ = json.Unmarshal([]byte(r.ArgsJSON), &cmd.Args)
	_ = json.Unmarshal([]byte(r.MetadataJSON), &cmd.Metadata)
	_ = json.Unmarshal([]byte(r.ProcessArgsJSON), &cmd.ProcessArgs)
	return cmd
}

// ── validation (unchanged) ────────────────────────────────────────────────────

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
	validOps := map[string]bool{
		"": true, "execute": true, "upload": true, "download": true,
		"process_list": true, "process_kill": true, "process_start": true,
		"persist_setup": true, "persist_remove": true,
	}
	if !validOps[cmd.OperationType] {
		return fmt.Errorf("invalid operation type: %s", cmd.OperationType)
	}
	if cmd.OperationType == "upload" && cmd.DestinationPath == "" {
		return fmt.Errorf("destination path required for upload operation")
	}
	if cmd.OperationType == "download" && cmd.SourcePath == "" {
		return fmt.Errorf("source path required for download operation")
	}
	if cmd.OperationType == "upload" && len(cmd.FileContent) > 100*1024*1024 {
		return fmt.Errorf("file content too large (max 100MB)")
	}
	return nil
}
