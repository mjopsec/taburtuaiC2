package services

import "time"

// AgentStatus represents the operational state of an agent
type AgentStatus string

const (
	StatusOnline    AgentStatus = "online"
	StatusOffline   AgentStatus = "offline"
	StatusDormant   AgentStatus = "dormant"
	StatusError     AgentStatus = "error"
	StatusSuspected AgentStatus = "suspected"
)

// AgentHealth is the complete runtime record for a registered agent
type AgentHealth struct {
	ID               string                 `json:"id"`
	Hostname         string                 `json:"hostname"`
	Username         string                 `json:"username"`
	OS               string                 `json:"os"`
	Architecture     string                 `json:"architecture"`
	ProcessID        int                    `json:"process_id"`
	ParentProcessID  int                    `json:"parent_process_id"`
	Status           AgentStatus            `json:"status"`
	LastSeen         time.Time              `json:"last_seen"`
	LastHeartbeat    time.Time              `json:"last_heartbeat"`
	FirstContact     time.Time              `json:"first_contact"`
	TotalConnections int                    `json:"total_connections"`
	CommandsExecuted int                    `json:"commands_executed"`
	FilesTransferred int                    `json:"files_transferred"`
	Privileges       string                 `json:"privileges"`
	NetworkInfo      NetworkInfo            `json:"network_info"`
	SystemInfo       SystemInfo             `json:"system_info"`
	SecurityInfo     SecurityInfo           `json:"security_info"`
	Performance      PerformanceMetrics     `json:"performance"`
	Metadata         map[string]interface{} `json:"metadata"`
	Errors           []ErrorInfo            `json:"errors"`
}

// NetworkInfo holds network-related agent data
type NetworkInfo struct {
	InternalIP    string   `json:"internal_ip"`
	ExternalIP    string   `json:"external_ip"`
	MACAddress    string   `json:"mac_address"`
	Gateway       string   `json:"gateway"`
	DNSServers    []string `json:"dns_servers"`
	OpenPorts     []int    `json:"open_ports"`
	NetworkShares []string `json:"network_shares"`
}

// SystemInfo holds OS and hardware data collected from the agent
type SystemInfo struct {
	CPUCount        int               `json:"cpu_count"`
	CPUUsage        float64           `json:"cpu_usage"`
	MemoryTotal     uint64            `json:"memory_total"`
	MemoryUsed      uint64            `json:"memory_used"`
	DiskSpace       uint64            `json:"disk_space"`
	DiskUsed        uint64            `json:"disk_used"`
	Uptime          int64             `json:"uptime"`
	InstalledSoft   []string          `json:"installed_software"`
	RunningProcs    []string          `json:"running_processes"`
	Services        []string          `json:"services"`
	EnvironmentVars map[string]string `json:"environment_vars"`
}

// SecurityInfo holds security product and policy state
type SecurityInfo struct {
	AntivirusStatus    string   `json:"antivirus_status"`
	FirewallStatus     string   `json:"firewall_status"`
	UAC                bool     `json:"uac_enabled"`
	DefenderStatus     string   `json:"defender_status"`
	RunningEDR         []string `json:"running_edr"`
	SecurityPatches    []string `json:"security_patches"`
	AppLockerStatus    string   `json:"applocker_status"`
	PowerShellLogging  bool     `json:"powershell_logging"`
	ScriptBlockLogging bool     `json:"script_block_logging"`
}

// PerformanceMetrics tracks agent response and transfer metrics
type PerformanceMetrics struct {
	ResponseTime     time.Duration `json:"response_time"`
	LastCommandTime  time.Duration `json:"last_command_time"`
	AverageLatency   time.Duration `json:"average_latency"`
	DataTransferRate float64       `json:"data_transfer_rate"`
	ErrorRate        float64       `json:"error_rate"`
	SuccessRate      float64       `json:"success_rate"`
}

// ErrorInfo records a single agent-side error
type ErrorInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Message     string    `json:"message"`
	Command     string    `json:"command,omitempty"`
	Severity    string    `json:"severity"`
	Recoverable bool      `json:"recoverable"`
}
