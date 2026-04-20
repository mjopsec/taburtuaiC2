package builder

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// profileYAML mirrors the YAML schema for OPSEC profile files
type profileYAML struct {
	Name               string `yaml:"name"`
	SleepInterval      string `yaml:"sleep_interval"`
	JitterPercent      int    `yaml:"jitter_percent"`
	MaxRetries         int    `yaml:"max_retries"`
	EnableSandboxCheck bool   `yaml:"enable_sandbox_check"`
	EnableVMCheck      bool   `yaml:"enable_vm_check"`
	EnableDebugCheck   bool   `yaml:"enable_debug_check"`
	SleepMasking       bool   `yaml:"sleep_masking"`
	UserAgentRotation  bool   `yaml:"user_agent_rotation"`
	KillDate           string `yaml:"kill_date"`
	WorkingHoursOnly   bool   `yaml:"working_hours_only"`
	WorkingHoursStart  int    `yaml:"working_hours_start"`
	WorkingHoursEnd    int    `yaml:"working_hours_end"`
}

// LoadProfile reads and parses an OPSEC profile YAML file
func LoadProfile(path string) (*OpsecProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %q: %w", path, err)
	}
	var y profileYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, fmt.Errorf("parse profile %q: %w", path, err)
	}

	interval, err := time.ParseDuration(y.SleepInterval)
	if err != nil || interval <= 0 {
		interval = 30 * time.Second
	}

	if y.MaxRetries <= 0 {
		y.MaxRetries = 5
	}

	return &OpsecProfile{
		Name:               y.Name,
		SleepInterval:      interval,
		JitterPercent:      y.JitterPercent,
		MaxRetries:         y.MaxRetries,
		EnableSandboxCheck: y.EnableSandboxCheck,
		EnableVMCheck:      y.EnableVMCheck,
		EnableDebugCheck:   y.EnableDebugCheck,
		SleepMasking:       y.SleepMasking,
		UserAgentRotation:  y.UserAgentRotation,
		KillDate:           y.KillDate,
		WorkingHoursOnly:   y.WorkingHoursOnly,
		WorkingHoursStart:  y.WorkingHoursStart,
		WorkingHoursEnd:    y.WorkingHoursEnd,
	}, nil
}
