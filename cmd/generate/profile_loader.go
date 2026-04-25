package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type masqueradeYAML struct {
	Enabled          bool   `yaml:"enabled"`
	Company          string `yaml:"company"`
	Product          string `yaml:"product"`
	Description      string `yaml:"description"`
	OriginalFilename string `yaml:"original_filename"`
	Version          string `yaml:"version"`
	Copyright        string `yaml:"copyright"`
}

type profileYAML struct {
	Name               string         `yaml:"name"`
	SleepInterval      string         `yaml:"sleep_interval"`
	JitterPercent      int            `yaml:"jitter_percent"`
	MaxRetries         int            `yaml:"max_retries"`
	EnableSandboxCheck bool           `yaml:"enable_sandbox_check"`
	EnableVMCheck      bool           `yaml:"enable_vm_check"`
	EnableDebugCheck   bool           `yaml:"enable_debug_check"`
	SleepMasking       bool           `yaml:"sleep_masking"`
	UserAgentRotation  bool           `yaml:"user_agent_rotation"`
	KillDate           string         `yaml:"kill_date"`
	WorkingHoursOnly   bool           `yaml:"working_hours_only"`
	WorkingHoursStart  int            `yaml:"working_hours_start"`
	WorkingHoursEnd    int            `yaml:"working_hours_end"`
	ExecMethod         string         `yaml:"exec_method"`
	Obfuscate          bool           `yaml:"obfuscate"`
	Masquerade         masqueradeYAML `yaml:"masquerade"`
}

// LoadProfile reads and parses an OPSEC profile YAML file.
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
		ExecMethod:         y.ExecMethod,
		Obfuscate:          y.Obfuscate,
		Masquerade: MasqueradeConfig{
			Enabled:          y.Masquerade.Enabled,
			Company:          y.Masquerade.Company,
			Product:          y.Masquerade.Product,
			Description:      y.Masquerade.Description,
			OriginalFilename: y.Masquerade.OriginalFilename,
			Version:          y.Masquerade.Version,
			Copyright:        y.Masquerade.Copyright,
		},
	}, nil
}
