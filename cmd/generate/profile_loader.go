package main

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed profiles/default.yaml
var profileDefault []byte

//go:embed profiles/aggressive.yaml
var profileAggressive []byte

//go:embed profiles/opsec.yaml
var profileOpsec []byte

//go:embed profiles/stealth.yaml
var profileStealth []byte

//go:embed profiles/paranoid.yaml
var profileParanoid []byte

var builtinProfiles = map[string][]byte{
	"default":    profileDefault,
	"aggressive": profileAggressive,
	"opsec":      profileOpsec,
	"stealth":    profileStealth,
	"paranoid":   profileParanoid,
}

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

// LoadProfile loads an OPSEC profile by name (e.g. "stealth") or by file path.
// Built-in names: default, aggressive, opsec, stealth, paranoid.
func LoadProfile(nameOrPath string) (*OpsecProfile, error) {
	var data []byte

	// Try built-in name first (case-insensitive, strip .yaml suffix if provided).
	key := strings.ToLower(strings.TrimSuffix(nameOrPath, ".yaml"))
	if embedded, ok := builtinProfiles[key]; ok {
		data = embedded
	} else {
		var err error
		data, err = os.ReadFile(nameOrPath)
		if err != nil {
			return nil, fmt.Errorf("read profile %q: %w", nameOrPath, err)
		}
	}
	var y profileYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, fmt.Errorf("parse profile %q: %w", nameOrPath, err)
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
