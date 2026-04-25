//go:build !windows

package exec

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// RunCommand executes a shell command on non-Windows platforms.
func RunCommand(method, command string, timeout int) (stdout, stderr string, exitCode int) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	_ = method
	return strings.TrimSpace(out.String()), strings.TrimSpace(errBuf.String()), exitCode
}

// PsEncode is a stub on non-Windows.
func PsEncode(command string) string { return command }

func psEncode(command string) string { return command }

func execPowerShell(_ context.Context, command string) (string, string, int) {
	return RunCommand("sh", command, 0)
}
