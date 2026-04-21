//go:build !windows

package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// runCommand executes a shell command on non-Windows platforms.
// The method parameter is ignored on Linux/macOS — sh is always used.
func runCommand(method, command string, timeout int) (stdout, stderr string, exitCode int) {
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
	exitCode = 0
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

// psEncode is a stub on non-Windows (only used by Windows execution paths).
func psEncode(command string) string { return command }
