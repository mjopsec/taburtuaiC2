package main

import (
	"strings"
	"testing"

	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// minAgent returns a bare Agent with no crypto, no evasion.
// ExecuteCommand uses only cmd fields + result — no network calls made here.
func minAgent() *Agent {
	return &Agent{
		ID:  "test-agent",
		cfg: &AgentConfig{},
	}
}

func cmd(opType string) *types.Command {
	return &types.Command{
		ID:            "test-cmd-id",
		OperationType: opType,
		Command:       "echo test",
	}
}

// TestExecuteCommandReturnsCommandID verifies that all paths set the returned
// CommandID correctly — a regression guard for the result plumbing.
func TestExecuteCommandReturnsCommandID(t *testing.T) {
	a := minAgent()
	c := cmd("execute")
	c.Command = "echo hello"
	r := ExecuteCommand(a, c)
	if r.CommandID != "test-cmd-id" {
		t.Errorf("CommandID: got %q, want %q", r.CommandID, "test-cmd-id")
	}
}

// TestExecuteCommandUnknownOpFallsToExecute verifies that an unrecognised
// OperationType routes to the default execute handler (not a nil-dereference
// or unhandled panic).
func TestExecuteCommandUnknownOpFallsToExecute(t *testing.T) {
	a := minAgent()
	c := cmd("nonexistent_op_xyzzy")
	c.Command = "echo fallback"
	r := ExecuteCommand(a, c)
	// Result must be non-nil with matching ID.
	if r == nil {
		t.Fatal("result is nil")
	}
	if r.CommandID != c.ID {
		t.Errorf("CommandID: got %q want %q", r.CommandID, c.ID)
	}
}

// TestUploadMissingPath verifies that upload without a destination path returns
// a non-zero exit code and a meaningful error, not a panic.
func TestUploadMissingPath(t *testing.T) {
	a := minAgent()
	c := cmd("upload")
	c.FileContent = []byte("data")
	// DestinationPath intentionally left empty.
	r := ExecuteCommand(a, c)
	if r.ExitCode == 0 {
		t.Error("expected non-zero exit code for upload with missing path")
	}
	if r.Error == "" {
		t.Error("expected error message for upload with missing path")
	}
}

// TestDownloadMissingPath verifies that download without a source path returns
// a non-zero exit code.
func TestDownloadMissingPath(t *testing.T) {
	a := minAgent()
	c := cmd("download")
	// SourcePath intentionally left empty.
	r := ExecuteCommand(a, c)
	if r.ExitCode == 0 {
		t.Error("expected non-zero exit code for download with missing path")
	}
}

// TestWorkingDirChange verifies that a non-existent WorkingDir produces an
// error rather than a panic.
func TestWorkingDirChange(t *testing.T) {
	a := minAgent()
	c := cmd("execute")
	c.Command = "echo test"
	c.WorkingDir = "/path/that/does/not/exist/xyzzy_12345"
	r := ExecuteCommand(a, c)
	if r.ExitCode == 0 {
		t.Error("expected non-zero exit code for invalid WorkingDir")
	}
	if !strings.Contains(r.Error, "directory") && !strings.Contains(r.Error, "Failed") {
		t.Errorf("error message doesn't mention directory: %q", r.Error)
	}
}

// TestBOFExecMissingData verifies bof_exec with no BOFData returns an error
// without panicking.
func TestBOFExecMissingData(t *testing.T) {
	a := minAgent()
	c := cmd("bof_exec")
	// BOFData intentionally empty.
	r := ExecuteCommand(a, c)
	if r.ExitCode == 0 {
		t.Error("expected non-zero exit code for bof_exec with no data")
	}
}

// TestHollowMissingShellcode verifies hollow with no shellcode returns an error.
func TestHollowMissingShellcode(t *testing.T) {
	a := minAgent()
	c := cmd("hollow")
	c.ProcessPath = "notepad.exe"
	// ShellcodeB64 intentionally empty.
	r := ExecuteCommand(a, c)
	if r.ExitCode == 0 {
		t.Error("expected non-zero exit code for hollow with no shellcode")
	}
}
