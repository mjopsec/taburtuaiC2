//go:build windows

package exec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

const (
	psBridgeTypeName   = "PSBridge.Runner"
	psBridgeMethodName = "Execute"
)

// PsRunspace executes psScript in-process if bridgePath (.NET shim DLL) is
// present; otherwise falls back to execPowerShell (spawns powershell.exe).
func PsRunspace(psScript, bridgePath string) (string, error) {
	if bridgePath != "" {
		if _, err := os.Stat(bridgePath); err == nil {
			abs, _ := filepath.Abs(bridgePath)
			retCode, err := DotnetExecute(abs, psBridgeTypeName, psBridgeMethodName, psScript)
			if err != nil {
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
