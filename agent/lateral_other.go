//go:build !windows

package main

import (
	"fmt"

	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleLateralWMI(cmd *types.Command, result *types.CommandResult) {
	result.Error = fmt.Sprintf("lateral_wmi is only supported on Windows (target: %s)", cmd.LateralTarget)
	result.ExitCode = 1
}

func handleLateralWinRM(cmd *types.Command, result *types.CommandResult) {
	result.Error = fmt.Sprintf("lateral_winrm is only supported on Windows (target: %s)", cmd.LateralTarget)
	result.ExitCode = 1
}

func handleLateralSchtask(cmd *types.Command, result *types.CommandResult) {
	result.Error = fmt.Sprintf("lateral_schtask is only supported on Windows (target: %s)", cmd.LateralTarget)
	result.ExitCode = 1
}

func handleLateralService(cmd *types.Command, result *types.CommandResult) {
	result.Error = fmt.Sprintf("lateral_service is only supported on Windows (target: %s)", cmd.LateralTarget)
	result.ExitCode = 1
}

func handleLateralDCOM(cmd *types.Command, result *types.CommandResult) {
	result.Error = fmt.Sprintf("lateral_dcom is only supported on Windows (target: %s)", cmd.LateralTarget)
	result.ExitCode = 1
}
