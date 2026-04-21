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
			printError(err.Error())
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
			{"cmd execute <id> \"<cmd>\"", "single command"},
			{"status <cmd-id>", "check command result"},
			{"history <id>", "execution history"},
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
