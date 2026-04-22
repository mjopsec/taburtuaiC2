// taburtuai-generate — implant builder and delivery template generator.
//
// Usage:
//   taburtuai-generate stager   [flags]   # compile minimal stager + wrap in delivery format
//   taburtuai-generate stageless [flags]  # compile full agent
//   taburtuai-generate template [flags]   # generate delivery templates (no compilation)
//   taburtuai-generate upload   [flags]   # upload a payload to C2 stage server
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "taburtuai-generate",
	Short: "taburtuai-generate — implant builder & delivery template generator",
	Long: `
  taburtuai-generate builds staged / stageless implants and generates
  initial-access delivery templates for red team engagements.

  Subcommands
  ───────────
  stager    Compile a minimal stager (downloads + executes from C2)
  stageless Compile the full agent as a self-contained implant
  template  Generate delivery templates (ClickFix, macro, HTA, LNK …)
  upload    Upload a local payload file to the C2 stage endpoint
`,
}

func init() {
	rootCmd.AddCommand(stagerCmd)
	rootCmd.AddCommand(stagelessCmd)
	rootCmd.AddCommand(templateCmd)
	rootCmd.AddCommand(uploadCmd)
}
