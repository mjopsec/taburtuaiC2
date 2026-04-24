package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// stagePost is a generic helper for stage API calls.
func stagePost(endpoint string, payload interface{}) (map[string]interface{}, error) {
	raw, _ := json.Marshal(payload)
	body, err := makeAPIRequestWithMethod("POST",
		"/api/v1/"+endpoint,
		bytes.NewBuffer(raw), "application/json")
	if err != nil {
		return nil, err
	}
	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
		msg := resp.Error
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	m, _ := resp.Data.(map[string]interface{})
	return m, nil
}

// ── stage parent ──────────────────────────────────────────────────────────────

var stageCmd = &cobra.Command{
	Use:   "stage",
	Short: "Stage management — upload, list, delete staged payloads",
}

// ── stage upload ──────────────────────────────────────────────────────────────

var stageUploadCmd = &cobra.Command{
	Use:   "upload <file>",
	Short: "Upload a payload file to the C2 stage server",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]
		format, _ := cmd.Flags().GetString("format")
		arch, _ := cmd.Flags().GetString("arch")
		ttl, _ := cmd.Flags().GetInt("ttl")
		desc, _ := cmd.Flags().GetString("desc")

		data, err := os.ReadFile(file)
		if err != nil {
			printError(fmt.Sprintf("Read file: %v", err))
			os.Exit(1)
		}

		m, err := stagePost("stage", map[string]interface{}{
			"payload_b64": base64.StdEncoding.EncodeToString(data),
			"format":      format,
			"arch":        arch,
			"os":          "windows",
			"ttl_hours":   ttl,
			"description": desc,
		})
		if err != nil {
			printError(fmt.Sprintf("Upload failed: %v", err))
			os.Exit(1)
		}

		printSuccess(fmt.Sprintf("Stage uploaded (%d bytes)", len(data)))
		if token, ok := m["token"].(string); ok {
			printInfo(fmt.Sprintf("Token    : %s", token))
		}
		if u, ok := m["stage_url"].(string); ok {
			printInfo(fmt.Sprintf("Stage URL: %s", u))
		}
		if exp, ok := m["expires_at"].(float64); ok && exp > 0 {
			printInfo(fmt.Sprintf("Expires  : %s", time.Unix(int64(exp), 0).Format(time.RFC3339)))
		}
	},
}

// ── stage list ────────────────────────────────────────────────────────────────

var stageListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all staged payloads",
	Run: func(cmd *cobra.Command, args []string) {
		body, err := makeAPIRequestWithMethod("GET", "/api/v1/stages", nil, "")
		if err != nil {
			printError(fmt.Sprintf("Request failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError(resp.Error)
			os.Exit(1)
		}
		m, _ := resp.Data.(map[string]interface{})
		stages, _ := m["stages"].([]interface{})
		if len(stages) == 0 {
			printInfo("No stages found")
			return
		}
		fmt.Printf("\n%-36s  %-10s  %-6s  %-7s  %s\n", "TOKEN", "FORMAT", "ARCH", "USED", "DESCRIPTION")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────")
		for _, s := range stages {
			st, _ := s.(map[string]interface{})
			token, _ := st["token"].(string)
			format, _ := st["format"].(string)
			arch, _ := st["arch"].(string)
			used, _ := st["used"].(bool)
			desc, _ := st["description"].(string)
			usedStr := "no"
			if used {
				usedStr = "yes"
			}
			if len(token) > 32 {
				token = token[:32] + ".."
			}
			fmt.Printf("%-36s  %-10s  %-6s  %-7s  %s\n", token, format, arch, usedStr, desc)
		}
		fmt.Println()
	},
}

// ── stage delete ──────────────────────────────────────────────────────────────

var stageDeleteCmd = &cobra.Command{
	Use:   "delete <token>",
	Short: "Delete a stage by token",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		token := args[0]
		body, err := makeAPIRequestWithMethod("DELETE",
			"/api/v1/stage/"+token, nil, "")
		if err != nil {
			printError(fmt.Sprintf("Delete failed: %v", err))
			os.Exit(1)
		}
		var resp APIResponse
		if err := json.Unmarshal(body, &resp); err != nil || !resp.Success {
			printError(resp.Error)
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("Stage %s deleted", token))
	},
}
