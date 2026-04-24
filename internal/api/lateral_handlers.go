package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

type lateralReq struct {
	Target  string `json:"target" binding:"required"` // remote hostname or IP
	User    string `json:"user"`
	Domain  string `json:"domain"`
	Pass    string `json:"pass"`
	Command string `json:"command" binding:"required"` // command to run on remote
}

func (h *Handlers) queueLateral(c *gin.Context, opType string) {
	agentID := c.Param("id")
	var req lateralReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cmd := &types.Command{
		ID:             uuid.New().String(),
		AgentID:        agentID,
		OperationType:  opType,
		LateralTarget:  req.Target,
		LateralUser:    req.User,
		LateralDomain:  req.Domain,
		LateralPass:    req.Pass,
		LateralCommand: req.Command,
		CreatedAt:      time.Now(),
		Status:         "pending",
		Timeout:        120,
	}

	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.server.Logger.LogCommandExecution(agentID, opType,
		fmt.Sprintf("target=%s method=%s", req.Target, opType), true)

	h.APIResponse(c, true, opType+" queued", map[string]interface{}{
		"command_id": cmd.ID,
		"target":     req.Target,
		"method":     opType,
	}, "")
}

// LateralWMI — POST /api/v1/agent/:id/lateral/wmi
func (h *Handlers) LateralWMI(c *gin.Context) { h.queueLateral(c, "lateral_wmi") }

// LateralWinRM — POST /api/v1/agent/:id/lateral/winrm
func (h *Handlers) LateralWinRM(c *gin.Context) { h.queueLateral(c, "lateral_winrm") }

// LateralSchtask — POST /api/v1/agent/:id/lateral/schtask
func (h *Handlers) LateralSchtask(c *gin.Context) { h.queueLateral(c, "lateral_schtask") }

// LateralService — POST /api/v1/agent/:id/lateral/service
func (h *Handlers) LateralService(c *gin.Context) { h.queueLateral(c, "lateral_service") }
