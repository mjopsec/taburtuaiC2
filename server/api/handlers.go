package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/server/core"
	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// Handlers contains all HTTP handlers
type Handlers struct {
	server *core.Server
}

// NewHandlers creates new handlers instance
func NewHandlers(server *core.Server) *Handlers {
	return &Handlers{server: server}
}

// APIResponse wraps API responses
func (h *Handlers) APIResponse(c *gin.Context, success bool, message string, data interface{}, err string) {
	resp := types.APIResponse{
		Success: success,
		Message: message,
		Data:    data,
		Error:   err,
	}

	status := http.StatusOK
	if !success {
		if c.Writer.Status() != 0 {
			status = c.Writer.Status()
		} else {
			status = http.StatusBadRequest
		}
	}

	c.JSON(status, resp)
}

// Dashboard shows the web dashboard
func (h *Handlers) Dashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "Taburtuai C2 Dashboard",
	})
}

// HealthCheck returns server health status
func (h *Handlers) HealthCheck(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"components": map[string]string{
			"logger":  "ok",
			"monitor": "ok",
			"crypto":  "ok",
		},
	}

	h.APIResponse(c, true, "", health, "")
}

// GetStats returns server statistics
func (h *Handlers) GetStats(c *gin.Context) {
	agentStats := h.server.Monitor.GetStats()
	logStats := h.server.Logger.GetStats()

	stats := map[string]interface{}{
		"agents": agentStats,
		"logs":   logStats,
		"server": map[string]interface{}{
			"version": "2.0.0",
			"uptime":  time.Since(serverStartTime).String(),
		},
	}

	h.APIResponse(c, true, "", stats, "")
}

// GetLogs returns recent logs
func (h *Handlers) GetLogs(c *gin.Context) {
	limit := 100
	if l, err := strconv.Atoi(c.Query("count")); err == nil {
		limit = l
	}

	logs := h.server.Logger.GetRecentLogs(limit)
	h.APIResponse(c, true, "", logs, "")
}

// GetQueueStats returns command queue statistics
func (h *Handlers) GetQueueStats(c *gin.Context) {
	stats := h.server.CommandQueue.GetStats()
	h.APIResponse(c, true, "", stats, "")
}

var serverStartTime = time.Now()
