package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/core"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

var serverStartTime = time.Now()

// Handlers holds all HTTP handler methods
type Handlers struct {
	server *core.Server
}

// NewHandlers creates a new Handlers instance
func NewHandlers(server *core.Server) *Handlers {
	return &Handlers{server: server}
}

// randPadB64 returns a base64-encoded string of n random bytes.
func randPadB64(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return base64.RawStdEncoding.EncodeToString(b)
}

// APIResponse writes a standard JSON response with random traffic padding.
func (h *Handlers) APIResponse(c *gin.Context, success bool, message string, data interface{}, errMsg string) {
	// Random pad between 16 and 144 bytes (base64-encoded) to normalise response sizes.
	b := make([]byte, 1)
	rand.Read(b) //nolint:errcheck
	padLen := 16 + int(b[0])%129 // [16, 144]
	resp := types.APIResponse{
		Success: success,
		Message: message,
		Data:    data,
		Error:   errMsg,
		Pad:     randPadB64(padLen),
	}

	status := http.StatusOK
	if !success {
		status = c.Writer.Status()
		if status == 0 || status == http.StatusOK {
			status = http.StatusBadRequest
		}
		h.server.Logger.Error(services.SYSTEM, "API error: "+errMsg, "", "", map[string]string{
			"endpoint":  c.Request.URL.Path,
			"method":    c.Request.Method,
			"client_ip": c.ClientIP(),
			"status":    strconv.Itoa(status),
		})
	}

	c.JSON(status, resp)
}

// Dashboard renders the web dashboard
func (h *Handlers) Dashboard(c *gin.Context) {
	h.server.Logger.Info(services.SYSTEM, "Dashboard accessed", "", "", map[string]string{
		"client_ip": c.ClientIP(),
	})
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":   "Taburtuai C2",
		"version": "2.0.0",
		"uptime":  time.Since(serverStartTime).String(),
	})
}

// HealthCheck returns server health status
func (h *Handlers) HealthCheck(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(serverStartTime).String(),
		"version":   "2.0.0",
		"server_id": h.serverID(),
		"components": map[string]string{
			"logger":        h.componentStatus("logger"),
			"monitor":       h.componentStatus("monitor"),
			"crypto":        h.componentStatus("crypto"),
			"command_queue": h.componentStatus("command_queue"),
		},
	}

	if c.Query("detailed") == "true" {
		health["details"] = h.detailedHealth()
	}

	status, issues := h.systemHealth()
	health["status"] = status
	if len(issues) > 0 {
		health["issues"] = issues
	}

	h.APIResponse(c, true, "", health, "")
}

// GetStats returns server and agent statistics
func (h *Handlers) GetStats(c *gin.Context) {
	stats := map[string]interface{}{
		"agents":        h.server.Monitor.GetStats(),
		"logs":          h.server.Logger.GetStats(),
		"command_queue": h.server.CommandQueue.GetStats(),
		"server": map[string]interface{}{
			"version":   "2.0.0",
			"uptime":    time.Since(serverStartTime).String(),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"server_id": h.serverID(),
		},
	}
	h.APIResponse(c, true, "", stats, "")
}

// GetLogs returns recent logs with optional filtering
func (h *Handlers) GetLogs(c *gin.Context) {
	limit := 100
	if l, err := strconv.Atoi(c.Query("count")); err == nil && l > 0 {
		if l > 1000 {
			limit = 1000
		} else {
			limit = l
		}
	}

	level := c.Query("level")
	category := c.Query("category")
	agentID := c.Query("agent_id")

	var logs []services.LogEntry
	switch {
	case agentID != "":
		logs = h.server.Logger.GetLogsByAgent(agentID, limit)
	case category != "":
		logs = h.server.Logger.GetLogsByCategory(services.LogCategory(category), limit)
	default:
		logs = h.server.Logger.GetRecentLogs(limit)
	}

	if level != "" {
		var filtered []services.LogEntry
		for _, l := range logs {
			if l.Level == level {
				filtered = append(filtered, l)
			}
		}
		logs = filtered
	}

	h.APIResponse(c, true, "", map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	}, "")
}

// GetQueueStats returns command queue statistics
func (h *Handlers) GetQueueStats(c *gin.Context) {
	h.APIResponse(c, true, "", h.server.CommandQueue.GetStats(), "")
}
