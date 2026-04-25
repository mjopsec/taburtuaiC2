package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/pkg/crypto"
)

// serverID returns a unique identifier for this server instance
func (h *Handlers) serverID() string {
	return "taburtuai-" + serverStartTime.Format("20060102-150405")
}

// componentStatus returns "ok", "disabled", or "error" for a named component
func (h *Handlers) componentStatus(component string) string {
	switch component {
	case "logger":
		if h.server.Logger != nil {
			return "ok"
		}
	case "monitor":
		if h.server.Monitor != nil {
			return "ok"
		}
	case "crypto":
		if h.server.CryptoMgr != nil {
			return "ok"
		}
		return "disabled"
	case "command_queue":
		if h.server.CommandQueue != nil {
			return "ok"
		}
	}
	return "error"
}

// detailedHealth returns memory, runtime, and subsystem detail
func (h *Handlers) detailedHealth() map[string]interface{} {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	return map[string]interface{}{
		"memory": map[string]interface{}{
			"alloc_mb":       bToMb(mem.Alloc),
			"total_alloc_mb": bToMb(mem.TotalAlloc),
			"sys_mb":         bToMb(mem.Sys),
			"gc_cycles":      mem.NumGC,
			"heap_objects":   mem.HeapObjects,
		},
		"runtime": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"cpu_count":  runtime.NumCPU(),
			"go_version": runtime.Version(),
			"arch":       runtime.GOARCH,
			"os":         runtime.GOOS,
		},
		"agents":        h.server.Monitor.GetStats(),
		"command_queue": h.server.CommandQueue.GetStats(),
	}
}

// systemHealth evaluates overall health and returns a status string + issues list
func (h *Handlers) systemHealth() (string, []string) {
	var issues []string
	status := "healthy"

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	if mem.Alloc > 1024*1024*1024 {
		issues = append(issues, "High memory usage (>1GB)")
		status = "degraded"
	}

	if runtime.NumGoroutine() > 1000 {
		issues = append(issues, "High goroutine count")
		status = "degraded"
	}

	agentStats := h.server.Monitor.GetStats()
	if total, ok := agentStats["total_agents"].(int); ok && total > 0 {
		if offline, ok := agentStats["offline_agents"].(int); ok {
			if ratio := float64(offline) / float64(total); ratio > 0.95 {
				issues = append(issues, "Critical: >95% agents offline")
				status = "critical"
			} else if ratio > 0.8 {
				issues = append(issues, "Warning: >80% agents offline")
				if status == "healthy" {
					status = "degraded"
				}
			}
		}
	}

	queueStats := h.server.CommandQueue.GetStats()
	if queued, ok := queueStats["total_queued"].(int); ok && queued > 5000 {
		issues = append(issues, "Command queue backlog >5000")
		if status == "healthy" {
			status = "degraded"
		}
	}

	return status, issues
}

// enforceAgentWrite checks team-server claim ownership for any handler that
// queues a command to an agent. Returns true (and writes a 409) if the caller
// does not hold the write lock; returns false when the caller may proceed.
func (h *Handlers) enforceAgentWrite(c *gin.Context, agentID string) bool {
	sessionID := c.GetHeader("X-Session-ID")
	if h.server.TeamHub.CanWrite(agentID, sessionID) {
		return false
	}
	_, claimant, _ := h.server.TeamHub.AgentClaim(agentID)
	c.Status(http.StatusConflict)
	h.APIResponse(c, false, "", nil,
		fmt.Sprintf("agent %s is claimed by %s — release it first or use their session", agentID[:8], claimant))
	return true
}

// encryptSessionKey encrypts raw ECDH session key bytes using the server's
// static CryptoMgr so the session key is never stored in plaintext in the
// agent metadata / SQLite database.  Falls back to plain base64 if CryptoMgr
// is unavailable (non-prod mode without ENCRYPTION_KEY set).
func encryptSessionKey(h *Handlers, key []byte) string {
	if h.server.CryptoMgr != nil {
		if enc, err := h.server.CryptoMgr.EncryptData(key); err == nil {
			return "enc:" + enc
		}
	}
	return base64.StdEncoding.EncodeToString(key)
}

// agentSessionMgr returns a crypto.Manager initialised with the ECDH-derived
// session key stored in the agent's metadata during checkin.
// Returns nil when no session key exists (pre-ECDH agents or unknown agent).
func (h *Handlers) agentSessionMgr(agentID string) *crypto.Manager {
	if agentID == "" {
		return nil
	}
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		return nil
	}
	stored, ok := agent.Metadata["_session_key"].(string)
	if !ok || stored == "" {
		return nil
	}

	// Decrypt if the stored value was encrypted by encryptSessionKey.
	var keyBytes []byte
	if len(stored) > 4 && stored[:4] == "enc:" && h.server.CryptoMgr != nil {
		dec, err := h.server.CryptoMgr.DecryptData(stored[4:])
		if err != nil {
			return nil
		}
		keyBytes = dec
	} else {
		var err error
		keyBytes, err = base64.StdEncoding.DecodeString(stored)
		if err != nil {
			return nil
		}
	}

	mgr, err := crypto.NewManagerFromRawKey(keyBytes)
	if err != nil {
		return nil
	}
	return mgr
}

// bToMb converts bytes to megabytes
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// uptimeSince returns duration since t as a human-readable string
func uptimeSince(t time.Time) string {
	return time.Since(t).Round(time.Second).String()
}
