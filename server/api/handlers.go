package api

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/server/core"
	"github.com/mjopsec/taburtuaiC2/server/services"
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

// APIResponse wraps API responses with enhanced error handling
func (h *Handlers) APIResponse(c *gin.Context, success bool, message string, data interface{}, err string) {
	resp := types.APIResponse{
		Success: success,
		Message: message,
		Data:    data,
		Error:   err,
	}

	// Jangan wrap data dalam nested structure untuk endpoints yang tidak membutuhkannya
	// Hanya tambahkan metadata untuk response yang sukses dan data bukan nil
	if success && data != nil {
		// Check if this is an endpoint that should have simple structure
		path := c.Request.URL.Path
		if path == "/api/v1/agents" || path == "/api/v1/stats" {
			// Keep original data structure for agents and stats
			resp.Data = data
		} else {
			// For other endpoints, add metadata wrapper
			resp.Data = map[string]interface{}{
				"result":    data,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"server_id": h.getServerID(),
			}
		}
	}

	status := http.StatusOK
	if !success {
		if c.Writer.Status() != 0 {
			status = c.Writer.Status()
		} else {
			status = http.StatusBadRequest
		}

		// Log API errors for monitoring
		h.server.Logger.Error(services.SYSTEM,
			"API Error: "+err,
			"", "", map[string]string{
				"endpoint":   c.Request.URL.Path,
				"method":     c.Request.Method,
				"client_ip":  c.ClientIP(),
				"user_agent": c.GetHeader("User-Agent"),
				"status":     strconv.Itoa(status),
			})
	}

	c.JSON(status, resp)
}

// Dashboard shows the web dashboard
func (h *Handlers) Dashboard(c *gin.Context) {
	// Log dashboard access
	h.server.Logger.Info(services.SYSTEM,
		"Dashboard accessed",
		"", "", map[string]string{
			"client_ip":  c.ClientIP(),
			"user_agent": c.GetHeader("User-Agent"),
		})

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":   "Taburtuai C2 Dashboard",
		"version": "2.0.0",
		"uptime":  time.Since(serverStartTime).String(),
	})
}

// HealthCheck returns enhanced server health status
func (h *Handlers) HealthCheck(c *gin.Context) {
	detailed := c.Query("detailed") == "true"
	includeMetrics := c.Query("metrics") == "true"

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(serverStartTime).String(),
		"version":   "2.0.0",
		"server_id": h.getServerID(),
	}

	// Basic component health check
	components := map[string]string{
		"logger":        h.checkComponentHealth("logger"),
		"monitor":       h.checkComponentHealth("monitor"),
		"crypto":        h.checkComponentHealth("crypto"),
		"command_queue": h.checkComponentHealth("command_queue"),
	}

	health["components"] = components

	if detailed {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		agentStats := h.server.Monitor.GetStats()
		queueStats := h.server.CommandQueue.GetStats()

		health["details"] = map[string]interface{}{
			"memory": map[string]interface{}{
				"alloc_mb":       bToMb(memStats.Alloc),
				"total_alloc_mb": bToMb(memStats.TotalAlloc),
				"sys_mb":         bToMb(memStats.Sys),
				"gc_cycles":      memStats.NumGC,
				"heap_objects":   memStats.HeapObjects,
			},
			"runtime": map[string]interface{}{
				"goroutines": runtime.NumGoroutine(),
				"cpu_count":  runtime.NumCPU(),
				"go_version": runtime.Version(),
				"compiler":   runtime.Compiler,
				"arch":       runtime.GOARCH,
				"os":         runtime.GOOS,
			},
			"agents":        agentStats,
			"command_queue": queueStats,
		}

		// Performance metrics
		if includeMetrics {
			health["metrics"] = h.getPerformanceMetrics()
		}
	}

	// Check for any critical issues
	healthStatus, issues := h.assessSystemHealth()
	health["status"] = healthStatus

	if len(issues) > 0 {
		health["issues"] = issues
		if healthStatus == "critical" {
			c.Status(http.StatusServiceUnavailable)
		} else if healthStatus == "degraded" {
			c.Status(http.StatusPartialContent)
		}
	}

	h.APIResponse(c, true, "", health, "")
}

// GetStats returns enhanced server statistics
func (h *Handlers) GetStats(c *gin.Context) {
	includePerformance := c.Query("performance") == "true"
	includeSecurity := c.Query("security") == "true"

	agentStats := h.server.Monitor.GetStats()
	logStats := h.server.Logger.GetStats()
	queueStats := h.server.CommandQueue.GetStats()

	stats := map[string]interface{}{
		"agents":        agentStats,
		"logs":          logStats,
		"command_queue": queueStats,
		"server": map[string]interface{}{
			"version":   "2.0.0",
			"uptime":    time.Since(serverStartTime).String(),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"server_id": h.getServerID(),
		},
	}

	// Add performance metrics if requested
	if includePerformance {
		stats["performance"] = h.getPerformanceMetrics()
	}

	// Add security statistics if requested
	if includeSecurity {
		stats["security"] = h.getSecurityStats()
	}

	h.APIResponse(c, true, "", stats, "")
}

// GetLogs returns recent logs with enhanced filtering
func (h *Handlers) GetLogs(c *gin.Context) {
	limit := 100
	if l, err := strconv.Atoi(c.Query("count")); err == nil && l > 0 {
		if l > 1000 { // Max 1000 logs
			limit = 1000
		} else {
			limit = l
		}
	}

	// Optional filtering
	level := c.Query("level")
	category := c.Query("category")
	agentID := c.Query("agent_id")

	var logs []services.LogEntry

	if agentID != "" {
		logs = h.server.Logger.GetLogsByAgent(agentID, limit)
	} else if category != "" {
		logs = h.server.Logger.GetLogsByCategory(services.LogCategory(category), limit)
	} else {
		logs = h.server.Logger.GetRecentLogs(limit)
	}

	// Filter by level if specified
	if level != "" {
		filteredLogs := []services.LogEntry{}
		for _, log := range logs {
			if log.Level == level {
				filteredLogs = append(filteredLogs, log)
			}
		}
		logs = filteredLogs
	}

	response := map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
		"filters": map[string]string{
			"level":    level,
			"category": category,
			"agent_id": agentID,
		},
	}

	h.APIResponse(c, true, "", response, "")
}

// GetSecurityLogs returns security events
func (h *Handlers) GetSecurityLogs(c *gin.Context) {
	limit := 50
	if l, err := strconv.Atoi(c.Query("count")); err == nil && l > 0 {
		if l > 500 {
			limit = 500
		} else {
			limit = l
		}
	}

	threatLevel := c.Query("threat_level")
	secEvents := h.server.Logger.GetSecurityEvents(limit)

	// Filter by threat level if specified
	if threatLevel != "" {
		filteredEvents := []services.SecurityEvent{}
		for _, event := range secEvents {
			if event.ThreatLevel == threatLevel {
				filteredEvents = append(filteredEvents, event)
			}
		}
		secEvents = filteredEvents
	}

	response := map[string]interface{}{
		"security_events": secEvents,
		"count":           len(secEvents),
		"threat_level":    threatLevel,
	}

	h.APIResponse(c, true, "", response, "")
}

// GetQueueStats returns enhanced command queue statistics
func (h *Handlers) GetQueueStats(c *gin.Context) {
	stats := h.server.CommandQueue.GetStats()

	// Add additional queue health metrics
	enhancedStats := map[string]interface{}{
		"queue_stats": stats,
		"health": map[string]interface{}{
			"total_capacity":     1000, // Max queue size per agent
			"average_queue_size": h.calculateAverageQueueSize(stats),
			"peak_usage":         h.getPeakQueueUsage(),
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	h.APIResponse(c, true, "", enhancedStats, "")
}

// SystemInfo returns detailed system information
func (h *Handlers) SystemInfo(c *gin.Context) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	systemInfo := map[string]interface{}{
		"server": map[string]interface{}{
			"version":    "2.0.0",
			"uptime":     time.Since(serverStartTime).String(),
			"start_time": serverStartTime.Format(time.RFC3339),
			"server_id":  h.getServerID(),
		},
		"runtime": map[string]interface{}{
			"go_version":   runtime.Version(),
			"goroutines":   runtime.NumGoroutine(),
			"cpu_count":    runtime.NumCPU(),
			"compiler":     runtime.Compiler,
			"architecture": runtime.GOARCH,
			"os":           runtime.GOOS,
		},
		"memory": map[string]interface{}{
			"allocated_mb":    bToMb(memStats.Alloc),
			"total_alloc_mb":  bToMb(memStats.TotalAlloc),
			"system_mb":       bToMb(memStats.Sys),
			"gc_cycles":       memStats.NumGC,
			"heap_objects":    memStats.HeapObjects,
			"stack_in_use_mb": bToMb(memStats.StackInuse),
		},
		"performance": h.getPerformanceMetrics(),
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}

	h.APIResponse(c, true, "", systemInfo, "")
}

// ========================================
// HELPER FUNCTIONS
// ========================================

// getServerID returns a unique server identifier
func (h *Handlers) getServerID() string {
	// Simple implementation - in production, use proper server ID
	return "taburtuai-" + serverStartTime.Format("20060102-150405")
}

// checkComponentHealth checks the health of individual components
func (h *Handlers) checkComponentHealth(component string) string {
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
		} else {
			return "disabled"
		}
	case "command_queue":
		if h.server.CommandQueue != nil {
			return "ok"
		}
	}
	return "error"
}

// assessSystemHealth performs comprehensive health assessment
func (h *Handlers) assessSystemHealth() (string, []string) {
	var issues []string
	status := "healthy"

	// Check memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	if memStats.Alloc > 1024*1024*1024 { // More than 1GB allocated
		issues = append(issues, "High memory usage detected")
		status = "degraded"
	}

	// Check agent statistics
	agentStats := h.server.Monitor.GetStats()
	if totalAgents, ok := agentStats["total_agents"].(int); ok && totalAgents > 0 {
		if offlineAgents, ok := agentStats["offline_agents"].(int); ok {
			offlineRatio := float64(offlineAgents) / float64(totalAgents)
			if offlineRatio > 0.8 { // More than 80% offline
				issues = append(issues, "High agent offline ratio")
				if offlineRatio > 0.95 {
					status = "critical"
				} else {
					status = "degraded"
				}
			}
		}
	}

	// Check goroutine count
	if runtime.NumGoroutine() > 1000 {
		issues = append(issues, "High goroutine count")
		status = "degraded"
	}

	// Check command queue health
	queueStats := h.server.CommandQueue.GetStats()
	if totalQueued, ok := queueStats["total_queued"].(int); ok && totalQueued > 5000 {
		issues = append(issues, "Command queue backlog")
		status = "degraded"
	}

	if len(issues) == 0 {
		return "healthy", nil
	}

	return status, issues
}

// getPerformanceMetrics returns performance metrics
func (h *Handlers) getPerformanceMetrics() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"memory_efficiency": map[string]interface{}{
			"heap_alloc_mb":   bToMb(memStats.HeapAlloc),
			"heap_sys_mb":     bToMb(memStats.HeapSys),
			"heap_objects":    memStats.HeapObjects,
			"gc_cpu_fraction": memStats.GCCPUFraction,
		},
		"runtime_performance": map[string]interface{}{
			"goroutines":     runtime.NumGoroutine(),
			"gc_cycles":      memStats.NumGC,
			"pause_total_ns": memStats.PauseTotalNs,
		},
		"uptime_seconds": time.Since(serverStartTime).Seconds(),
	}
}

// getSecurityStats returns security-related statistics
func (h *Handlers) getSecurityStats() map[string]interface{} {
	logStats := h.server.Logger.GetStats()

	securityStats := map[string]interface{}{
		"security_events":  logStats["security_events"],
		"security_summary": logStats["security_summary"],
		"auth_events":      h.getAuthenticationStats(),
		"threat_detection": map[string]interface{}{
			"dangerous_commands": h.countDangerousCommands(),
			"failed_auths":       h.countFailedAuthentications(),
		},
	}

	return securityStats
}

// getAuthenticationStats returns authentication statistics
func (h *Handlers) getAuthenticationStats() map[string]interface{} {
	authLogs := h.server.Logger.GetLogsByCategory(services.AUTHENTICATION, 100)

	successCount := 0
	failureCount := 0

	for _, log := range authLogs {
		if log.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	return map[string]interface{}{
		"total_attempts": len(authLogs),
		"successful":     successCount,
		"failed":         failureCount,
		"success_rate":   float64(successCount) / float64(len(authLogs)) * 100,
	}
}

// countDangerousCommands counts recent dangerous commands
func (h *Handlers) countDangerousCommands() int {
	secEvents := h.server.Logger.GetSecurityEvents(100)
	count := 0

	for _, event := range secEvents {
		if event.EventType == "DANGEROUS_COMMAND" {
			count++
		}
	}

	return count
}

// countFailedAuthentications counts recent failed authentications
func (h *Handlers) countFailedAuthentications() int {
	secEvents := h.server.Logger.GetSecurityEvents(100)
	count := 0

	for _, event := range secEvents {
		if event.EventType == "AUTH_FAILURE" {
			count++
		}
	}

	return count
}

// calculateAverageQueueSize calculates average queue size across agents
func (h *Handlers) calculateAverageQueueSize(stats map[string]interface{}) float64 {
	if byAgent, ok := stats["by_agent"].(map[string]map[string]int); ok {
		total := 0
		count := 0

		for _, agentStats := range byAgent {
			if queued, ok := agentStats["queued"]; ok {
				total += queued
				count++
			}
		}

		if count > 0 {
			return float64(total) / float64(count)
		}
	}

	return 0
}

// getPeakQueueUsage returns peak queue usage (placeholder implementation)
func (h *Handlers) getPeakQueueUsage() int {
	// In a real implementation, this would track peak usage over time
	// For now, return current total queued
	stats := h.server.CommandQueue.GetStats()
	if totalQueued, ok := stats["total_queued"].(int); ok {
		return totalQueued
	}
	return 0
}

// bToMb converts bytes to megabytes
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

var serverStartTime = time.Now()
