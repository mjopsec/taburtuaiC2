package api

import (
	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/server/core"
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

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(r.middleware.ErrorRecovery())
	router.Use(r.middleware.Logging())
	router.Use(r.middleware.CORS())
	router.Use(r.middleware.Auth())

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

		// File operations
		v1.POST("/agent/:id/upload", r.handlers.UploadToAgent)
		v1.POST("/agent/:id/download", r.handlers.DownloadFromAgent)

		// Process management
		process := v1.Group("/agent/:id/process")
		{
			process.POST("/list", r.handlers.ListProcesses)
			process.POST("/kill", r.handlers.KillProcess)
			process.POST("/start", r.handlers.StartProcess)
		}

		// Persistence
		persist := v1.Group("/agent/:id/persist")
		{
			persist.POST("/setup", r.handlers.SetupPersistence)
			persist.POST("/remove", r.handlers.RemovePersistence)
		}

		// Monitoring
		v1.GET("/stats", r.handlers.GetStats)
		v1.GET("/health", r.handlers.HealthCheck)
		v1.GET("/logs", r.handlers.GetLogs)
		v1.GET("/queue/stats", r.handlers.GetQueueStats)
	}

	return router
}
