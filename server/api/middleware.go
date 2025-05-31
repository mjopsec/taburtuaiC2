package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/server/core"
)

// Middleware provides HTTP middleware functions
type Middleware struct {
	server *core.Server
}

// NewMiddleware creates new middleware instance
func NewMiddleware(server *core.Server) *Middleware {
	return &Middleware{server: server}
}

// CORS handles CORS headers
func (m *Middleware) CORS() gin.HandlerFunc {
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

// Auth handles authentication
func (m *Middleware) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.server.Config.AuthEnabled {
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
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Authorization header required",
			})
			c.Abort()
			return
		}

		expectedAuth := "Bearer " + m.server.Config.APIKey
		if authHeader != expectedAuth {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Invalid API key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Logging logs HTTP requests
func (m *Middleware) Logging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		message := fmt.Sprintf("%s %s %d %v", method, path, statusCode, latency)
		m.server.Logger.Info("HTTP", message, "", "", nil)

		if statusCode >= 400 {
			m.server.Logger.Error("AUDIT",
				fmt.Sprintf("HTTP %d from %s: %s %s", statusCode, clientIP, method, path),
				"", "", nil)
		}
	}
}

// ErrorRecovery handles panics
func (m *Middleware) ErrorRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				m.server.Logger.Error("SYSTEM",
					fmt.Sprintf("Panic recovered: %v", err), "", "", nil)

				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error":   "Internal server error",
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}
