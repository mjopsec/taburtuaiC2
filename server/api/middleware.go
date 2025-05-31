package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/server/core"
	"github.com/mjopsec/taburtuaiC2/server/services"
)

// Middleware provides HTTP middleware functions
type Middleware struct {
	server *core.Server
}

// NewMiddleware creates new middleware instance
func NewMiddleware(server *core.Server) *Middleware {
	return &Middleware{server: server}
}

// CORS handles CORS headers with enhanced security
func (m *Middleware) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		// In production, you should configure allowed origins properly
		// For now, we'll allow all origins but add security headers
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Requested-With")
		c.Header("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// Auth handles authentication with enhanced security
func (m *Middleware) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.server.Config.AuthEnabled {
			c.Next()
			return
		}

		// Skip auth for specific endpoints
		skipAuthPaths := []string{
			"/api/v1/health",
			"/api/v1/checkin", // Allow agent checkin without auth
			"/",               // Dashboard
			"/static/",        // Static files
		}

		path := c.Request.URL.Path
		for _, skipPath := range skipAuthPaths {
			if path == skipPath || strings.HasPrefix(path, skipPath) {
				c.Next()
				return
			}
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.server.Logger.Warn(services.AUDIT,
				fmt.Sprintf("Missing authorization header from %s", c.ClientIP()),
				"", "", map[string]string{
					"client_ip":  c.ClientIP(),
					"user_agent": c.GetHeader("User-Agent"),
					"path":       path,
				})

			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Authorization header required",
			})
			c.Abort()
			return
		}

		// Validate Bearer token format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.server.Logger.Warn(services.AUDIT,
				fmt.Sprintf("Invalid authorization header format from %s", c.ClientIP()),
				"", "", map[string]string{
					"client_ip": c.ClientIP(),
					"path":      path,
				})

			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		expectedAuth := "Bearer " + m.server.Config.APIKey
		if authHeader != expectedAuth {
			m.server.Logger.Warn(services.AUDIT,
				fmt.Sprintf("Invalid API key from %s", c.ClientIP()),
				"", "", map[string]string{
					"client_ip":  c.ClientIP(),
					"user_agent": c.GetHeader("User-Agent"),
					"path":       path,
				})

			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Invalid API key",
			})
			c.Abort()
			return
		}

		// Log successful authentication
		m.server.Logger.Info(services.AUDIT,
			fmt.Sprintf("Successful authentication from %s", c.ClientIP()),
			"", "", map[string]string{
				"client_ip": c.ClientIP(),
				"path":      path,
			})

		c.Next()
	}
}

// RateLimit implements advanced rate limiting middleware
func (m *Middleware) RateLimit() gin.HandlerFunc {
	type clientInfo struct {
		requests []time.Time
		blocked  time.Time
		warnings int
	}

	clients := make(map[string]*clientInfo)
	mutex := sync.RWMutex{}

	const (
		maxRequests      = 100             // Max requests per window
		windowSize       = time.Minute     // Time window
		blockDuration    = 5 * time.Minute // Block duration for abuse
		warningThreshold = 80              // Warning at 80% of limit
	)

	// Cleanup routine
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			mutex.Lock()
			now := time.Now()
			cutoff := now.Add(-windowSize)

			for ip, clientData := range clients {
				// Remove old requests outside window
				newRequests := []time.Time{}
				for _, reqTime := range clientData.requests {
					if reqTime.After(cutoff) {
						newRequests = append(newRequests, reqTime)
					}
				}
				clientData.requests = newRequests

				// Remove clients with no recent activity and not blocked
				if len(clientData.requests) == 0 && clientData.blocked.Before(now) {
					delete(clients, ip)
				}
			}
			mutex.Unlock()
		}
	}()

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		// Skip rate limiting for specific paths
		skipRateLimitPaths := []string{
			"/api/v1/health",
			"/static/",
		}

		path := c.Request.URL.Path
		for _, skipPath := range skipRateLimitPaths {
			if path == skipPath || strings.HasPrefix(path, skipPath) {
				c.Next()
				return
			}
		}

		mutex.Lock()
		defer mutex.Unlock()

		clientData, exists := clients[clientIP]
		if !exists {
			clientData = &clientInfo{requests: []time.Time{}}
			clients[clientIP] = clientData
		}

		// Check if client is blocked
		if now.Before(clientData.blocked) {
			remaining := clientData.blocked.Sub(now)
			c.Header("Retry-After", fmt.Sprintf("%.0f", remaining.Seconds()))

			m.server.Logger.Warn(services.AUDIT,
				fmt.Sprintf("Blocked request from %s (rate limited)", clientIP),
				"", "", map[string]string{
					"client_ip":     clientIP,
					"blocked_until": clientData.blocked.Format(time.RFC3339),
				})

			c.JSON(http.StatusTooManyRequests, gin.H{
				"success":     false,
				"error":       "Rate limit exceeded. Access temporarily blocked.",
				"retry_after": remaining.Seconds(),
			})
			c.Abort()
			return
		}

		// Clean old requests
		cutoff := now.Add(-windowSize)
		newRequests := []time.Time{}
		for _, reqTime := range clientData.requests {
			if reqTime.After(cutoff) {
				newRequests = append(newRequests, reqTime)
			}
		}
		clientData.requests = newRequests

		// Check rate limit
		if len(clientData.requests) >= maxRequests {
			clientData.blocked = now.Add(blockDuration)

			m.server.Logger.Error(services.AUDIT,
				fmt.Sprintf("Rate limit exceeded for IP %s - blocked for %v", clientIP, blockDuration),
				"", "", map[string]string{
					"action":         "blocked",
					"requests_count": fmt.Sprintf("%d", len(clientData.requests)),
					"block_duration": blockDuration.String(),
				})

			c.Header("Retry-After", fmt.Sprintf("%.0f", blockDuration.Seconds()))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success":     false,
				"error":       "Rate limit exceeded. Access temporarily blocked.",
				"retry_after": blockDuration.Seconds(),
			})
			c.Abort()
			return
		}

		// Warning threshold check
		if len(clientData.requests) >= warningThreshold && clientData.warnings < 3 {
			clientData.warnings++
			m.server.Logger.Warn(services.AUDIT,
				fmt.Sprintf("Rate limit warning for IP %s (%d/%d requests)", clientIP, len(clientData.requests), maxRequests),
				"", "", map[string]string{
					"client_ip":      clientIP,
					"requests_count": fmt.Sprintf("%d", len(clientData.requests)),
					"warning_count":  fmt.Sprintf("%d", clientData.warnings),
				})
		}

		// Add current request
		clientData.requests = append(clientData.requests, now)

		// Add rate limit headers
		remaining := maxRequests - len(clientData.requests)
		if remaining < 0 {
			remaining = 0
		}

		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", maxRequests))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", now.Add(windowSize).Unix()))
		c.Header("X-RateLimit-Window", windowSize.String())

		c.Next()
	}
}

// Logging logs HTTP requests with enhanced details
func (m *Middleware) Logging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		method := c.Request.Method
		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()
		responseSize := c.Writer.Size()

		if raw != "" {
			path = path + "?" + raw
		}

		// Create detailed log message
		message := fmt.Sprintf("%s %s %d %v %dB", method, path, statusCode, latency, responseSize)

		metadata := map[string]string{
			"client_ip":     clientIP,
			"user_agent":    userAgent,
			"method":        method,
			"path":          path,
			"status_code":   fmt.Sprintf("%d", statusCode),
			"latency_ms":    fmt.Sprintf("%.2f", float64(latency.Nanoseconds())/1000000),
			"response_size": fmt.Sprintf("%d", responseSize),
		}

		// Log based on status code
		if statusCode >= 500 {
			m.server.Logger.Error(services.SYSTEM, message, "", "", metadata)
		} else if statusCode >= 400 {
			m.server.Logger.Warn(services.AUDIT, message, "", "", metadata)
		} else {
			m.server.Logger.Info(services.SYSTEM, message, "", "", metadata)
		}

		// Log security events for suspicious activities
		if statusCode == 401 || statusCode == 403 {
			m.server.Logger.Warn(services.AUDIT,
				fmt.Sprintf("Security event: HTTP %d from %s: %s %s", statusCode, clientIP, method, path),
				"", "", metadata)
		}

		// Log slow requests
		if latency > 5*time.Second {
			m.server.Logger.Warn(services.SYSTEM,
				fmt.Sprintf("Slow request detected: %s %s took %v", method, path, latency),
				"", "", metadata)
		}
	}
}

// ErrorRecovery handles panics with enhanced error reporting
func (m *Middleware) ErrorRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Log detailed panic information
				metadata := map[string]string{
					"client_ip":  c.ClientIP(),
					"user_agent": c.GetHeader("User-Agent"),
					"method":     c.Request.Method,
					"path":       c.Request.URL.Path,
					"panic_type": fmt.Sprintf("%T", err),
				}

				m.server.Logger.Error(services.SYSTEM,
					fmt.Sprintf("Panic recovered: %v", err), "", "", metadata)

				// In development, you might want to include more details
				// In production, keep error messages generic for security
				c.JSON(http.StatusInternalServerError, gin.H{
					"success":   false,
					"error":     "Internal server error",
					"timestamp": time.Now().Format(time.RFC3339),
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}

// SecurityHeaders adds security headers to all responses
func (m *Middleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")

		// Hide server information
		c.Header("Server", "Taburtuai-C2")

		// Prevent caching of sensitive endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}

		c.Next()
	}
}

// RequestSizeLimit limits the size of request bodies
func (m *Middleware) RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip for file upload endpoints (they have their own limits)
		if strings.Contains(c.Request.URL.Path, "/upload") {
			c.Next()
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}

// ValidateContentType validates Content-Type headers for API endpoints
func (m *Middleware) ValidateContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only validate for API endpoints with POST/PUT methods
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") ||
			(c.Request.Method != "POST" && c.Request.Method != "PUT") {
			c.Next()
			return
		}

		// Skip for file upload endpoints
		if strings.Contains(c.Request.URL.Path, "/upload") {
			c.Next()
			return
		}

		contentType := c.GetHeader("Content-Type")
		if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
			m.server.Logger.Warn(services.AUDIT,
				fmt.Sprintf("Invalid Content-Type from %s: %s", c.ClientIP(), contentType),
				"", "", map[string]string{
					"client_ip":    c.ClientIP(),
					"content_type": contentType,
					"path":         c.Request.URL.Path,
				})

			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Content-Type must be application/json",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
