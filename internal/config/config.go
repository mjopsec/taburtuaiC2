package config

import (
	"errors"
	"os"
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/services"
)

// Config holds server configuration
type Config struct {
	Host          string
	Port          string
	LogLevel      services.LogLevel
	LogDir        string
	DBPath        string
	EncryptionKey string
	SecondaryKey  string
	AuthEnabled   bool
	APIKey        string
	MaxAgents     int
	AgentTimeout  time.Duration
	// Malleable HTTP profile — registers alias routes matching the agent's profile.
	// Values: default | office365 | cdn | jquery | slack | ocsp
	Profile string

	// TLS / HTTPS
	TLSEnabled  bool   // enable HTTPS listener
	TLSCertFile string // path to PEM certificate (empty = auto-generate)
	TLSKeyFile  string // path to PEM private key  (empty = auto-generate)
	TLSPort     string // HTTPS listen port (default: 8443)

	// WebSocket listener
	WSEnabled bool   // enable WebSocket listener
	WSPort    string // WebSocket listen port (default: 8081)

	// RBAC — team server roles
	AdminKey string // secret key to register as admin role (empty = no admin promotion)

	// DNS authoritative listener
	DNSEnabled bool   // enable DNS listener
	DNSPort    string // UDP port (default: 5353)
	DNSDomain  string // authoritative zone, e.g. "c2.example.com"
}

// Load loads configuration from environment variables.
// ENCRYPTION_KEY, SECONDARY_KEY, and API_KEY must be set explicitly —
// there are no built-in defaults so a misconfigured server fails at Validate().
func Load() *Config {
	config := &Config{
		Host:          getEnvOrDefault("HOST", ""),
		Port:          getEnvOrDefault("PORT", "8080"),
		LogLevel:      services.INFO,
		LogDir:        getEnvOrDefault("LOG_DIR", "./logs"),
		DBPath:        getEnvOrDefault("DB_PATH", "./data/taburtuai.db"),
		EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
		SecondaryKey:  os.Getenv("SECONDARY_KEY"),
		AuthEnabled:   getEnvOrDefault("AUTH_ENABLED", "false") == "true",
		APIKey:        os.Getenv("API_KEY"),
		MaxAgents:     100,
		AgentTimeout:  5 * time.Minute,
		TLSEnabled:    getEnvOrDefault("TLS_ENABLED", "false") == "true",
		TLSCertFile:   getEnvOrDefault("TLS_CERT", ""),
		TLSKeyFile:    getEnvOrDefault("TLS_KEY", ""),
		TLSPort:       getEnvOrDefault("TLS_PORT", "8443"),
		WSEnabled:     getEnvOrDefault("WS_ENABLED", "false") == "true",
		WSPort:        getEnvOrDefault("WS_PORT", "8081"),
		AdminKey:      getEnvOrDefault("ADMIN_KEY", ""),
		DNSEnabled:    getEnvOrDefault("DNS_ENABLED", "false") == "true",
		DNSPort:       getEnvOrDefault("DNS_PORT", "5353"),
		DNSDomain:     getEnvOrDefault("DNS_DOMAIN", ""),
	}

	// Parse log level from environment
	if logLevelStr := os.Getenv("LOG_LEVEL"); logLevelStr != "" {
		switch logLevelStr {
		case "DEBUG":
			config.LogLevel = services.DEBUG
		case "INFO":
			config.LogLevel = services.INFO
		case "WARN":
			config.LogLevel = services.WARN
		case "ERROR":
			config.LogLevel = services.ERROR
		case "CRITICAL":
			config.LogLevel = services.CRITICAL
		}
	}

	return config
}

// SetLogLevel parses and applies a log-level string.
func (c *Config) SetLogLevel(s string) {
	switch s {
	case "DEBUG":
		c.LogLevel = services.DEBUG
	case "INFO":
		c.LogLevel = services.INFO
	case "WARN":
		c.LogLevel = services.WARN
	case "ERROR":
		c.LogLevel = services.ERROR
	case "CRITICAL":
		c.LogLevel = services.CRITICAL
	}
}

// Validate returns an error when required secrets are missing or appear to be
// placeholder values. Call this at server startup and abort if it fails.
func (c *Config) Validate() error {
	if c.EncryptionKey == "" {
		return errors.New("ENCRYPTION_KEY env var is required but not set")
	}
	if c.SecondaryKey == "" {
		return errors.New("SECONDARY_KEY env var is required but not set")
	}
	if c.AuthEnabled && c.APIKey == "" {
		return errors.New("API_KEY env var is required when AUTH_ENABLED=true")
	}
	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
