package config

import (
	"os"
	"time"

	"github.com/mjopsec/taburtuaiC2/server/services"
)

// Config holds server configuration
type Config struct {
	Port          string
	LogLevel      services.LogLevel
	LogDir        string
	EncryptionKey string
	SecondaryKey  string
	AuthEnabled   bool
	APIKey        string
	MaxAgents     int
	AgentTimeout  time.Duration
}

// Load loads configuration from environment
func Load() *Config {
	config := &Config{
		Port:          getEnvOrDefault("PORT", "8080"),
		LogLevel:      services.INFO,
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

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
