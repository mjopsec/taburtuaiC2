package core

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// fwdSession is one live port-forward tunnel.
// The operator connects to a local TCP port; bytes are relayed through
// the C2 HTTP channel to the agent, which forwards to the internal target.
type fwdSession struct {
	ID        string
	AgentID   string
	Target    string // rhost:rport the agent should dial
	LocalPort int

	toAgent   chan []byte // operator→agent
	fromAgent chan []byte // agent→operator
	tcpConn   net.Conn   // operator's TCP connection (nil until connected)
	ln        net.Listener
	done      chan struct{}
	once      sync.Once
}

// close tears down the session cleanly.
func (s *fwdSession) close() {
	s.once.Do(func() {
		close(s.done)
		if s.ln != nil {
			s.ln.Close()
		}
		if s.tcpConn != nil {
			s.tcpConn.Close()
		}
	})
}

// PortFwdManager manages active port-forward sessions.
type PortFwdManager struct {
	mu       sync.RWMutex
	sessions map[string]*fwdSession
	total    int64
}

// NewPortFwdManager returns an initialised manager.
func NewPortFwdManager() *PortFwdManager {
	return &PortFwdManager{sessions: make(map[string]*fwdSession)}
}

// Create opens a local TCP listener on localPort (0 = OS-assigned) and
// registers the session. Returns the session so the caller can embed the
// ID in the queued command.
func (m *PortFwdManager) Create(agentID, target string, localPort int) (*fwdSession, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("portfwd listen %s: %w", addr, err)
	}

	id := fmt.Sprintf("fwd-%d", atomic.AddInt64(&m.total, 1))
	sess := &fwdSession{
		ID:        id,
		AgentID:   agentID,
		Target:    target,
		LocalPort: ln.Addr().(*net.TCPAddr).Port,
		toAgent:   make(chan []byte, 64),
		fromAgent: make(chan []byte, 64),
		ln:        ln,
		done:      make(chan struct{}),
	}

	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()

	go m.acceptLoop(sess)
	return sess, nil
}

// Get returns a session by ID.
func (m *PortFwdManager) Get(id string) (*fwdSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Delete stops and removes a session.
func (m *PortFwdManager) Delete(id string) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if ok {
		sess.close()
	}
}

// List returns a snapshot of all active sessions.
func (m *PortFwdManager) List() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]map[string]interface{}, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, map[string]interface{}{
			"id":         s.ID,
			"agent_id":   s.AgentID,
			"target":     s.Target,
			"local_port": s.LocalPort,
		})
	}
	return out
}

// acceptLoop waits for one operator TCP connection on the listener, then
// starts the operator-side relay goroutines. Only one connection per session.
func (m *PortFwdManager) acceptLoop(sess *fwdSession) {
	conn, err := sess.ln.Accept()
	if err != nil {
		return
	}
	sess.ln.Close() // only one connection per session
	sess.tcpConn = conn

	// Operator → agent: read TCP, push to channel
	go func() {
		defer sess.close()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				select {
				case sess.toAgent <- chunk:
				case <-sess.done:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Agent → operator: drain fromAgent channel, write to TCP
	go func() {
		defer sess.close()
		for {
			select {
			case chunk := <-sess.fromAgent:
				if _, err := conn.Write(chunk); err != nil {
					return
				}
			case <-sess.done:
				return
			}
		}
	}()
}

// PullForAgent blocks up to timeout for queued operator→agent data.
// Returns nil if no data arrives within the timeout (agent should re-poll).
func (m *PortFwdManager) PullForAgent(sessID string, timeout time.Duration) ([]byte, error) {
	sess, ok := m.Get(sessID)
	if !ok {
		return nil, fmt.Errorf("unknown session %s", sessID)
	}
	select {
	case chunk := <-sess.toAgent:
		return chunk, nil
	case <-sess.done:
		return nil, io.EOF
	case <-time.After(timeout):
		return nil, nil
	}
}

// PushFromAgent enqueues agent→operator data.
func (m *PortFwdManager) PushFromAgent(sessID string, data []byte) error {
	sess, ok := m.Get(sessID)
	if !ok {
		return fmt.Errorf("unknown session %s", sessID)
	}
	select {
	case sess.fromAgent <- data:
		return nil
	case <-sess.done:
		return io.EOF
	case <-time.After(5 * time.Second):
		return fmt.Errorf("fromAgent buffer full")
	}
}
