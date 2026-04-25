package httpslistener

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/listener"
	"github.com/mjopsec/taburtuaiC2/pkg/tlsutil"
)

// HTTPSListener handles TLS-encrypted agent communication.
type HTTPSListener struct {
	config  *listener.Config
	handler listener.Handler
	server  *http.Server
	tlsCert tls.Certificate
	stats   *listener.Stats
	status  listener.Status
	mu      sync.RWMutex

	bytesIn    int64
	bytesOut   int64
	totalReqs  int64
	errorCount int64
}

// New creates an HTTPS listener. certPEM/keyPEM may be nil; in that case a
// self-signed certificate is generated automatically using the listener host.
func New(cfg *listener.Config, handler listener.Handler, certPEM, keyPEM []byte) (*HTTPSListener, error) {
	var cert tls.Certificate
	var err error

	if len(certPEM) > 0 && len(keyPEM) > 0 {
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
	} else {
		hosts := []string{cfg.Host}
		if cfg.Host == "" || cfg.Host == "0.0.0.0" {
			hosts = []string{"127.0.0.1", "localhost"}
		}
		cert, _, _, err = tlsutil.LoadOrGenerate("", "", hosts)
	}
	if err != nil {
		return nil, fmt.Errorf("https listener tls: %w", err)
	}

	return &HTTPSListener{
		config:  cfg,
		handler: handler,
		tlsCert: cert,
		stats: &listener.Stats{
			ListenerID: cfg.ID,
			StartedAt:  time.Now(),
		},
		status: listener.StatusStopped,
	}, nil
}

// Start begins accepting HTTPS connections.
func (h *HTTPSListener) Start(ctx context.Context) error {
	h.mu.Lock()
	h.status = listener.StatusStarting
	h.mu.Unlock()

	mux := http.NewServeMux()
	h.registerRoutes(mux)

	h.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", h.config.Host, h.config.Port),
		Handler:      mux,
		TLSConfig:    tlsutil.ServerTLSConfig(h.tlsCert),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	h.mu.Lock()
	h.status = listener.StatusRunning
	h.stats.StartedAt = time.Now()
	h.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = h.Stop()
	}()

	// Cert is already in server.TLSConfig — pass empty strings.
	if err := h.server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		h.mu.Lock()
		h.status = listener.StatusError
		h.mu.Unlock()
		return fmt.Errorf("https listener: %w", err)
	}
	return nil
}

// Stop shuts down the HTTPS listener gracefully.
func (h *HTTPSListener) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.server.Shutdown(ctx); err != nil {
			return err
		}
	}
	h.status = listener.StatusStopped
	return nil
}

func (h *HTTPSListener) GetConfig() *listener.Config { return h.config }
func (h *HTTPSListener) GetStatus() listener.Status  { return h.status }
func (h *HTTPSListener) GetStats() *listener.Stats {
	h.stats.BytesIn = atomic.LoadInt64(&h.bytesIn)
	h.stats.BytesOut = atomic.LoadInt64(&h.bytesOut)
	h.stats.Errors = atomic.LoadInt64(&h.errorCount)
	return h.stats
}

func (h *HTTPSListener) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/checkin", h.handleCheckin)
	mux.HandleFunc("/poll", h.handlePoll)
	mux.HandleFunc("/result", h.handleResult)
}

func (h *HTTPSListener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	atomic.AddInt64(&h.totalReqs, 1)

	var data listener.CheckinData
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1*1024*1024)).Decode(&data); err != nil {
		atomic.AddInt64(&h.errorCount, 1)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	atomic.AddInt64(&h.bytesIn, r.ContentLength)

	resp, err := h.handler.OnCheckin(&data)
	if err != nil {
		atomic.AddInt64(&h.errorCount, 1)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	h.writeJSON(w, resp)
}

func (h *HTTPSListener) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	atomic.AddInt64(&h.totalReqs, 1)

	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		http.NotFound(w, r)
		return
	}

	resp, err := h.handler.OnPoll(agentID)
	if err != nil || resp == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.writeJSON(w, resp)
}

func (h *HTTPSListener) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	atomic.AddInt64(&h.totalReqs, 1)

	agentID := r.Header.Get("X-Agent-ID")
	var body []byte
	var buf [4096]byte
	for {
		n, err := r.Body.Read(buf[:])
		body = append(body, buf[:n]...)
		if err != nil || len(body) > 100*1024*1024 {
			break
		}
	}
	atomic.AddInt64(&h.bytesIn, int64(len(body)))

	if err := h.handler.OnResult(agentID, body); err != nil {
		atomic.AddInt64(&h.errorCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *HTTPSListener) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	encoded, _ := json.Marshal(data)
	atomic.AddInt64(&h.bytesOut, int64(len(encoded)))
	_, _ = w.Write(encoded)
}
