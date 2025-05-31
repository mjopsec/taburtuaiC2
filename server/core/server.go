package core

import (
	"fmt"
	"time"

	"github.com/mjopsec/taburtuaiC2/server/config"
	"github.com/mjopsec/taburtuaiC2/server/services"
	"github.com/mjopsec/taburtuaiC2/shared/crypto"
)

// Server is the main server structure
type Server struct {
	Config       *config.Config
	CryptoMgr    *crypto.Manager
	CommandQueue *CommandQueue
	Monitor      *services.AgentMonitor
	Logger       *services.Logger
}

// NewServer creates a new server instance
func NewServer(cfg *config.Config) (*Server, error) {
	// Initialize crypto manager
	cryptoMgr, err := crypto.NewManager(cfg.EncryptionKey, cfg.SecondaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize crypto: %v", err)
	}

	// Initialize logger
	logger, err := services.NewLogger(cfg.LogLevel, cfg.LogDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %v", err)
	}

	// Initialize monitor with proper parameters
	monitor := services.NewAgentMonitor(
		30*time.Second,   // heartbeatWindow
		cfg.AgentTimeout, // offlineWindow (use from config)
		10*time.Second,   // checkInterval
	)

	// Initialize command queue
	cmdQueue := NewCommandQueue()

	return &Server{
		Config:       cfg,
		CryptoMgr:    cryptoMgr,
		CommandQueue: cmdQueue,
		Monitor:      monitor,
		Logger:       logger,
	}, nil
}

// Start starts the server
func (s *Server) Start() {
	s.Monitor.Start()
	s.Logger.Info(services.SYSTEM, "Server started", "", "", nil)
}

// Stop stops the server
func (s *Server) Stop() {
	s.Monitor.Stop()
	s.Logger.Close()
}
