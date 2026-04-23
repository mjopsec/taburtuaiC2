package core

import (
	"fmt"
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/config"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/internal/storage"
	"github.com/mjopsec/taburtuaiC2/pkg/crypto"
)

// Server is the main server structure
type Server struct {
	Config       *config.Config
	CryptoMgr    *crypto.Manager
	CommandQueue *CommandQueue
	Monitor      *services.AgentMonitor
	Logger       *services.Logger
	Store        *storage.Store
	TeamHub      *services.TeamHub
}

// NewServer creates a new server instance
func NewServer(cfg *config.Config) (*Server, error) {
	cryptoMgr, err := crypto.NewManager(cfg.EncryptionKey, cfg.SecondaryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize crypto: %v", err)
	}

	logger, err := services.NewLogger(cfg.LogLevel, cfg.LogDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %v", err)
	}

	store, err := storage.New(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	monitor := services.NewAgentMonitor(
		30*time.Second,
		cfg.AgentTimeout,
		10*time.Second,
		store,
	)

	cmdQueue := NewCommandQueue(store)
	teamHub := services.NewTeamHub()

	return &Server{
		Config:       cfg,
		CryptoMgr:    cryptoMgr,
		CommandQueue: cmdQueue,
		Monitor:      monitor,
		Logger:       logger,
		Store:        store,
		TeamHub:      teamHub,
	}, nil
}

// Start starts the server
func (s *Server) Start() {
	s.Monitor.Start()
	s.TeamHub.Start()
	s.Logger.Info(services.SYSTEM, "Server started", "", "", nil)
}

// Stop stops the server
func (s *Server) Stop() {
	s.Monitor.Stop()
	s.Logger.Close()
	if s.Store != nil {
		_ = s.Store.Close()
	}
}
