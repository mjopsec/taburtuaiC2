package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mjopsec/taburtuaiC2/server/api"
	"github.com/mjopsec/taburtuaiC2/server/config"
	"github.com/mjopsec/taburtuaiC2/server/core"
)

func main() {
	// ASCII banner
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════╗
║                    Taburtuai C2 Server v2.0                 ║
║                        Phase 2 - Modular                    ║
╚══════════════════════════════════════════════════════════════╝
`)

	// Load configuration
	cfg := config.Load()

	// Create server
	server, err := core.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server services
	server.Start()

	// Create router
	router := api.NewRouter(server)
	ginRouter := router.Setup()

	// Start command queue cleanup
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			server.CommandQueue.CleanOldResults(24 * 7 * time.Hour)
		}
	}()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down server...")
		server.Stop()
		os.Exit(0)
	}()

	// Print server info
	fmt.Printf("\nServer Configuration:\n")
	fmt.Printf("  Port: %s\n", cfg.Port)
	fmt.Printf("  Auth: %v\n", cfg.AuthEnabled)
	fmt.Printf("  Logs: %s\n", cfg.LogDir)
	fmt.Printf("\nServer running at http://localhost:%s\n", cfg.Port)

	// Start HTTP server
	if err := ginRouter.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
