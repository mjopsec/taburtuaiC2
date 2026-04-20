package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mjopsec/taburtuaiC2/internal/api"
	"github.com/mjopsec/taburtuaiC2/internal/config"
	"github.com/mjopsec/taburtuaiC2/internal/core"
)

const version = "2.0.0"

func main() {
	// ── CLI flags (override env vars) ────────────────────────────────────────
	port     := flag.String("port",      "", "listening port (default: 8080 / $PORT)")
	host     := flag.String("host",      "", "bind address (default: 0.0.0.0 / $HOST)")
	logLevel := flag.String("log-level", "", "log level: DEBUG|INFO|WARN|ERROR (default: INFO)")
	logDir   := flag.String("log-dir",   "", "log output directory (default: ./logs)")
	dbPath   := flag.String("db",        "", "SQLite database path (default: ./data/taburtuai.db)")
	apiKey   := flag.String("api-key",   "", "API key for operator auth")
	authOn   := flag.Bool("auth",        false, "enable API key authentication")
	flag.Parse()

	// ── Load base config from env ─────────────────────────────────────────────
	cfg := config.Load()

	// ── Apply flag overrides ──────────────────────────────────────────────────
	if *port     != "" { cfg.Port     = *port     }
	if *host     != "" { cfg.Host     = *host     }
	if *logLevel != "" { cfg.SetLogLevel(*logLevel) }
	if *logDir   != "" { cfg.LogDir   = *logDir   }
	if *dbPath   != "" { cfg.DBPath   = *dbPath   }
	if *apiKey   != "" { cfg.APIKey   = *apiKey   }
	if *authOn             { cfg.AuthEnabled = true }

	// ── Banner ────────────────────────────────────────────────────────────────
	c   := "\033[36m"  // cyan
	r   := "\033[31m"  // red
	y   := "\033[33m"  // yellow
	w   := "\033[97m"  // white
	d   := "\033[2m"   // dim
	b   := "\033[1m"   // bold
	rst := "\033[0m"

	fmt.Println()
	fmt.Println(b + c + "  ▀█▀ ▄▀█ █▄▄ █ █ █▀█" + rst)
	fmt.Println(b + c + "  ░█░ █▀█ █▄█ █▄█ █▀▄" + rst)
	fmt.Println(b + r + "  ▀█▀ █ █ ▄▀█ █  █▀▀ ▀▀█" + rst)
	fmt.Println(b + r + "  ░█░ █▄█ █▀█ █  █▄▄ ▄▄▀" + rst)
	fmt.Println()
	fmt.Println("  " + d + "author" + rst + "  " + w + b + "mjopsec" + rst +
		"   " + d + "version" + rst + "  " + y + b + version + rst)
	fmt.Println()

	// ── Create & start server ─────────────────────────────────────────────────
	server, err := core.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	server.Start()

	router    := api.NewRouter(server)
	ginRouter := router.Setup()

	// Periodic old-result cleanup
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			server.CommandQueue.CleanOldResults(24 * 7 * time.Hour)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		server.Stop()
		os.Exit(0)
	}()

	// ── Print config summary ──────────────────────────────────────────────────
	bind := cfg.Host
	if bind == "" { bind = "0.0.0.0" }
	fmt.Printf("  %saddr%s    %s%s:%s%s\n",  d, rst, w+b, bind, cfg.Port, rst)
	fmt.Printf("  %sauth%s    %v\n",          d, rst, cfg.AuthEnabled)
	fmt.Printf("  %slogs%s    %s\n",          d, rst, cfg.LogDir)
	fmt.Printf("  %sdb%s      %s\n",          d, rst, cfg.DBPath)
	fmt.Println()

	addr := ":" + cfg.Port
	if cfg.Host != "" {
		addr = cfg.Host + ":" + cfg.Port
	}
	if err := ginRouter.Run(addr); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
