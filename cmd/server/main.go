package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/api"
	"github.com/mjopsec/taburtuaiC2/internal/config"
	"github.com/mjopsec/taburtuaiC2/internal/core"
)

const version = "2.0.0"

// ANSI helpers
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiCyan   = "\033[36m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiWhite  = "\033[97m"
	ansiGreen  = "\033[32m"
)

func main() {
	// Suppress all Gin debug output — must be set before any gin code runs.
	gin.SetMode(gin.ReleaseMode)

	// ── CLI flags (override env vars) ────────────────────────────────────────
	port     := flag.String("port",      "", "listening port (default: 8080 / $PORT)")
	host     := flag.String("host",      "", "bind address (default: 0.0.0.0 / $HOST)")
	logLevel := flag.String("log-level", "", "log level: DEBUG|INFO|WARN|ERROR (default: INFO)")
	logDir   := flag.String("log-dir",   "", "log output directory (default: ./logs)")
	dbPath   := flag.String("db",        "", "SQLite database path (default: ./data/taburtuai.db)")
	apiKey   := flag.String("api-key",   "", "API key for operator auth")
	authOn   := flag.Bool("auth",        false, "enable API key authentication")
	profile  := flag.String("profile",   "", "malleable C2 profile: default|office365|cdn|jquery|slack|ocsp")
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
	if *profile  != "" { cfg.Profile  = *profile  }

	// ── Banner ────────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + ansiCyan  + "  ▀█▀ ▄▀█ █▄▄ █ █ █▀█" + ansiReset)
	fmt.Println(ansiBold + ansiCyan  + "  ░█░ █▀█ █▄█ █▄█ █▀▄" + ansiReset)
	fmt.Println(ansiBold + ansiRed   + "  ▀█▀ █ █ ▄▀█ █  █▀▀ ▀▀█" + ansiReset)
	fmt.Println(ansiBold + ansiRed   + "  ░█░ █▄█ █▀█ █  █▄▄ ▄▄▀" + ansiReset)
	fmt.Println()
	fmt.Printf("  %sauthor%s  %s%smjopsec%s   %sversion%s  %s%s%s\n",
		ansiDim, ansiReset,
		ansiWhite, ansiBold, ansiReset,
		ansiDim, ansiReset,
		ansiYellow, ansiBold+version, ansiReset)
	fmt.Println()

	// ── Create & start server ─────────────────────────────────────────────────
	server, err := core.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	server.Start()

	router    := api.NewRouter(server)
	ginRouter := router.Setup()
	router.RegisterProfileAliases(ginRouter, cfg.Profile)

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
		fmt.Println()
		fmt.Println("  " + ansiDim + "shutting down …" + ansiReset)
		server.Stop()
		os.Exit(0)
	}()

	// ── Config summary box ────────────────────────────────────────────────────
	bind := cfg.Host
	if bind == "" { bind = "0.0.0.0" }
	profileName := cfg.Profile
	if profileName == "" { profileName = "default" }
	authStatus := ansiDim + "disabled" + ansiReset
	if cfg.AuthEnabled {
		authStatus = ansiGreen + ansiBold + "enabled" + ansiReset
	}

	sep := "  " + ansiDim + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + ansiReset
	row := func(label, value string) {
		fmt.Printf("   %s%-10s%s %s\n", ansiDim, label, ansiReset, value)
	}

	fmt.Println(sep)
	row("bind",    ansiWhite+ansiBold+bind+":"+cfg.Port+ansiReset)
	row("auth",    authStatus)
	row("profile", profileName)
	row("logs",    cfg.LogDir)
	row("db",      cfg.DBPath)
	fmt.Println(sep)
	fmt.Println()

	addr := ":" + cfg.Port
	if cfg.Host != "" {
		addr = cfg.Host + ":" + cfg.Port
	}

	fmt.Printf("  %s%s[✓]%s  ready  ·  listening on %s%s%s:%s%s\n\n",
		ansiGreen, ansiBold, ansiReset,
		ansiWhite, ansiBold, bind, cfg.Port, ansiReset)

	// Use http.ListenAndServe directly so Gin doesn't print its own listen line.
	srv := &http.Server{
		Addr:    addr,
		Handler: ginRouter,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
