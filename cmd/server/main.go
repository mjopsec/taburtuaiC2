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

	"context"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/api"
	"github.com/mjopsec/taburtuaiC2/internal/config"
	"github.com/mjopsec/taburtuaiC2/internal/core"
	"github.com/mjopsec/taburtuaiC2/internal/listener"
	dnslistener "github.com/mjopsec/taburtuaiC2/internal/listener/dns"
	wslistener "github.com/mjopsec/taburtuaiC2/internal/listener/ws"
	"github.com/mjopsec/taburtuaiC2/pkg/tlsutil"
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
	tlsOn    := flag.Bool("tls",         false, "enable HTTPS/TLS listener")
	tlsCert  := flag.String("tls-cert",  "", "TLS certificate PEM file (auto-generated if omitted)")
	tlsKey   := flag.String("tls-key",   "", "TLS private key PEM file (auto-generated if omitted)")
	tlsPort  := flag.String("tls-port",  "", "HTTPS listen port (default: 8443 / $TLS_PORT)")
	wsOn     := flag.Bool("ws",          false, "enable WebSocket listener")
	wsPort   := flag.String("ws-port",   "", "WebSocket listen port (default: 8081 / $WS_PORT)")
	adminKey  := flag.String("admin-key",  "", "secret key to register operators with admin role ($ADMIN_KEY)")
	dnsOn     := flag.Bool("dns",          false, "enable DNS authoritative listener")
	dnsPort   := flag.String("dns-port",   "", "DNS listen port UDP (default: 5353 / $DNS_PORT)")
	dnsDomain := flag.String("dns-domain", "", "authoritative zone, e.g. c2.example.com ($DNS_DOMAIN)")
	flag.Parse()

	// ── Load base config from env ─────────────────────────────────────────────
	cfg := config.Load()

	// ── Apply flag overrides ──────────────────────────────────────────────────
	if *port     != "" { cfg.Port        = *port     }
	if *host     != "" { cfg.Host        = *host     }
	if *logLevel != "" { cfg.SetLogLevel(*logLevel)  }
	if *logDir   != "" { cfg.LogDir      = *logDir   }
	if *dbPath   != "" { cfg.DBPath      = *dbPath   }
	if *apiKey   != "" { cfg.APIKey      = *apiKey   }
	if *authOn          { cfg.AuthEnabled = true      }
	if *profile  != "" { cfg.Profile     = *profile  }
	if *tlsOn           { cfg.TLSEnabled  = true      }
	if *tlsCert  != "" { cfg.TLSCertFile = *tlsCert  }
	if *tlsKey   != "" { cfg.TLSKeyFile  = *tlsKey   }
	if *tlsPort  != "" { cfg.TLSPort     = *tlsPort  }
	if *wsOn            { cfg.WSEnabled   = true      }
	if *wsPort   != "" { cfg.WSPort      = *wsPort   }
	if *adminKey   != "" { cfg.AdminKey   = *adminKey  }
	if *dnsOn             { cfg.DNSEnabled = true       }
	if *dnsPort    != "" { cfg.DNSPort    = *dnsPort   }
	if *dnsDomain  != "" { cfg.DNSDomain  = *dnsDomain }

	// ── Validate required secrets ─────────────────────────────────────────────
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] Configuration error: %v\n  Set the required environment variables and restart.", err)
	}

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
	tlsStatus := ansiDim + "disabled" + ansiReset
	if cfg.TLSEnabled {
		tlsStatus = ansiGreen + ansiBold + "enabled" + ansiReset
	}
	wsStatus := ansiDim + "disabled" + ansiReset
	if cfg.WSEnabled {
		wsStatus = ansiGreen + ansiBold + "enabled  :" + cfg.WSPort + ansiReset
	}
	dnsStatus := ansiDim + "disabled" + ansiReset
	if cfg.DNSEnabled {
		zone := cfg.DNSDomain
		if zone == "" {
			zone = "no domain set"
		}
		dnsStatus = ansiGreen + ansiBold + "enabled  :" + cfg.DNSPort + "  zone=" + zone + ansiReset
	}

	sep := "  " + ansiDim + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + ansiReset
	row := func(label, value string) {
		fmt.Printf("   %s%-10s%s %s\n", ansiDim, label, ansiReset, value)
	}

	fmt.Println(sep)
	row("bind",    ansiWhite+ansiBold+bind+":"+cfg.Port+ansiReset)
	row("auth",    authStatus)
	row("tls",     tlsStatus)
	row("ws",      wsStatus)
	row("dns",     dnsStatus)
	row("profile", profileName)
	row("logs",    cfg.LogDir)
	row("db",      cfg.DBPath)
	fmt.Println(sep)
	fmt.Println()

	addr := ":" + cfg.Port
	if cfg.Host != "" {
		addr = cfg.Host + ":" + cfg.Port
	}

	// ── Start optional listeners ──────────────────────────────────────────────
	if cfg.WSEnabled {
		go startWS(cfg, server)
	}
	if cfg.DNSEnabled {
		go startDNS(cfg, server)
	}

	// ── Start HTTP / HTTPS listener ───────────────────────────────────────────
	if cfg.TLSEnabled {
		startTLS(cfg, addr, ginRouter)
	} else {
		fmt.Printf("  %s%s[!]%s  %sWARNING: TLS disabled — beacon traffic is unencrypted.%s\n",
			ansiYellow, ansiBold, ansiReset, ansiYellow, ansiReset)
		fmt.Printf("       Use --tls (or TLS_ENABLED=true) for production deployments.\n\n")
		fmt.Printf("  %s%s[✓]%s  ready  ·  listening on %s%s%s:%s%s\n\n",
			ansiGreen, ansiBold, ansiReset,
			ansiWhite, ansiBold, bind, cfg.Port, ansiReset)

		srv := &http.Server{Addr: addr, Handler: ginRouter}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}
}

// startTLS launches the HTTPS server and (optionally) an HTTP→HTTPS redirect
// on the plain-text port.
func startTLS(cfg *config.Config, httpAddr string, handler http.Handler) {
	bind := cfg.Host
	if bind == "" {
		bind = "0.0.0.0"
	}

	// Determine hosts for the self-signed cert SAN list.
	certHosts := []string{bind}
	if bind == "0.0.0.0" {
		certHosts = []string{"127.0.0.1", "localhost"}
	}

	// Load existing cert files, or generate a new self-signed cert.
	tlsCert, _, _, err := tlsutil.LoadOrGenerate(cfg.TLSCertFile, cfg.TLSKeyFile, certHosts)
	if err != nil {
		log.Fatalf("TLS certificate error: %v", err)
	}

	tlsAddr := ":" + cfg.TLSPort
	if cfg.Host != "" {
		tlsAddr = cfg.Host + ":" + cfg.TLSPort
	}

	srv := &http.Server{
		Addr:         tlsAddr,
		Handler:      handler,
		TLSConfig:    tlsutil.ServerTLSConfig(tlsCert),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// HTTP → HTTPS redirect on the plain port.
	go func() {
		redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host
			// Replace port in Host header with TLS port if present.
			if cfg.TLSPort != "443" {
				host := r.Host
				// Strip existing port if any.
				for i := len(host) - 1; i >= 0; i-- {
					if host[i] == ':' {
						host = host[:i]
						break
					}
				}
				target = "https://" + host + ":" + cfg.TLSPort
			}
			http.Redirect(w, r, target+r.RequestURI, http.StatusMovedPermanently)
		})
		redirectSrv := &http.Server{
			Addr:    httpAddr,
			Handler: redirectHandler,
		}
		_ = redirectSrv.ListenAndServe()
	}()

	certSource := "auto-generated"
	if cfg.TLSCertFile != "" {
		certSource = cfg.TLSCertFile
	}

	fmt.Printf("  %s%s[✓]%s  ready  ·  HTTPS on %s%s%s:%s%s  (cert: %s)\n",
		ansiGreen, ansiBold, ansiReset,
		ansiWhite, ansiBold, bind, cfg.TLSPort, ansiReset,
		certSource)
	fmt.Printf("       HTTP  :%s → redirect to HTTPS\n\n", cfg.Port)

	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("https server error: %v", err)
	}
}

// startWS launches the WebSocket listener in the calling goroutine.
func startWS(cfg *config.Config, server *core.Server) {
	port, err := strconv.Atoi(cfg.WSPort)
	if err != nil {
		log.Fatalf("invalid ws port %q: %v", cfg.WSPort, err)
	}

	lCfg := &listener.Config{
		ID:   "ws-default",
		Name: "WebSocket",
		Type: listener.TypeWebSocket,
		Host: cfg.Host,
		Port: port,
	}

	handler := core.NewListenerHandler(server)
	wsl := wslistener.New(lCfg, handler)

	bind := cfg.Host
	if bind == "" {
		bind = "0.0.0.0"
	}
	fmt.Printf("  %s%s[✓]%s  WebSocket listener  ·  ws://%s%s%s:%s%s/ws\n\n",
		ansiGreen, ansiBold, ansiReset,
		ansiWhite, ansiBold, bind, cfg.WSPort, ansiReset)

	if err := wsl.Start(context.Background()); err != nil {
		log.Printf("WebSocket listener error: %v", err)
	}
}

// startDNS launches the authoritative DNS listener in the calling goroutine.
func startDNS(cfg *config.Config, server *core.Server) {
	if cfg.DNSDomain == "" {
		log.Printf("DNS listener: DNS_DOMAIN not set — skipping")
		return
	}
	port, err := strconv.Atoi(cfg.DNSPort)
	if err != nil {
		log.Fatalf("invalid dns port %q: %v", cfg.DNSPort, err)
	}

	lCfg := &listener.Config{
		ID:   "dns-default",
		Name: "DNS",
		Type: listener.TypeDNS,
		Host: cfg.Host,
		Port: port,
	}

	handler := core.NewListenerHandler(server)
	dl := dnslistener.New(lCfg, handler, cfg.DNSDomain)

	bind := cfg.Host
	if bind == "" {
		bind = "0.0.0.0"
	}
	fmt.Printf("  %s%s[✓]%s  DNS listener  ·  udp://%s%s%s:%s%s  zone=%s\n\n",
		ansiGreen, ansiBold, ansiReset,
		ansiWhite, ansiBold, bind, cfg.DNSPort, ansiReset,
		cfg.DNSDomain)

	if err := dl.Start(context.Background()); err != nil {
		log.Printf("DNS listener error: %v", err)
	}
}
