# Taburtuai C2 — Architecture

## Directory Layout

```
taburtuaiC2/
├── cmd/                        # Binary entry points
│   ├── server/main.go          # Team server (start with: go run ./cmd/server)
│   └── operator/main.go        # Operator CLI (start with: go run ./cmd/operator)
│
├── internal/                   # Private server packages (not importable externally)
│   ├── api/                    # HTTP REST API (Gin handlers, middleware, routes)
│   ├── config/                 # Server configuration (env-based)
│   ├── core/                   # Core server struct, command queue
│   ├── modules/                # Plugin module manager + built-in modules
│   └── services/               # Logger, agent monitor, auth, group manager
│
├── pkg/                        # Shared public packages (importable by agent + server)
│   ├── crypto/                 # AES-256-GCM multi-layer encryption
│   └── types/                  # Shared types: Command, AgentInfo, APIResponse
│
├── agent/                      # Implant source (compiled separately per target)
│   ├── agent.go                # Core loop: checkin, poll, execute
│   ├── commands.go             # Command dispatch and execution
│   ├── evasion.go              # Sandbox/VM/debugger detection
│   ├── persistence.go          # Cross-platform persistence mechanisms
│   └── main.go                 # Agent entry point
│
├── listener/                   # Modular listener framework
│   ├── base.go                 # Listener interface + Config/Stats types
│   ├── manager.go              # Multi-listener orchestration
│   └── http/
│       └── http_listener.go    # HTTP transport implementation
│
├── builder/                    # Payload generation engine
│   ├── generator.go            # Cross-compile agent with config baked in
│   └── profiles/               # OPSEC profiles (default, stealth, aggressive)
│       ├── default.yaml
│       ├── stealth.yaml
│       └── aggressive.yaml
│
├── config/
│   └── taburtuai.yaml          # Server config file
│
├── scripts/
│   └── build/
│       ├── build_agent.sh      # Cross-compile agent binary
│       ├── build_server.sh     # Build server binary
│       └── build_all.sh        # Build everything
│
├── web/
│   ├── templates/              # HTML dashboard templates
│   └── static/                 # CSS, JS, assets
│
├── docs/
│   ├── ROADMAP.md              # Development phases
│   └── ARCHITECTURE.md         # This file
│
├── go.mod                      # Module: github.com/mjopsec/taburtuaiC2
└── go.sum
```

---

## Component Interaction

```
Operator CLI (cmd/operator)
        │  REST API calls
        ▼
Team Server (cmd/server)
        │
        ├── internal/api        ← HTTP routing + handlers
        │       │
        │       ├── internal/core/server.go     ← Server struct
        │       ├── internal/core/command_queue ← Per-agent queues
        │       ├── internal/services/monitor   ← Agent health tracking
        │       ├── internal/services/logger    ← Structured logging
        │       └── pkg/crypto                  ← Encrypt/decrypt traffic
        │
        └── listener/manager    ← (Phase 4+) multi-protocol listeners
                │
                ├── listener/http     ← HTTP transport
                ├── listener/https    ← HTTPS (Phase 4)
                ├── listener/dns      ← DNS tunneling (Phase 4)
                └── listener/smb      ← Named pipe (Phase 4)

Agent (compiled from agent/)
        │  HTTP POST /checkin, GET /poll, POST /result
        ▼
listener/http or listener/https
        │
        ▼
internal/api → internal/core/command_queue → Agent
```

---

## Data Flow: Command Execution

```
1. Operator sends:   POST /api/v1/command  {agent_id, command}
2. Server creates:   types.Command{ID, AgentID, Command, Status:"pending"}
3. Queue adds:       CommandQueue.Add(agentID, cmd)
4. Agent polls:      GET /api/v1/command/{agentID}/next
5. Server returns:   encrypted Command JSON
6. Agent executes:   runs command, captures output
7. Agent submits:    POST /api/v1/command/result  {command_id, exit_code, output}
8. Server stores:    CommandQueue.CompleteCommand(id, result)
9. Operator polls:   GET /api/v1/command/{commandID}/status
```

---

## Encryption Model (Current)

```
Agent → Server:
  payload → gzip compress → random padding → AES-256-GCM(nonce+cipher) → base64 → obfuscation marker prefix

Key derivation:
  primary_key   = SHA256("SpookyOrcaC2AES1")       ← configured at build time
  secondary_key = SHA256("TaburtuaiSecondary")     ← configured at build time
```

**Phase 3 upgrade:** Replace with ECDH (X25519) key exchange. Each session generates fresh keys. Server has no static symmetric key — only its X25519 keypair.

---

## Module Interface

Every post-exploitation module implements:

```go
type ModuleInterface interface {
    Initialize(config map[string]interface{}) error
    Execute(ctx context.Context, params *ModuleParams) (*ModuleResult, error)
    Cleanup() error
    GetInfo() *ModuleInfo
    Validate(params *ModuleParams) error
}
```

Built-in modules: `PortScanner`, `FileSystem`, `CredentialHarvester`

---

## Listener Interface

Every transport implements:

```go
type Listener interface {
    Start(ctx context.Context) error
    Stop() error
    GetConfig() *Config
    GetStatus() Status
    GetStats() *Stats
}
```

The `listener.Manager` runs multiple transports simultaneously. Agent can switch transports if primary is blocked.

---

## OPSEC Profile System

Profiles are baked into the agent at **build time** via `-ldflags -X`:

```
builder.Generator.Build(cfg) → go build -ldflags="-X main.serverURL=... -X main.encKey=..."
```

Per-profile settings:
- Sleep interval + jitter
- Working hours restriction
- Kill date
- Sandbox/VM/debug evasion toggles
- User-Agent rotation pool
- Sleep masking (Phase 3)

---

## Go Module Map

```
github.com/mjopsec/taburtuaiC2/cmd/server     → binary: server
github.com/mjopsec/taburtuaiC2/cmd/operator   → binary: operator CLI
github.com/mjopsec/taburtuaiC2/internal/api   → package api
github.com/mjopsec/taburtuaiC2/internal/core  → package core
github.com/mjopsec/taburtuaiC2/internal/config → package config
github.com/mjopsec/taburtuaiC2/internal/services → package services
github.com/mjopsec/taburtuaiC2/internal/modules  → package modules
github.com/mjopsec/taburtuaiC2/pkg/crypto     → package crypto
github.com/mjopsec/taburtuaiC2/pkg/types      → package types
github.com/mjopsec/taburtuaiC2/listener       → package listener
github.com/mjopsec/taburtuaiC2/listener/http  → package httplistener
github.com/mjopsec/taburtuaiC2/builder        → package builder
```
