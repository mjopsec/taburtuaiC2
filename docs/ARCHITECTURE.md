# Taburtuai C2 — Architecture

## Directory Layout

```
taburtuaiC2/
├── cmd/                        # Binary entry points (Go convention)
│   ├── server/                 # Team server binary
│   ├── operator/               # Operator CLI binary
│   ├── agent/                  # Implant binary (compiled per target)
│   ├── generate/               # Implant builder & delivery tool
│   ├── stager/                 # Stager binary
│   ├── sign/                   # Authenticode signing helper
│   ├── strenc/                 # String encryption helper
│   └── listener/               # SMB named-pipe → HTTPS C2 relay binary
│
├── implant/                    # Implant technique packages (importable)
│   ├── syscall/                # Hell's Gate, Win32 API procs, NT syscall wrappers
│   ├── evasion/                # AMSI, ETW, HWBP, unhook, sleep masking
│   ├── inject/                 # CRT, APC, hollow, hijack, stomp, mapinject, PPID
│   ├── creds/                  # LSASS, SAM, browser creds, clipboard
│   ├── lateral/                # WMI, WinRM, DCOM, schtask, service
│   ├── persist/                # Registry, schtask, service, startup folder
│   ├── recon/                  # Screenshot, keylog, netscan, ARP
│   ├── pivot/                  # SOCKS5, port forwarding
│   └── exec/                   # Execution, BOF, .NET, PS runspace, LOLBins
│
├── internal/                   # Private server packages
│   ├── api/                    # HTTP REST API handlers + routes
│   ├── config/                 # Server configuration
│   ├── core/                   # Server struct, command queue, port forward manager
│   ├── services/               # Logger, monitor, auth, team server
│   └── storage/                # SQLite persistence layer
│
├── pkg/                        # Shared public packages
│   ├── crypto/                 # AES-256-GCM + ECDH session key
│   ├── types/                  # Shared types: Command, AgentInfo, APIResponse
│   ├── profiles/               # Malleable C2 HTTP profiles
│   ├── tlsutil/                # TLS cert helpers
│   ├── transport/              # Agent-side covert transports (DoH, ICMP, SMB, WS, DNS)
│   └── strenc/                 # String encryption runtime
│
├── listener/                   # Server-side protocol listeners
│   ├── base.go                 # Listener interface + Config/Stats
│   ├── manager.go              # Multi-listener orchestration
│   ├── http/                   # HTTP listener
│   ├── https/                  # HTTPS listener
│   ├── ws/                     # WebSocket listener
│   └── dns/                    # DNS authoritative listener
│
├── builder/                    # Payload generation engine (profile-based)
│   ├── generator.go
│   └── profiles/               # OPSEC YAML profiles
│
├── config/
│   └── taburtuai.yaml          # Server config
│
├── web/                        # Web UI (Vue 3 + TypeScript)
│   └── src/
│
├── wiki/                       # Operator documentation (25 pages)
├── docs/                       # Architecture + Roadmap only
├── tools/                      # Non-Go scripts and generated artifacts
└── go.mod                      # Module: github.com/mjopsec/taburtuaiC2
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
        │       ├── internal/core/server.go       ← Server struct
        │       ├── internal/core/command_queue   ← Per-agent queues (SQLite)
        │       ├── internal/services/monitor     ← Agent health tracking
        │       ├── internal/services/logger      ← Structured logging
        │       └── pkg/crypto                    ← Encrypt/decrypt traffic
        │
        └── listener/manager    ← multi-protocol listeners
                │
                ├── listener/http     ← HTTP transport
                ├── listener/https    ← HTTPS + TLS
                ├── listener/ws       ← WebSocket
                └── listener/dns      ← DNS authoritative

Agent (compiled from cmd/agent/)
        │  imports implant/* packages for technique execution
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
6. Agent executes:   runs command via implant/* package
7. Agent submits:    POST /api/v1/command/result  {command_id, exit_code, output}
8. Server stores:    CommandQueue.CompleteCommand(id, result)
9. Operator polls:   GET /api/v1/command/{commandID}/status
```

---

## Implant Package Dependency Graph

```
implant/syscall/          ← no implant dependencies (only x/sys/windows)
        ↑
implant/evasion/          ← depends on syscall
implant/inject/           ← depends on syscall
implant/creds/            ← depends on syscall
        ↑
implant/recon/            ← minimal syscall usage (GDI for screenshot)
implant/lateral/          ← no syscall dependency (uses exec.Command)
implant/persist/          ← no syscall dependency
implant/exec/             ← mixed (BOF/peloader use syscall)
implant/pivot/            ← no syscall dependency (network only)
        ↑
cmd/agent/                ← imports all implant/* packages
```

---

## Encryption Model

```
Agent → Server:
  payload → gzip compress → random padding → AES-256-GCM(nonce+cipher) → base64 → marker

ECDH session establishment:
  1. Agent generates ephemeral X25519 keypair
  2. Agent sends pubkey in checkin payload
  3. Server responds with its pubkey
  4. Both derive shared session key (X25519 DH + HKDF)
  5. All subsequent traffic uses session key, not static key
```

---

## Go Module Map

```
github.com/mjopsec/taburtuaiC2/cmd/server       → binary: server
github.com/mjopsec/taburtuaiC2/cmd/operator     → binary: operator CLI
github.com/mjopsec/taburtuaiC2/cmd/agent        → binary: agent implant
github.com/mjopsec/taburtuaiC2/cmd/generate     → binary: implant builder
github.com/mjopsec/taburtuaiC2/cmd/stager       → binary: stager
github.com/mjopsec/taburtuaiC2/cmd/sign         → binary: Authenticode signing helper
github.com/mjopsec/taburtuaiC2/cmd/strenc       → binary: string encryption helper
github.com/mjopsec/taburtuaiC2/cmd/listener     → binary: SMB relay (named pipe → HTTPS C2)
github.com/mjopsec/taburtuaiC2/implant/syscall  → package winsyscall
github.com/mjopsec/taburtuaiC2/implant/evasion  → package evasion
github.com/mjopsec/taburtuaiC2/implant/inject   → package inject
github.com/mjopsec/taburtuaiC2/implant/creds    → package creds
github.com/mjopsec/taburtuaiC2/implant/lateral  → package lateral
github.com/mjopsec/taburtuaiC2/implant/persist  → package persist
github.com/mjopsec/taburtuaiC2/implant/recon    → package recon
github.com/mjopsec/taburtuaiC2/implant/pivot    → package pivot
github.com/mjopsec/taburtuaiC2/implant/exec     → package exec
github.com/mjopsec/taburtuaiC2/internal/api     → package api
github.com/mjopsec/taburtuaiC2/internal/core    → package core
github.com/mjopsec/taburtuaiC2/internal/storage → package storage
github.com/mjopsec/taburtuaiC2/pkg/crypto       → package crypto
github.com/mjopsec/taburtuaiC2/pkg/types        → package types
github.com/mjopsec/taburtuaiC2/listener         → package listener
```
