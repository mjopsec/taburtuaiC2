# taburtuaiC2

A modular, OPSEC-minded Command & Control framework written in Go.
Built for authorized red team engagements only.

---

## Structure

```
taburtuaiC2/
├── cmd/
│   ├── server/        # Team server entry point
│   └── operator/      # Operator CLI entry point
├── internal/
│   ├── api/           # HTTP handlers, middleware, routing
│   ├── config/        # Server configuration (env-based)
│   ├── core/          # Server struct, command queue
│   ├── modules/       # Plugin module manager
│   └── services/      # Logger, agent monitor, auth
├── pkg/
│   ├── crypto/        # AES-256-GCM encryption
│   └── types/         # Shared types (Command, AgentInfo, etc.)
├── agent/             # Implant source (compiled per target)
├── listener/          # Modular transport listeners
├── builder/           # Payload generator + OPSEC profiles
├── config/            # taburtuai.yaml
├── scripts/build/     # Build scripts
├── web/               # Dashboard templates
└── docs/              # ROADMAP.md, ARCHITECTURE.md
```

---

## Quick Start

**Run the server**
```bash
go run ./cmd/server
```

**Run the operator CLI**
```bash
go run ./cmd/operator --server http://localhost:8080 --api-key your-key
```

**Build agent (Linux x64)**
```bash
bash scripts/build/build_agent.sh \
  --server http://your-c2:8080 \
  --key YourEncKey \
  --os linux --arch amd64
```

**Build agent (Windows x64, stealth)**
```bash
bash scripts/build/build_agent.sh \
  --server http://your-c2:8080 \
  --key YourEncKey \
  --os windows --arch amd64 \
  --stealth --compress
```

---

## Configuration

Server reads from environment variables (with defaults):

| Variable         | Default                    | Description             |
|------------------|----------------------------|-------------------------|
| `PORT`           | `8080`                     | Listening port          |
| `ENCRYPTION_KEY` | *(set this)*               | Primary AES key         |
| `SECONDARY_KEY`  | *(set this)*               | Secondary AES key       |
| `AUTH_ENABLED`   | `false`                    | Require API key on all requests |
| `API_KEY`        | *(set this)*               | Bearer token for operators |
| `LOG_DIR`        | `./logs`                   | Log output directory    |
| `LOG_LEVEL`      | `INFO`                     | DEBUG/INFO/WARN/ERROR   |
| `DB_PATH`        | `./data/taburtuai.db`      | SQLite database path    |

---

## API

All endpoints are under `/api/v1`.

| Method | Path                              | Description              |
|--------|-----------------------------------|--------------------------|
| POST   | `/checkin`                        | Agent check-in           |
| GET    | `/agents`                         | List all agents          |
| GET    | `/agents/:id`                     | Get agent details        |
| DELETE | `/agents/:id`                     | Remove agent             |
| POST   | `/command`                        | Queue a command          |
| GET    | `/command/:id/next`               | Agent polls next command |
| POST   | `/command/result`                 | Agent submits result     |
| GET    | `/command/:id/status`             | Check command status     |
| GET    | `/agent/:id/commands`             | Command history          |
| DELETE | `/agent/:id/queue`                | Clear pending queue      |
| POST   | `/agent/:id/upload`               | Upload file to agent     |
| POST   | `/agent/:id/download`             | Download file from agent |
| POST   | `/agent/:id/process/list`         | List processes           |
| POST   | `/agent/:id/process/kill`         | Kill process             |
| POST   | `/agent/:id/process/start`        | Start process            |
| POST   | `/agent/:id/persistence/setup`    | Setup persistence        |
| POST   | `/agent/:id/persistence/remove`   | Remove persistence       |
| GET    | `/health`                         | Server health check      |
| GET    | `/stats`                          | Server statistics        |

---

## Phases

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full development plan.

| Phase | Status | Focus |
|-------|--------|-------|
| 1 — Foundation      | ✅ Done    | API, agent, logging, auth |
| 2 — Core Operations | ✅ Done    | Files, processes, persistence |
| 3 — OPSEC           | 🔨 In Progress | Malleable profiles, ECDH, SQLite |
| 4 — Listeners       | Planned   | HTTPS, DNS, SMB, WebSocket |
| 5 — Team Server     | Planned   | Multi-operator, RBAC, gRPC |
| 6 — Payloads        | Planned   | Staged, shellcode, obfuscation |
| 7 — Post-Ex         | Planned   | Injection, tokens, credentials |
| 8 — Pivoting        | Planned   | SOCKS5, port forward, P2P relay |

---

## Legal

For authorized penetration testing and red team engagements only.
Unauthorized use against systems you do not own is illegal.
