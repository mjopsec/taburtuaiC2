# taburtuaiC2

A modular, OPSEC-minded Command & Control framework written in Go.  
Built for authorized red team engagements only.

> **Author:** mjopsec &nbsp;·&nbsp; **Version:** 2.0.0 &nbsp;·&nbsp; **License:** MIT

---

## Features

- **Encrypted comms** — AES-256-GCM static key + ECDH P-256 per-session key exchange
- **SQLite persistence** — agents and command history survive server restarts
- **Malleable C2 profiles** — YAML-driven beacon behavior baked into each payload at build time
- **Sleep obfuscation** — Windows `VirtualProtect` sleep masking (`PAGE_NOACCESS` during sleep)
- **Kill date & working hours** — agent self-terminates outside configured time windows
- **Web dashboard** — SPA with Overview, Agents, Commands, and Logs pages
- **File operations** — upload / download with AES-encrypted transfer
- **Process management** — list, kill, start processes on the target
- **Persistence** — multiple persistence mechanisms per platform
- **Cross-platform agent** — Windows / Linux / macOS (build-tagged platform code)

---

## Project Structure

```
taburtuaiC2/
├── cmd/
│   ├── server/            # Team server entry point
│   └── operator/          # Operator CLI entry point
├── internal/
│   ├── api/               # HTTP handlers, middleware, routing (Gin)
│   ├── config/            # Server configuration (env-based)
│   ├── core/              # Server struct, SQLite-backed command queue
│   ├── modules/           # Plugin module manager
│   ├── services/          # Logger, agent monitor (write-through cache)
│   └── storage/           # SQLite store (agents, commands)
├── pkg/
│   ├── crypto/            # AES-256-GCM + ECDH session key exchange
│   └── types/             # Shared types (Command, AgentInfo, etc.)
├── agent/
│   ├── core/              # Agent beacon loop, checkin, command dispatch
│   ├── evasion/           # Sleep masking (Windows VirtualProtect)
│   └── persistence/       # Persistence mechanisms
├── builder/
│   ├── profiles/          # OPSEC profiles (default / stealth / aggressive)
│   └── templates/         # Payload templates
├── listener/
│   └── http/              # HTTP listener
├── web/
│   ├── static/
│   │   ├── css/           # variables · base · layout · components
│   │   └── js/            # api · ui · app · pages (overview/agents/commands/logs)
│   └── templates/         # dashboard.html shell
├── config/                # taburtuai.yaml
├── scripts/build/         # Build scripts
└── docs/                  # ROADMAP.md, ARCHITECTURE.md
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

**Build agent — Linux x64**
```bash
bash scripts/build/build_agent.sh \
  --server http://your-c2:8080 \
  --key YourEncKey \
  --os linux --arch amd64
```

**Build agent — Windows x64 with stealth profile**
```bash
bash scripts/build/build_agent.sh \
  --server http://your-c2:8080 \
  --key YourEncKey \
  --os windows --arch amd64 \
  --profile builder/profiles/stealth.yaml \
  --stealth --compress
```

---

## Configuration

Server reads from environment variables (all have safe defaults):

| Variable         | Default                   | Description                         |
|------------------|---------------------------|-------------------------------------|
| `PORT`           | `8080`                    | Listening port                      |
| `ENCRYPTION_KEY` | *(required)*              | Primary AES-256 key (base64)        |
| `SECONDARY_KEY`  | *(optional)*              | Secondary AES-256 key (base64)      |
| `AUTH_ENABLED`   | `false`                   | Require API key on all requests     |
| `API_KEY`        | *(required if auth on)*   | Bearer token for operators          |
| `LOG_DIR`        | `./logs`                  | Log output directory                |
| `LOG_LEVEL`      | `INFO`                    | `DEBUG` / `INFO` / `WARN` / `ERROR` |
| `DB_PATH`        | `./data/taburtuai.db`     | SQLite database path                |

---

## OPSEC Profiles

Profiles are YAML files in `builder/profiles/` baked into the agent at compile time via `-ldflags`.

| Profile       | Interval | Jitter | Evasion | Sleep Masking |
|---------------|----------|--------|---------|---------------|
| `default`     | 60 s     | 20 %   | off     | off           |
| `stealth`     | 300 s    | 40 %   | on      | on            |
| `aggressive`  | 10 s     | 10 %   | off     | off           |

Each profile can also set `kill_date`, `working_hours_only`, `working_hours_start/end`, and `user_agent_rotation`.

---

## API Reference

All endpoints are under `/api/v1`.

| Method | Path                              | Description                    |
|--------|-----------------------------------|--------------------------------|
| POST   | `/checkin`                        | Agent check-in (ECDH handshake)|
| GET    | `/agents`                         | List all agents                |
| GET    | `/agents/:id`                     | Get agent details              |
| DELETE | `/agents/:id`                     | Remove agent                   |
| POST   | `/command`                        | Queue a command                |
| GET    | `/command/:id/next`               | Agent polls next command       |
| POST   | `/command/result`                 | Agent submits result           |
| GET    | `/command/:id/status`             | Check command status           |
| GET    | `/agent/:id/commands`             | Command history                |
| DELETE | `/agent/:id/queue`                | Clear pending queue            |
| POST   | `/agent/:id/upload`               | Upload file to agent           |
| POST   | `/agent/:id/download`             | Download file from agent       |
| POST   | `/agent/:id/process/list`         | List processes                 |
| POST   | `/agent/:id/process/kill`         | Kill process                   |
| POST   | `/agent/:id/process/start`        | Start process                  |
| POST   | `/agent/:id/persistence/setup`    | Install persistence            |
| POST   | `/agent/:id/persistence/remove`   | Remove persistence             |
| GET    | `/health`                         | Server health check            |
| GET    | `/stats`                          | Server statistics              |
| GET    | `/server/logs`                    | Fetch server logs              |
| GET    | `/server/queue-stats`             | Queue statistics               |

---

## Development Phases

| Phase | Status         | Focus                                                  |
|-------|----------------|--------------------------------------------------------|
| 1     | ✅ Done        | API skeleton, agent beacon, logging, auth              |
| 2     | ✅ Done        | File ops, process management, persistence              |
| 3     | ✅ Done        | SQLite persistence, ECDH, sleep masking, OPSEC profiles|
| 4     | 🔲 Planned     | Listeners — HTTPS, DNS, SMB, WebSocket                 |
| 5     | 🔲 Planned     | Team server — multi-operator, RBAC, gRPC               |
| 6     | 🔲 Planned     | Payloads — staged, shellcode, obfuscation              |
| 7     | 🔲 Planned     | Post-exploitation — injection, tokens, credentials     |
| 8     | 🔲 Planned     | Pivoting — SOCKS5, port forward, P2P relay             |

See [docs/ROADMAP.md](docs/ROADMAP.md) for detailed task breakdowns.

---

## Legal

This tool is provided for **authorized penetration testing and red team engagements only**.  
Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.
