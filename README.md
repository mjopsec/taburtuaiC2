# taburtuai C2

> **Author:** mjopsec &nbsp;·&nbsp; **Version:** 2.0.0 &nbsp;·&nbsp; **License:** MIT

A modular, OPSEC-minded Command & Control framework written in Go, built exclusively for authorized red team engagements and penetration testing exercises.



## What It Is

Taburtuai C2 is a full-stack command and control framework server, operator CLI, implant builder, and agent designed around realistic adversary tradecraft. It prioritizes operational security at every layer: encrypted traffic that blends into normal web activity, agents that hide during sleep, and techniques that evade modern endpoint detection.

The framework supports the full lifecycle of a red team engagement: initial access delivery, persistence, lateral movement, credential access, and exfiltration — all coordinated from a single team server with multi-operator support.



## Core Capabilities

**Infrastructure**
- Team server with SQLite-backed durability — agents, commands, and results survive restarts
- Multi-listener architecture: HTTP, HTTPS/TLS, WebSocket, DNS authoritative
- Multi-operator support with agent claim/release and broadcast events
- Vue 3 web dashboard for real-time monitoring
- Two-phase encrypted comms: AES-256-GCM bootstrap → ECDH P-256 ephemeral session key

**Implant & Evasion**
- Sleep masking: `VirtualProtect(PAGE_NOACCESS)` + RC4 memory encryption during sleep
- AMSI and ETW patching (in-process bypass without spawning child processes)
- NTDLL unhooking: restore `.text` from clean disk copy, removing EDR hooks
- Hardware breakpoint (HWBP) installation via Vectored Exception Handler
- Anti-debug, anti-VM, and anti-sandbox checks
- Hell's Gate indirect syscall (PEB walk + SSN resolution + `syscall;ret` gadget)
- Malleable C2 HTTP profiles: Office365, CDN, jQuery, Slack, OCSP traffic mimicry

**Post-Exploitation**
- Process injection: CRT, APC, hollowing, thread hijacking, module stomping, section mapping
- PPID spoofing: spawn processes under a chosen parent PID
- Credential access: LSASS dump, SAM hive, browser passwords, clipboard
- Lateral movement: WMI, WinRM, DCOM, scheduled tasks, Windows services
- Token manipulation: steal/impersonate/make tokens, RunAs under alternate identity
- Alternate Data Streams: write, read, execute payloads from NTFS ADS
- BOF/COFF loader: execute Beacon Object Files in-memory
- Network pivot: in-process SOCKS5 proxy, port forwarding, TCP scan, ARP scan
- Registry: read, write, delete, enumerate keys and values
- Reconnaissance: desktop screenshot, keylogger, process listing
- Persistence: registry Run, scheduled tasks, services, WMI subscriptions, startup folder

**Payload Builder**
- Cross-platform targets: Windows (primary), Linux, macOS
- Output formats: EXE, DLL, ELF, shellcode, PowerShell script
- OPSEC profiles baked at compile time: `default`, `stealth`, `aggressive`, `opsec`, `paranoid`
- PE masquerade: version resource and company/product metadata spoofing
- Optional Garble-based code obfuscation and binary compression
- Alternative transports: DNS-over-HTTPS, ICMP echo, SMB named pipe



## Architecture Overview

```
Operator CLI ──────────────────────────────────────────────┐
Web Dashboard ──────────────────┐                          │
                                ▼                          ▼
                         ┌─────────────────────────────────────┐
                         │           Team Server               │
                         │  ┌──────────┐  ┌────────────────┐   │
                         │  │ REST API │  │  SQLite Queue  │   │
                         │  └──────────┘  └────────────────┘   │
                         │  ┌──────────┐  ┌────────────────┐   │
                         │  │ Profiles │  │  Team Server   │   │
                         │  └──────────┘  └────────────────┘   │
                         └─────────────────────────────────────┘
                                         │
                              Encrypted Beacon
                              (AES-256-GCM)
                                         │
                         ┌───────────────▼─────────────────────┐
                         │               Agent                 │
                         │  ┌──────────────────────────────┐   │
                         │  │  Beacon Loop (configurable)  │   │
                         │  │  Sleep Mask  │  Evasion      │   │
                         │  │  60+ commands dispatched     │   │
                         │  └──────────────────────────────┘   │
                         └─────────────────────────────────────┘
```



## Documentation

Full operator documentation is available in the [wiki](wiki/Home.md):

| Page | Description |
|------|-------------|
| [Quick Start](wiki/01-quick-start.md) | Get the server, CLI, and first agent running in minutes |
| [Architecture](wiki/02-architecture.md) | How components fit together and how traffic flows |
| [Configuration](wiki/03-configuration.md) | Server and agent configuration reference |
| [Building Payloads](wiki/04-building-payloads.md) | Generate command: stager, stageless, formats, profiles |
| [Operator Console](wiki/05-operator-console.md) | Interactive console usage and all available commands |
| [Agent Management](wiki/06-agent-management.md) | List, inspect, and manage connected agents |
| [Command Execution](wiki/07-command-execution.md) | shell, cmd, status, history — with output examples |
| [File Operations](wiki/08-file-operations.md) | Upload and download files through the encrypted channel |
| [Process Management](wiki/09-process-management.md) | List, kill, and start processes on the target |
| [Persistence](wiki/10-persistence.md) | Registry, scheduled tasks, services, WMI — all methods |
| [Code Injection](wiki/11-code-injection.md) | All 6 injection methods with OPSEC comparison |
| [Evasion](wiki/12-evasion.md) | AMSI, ETW, HWBP, sleep masking, NTDLL unhook |
| [Credential Access](wiki/13-credential-access.md) | LSASS, SAM, browser passwords, clipboard |
| [Reconnaissance](wiki/14-reconnaissance.md) | Screenshot, keylogger, network and ARP scan |
| [Token Manipulation](wiki/15-token-manipulation.md) | Token steal, impersonate, make_token, RunAs |
| [Lateral Movement](wiki/16-lateral-movement.md) | WMI, WinRM, DCOM, schtask, service |
| [Network Pivot](wiki/17-network-pivot.md) | SOCKS5 proxy, port forwarding, registry |
| [C2 Profiles](wiki/18-c2-profiles.md) | Malleable HTTP profiles and OPSEC profiles |
| [OPSEC Guide](wiki/19-opsec-guide.md) | Operational security practices for engagements |
| [Engagement Scenarios](wiki/20-engagement-scenarios.md) | Full attack chain examples end to end |



## Legal

This tool is provided solely for **authorized penetration testing, red team engagements, and security research**.  
Use against systems you do not own or lack explicit written permission to test is illegal and unethical.  
The author assumes no liability for misuse.
