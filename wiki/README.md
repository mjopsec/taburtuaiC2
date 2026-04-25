# Taburtuai C2 — Operator Wiki

> Full documentation for operators running authorized red team engagements with Taburtuai C2 v2.0.0.

## Contents

### Getting Started
- [Quick Start](01-quick-start.md) — server + agent running in under 10 minutes
- [Architecture](02-architecture.md) — how every component connects
- [Configuration](03-configuration.md) — complete server and agent config reference

### Payload Generation
- [Building Payloads](04-building-payloads.md) — formats, OPSEC profiles, masquerading
- [Stager & Staged Delivery](21-stager.md) — staged workflow, delivery formats, ClickFix, one-shot tokens

### Operator Console
- [Operator Console](05-operator-console.md) — interactive console and full command reference
- [Agent Management](06-agent-management.md) — list, inspect, delete agents

### Post-Exploitation
- [Command Execution](07-command-execution.md) — shell, cmd, status, history
- [File Operations](08-file-operations.md) — upload and download
- [Process Management](09-process-management.md) — list, kill, start
- [Persistence](10-persistence.md) — all persistence mechanisms
- [Code Injection](11-code-injection.md) — 6 injection methods compared
- [Evasion](12-evasion.md) — AMSI, ETW, HWBP, sleep masking, unhooking
- [Credential Access](13-credential-access.md) — LSASS, SAM, browsers, clipboard
- [Reconnaissance](14-reconnaissance.md) — screenshot, keylogger, network scan
- [Token Manipulation](15-token-manipulation.md) — steal, impersonate, make, runas
- [Lateral Movement](16-lateral-movement.md) — WMI, WinRM, DCOM, schtask, service
- [Network Pivot](17-network-pivot.md) — SOCKS5, port forward, registry

### Reference
- [C2 Profiles](18-c2-profiles.md) — malleable HTTP and OPSEC profiles explained
- [OPSEC Guide](19-opsec-guide.md) — staying undetected during engagements
- [Engagement Scenarios](20-engagement-scenarios.md) — full attack chain examples

---

## Conventions Used in This Wiki

```
<agent-id>     UUID of the target agent (or prefix — the CLI fuzzy-matches)
<cmd-id>       UUID returned after queuing a command
[flag]         Optional flag
--flag <val>   Required flag with a value
```

All examples assume the console is open (`taburtuai console --server http://HOST:PORT`).  
One-liner equivalents prepend `taburtuai --server http://HOST:PORT` to every command.
