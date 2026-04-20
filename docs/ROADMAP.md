# Taburtuai C2 — Development Roadmap

> Goal: Build an OPSEC-minded, modular, adaptive C2 framework that goes beyond standard tooling.  
> Each phase is independently mergeable. Phases build on each other but can be developed in parallel branches.

---

## Phase 1 — Foundation ✅ DONE
**Goal:** Functional skeleton — server boots, agent checks in, commands execute.

- [x] REST API (Gin) — checkin, command queue, result submission
- [x] Agent: HTTP transport, AES-256-GCM + gzip encryption
- [x] Command types: execute, upload, download, process list/kill/start, persist
- [x] Server-side agent monitoring, health tracking, rate limiting
- [x] Authentication (API key + Bearer token)
- [x] Multi-format logging (text, JSON, security events)
- [x] Web dashboard (HTML)
- [x] CLI operator (`cmd/operator/`)

---

## Phase 2 — Core Operations ✅ DONE
**Goal:** Full post-exploitation capability on a single host.

- [x] File upload/download with encryption
- [x] Process enumeration, kill, spawn
- [x] Cross-platform persistence:
  - Windows: Registry Run, Scheduled Tasks, Startup Folder
  - Linux: Cron (@reboot), systemd user service, .bashrc
  - macOS: LaunchAgent plist
- [x] Evasion stubs: sandbox/VM/debugger detection
- [x] Module manager interface (plugin architecture)
- [x] Agent group management, bulk command dispatch
- [x] Build system (`scripts/build/`)

---

## Phase 3 — OPSEC Hardening 🎯 NEXT
**Goal:** Make traffic and agent behavior blend into the environment. This is the biggest differentiator vs commodity C2s.

### 3.1 Malleable C2 Profiles
- [ ] YAML-based traffic profiles (URI paths, headers, User-Agents, response bodies)
- [ ] Per-listener profile assignment
- [ ] Rotate profiles on reconnect
- [ ] Mimic legitimate app traffic (Office365, Azure, Google APIs)

### 3.2 Proper Key Exchange
- [ ] Replace hardcoded shared key with ECDH (Noise Protocol or X25519)
- [ ] Per-session symmetric keys derived from key exchange
- [ ] Key rotation on reconnect
- [ ] Certificate pinning for HTTPS listener

### 3.3 Agent Sleep Obfuscation
- [ ] Proper sleep masking: encrypt agent memory during sleep (Windows: VirtualProtect + AES)
- [ ] Stack spoofing stubs
- [ ] Syscall-based sleep (Windows: NtDelayExecution) to avoid timing analysis

### 3.4 Traffic Shaping
- [ ] Configurable beacon interval + jitter (already in config, needs profile-driven)
- [ ] Working-hours-only beaconing (kill switch outside 08:00-18:00)
- [ ] Bandwidth throttling for large transfers
- [ ] Domain Fronting support (CDN-based C2 via Host header)

### 3.5 Kill Switch & Self-Destruct
- [ ] Kill date baked into agent at build time
- [ ] Remote kill command (agent deletes itself + persistence)
- [ ] Anti-forensic: wipe agent artifacts on exit

### 3.6 SQLite Persistence
- [ ] Replace in-memory agent/command storage with SQLite
- [ ] Migrations system (`internal/storage/migrations/`)
- [ ] Agent history survives server restarts
- [ ] Command audit log persisted to DB

---

## Phase 4 — Multi-Protocol Listeners 🔌
**Goal:** One C2, many transport options. Critical for bypassing network controls.

### 4.1 HTTPS Listener
- [ ] TLS with operator-provided cert or auto Let's Encrypt (ACME)
- [ ] SNI-based multiplexing (serve multiple domains from one IP)
- [ ] HTTP/2 support for blending with modern web traffic

### 4.2 DNS Listener
- [ ] DNS tunneling (A, TXT, CNAME record encoding)
- [ ] Subdomain-based data exfiltration
- [ ] Encoding: Base32/Base64 over DNS labels
- [ ] Integrate with `miekg/dns` library

### 4.3 SMB / Named Pipe Listener
- [ ] Windows Named Pipe server
- [ ] Lateral movement within network: agent-to-agent relay
- [ ] No internet required — pivoting through compromised hosts

### 4.4 WebSocket Listener
- [ ] Persistent bidirectional channel
- [ ] Lower latency than polling
- [ ] Disguise as legitimate WebSocket app (e.g., chat, monitoring)

### 4.5 gRPC Listener (Internal Team Server)
- [ ] Operator ↔ Team Server protocol over gRPC (replaces REST for operators)
- [ ] TLS mutual auth for operators
- [ ] Event streaming (real-time agent events pushed to operators)

---

## Phase 5 — Team Server & Multi-Operator 👥
**Goal:** Enable collaborative red team operations with proper RBAC.

### 5.1 Operator Authentication
- [ ] Named operator accounts (not shared API keys)
- [ ] Role-based access: `admin`, `operator`, `viewer`
- [ ] Per-operator audit log
- [ ] Session tokens with expiry

### 5.2 Real-Time Collaboration
- [ ] Operator event stream (WebSocket or gRPC streaming)
- [ ] Shared command history visible to all operators
- [ ] "Typed by" indicator — show who queued each command
- [ ] Operator chat / notes tied to engagement

### 5.3 Engagement Management
- [ ] Named engagements / operations
- [ ] Scope definition (IP ranges, domains)
- [ ] Agent tagging by engagement
- [ ] Export engagement data (JSON, PDF report)

---

## Phase 6 — Advanced Payload Generation 🛠️
**Goal:** Generate diverse, obfuscated payloads for different delivery methods.

### 6.1 Staged Payloads
- [ ] Stage 0 (stager): tiny downloader that fetches Stage 1
- [ ] Stage 1 (loader): loads Stage 2 into memory
- [ ] Stage 2 (implant): full agent, never touches disk
- [ ] Stager formats: PowerShell one-liner, macro, HTA, VBA

### 6.2 Output Formats
- [ ] Shellcode (raw, position-independent)
- [ ] Reflective DLL injection loader
- [ ] PowerShell base64-encoded dropper
- [ ] C source code (for custom compilation on target)
- [ ] EXE/ELF (current)

### 6.3 Obfuscation Pipeline
- [ ] String encryption at build time (XOR / AES with compile-time key)
- [ ] Import table obfuscation (syscall-direct where possible)
- [ ] Control flow flattening stub
- [ ] Garble integration (`burrowers/garble`) for Go binary obfuscation

### 6.4 Payload Signing
- [ ] Code signing with operator-provided cert (Windows Authenticode)
- [ ] Timestamp signing for longevity past cert expiry

---

## Phase 7 — Post-Exploitation Modules 💣
**Goal:** Built-in post-ex capabilities loaded on-demand (BOF-style or Go plugin).

### 7.1 Injection Techniques (Windows)
- [ ] Classic CreateRemoteThread injection
- [ ] Process hollowing (NtUnmapViewOfSection)
- [ ] APC injection (QueueUserAPC)
- [ ] Early bird APC injection
- [ ] Syscall-direct injection (bypass userland hooks)
- [ ] Shellcode runner in Go with VirtualAlloc

### 7.2 Token & Privilege Manipulation
- [ ] Token impersonation (steal token from process)
- [ ] `Make/ImpersonateToken`, `DuplicateTokenEx`
- [ ] UAC bypass techniques
- [ ] LSASS dump (MiniDumpWriteDump or direct syscall)

### 7.3 Credential Access
- [ ] SAM/NTDS.dit extraction stubs
- [ ] DPAPI decryption (Chrome, Windows Credential Manager)
- [ ] Kerberos ticket extraction (pass-the-ticket)
- [ ] NTLM hash extraction

### 7.4 Lateral Movement
- [ ] WMI remote execution
- [ ] PSExec-style SMB service install
- [ ] DCOM lateral movement
- [ ] Pass-the-Hash (NTLM relay)
- [ ] Pass-the-Ticket (Kerberos)
- [ ] SSH key reuse (Linux pivoting)

### 7.5 Discovery & Enumeration
- [ ] Active Directory enumeration (LDAP queries, no ADSI required)
- [ ] Network share discovery
- [ ] Kerberoastable account discovery
- [ ] Trust relationship mapping

---

## Phase 8 — Pivot Infrastructure 🔀
**Goal:** Route traffic through compromised hosts to reach segmented networks.

### 8.1 SOCKS5 Proxy
- [ ] Agent acts as SOCKS5 proxy (operator tunnels through agent)
- [ ] Multiplexed over existing C2 channel
- [ ] Automatic route advertisement to team server

### 8.2 Port Forwarding
- [ ] Local → Remote port forward
- [ ] Remote → Local reverse port forward
- [ ] Bind vs connect modes

### 8.3 Agent-to-Agent Relay (Peer-to-Peer)
- [ ] SMB Named Pipe relay: internal agents relay through internet-connected agent
- [ ] No direct internet access required for internal agents
- [ ] Automatic path discovery

### 8.4 Traffic Relay Chain
- [ ] Multi-hop: Operator → Redirector → Agent → Target
- [ ] Redirectors: HAProxy / Nginx / socat configs generated automatically

---

## Phase 9 — Intelligence & Reporting 📊
**Goal:** Turn raw operator data into actionable reports and TTPs.

### 9.1 MITRE ATT&CK Mapping
- [ ] Tag each command/module with ATT&CK Technique IDs
- [ ] Auto-generate ATT&CK Navigator layer from operation
- [ ] Detect coverage gaps

### 9.2 Automated Reporting
- [ ] HTML/PDF report generation (engagement summary)
- [ ] Timeline of all operator actions
- [ ] IOC list (IPs, domains, hashes, persistence names)
- [ ] Screenshot capture module (agent-side)

### 9.3 Threat Intelligence
- [ ] IOC tracking database
- [ ] Deconfliction: warn operators when targeting overlaps

---

## Priority Matrix

| Feature                          | Impact | Effort | Do Next? |
|----------------------------------|--------|--------|----------|
| SQLite persistence               | High   | Low    | YES      |
| Malleable C2 profiles            | High   | Medium | YES      |
| ECDH key exchange                | High   | Medium | YES      |
| HTTPS listener                   | High   | Low    | YES      |
| Sleep obfuscation (Windows)      | High   | High   | Phase 3  |
| DNS listener                     | Medium | High   | Phase 4  |
| SOCKS5 proxy                     | High   | Medium | Phase 8  |
| gRPC team server                 | Medium | High   | Phase 5  |
| Garble obfuscation               | Medium | Low    | Phase 6  |
| Process injection                | High   | High   | Phase 7  |

---

## What Makes Taburtuai Different

| Feature                          | Metasploit | CS | Havoc | Taburtuai Goal |
|----------------------------------|------------|-----|-------|----------------|
| OPSEC profiles (malleable)       | ❌         | ✅  | ✅    | ✅             |
| Written in Go (cross-compile)    | ❌         | ❌  | ❌    | ✅             |
| Open source                      | ✅         | ❌  | ✅    | ✅             |
| DNS tunneling                    | ✅         | ✅  | ❌    | ✅ (Phase 4)   |
| SMB relay/pivot                  | ✅         | ✅  | ✅    | ✅ (Phase 4/8) |
| Working-hours beaconing          | ❌         | ✅  | ✅    | ✅ (Phase 3)   |
| Plugin module system             | ✅         | ✅  | ✅    | ✅ (Phase 2+)  |
| Adaptive sleep masking           | ❌         | ✅  | ✅    | ✅ (Phase 3)   |
| Multi-operator + RBAC            | ❌         | ✅  | ✅    | ✅ (Phase 5)   |
| Staged payload delivery          | ✅         | ✅  | ✅    | ✅ (Phase 6)   |
| ATT&CK mapped reporting          | ❌         | ❌  | ❌    | ✅ (Phase 9)   |
