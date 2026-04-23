# 01 — Introduction & Arsitektur

## Apa itu Taburtuai C2?

**Taburtuai** adalah Command & Control (C2) framework yang dirancang untuk red team operations,
authorized penetration testing, dan penelitian keamanan ofensif. Framework ini menyediakan
infrastruktur lengkap untuk:

- **Deploy implant** ke mesin target melalui berbagai metode delivery
- **Post-exploitation** terstruktur: eksekusi perintah, file ops, persistence, injection
- **Defense evasion**: bypass AMSI/ETW, NTDLL unhooking, sleep masking, token manipulation
- **Lateral movement**: pivoting via SOCKS5, credential dumping, network recon
- **Multi-operator**: koordinasi tim red team secara real-time

Nama "Taburtuai" berasal dari kata lokal yang berarti *"penghubung tersembunyi"* — mencerminkan
komunikasi terselubung antara operator dan target.

---

## Komponen Utama

```
taburtuaiC2/
├── bin/
│   ├── server                     ← C2 server (menerima beacon, antrian perintah)
│   ├── operator                   ← Operator CLI (kontrol agent, lihat hasil)
│   ├── generate                   ← Implant builder & delivery template
│   └── agent_windows_stealth.exe  ← Implant hasil build
├── cmd/
│   ├── server/                    ← Source server
│   ├── operator/                  ← Source operator CLI
│   ├── generate/                  ← Source generator
│   └── listener/smb_relay.go      ← SMB relay binary (opsional)
├── agent/                         ← Source implant (cross-platform)
├── internal/
│   ├── api/                       ← HTTP handlers (semua endpoint REST)
│   ├── core/                      ← Server core (startup, wiring komponen)
│   └── services/                  ← Business logic (monitor, queue, team hub)
├── pkg/
│   ├── types/                     ← Shared types (Command, Agent, APIResponse)
│   ├── transport/                 ← Transport alternatif (DoH, ICMP, SMB)
│   └── strenc/                    ← Compile-time string encryption
├── data/                          ← SQLite database (auto-created)
├── logs/                          ← Log files
├── wiki/                          ← Dokumentasi ini
└── Makefile                       ← Build system
```

---

## Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────────────┐
│                         OPERATOR (Red Teamer)                       │
│   ┌─────────────────┐          ┌────────────────────────────────┐   │
│   │  bin/operator   │          │    SSE Event Stream            │   │
│   │  (CLI / console)│          │  (real-time multi-operator)    │   │
│   └────────┬────────┘          └────────────────────────────────┘   │
└────────────┼────────────────────────────────────────────────────────┘
             │ REST API (JSON + AES-256-GCM)
             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          C2 SERVER                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  REST API    │  │ Command Queue│  │  Agent Monitor           │  │
│  │  (Gin HTTP)  │  │  (in-memory) │  │  (heartbeat tracking)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Team Hub    │  │  CryptoMgr   │  │  Logger (structured)     │  │
│  │  (SSE fanout)│  │  (AES-GCM)   │  │  (audit + events)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                  ┌─────────┴──────────┐
                  │   Beacon Channel   │
                  │  (HTTPS / DoH /    │
                  │   ICMP / SMB pipe) │
                  └─────────┬──────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────┐
│                          AGENT (Implant)                            │
│  ┌─────────────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │  Beacon Loop    │  │ Command Exec  │  │  OPSEC Controls      │  │
│  │  (interval+jitter│ │ (shell/PS/WMI)│  │  (kill date, hours,  │  │
│  │  + sleep mask)  │  │               │  │   jitter, encrypt)   │  │
│  └─────────────────┘  └───────────────┘  └──────────────────────┘  │
│  ┌─────────────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │  Evasion        │  │  Injection    │  │  Transport Selector  │  │
│  │  (AMSI/ETW/hook)│  │  (CRT/APC/   │  │  (HTTP/DoH/ICMP/SMB) │  │
│  └─────────────────┘  │   hollow/...) │  └──────────────────────┘  │
│                        └───────────────┘                            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Alur Komunikasi Detail

### 1. Agent Registration (Pertama Kali)

```
Agent                                    C2 Server
  │                                          │
  │  POST /beacon                            │
  │  Body: AES-GCM {                         │
  │    "hostname": "DESKTOP-ABC",            │
  │    "username": "john.doe",               │
  │    "os": "windows",                      │
  │    "arch": "amd64",                      │
  │    "pid": 4512,                          │
  │    "agent_version": "1.0"               │
  │  }                                       │
  │─────────────────────────────────────────►│
  │                                          │
  │  200 OK                                  │
  │  Body: {"success":true,"agent_id":"..."}│
  │◄─────────────────────────────────────────│
```

### 2. Beacon Poll Loop

```
Agent                                    C2 Server
  │                                          │
  │  [sleep interval ± jitter detik]         │
  │                                          │
  │  GET /beacon?agent_id=UUID               │
  │─────────────────────────────────────────►│
  │                                          │  ┌─ Command Queue kosong?
  │  204 No Content                          │  │  → return 204
  │◄─────────────────────────────────────────│  │
  │                                          │  └─ Ada perintah?
  │  200 OK                                  │     → return command JSON
  │  Body: AES-GCM {command object}          │
  │◄─────────────────────────────────────────│
  │                                          │
  │  [eksekusi perintah]                     │
  │                                          │
  │  POST /result                            │
  │  Body: AES-GCM {result object}           │
  │─────────────────────────────────────────►│
  │                                          │
  │  200 OK                                  │
  │◄─────────────────────────────────────────│
```

### 3. Operator ke Server

```
Operator                                 C2 Server
  │                                          │
  │  POST /api/v1/command/execute            │
  │  Headers: X-Session-ID: sess-abc         │
  │  Body: {                                 │
  │    "agent_id": "UUID",                   │
  │    "command": "whoami",                  │
  │    "timeout": 30                         │
  │  }                                       │
  │─────────────────────────────────────────►│
  │                                          │  Enqueue ke CommandQueue
  │  200 OK                                  │
  │  Body: {"command_id": "cmd-UUID"}       │
  │◄─────────────────────────────────────────│
  │                                          │
  │  GET /api/v1/command/cmd-UUID/status     │
  │─────────────────────────────────────────►│
  │  {"status":"completed","output":"..."}  │
  │◄─────────────────────────────────────────│
```

---

## Enkripsi & Keamanan

### Layer Enkripsi

```
┌──────────────────────────────────────────────────────────┐
│ Layer 3: Transport (opsional HTTPS / TLS 1.3)            │
│   └─ Enkripsi transport — endpoint ke endpoint           │
├──────────────────────────────────────────────────────────┤
│ Layer 2: Application (AES-256-GCM)                       │
│   └─ Setiap payload dienkripsi dengan key bake-in        │
│   └─ Nonce unik per request (96-bit random)              │
│   └─ Authentication tag 128-bit                          │
├──────────────────────────────────────────────────────────┤
│ Layer 1: Payload Encoding (base64 + nonce prefix)        │
│   └─ Nonce (12 byte) || Ciphertext || AuthTag            │
└──────────────────────────────────────────────────────────┘
```

### UUID Deterministik Agent

Agent tidak generate UUID random — UUID di-derive dari kombinasi:
```
UUID = SHA256(hostname + username + c2_server_url) → UUIDv4 format
```

**Implikasi:**
- Agent yang restart di mesin yang sama → UUID tetap sama (tidak muncul sebagai agent baru)
- Tidak ada metadata random di binary yang bisa di-fingerprint

---

## Supported Platforms

| Platform | Agent | Server | Operator |
|----------|-------|--------|----------|
| Windows amd64 | ✓ (utama) | ✓ | ✓ |
| Windows 386 | ✓ | — | ✓ |
| Linux amd64 | ✓ | ✓ (rekomendasi) | ✓ |
| macOS amd64 | ✓ | ✓ | ✓ |
| macOS arm64 | ✓ | ✓ | ✓ |

> **Catatan:** Fitur Windows-only (injection, AMSI/ETW bypass, token ops, registry, ICMP/SMB transport)
> hanya tersedia di agent Windows. Agent Linux/macOS hanya mendukung shell execution dan file ops dasar.

---

## Transport yang Tersedia

| Transport | Protokol | Kapan Dipakai | Build Target |
|-----------|----------|---------------|--------------|
| HTTP/HTTPS | TCP 80/443 | Default, semua skenario | `agent-win-stealth` |
| DNS-over-HTTPS | DNS via HTTPS (port 443) | Egress sangat terbatas, hanya DNS | `agent-win-doh` |
| ICMP | ICMP Echo | Firewall sangat ketat, tidak ada TCP keluar | `agent-win-icmp` |
| SMB Named Pipe | SMB (port 445) | Internal pivot, mesin tidak ada internet | `agent-win-smb` |

---

## OPSEC Controls Bawaan

| Control | Parameter Build | Default | Fungsi |
|---------|----------------|---------|--------|
| Beacon interval | `INTERVAL` | `30` detik | Jeda antar poll ke server |
| Jitter | `JITTER` | `20` % | Variasi interval (acak ±20%) |
| Kill date | `KILL_DATE` | kosong | Agent mati otomatis di tanggal ini |
| Working hours | `WORKING_HOURS` | kosong | Agent hanya aktif jam tertentu |
| Sleep masking | `SLEEP_MASKING` | `true` | Enkripsi memori saat idle |
| Exec method | `EXEC_METHOD` | `powershell` | Metode default eksekusi command |
| Transport | `TRANSPORT` | `http` | Channel komunikasi ke C2 |
| String encryption | `make encrypted` | off | Enkripsi string literal di binary |

---

## Fitur Lengkap per Kategori

```
COMMAND EXECUTION
  ├─ shell (cmd.exe, powershell, wmi, mshta)
  ├─ interactive shell session
  ├─ working directory control
  └─ per-command timeout

FILE OPERATIONS
  ├─ upload file ke target
  ├─ download file dari target
  ├─ list direktori
  ├─ delete file
  └─ Alternate Data Stream (ADS) exec

PERSISTENCE
  ├─ HKCU\Run registry key
  ├─ HKLM\Run registry key
  ├─ Scheduled task (logon/boot trigger)
  ├─ Windows service
  └─ Startup folder shortcut

PROCESS MANAGEMENT
  ├─ list proses (PID, nama, user, PID parent)
  ├─ kill proses
  └─ start proses (dengan PPID spoof)

PROCESS INJECTION
  ├─ Remote Thread (CRT)
  ├─ APC Injection
  ├─ Process Hollowing
  ├─ Thread Hijacking
  ├─ Module Stomping (.text overwrite)
  └─ Section Mapping (NtCreateSection)

DEFENSE EVASION
  ├─ AMSI patch (AmsiScanBuffer → ret 0)
  ├─ ETW patch (EtwEventWrite → ret 0)
  ├─ NTDLL unhooking (fresh .text dari disk)
  ├─ Sleep obfuscation (XOR memory saat idle)
  └─ Hardware Breakpoints (DR0-DR3)

TOKEN MANIPULATION
  ├─ enumerate tokens per proses
  ├─ steal token (impersonate via PID)
  ├─ make token (LogonUser)
  ├─ runas (spawn process as other user)
  └─ revert to self

CREDENTIAL ACCESS
  ├─ LSASS minidump
  ├─ SAM/SYSTEM/SECURITY hive dump
  ├─ Browser credential harvest (Chrome, Edge, Firefox)
  └─ Clipboard read

RECONNAISSANCE
  ├─ Desktop screenshot
  ├─ Keylogger (start/dump/stop/clear)
  └─ Token enumeration

NETWORK & PIVOTING
  ├─ TCP port scan (multi-target, multi-port, banner grab)
  ├─ ARP table dump
  └─ SOCKS5 proxy listener (in-agent)

REGISTRY OPERATIONS (Windows)
  ├─ read value
  ├─ write value (REG_SZ, REG_DWORD, REG_BINARY, dll)
  ├─ delete key/value
  └─ list subkeys & values

ADVANCED
  ├─ BOF execution (Beacon Object File / COFF)
  ├─ Anti-debug check
  ├─ Anti-VM check
  ├─ Timegate (working hours + kill date runtime)
  ├─ LOLBin fetch (certutil, bitsadmin, curl, PS)
  └─ Alternate Data Stream exec (ADS)

MALLEABLE PROFILES
  ├─ office365 (OneDrive traffic)
  ├─ cdn (Cloudflare CDN)
  ├─ jquery (CDN library request)
  ├─ slack (Slack API)
  └─ ocsp (certificate OCSP request)

ADVANCED TRANSPORTS
  ├─ DNS-over-HTTPS (Cloudflare / Google)
  ├─ ICMP (IcmpSendEcho2, no raw socket needed)
  └─ SMB Named Pipe (relay pattern)

MULTI-OPERATOR TEAM SERVER
  ├─ operator registration & session ID
  ├─ agent claiming (exclusive write lock)
  ├─ real-time SSE event stream
  └─ broadcast event ke semua operator
```

---

**Selanjutnya:** [02 — Setup & Instalasi](02-setup.md)
