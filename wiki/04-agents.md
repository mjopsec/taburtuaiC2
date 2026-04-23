# 04 — Agent Management

## Konsep Agent

Setiap mesin yang menjalankan implant Taburtuai terdaftar sebagai **agent**. Agent diidentifikasi
oleh UUID deterministik yang di-derive dari `SHA256(hostname + username + c2_server_url)`.

**Implikasi UUID deterministik:**
- Agent yang restart di mesin yang sama → UUID tetap sama (tidak duplikat di list)
- Tidak ada identifier random yang bisa di-fingerprint di binary
- Operator bisa predict UUID sebelum agent connect (untuk pre-claim)

**Siklus hidup agent:**
```
Stager dijalankan
    │
    ▼
Agent download & start
    │
    ▼
Registration (POST /beacon) → terdaftar di monitor
    │
    ▼
Poll loop (GET /beacon setiap interval ± jitter)
    │
    ├── Agent aktif → status: online
    └── Tidak beacon > 3x interval → status: offline
```

---

## List Semua Agent

### Via Console

```
taburtuai(IP:8000) › agents list
```

**Output (banyak agent):**
```
[+] Found 4 agent(s):

AGENT ID         HOSTNAME           USERNAME        OS       ARCH   STATUS   LAST SEEN
2703886d         DESKTOP-QLPBF95    john.doe        windows  x64    online   5s ago
3a14f22b         CORP-WS-042        SYSTEM          windows  x64    online   12s ago
9c821d77         FILESERVER-01      administrator   windows  x64    offline  4m 32s ago
b71e9c34         UBUNTU-DEV         root            linux    x64    online   8s ago
```

**Kolom yang ditampilkan:**

| Kolom | Keterangan |
|-------|------------|
| AGENT ID | 8 karakter pertama UUID (untuk prefix matching) |
| HOSTNAME | Nama mesin target |
| USERNAME | User yang menjalankan agent |
| OS | `windows` / `linux` / `darwin` |
| ARCH | `x64` / `x86` |
| STATUS | `online` / `offline` |
| LAST SEEN | Waktu beacon terakhir |

### Filter Status

```
taburtuai(IP:8000) › agents list --status online
```

**Output:**
```
[+] Found 3 online agent(s):

AGENT ID         HOSTNAME           USERNAME        STATUS   LAST SEEN
2703886d         DESKTOP-QLPBF95    john.doe        online   5s ago
3a14f22b         CORP-WS-042        SYSTEM          online   12s ago
b71e9c34         UBUNTU-DEV         root            online   8s ago
```

### Via CLI (Non-Interactive)

```bash
./bin/operator agents list --server http://IP:8000
./bin/operator agents list --server http://IP:8000 --status online
./bin/operator agents list --server http://IP:8000 --format json
```

**Output JSON:**
```json
[
  {
    "id": "2703886d-32fb-4a1c-8f2d-9b3e4c5d6e7f",
    "hostname": "DESKTOP-QLPBF95",
    "username": "john.doe",
    "os": "windows",
    "arch": "amd64",
    "status": "online",
    "ip": "192.168.1.105",
    "pid": 4512,
    "last_seen": "2026-04-23T09:05:42Z",
    "registered_at": "2026-04-23T08:00:00Z",
    "beacon_interval": 30,
    "version": "1.0"
  }
]
```

---

## Info Detail Agent

```
taburtuai(IP:8000) › agents info 2703886d
```

**Output:**
```
[+] Agent: 2703886d-32fb-4a1c-8f2d-9b3e4c5d6e7f

  Hostname     : DESKTOP-QLPBF95
  Username     : john.doe
  OS           : windows (Microsoft Windows 11 Home, Build 22621)
  Architecture : amd64
  IP Address   : 192.168.1.105
  Process ID   : 4512
  Process Name : agent_windows_stealth.exe

  Status       : online
  Last Seen    : 5 seconds ago (2026-04-23T09:05:42Z)
  Registered   : 2026-04-23T08:00:00Z (1h 5m ago)
  Uptime       : 1h 5m 42s

  Beacon       : interval=30s  jitter=20%
  Transport    : http
  Version      : 1.0

  Commands     : 47 total  (42 completed, 2 failed, 3 pending)
```

---

## Prefix Matching (Shorthand ID)

Tidak perlu mengetik UUID penuh — cukup 8 karakter pertama yang unique:

```
taburtuai(IP:8000) › cmd 2703886d "whoami"
# sama dengan
taburtuai(IP:8000) › cmd 2703886d-32fb-4a1c-8f2d-9b3e4c5d6e7f "whoami"
```

Kalau prefix tidak unique (dua agent yang ID-nya mulai sama), console akan menampilkan error:
```
[!] Ambiguous agent ID '27': multiple matches found
    2703886d DESKTOP-QLPBF95
    2709ab12 CORP-WS-013
[i] Provide more characters to disambiguate.
```

---

## Stats Server

```
taburtuai(IP:8000) › stats
```

**Output:**
```
[+] Server Statistics

  Server uptime  : 3h 42m 15s
  Total agents   : 4   (3 online, 1 offline)
  Commands       : 124 total  (118 completed, 6 failed)
  Queue backlog  : 0 pending commands

  Memory usage   : 48 MB
  Goroutines     : 24
  Go version     : go1.21.5
  OS/Arch        : linux/amd64

  Team operators : 2 connected
```

---

## Hapus Agent

Hapus agent dari daftar (tidak mematikan proses agent di target):

```
taburtuai(IP:8000) › agents delete 2703886d
```

**Output:**
```
[*] Deleting agent 2703886d...
[?] Are you sure? Agent and all command history will be removed. (y/N): y
[+] Agent 2703886d deleted.
[i] Note: Agent process may still be running on the target machine.
```

> **Perhatian:** Menghapus agent tidak mematikan proses di target. Agent yang masih hidup
> akan re-register dengan UUID yang sama saat beacon berikutnya.

---

## Monitor Real-Time

Pantau semua agent secara real-time (update setiap 5 detik):

```
taburtuai(IP:8000) › monitor
```

**Output (refresh otomatis):**
```
[Live Monitor — Ctrl+C to exit]
Last update: 09:10:42

AGENT ID         HOSTNAME           STATUS   LAST SEEN   PENDING   COMPLETED
2703886d         DESKTOP-QLPBF95    online   2s ago      0         47
3a14f22b         CORP-WS-042        online   8s ago      1         23
9c821d77         FILESERVER-01      offline  5m ago      0         12
b71e9c34         UBUNTU-DEV         online   4s ago      0         8
```

---

## Update Beacon Interval (Runtime)

Ubah interval beacon tanpa rebuild agent:

```
taburtuai(IP:8000) › cmd 2703886d "sleep 60 20"
```

Perintah ini menginstruksikan agent mengubah interval ke 60 detik dengan jitter 20%
untuk sesi saat ini (reset ke default setelah restart).

---

## Beacon Interval dan Deteksi

Interval default dan cara kerjanya:

```
Interval = 30 detik
Jitter   = 20%

Waktu aktual antar beacon:
  Minimum = 30 × (1 - 0.20) = 24 detik
  Maximum = 30 × (1 + 0.20) = 36 detik
  Random antara 24-36 detik setiap poll
```

**Rekomendasi per skenario:**

| Skenario | Interval | Jitter | Alasan |
|----------|----------|--------|--------|
| Lab/testing | 10s | 10% | Cepat, tidak perlu stealth |
| Engagement aktif | 30s | 20% | Balance antara responsif dan stealth |
| Reconnaissance diam-diam | 120s | 30% | Susah dideteksi pola-nya |
| Long-haul persistence | 300s | 40% | Minimal network noise |

---

## Offline Agent

Agent dengan status `offline` sudah tidak beacon dalam waktu `3 × interval`.
Bisa karena:
1. Mesin target dimatikan/reboot
2. Proses agent di-kill
3. Network connectivity problem
4. Kill date tercapai
5. Working hours di luar jam aktif

Agent offline **tidak dihapus otomatis** — tetap ada di list sampai operator menghapusnya.
Jika agent aktif kembali, status otomatis berubah ke `online`.

---

**Selanjutnya:** [05 — Command Execution](05-execution.md)
