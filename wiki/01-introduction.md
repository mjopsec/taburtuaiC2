# 01 — Introduction

## Apa itu Taburtuai C2?

**Taburtuai** adalah Command & Control (C2) framework yang dirancang untuk red team operations
dan authorized penetration testing. Framework ini memungkinkan operator untuk:

- Mengendalikan agent (implant) yang berjalan di mesin target
- Melaksanakan teknik post-exploitation secara terstruktur dan OPSEC-aware
- Mengirimkan payload secara staged maupun stageless
- Mengeksekusi berbagai teknik evasion, injection, credential access, dan pivoting

Nama "Taburtuai" berasal dari bahasa lokal yang berarti "penghubung yang tersembunyi" —
mencerminkan filosofi framework ini: komunikasi tersembunyi antara operator dan target.

---

## Komponen Utama

```
taburtuaiC2/
├── bin/
│   ├── server       ← C2 server (terima beacon agent, tampung perintah)
│   ├── operator     ← CLI operator (beri perintah, lihat hasil)
│   ├── generate     ← Builder (compile agent/stager, buat delivery template)
│   └── agent_windows_stealth.exe ← Implant agent Windows
└── wiki/            ← Dokumentasi (sedang kamu baca ini)
```

### 1. C2 Server (`bin/server`)

Otak dari seluruh sistem. Fungsinya:

- Menerima beacon (check-in) dari agent secara periodik
- Menyimpan antrian perintah untuk setiap agent
- Melayani endpoint stager (`/stage/<token>`) untuk staged delivery
- Menyimpan semua data ke SQLite database (`data/taburtuai.db`)
- Mengenkripsi semua payload dengan AES-256-GCM

```
C2 Server mendengarkan di satu port:
  /beacon                → endpoint agent (poll command, kirim hasil)
  /stage/<token>         → endpoint stager (download payload sekali)
  /api/v1/*              → endpoint operator (autentikasi API key)
```

### 2. Operator CLI (`bin/operator`)

Tool yang dipakai oleh red teamer untuk:

- Mengelola agent (list, info, delete)
- Mengirim perintah ke agent
- Mengambil hasil eksekusi
- Upload/download file
- Akses interactive shell

Dua mode penggunaan:
- **Standalone CLI**: `./bin/operator agents list --server http://IP:PORT`
- **Interactive console**: `./bin/operator console --server http://IP:PORT`

### 3. Implant Builder (`bin/generate`)

Mengkompilasi agent/stager dengan konfigurasi yang di-bake langsung ke binary:

- **`generate stager`** — kompilasi stager minimal + bungkus ke format delivery
- **`generate stageless`** — kompilasi full agent self-contained
- **`generate template`** — buat delivery template (ClickFix, macro, HTA, LNK, ISO)

### 4. Agent (Implant)

Binary yang berjalan di mesin target. Karakteristik:

- Cross-platform: mendukung Windows (amd64/x86), Linux, macOS
- Beacon-based: agent yang hubungi server, bukan sebaliknya (firewall friendly)
- Semua komunikasi dienkripsi AES-256-GCM
- UUID deterministik: sama agent di mesin sama = UUID sama
- Kill date, working hours, jitter — built-in OPSEC controls

---

## Arsitektur Komunikasi

```
┌──────────────┐   HTTPS/HTTP (encrypted)   ┌──────────────┐
│   OPERATOR   │ ─────────────────────────► │  C2 SERVER   │
│  (red team)  │ ◄─────────────────────────  │  (internet)  │
└──────────────┘   REST API + AES payload   └──────┬───────┘
                                                   │
                                     beacon poll (setiap N detik)
                                                   │
                                            ┌──────▼───────┐
                                            │    AGENT     │
                                            │   (target)   │
                                            └──────────────┘
```

### Alur Komunikasi

1. **Agent startup** → agent generate UUID dari hostname+username+C2URL (deterministik)
2. **Registration** → POST `/beacon` dengan info host (OS, arch, username, hostname)
3. **Poll loop** → GET `/beacon` setiap interval+jitter detik → server kirim perintah
4. **Eksekusi** → agent eksekusi perintah → kirim hasil ke server
5. **Operator** → operator poll API → lihat hasil perintah

### Enkripsi

Semua payload dienkripsi berlapis:

```
Layer 1: Transport — HTTP biasa (cleartext transport layer)
Layer 2: Application — AES-256-GCM dengan nonce random per request
         Key = ENCRYPTION_KEY (di-bake ke agent saat compile)
Layer 3: Stage — payload staged delivery di-enkripsi AES-256-GCM di database
```

> **Catatan:** Transport layer menggunakan HTTP (bukan HTTPS) secara default.
> Untuk production engagement, gunakan HTTPS dengan reverse proxy (nginx/caddy)
> atau rencanakan pengembangan HTTPS native di versi mendatang.

---

## Model Threat (Apa yang Disembunyikan)

| Artefak | Taburtuai | Keterangan |
|---|---|---|
| Network traffic pattern | Disamarkan | Interval + jitter mencegah deteksi pola reguler |
| Payload di disk | Opsional | Staged delivery bisa fileless (agent tidak pernah di disk) |
| Console window | Disembunyikan | `-H windowsgui` + CREATE_NO_WINDOW + HideWindow |
| Agent identity | Tersembunyi | UUID deterministik, tidak expose metadata build |
| C2 server | Tersembunyi | Hanya satu port, semua endpoint terlihat seperti web biasa |
| Komunikasi agent | Terenkripsi | AES-256-GCM, tidak bisa dibaca dari network dump |

---

## OPSEC Profile Agent

Saat build agent, kamu bisa mengkonfigurasi OPSEC profile:

| Parameter | Fungsi | Default |
|---|---|---|
| `INTERVAL` | Berapa detik antar beacon | `30` |
| `JITTER` | Variasi interval (% random) | `20` |
| `KILL_DATE` | Tanggal agent berhenti otomatis | kosong (tidak mati) |
| `WORKING_HOURS` | Jam kerja (agent aktif saat jam kerja saja) | mati |
| `ENABLE_EVASION` | Aktifkan fitur evasion | `true` |
| `SLEEP_MASKING` | Obfuscate memori saat idle | `true` |
| `EXEC_METHOD` | Cara eksekusi shell command | `powershell` |

---

## Fase Pengembangan

Taburtuai dikembangkan secara bertahap:

| Fase | Fitur | Status |
|---|---|---|
| Core | Beacon, shell execution, file ops | Selesai |
| Level 2 | Injection, timestomp, staged delivery | Selesai |
| Phase 3 | AMSI/ETW bypass, token ops, screenshot, keylog | Selesai |
| Phase 4 | Hollow, hijack, stomp, mapinject | Dalam pengembangan |
| Phase 5 | LSASS, SAM, browser creds, clipboard | Planned |
| Phase 6-8 | Sleep obf, unhook NTDLL, HWBP | Planned |
| Phase 9 | BOF execution | Planned |
| Phase 10 | Anti-debug, anti-VM, timegate | Planned |
| Phase 11 | Net scan, ARP scan, SOCKS5, registry, pivoting | Planned |

---

**Selanjutnya:** [02 — Setup & Instalasi](02-setup.md)
