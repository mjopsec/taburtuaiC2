# 04 — Agent Management

## Konsep Agent

Setiap mesin yang menjalankan implant taburtuai terdaftar sebagai **agent**. Agent diidentifikasi
dengan UUID deterministik yang dibuat dari kombinasi `hostname + username + serverURL`.

Ini berarti:
- Agent yang sama di mesin yang sama selalu punya UUID yang sama
- Rebuild dan deploy ulang tidak mengubah UUID
- Operator bisa queue perintah untuk agent bahkan sebelum agent restart

---

## Daftar Agent

### `agents list`

Tampilkan semua agent yang terdaftar.

```
taburtuai(IP:PORT) › agents list
```

```
AGENT ID                             HOSTNAME         USERNAME   STATUS   LAST SEEN
-------------------------------------------------------------------------------------
2703886d-32fb-4a1c-8f2d-9b3e4c5d6e7f DESKTOP-QLPBF95  windows    online   12s ago
6a3db720-880a-4b3c-9f1d-2e5c7a8b9c0d blackout          nurkh      offline  2h ago
```

**Penjelasan kolom:**

| Kolom | Keterangan |
|---|---|
| AGENT ID | UUID unik agent (deterministik dari hostname+username) |
| HOSTNAME | Nama komputer target |
| USERNAME | User yang menjalankan agent |
| STATUS | `online` (beacon aktif) / `offline` (tidak ada beacon) |
| LAST SEEN | Kapan terakhir agent check-in |

**Status agent:**
- `online` → beacon terakhir dalam 2× interval (agent masih aktif)
- `offline` → tidak ada beacon, agent mati / jaringan terputus

### Filter dengan Prefix ID

Kamu tidak perlu mengetik UUID lengkap — cukup prefix yang unik:

```
# Ini semua valid untuk agent ID 2703886d-32fb-...
cmd 2703886d "whoami"
cmd 2703886d-32fb "whoami"
cmd 2703886d-32fb-4a1c-8f2d-9b3e4c5d6e7f "whoami"
```

---

## Detail Agent

### `agents info <id>`

Tampilkan informasi lengkap satu agent.

```
taburtuai(IP:PORT) › agents info 2703886d
```

```
[+] Agent Information:
    ID          : 2703886d-32fb-4a1c-8f2d-9b3e4c5d6e7f
    Hostname    : DESKTOP-QLPBF95
    Username    : windows
    Domain      : WORKGROUP
    OS          : windows
    Arch        : amd64
    IP          : 192.168.1.50
    Status      : online
    First Seen  : 2026-04-23 14:30:00
    Last Seen   : 2026-04-23 16:55:12
    Beacon Count: 84
    Interval    : 30s ± 20% jitter
    Exec Method : powershell
    Evasion     : enabled
    Kill Date   : 2026-12-31
```

---

## Hapus Agent

### `agents delete <id>`

Hapus record agent dari database. **Agent yang berjalan di target tidak dihentikan** —
hanya catatan di server yang dihapus. Kalau agent masih jalan dan beacon lagi, agent
akan terdaftar kembali otomatis.

```
taburtuai(IP:PORT) › agents delete 6a3db720
[!] This will remove agent 6a3db720 from the database.
[+] Agent 6a3db720 deleted successfully.
```

**Kapan perlu delete:**
- Membersihkan agent `offline` lama dari engagement sebelumnya
- Mereset agent yang UUID-nya sudah tidak valid
- Housekeeping database

---

## Command History

### `history <id>`

Lihat semua perintah yang pernah dikirim ke agent ini beserta statusnya.

```
taburtuai(IP:PORT) › history 2703886d
```

```
CMD ID         TYPE           STATUS     CREATED              OUTPUT
-----------------------------------------------------------------------
a1b2c3d4-...   execute        completed  2026-04-23 16:30:00  DESKTOP-QLPBF95\windows
e5f6g7h8-...   execute        completed  2026-04-23 16:31:00  10.0.0.1\n10.0.0.2\n...
i9j0k1l2-...   upload         completed  2026-04-23 16:32:00  File uploaded successfully
m3n4o5p6-...   persist_setup  completed  2026-04-23 16:35:00  Registry key added
```

### `status <cmd-id>`

Lihat status dan hasil satu perintah spesifik.

```
taburtuai(IP:PORT) › status a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

```
[+] Command Status:
    ID         : a1b2c3d4-e5f6-7890-abcd-ef1234567890
    Type       : execute
    Status     : completed
    Created    : 2026-04-23 16:30:00
    Executed   : 2026-04-23 16:30:12
    Exit Code  : 0
    Output     :
      DESKTOP-QLPBF95\windows
```

**Status yang mungkin:**

| Status | Keterangan |
|---|---|
| `pending` | Menunggu agent poll berikutnya |
| `executing` | Agent sedang mengeksekusi |
| `completed` | Berhasil (exit code 0) |
| `failed` | Gagal (exit code ≠ 0) |
| `timeout` | Melewati batas waktu eksekusi |

---

## Command Queue

### `queue stats`

Lihat ringkasan antrian perintah semua agent.

```
taburtuai(IP:PORT) › queue stats
```

```
[+] Queue Statistics:
    Total pending  : 3
    Total executing: 0
    Total completed: 127
    Total failed   : 2
    
    Per agent:
    2703886d: 2 pending, 125 completed
    6a3db720: 1 pending, 2 completed
```

### `queue clear <id>`

Hapus semua perintah pending untuk agent tertentu.

```
taburtuai(IP:PORT) › queue clear 2703886d
[+] Cleared 2 pending commands for agent 2703886d.
```

**Kapan perlu clear queue:**
- Agent crash dan ada perintah pending yang tidak relevan lagi
- Terlanjur queue banyak perintah yang ingin dibatalkan
- Sebelum restart agent untuk memulai sesi bersih

---

## Server Stats

### `stats`

Lihat statistik server secara keseluruhan.

```
taburtuai(IP:PORT) › stats
```

```
[+] Server Statistics:
    Uptime       : 2h 34m 12s
    Total agents : 2 (1 online, 1 offline)
    Commands     : 129 total (127 completed, 2 failed)
    Stages       : 3 active
    DB size      : 24.5 MB
```

---

## Tips Manajemen Agent

### Identifikasi Agent Berdasarkan Hostname

Kalau ada banyak agent dan lupa UUID-nya:

```
taburtuai(IP:PORT) › agents list
# Cari hostname yang kamu mau, ambil prefix ID-nya
# Misalnya: 2703886d → agents dengan hostname DESKTOP-QLPBF95
```

### Cek Agent Masih Hidup Sebelum Kirim Perintah

```
taburtuai(IP:PORT) › agents info 2703886d
# Lihat kolom Status dan Last Seen
# Kalau Last Seen > 5 menit dan status offline → agent kemungkinan sudah mati
```

### Bersihkan Agent Lama

```
taburtuai(IP:PORT) › agents list
# Identifikasi agent offline dari engagement lama
taburtuai(IP:PORT) › agents delete <id-lama>
```

---

**Selanjutnya:** [05 — Command Execution](05-execution.md)
