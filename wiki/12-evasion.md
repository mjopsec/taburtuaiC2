# Evasion

Techniques to bypass endpoint detection: AMSI patching, ETW suppression, NTDLL unhooking, hardware breakpoints, and sleep masking.

---

## Why Evasion Matters

Modern EDR products (CrowdStrike, SentinelOne, MDE) hook Windows APIs at multiple layers:

1. **AMSI (Antimalware Scan Interface)** — any PowerShell or .NET code is scanned before execution
2. **ETW (Event Tracing for Windows)** — kernel and user-mode telemetry feeds EDR real-time
3. **Userland hooks** — EDR injects a DLL into your process and patches `ntdll.dll` functions to intercept every syscall

The evasion techniques below address each layer. Apply them in order before running anything detectable.

---

## Recommended Order of Operations

Before running any tools or injection on a monitored target:

```
1. evasion unhook    → remove EDR's userland hooks from NTDLL
2. bypass amsi       → patch AMSI (before any PowerShell or .NET)
3. bypass etw        → suppress ETW telemetry
4. (proceed with injection, creds, etc.)
```

---

## AMSI Bypass

AMSI intercepts calls from PowerShell, VBScript, JScript, .NET, and other scripting engines and passes the content to registered AV/EDR engines for scanning. Patching it makes those engines receive an empty or clean buffer.

### Patch Agent's Own Process

```
❯ bypass amsi a1b2
[*] Patching AmsiScanBuffer in agent process...
[+] AMSI bypass applied.
```

**What this does:** Overwrites the first few bytes of `AmsiScanBuffer` in `amsi.dll` with a `ret 0` instruction (returns `AMSI_RESULT_CLEAN` without scanning). This affects the agent's process only.

**When to use:** Before running PowerShell commands via the agent, before `.NET` assembly execution, before using PS runspace.

### Patch a Remote Process

If you've already injected into a remote process and want to run PowerShell from that context:

```
❯ bypass amsi a1b2 --pid 4208
[*] Patching AmsiScanBuffer in PID 4208...
[+] AMSI bypass applied in remote process.
```

**Note:** Patching AMSI in a remote process requires `PROCESS_VM_WRITE` access, which means the target must be at the same or lower integrity level, or you need admin rights.

---

## ETW Bypass

ETW feeds kernel events, API call sequences, and PowerShell script block logging to EDR. Patching `EtwEventWrite` in the agent's process prevents those events from being generated.

```
❯ bypass etw a1b2
[*] Patching EtwEventWrite in agent process...
[+] ETW bypass applied.
```

**What this does:** Patches `EtwEventWrite` in `ntdll.dll` within the agent's process to `ret 0`. Any ETW event the agent would generate is silently discarded.

**Limitation:** This patches the user-mode ETW provider. Kernel-mode ETW (Kernel Tracing, PPL-protected telemetry) is not affected. On MDE/EDR with kernel sensors, some events still reach the cloud.

---

## NTDLL Unhooking

EDR products inject a monitoring DLL into every process at startup and patch `ntdll.dll` functions (NtOpenProcess, NtCreateThreadEx, NtAllocateVirtualMemory, etc.) to redirect calls through their hooks before reaching the kernel.

Unhooking restores the original, clean `ntdll.dll` `.text` section from a fresh copy on disk, removing all EDR patches.

```
❯ evasion unhook a1b2
[*] Restoring NTDLL .text section from disk...
[+] NTDLL unhooked successfully.
```

**How it works:**
1. Opens `C:\Windows\System32\ntdll.dll` from disk using a file handle that bypasses user-mode hooks
2. Maps the clean copy into memory
3. Locates the `.text` section of the already-loaded in-memory `ntdll.dll`
4. Changes page protections to RW
5. Copies the clean `.text` section over the hooked one
6. Restores protections to RX

**Why this is powerful:** After unhooking, all subsequent syscall wrappers in the agent's process go through the unpatched code path. Most EDR userland hooks are effectively removed.

**Limitations:**
- Kernel-mode hooks (via PatchGuard callbacks) are not affected
- EDRs with PPL (Protected Processes Light) or Kernel Callbacks may still see kernel-level events
- The act of replacing NTDLL .text is itself suspicious if detected

---

## Hardware Breakpoints (HWBP)

Install or remove debug hardware breakpoints (DR0–DR3) via Vectored Exception Handler (VEH), without setting the `IsDebugged` flag in the PEB.

```
# Install a hardware breakpoint on a specific address (e.g., AmsiScanBuffer)
❯ evasion hwbp set a1b2 --addr 0x00007FFAB1234567 --register 0

# Remove it
❯ evasion hwbp clear a1b2 --register 0
```

**Use case:** Advanced AMSI/ETW bypass that doesn't modify function bytes. Instead of patching `AmsiScanBuffer`, install a DR0 hardware breakpoint on it. When AMSI calls the function, the CPU raises a `EXCEPTION_SINGLE_STEP` exception, the VEH handler intercepts it and can modify the return value or arguments — then resumes execution.

**Advantages over byte patching:**
- No memory modification detectable by integrity scanners
- The function bytes remain intact — patch-detection mechanisms won't fire
- Works even when the target memory page has restricted write permissions

**Use case scenario:** Some EDRs monitor `VirtualProtect` calls that change page protections (which traditional byte-patching requires). HWBP bypass avoids that entirely.

---

## Sleep Masking

During sleep periods, the agent's own memory (including its shellcode) is XOR-encrypted and page permissions are set to `PAGE_NOACCESS`. Memory scanners that scan sleeping processes find no readable executable content.

This is configured at build time:
```bash
./bin/taburtuai-generate stageless --sleep-mask --profile opsec ...
```

Or triggered for a specific duration at runtime:
```
❯ evasion sleep a1b2 --duration 30
[*] Obfuscated sleep for 30 seconds...
[+] Sleep complete.
```

**How it works in the agent:**
1. Before sleeping, the agent calculates which PE sections to mask (non-.text2 sections + tracked heap blocks)
2. RC4-encrypts all those regions using a random key
3. Calls `VirtualProtect(PAGE_NOACCESS)` on each region
4. Sleeps via a spoofed call stack (`NtWaitForSingleObject` via ROP chain)
5. On wake, restores `PAGE_EXECUTE_READ` permissions and RC4-decrypts

**Why the spoofed call stack:** While sleeping, if an EDR inspects the thread's call stack, it should see something plausible (e.g., `ntdll!NtWaitForSingleObject` called from `kernel32!SleepEx`) rather than your agent's functions. The call stack is forged using a ROP chain.

**The .text2 section:** Functions that run during sleep (the sleep routine itself, the memory masking code) live in a special `.text2` section that is never masked — it must remain executable to unmask everything else.

---

## Anti-Debug and Anti-VM Checks

Run checks to detect if the agent is running inside a debugger, VM, or sandbox before doing anything:

```
❯ opsec antidebug a1b2
[*] Running anti-debug checks...
[+] No debugger detected.

❯ opsec antivm a1b2
[*] Running anti-VM/sandbox checks...
[+] No VM/sandbox detected.
```

**What gets checked:**

| Check | Mechanism |
|-------|-----------|
| Debugger present | `IsDebuggerPresent()`, `NtQueryInformationProcess(ProcessDebugPort)` |
| PEB being debugged | Read `PEB.BeingDebugged` flag directly |
| Timing check | RDTSC delta — VM execution is slower than native |
| VM artifacts | Registry keys for VirtualBox, VMware, Hyper-V |
| Sandbox artifacts | CPUID hypervisor bit, known sandbox processes |
| Hardware check | Low physical CPU count, insufficient RAM |

**When to use:** Before any OPSEC-sensitive operation on a target you're not 100% sure is real. Sandboxes and detonation chambers often have these detectable characteristics.

If checks fire positive, abort the current operation. The engagement may be a honeypot or the sample is being analyzed.

---

## Combining Evasion (Recommended Pattern)

For a monitored Windows target with MDE or CrowdStrike:

```
# 1. Remove EDR userland hooks first
❯ evasion unhook a1b2

# 2. Patch AMSI so PowerShell isn't scanned
❯ bypass amsi a1b2

# 3. Suppress ETW telemetry
❯ bypass etw a1b2

# 4. Verify environment is real (not sandboxed/debugged)
❯ opsec antidebug a1b2
❯ opsec antivm a1b2

# 5. Now run your techniques safely
❯ creds lsass a1b2
❯ inject remote a1b2 --pid 1124 --file sc.bin --method map
```
