# taburtuaiC2 — Development Roadmap

> Goal: enterprise-grade modular C2 that surpasses Cobalt Strike, Havoc, and Sliver in technique depth and implementation quality.  
> Approach: phased, test-as-you-build. Each phase ships a working, operator-usable capability increment.

---

## Already Shipped

| Phase | Capability |
|-------|-----------|
| 1 | Basic C2: checkin, exec (cmd/powershell/wmi/mshta), upload/download, process management |
| 1 | Persistence: registry_run, schtasks, startup_folder, cron_reboot, systemd_user, bashrc, launchagent |
| 1 | Build profiles (default/opsec/stealth/paranoid), garble obfuscation, goversioninfo PE masquerade |
| 1 | NTFS ADS: write/read/exec via LOLBin |
| 1 | LOLBin fetch: certutil/bitsadmin/curl/powershell |
| 2 | Process injection: CRT + APC into remote process |
| 2 | Fileless in-memory exec (inject self, no disk write) |
| 2 | PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS |
| 2 | Timestomping (copy timestamps from reference file or explicit RFC3339 time) |
| 2 | Staged payload delivery (fetch URL → base64 → inject in-memory) |

---

## Phase 3 — EDR Bypass Fundamentals ← **Current**

| # | Technique | File | Status |
|---|-----------|------|--------|
| 3.1 | AMSI byte-patch (in-process + remote PID) | agent/amsi_windows.go | ✅ |
| 3.2 | ETW byte-patch (EtwEventWrite, in-process + remote) | agent/etw_windows.go | ✅ |
| 3.3 | Token steal + impersonate (from any process) | agent/token_windows.go | ✅ |
| 3.4 | make_token (LogonUser, lateral movement) | agent/token_windows.go | ✅ |
| 3.5 | Token revert (revert to self) | agent/token_windows.go | ✅ |
| 3.6 | Screenshot capture (GDI BitBlt → PNG → base64) | agent/screenshot_windows.go | ✅ |
| 3.7 | Keylogger: start/dump/stop (polling GetAsyncKeyState) | agent/keylog_windows.go | ✅ |
| 3.8 | Persistence: Windows Service (sc.exe) | agent/persistence.go | ✅ |
| 3.9 | Persistence: WMI Event Subscription | agent/persistence.go | ✅ |

---

## Phase 4 — Advanced Process Injection

| # | Technique | Notes |
|---|-----------|-------|
| 4.1 | Process hollowing | Suspend → NtUnmapViewOfSection → remap PE → SetThreadContext → Resume |
| 4.2 | Ghost process injection | NtCreateSection from file marked delete-pending → hollow |
| 4.3 | Module stomping (local) | Overwrite legitimate DLL's .text section |
| 4.4 | Remote module stomping | Same across process boundary |
| 4.5 | Local mapping injection | NtCreateSection + NtMapViewOfSection → execute |
| 4.6 | Remote mapping injection | Cross-process shared section |
| 4.7 | Thread hijacking | Suspend + GetThreadContext + patch RIP + Resume |
| 4.8 | Threadless injection | HijackExport → overwrite + restore without spawning thread |
| 4.9 | Reflective DLL injection | Self-loading DLL from memory (no LoadLibrary) |
| 4.10 | sRDI — Shellcode Reflective DLL Injection | Convert PE/DLL to position-independent shellcode |
| 4.11 | Local PE execution (fileless) | Map + fix imports + run PE entirely in memory |
| 4.12 | Proxy execute via Timer APIs | NtAllocateVirtualMemory → execute via CreateTimerQueueTimer callback |
| 4.13 | Proxy execute via Work Item APIs | RtlQueueWorkItem / TpAllocWork |

---

## Phase 5 — Credential Access

| # | Technique | Notes |
|---|-----------|-------|
| 5.1 | LSASS minidump via MiniDumpWriteDump | Classic, high-noise |
| 5.2 | LSASS via handle duplication | Duplicate handle from existing open handle in another process |
| 5.3 | LSASS via RtlReportSilentProcessExit | Trigger WER to produce dump without opening LSASS |
| 5.4 | LSASS via Seclogon race condition | seclogon handle hijack technique |
| 5.5 | SAM database dump (reg save HKLM\SAM) | Local offline dump |
| 5.6 | SAM dump from disk (VSS shadow copy) | Volume Shadow Copy bypass |
| 5.7 | Chrome cookies (DPAPI AES-256-GCM) | Encrypted cookie decryption |
| 5.8 | Chrome saved credentials (Login Data SQLite) | Master password bypass |
| 5.9 | Firefox cookies (cookies.sqlite) | SQLite extraction |
| 5.10 | Firefox saved credentials (key4.db + logins.json) | NSS key derivation |
| 5.11 | Clipboard capture (GetClipboardData) | Credential/OTP harvesting |

---

## Phase 6 — Sleep Obfuscation & Memory Encryption

| # | Technique | Notes |
|---|-----------|-------|
| 6.1 | Ekko sleep obfuscation | ROP chain: NtSetTimer → encrypt image → sleep → decrypt → resume |
| 6.2 | Ekko + stack spoofing | Fake legitimate call stack during sleep window |
| 6.3 | Heap encryption during Ekko sleep | Encrypt heap allocations while inactive |
| 6.4 | Foliage sleep obfuscation | Alternative ROP-based sleep encrypt |
| 6.5 | RtlEncryptMemory / RtlDecryptMemory | Native API for memory encryption |
| 6.6 | PeFluctuation | Change PE section permissions (RW→RX) during sleep |

---

## Phase 7 — Syscalls & NTDLL Unhooking

| # | Technique | Notes |
|---|-----------|-------|
| 7.1 | Direct syscalls (static SSN table) | Embed syscall numbers for Win10/11 |
| 7.2 | Hell's Gate — dynamic SSN resolution | Read SSN from ntdll memory at runtime |
| 7.3 | Halo's Gate — hooked stub bypass | Find SSN from nearby unhooked stub |
| 7.4 | NTDLL unhooking: fresh copy from disk | Map ntdll.dll from disk, overwrite hooked stubs |
| 7.5 | NTDLL unhooking: via KnownDlls section | Use KnownDlls\\ntdll handle for clean copy |
| 7.6 | NTDLL unhooking: via suspend/resume trick | Use another thread to copy clean ntdll |
| 7.7 | KnownDll cache poisoning injection | Write shellcode to KnownDlls section |
| 7.8 | API set name resolution (ApiSetMap walking) | Handle API-MS-Win forwarded exports correctly |

---

## Phase 8 — Hardware Breakpoint (HWBP) Techniques

| # | Technique | Notes |
|---|-----------|-------|
| 8.1 | VEH-based HWBP hooking | Set DR0-DR3 via SetThreadContext, handle via VEH |
| 8.2 | Patchless AMSI bypass via HWBP | Hook AmsiScanBuffer return without writing to .text |
| 8.3 | Patchless ETW bypass via HWBP | Hook EtwEventWrite without writing to .text |
| 8.4 | Tampered syscalls via HWBP | Intercept + modify syscall arguments in VEH handler |
| 8.5 | Threadless injection via HWBP BoF | Overwrite export → HWBP to restore after execution |
| 8.6 | Credential dumping via HWBP | Hook NtReadVirtualMemory, redirect reads |

---

## Phase 9 — BOF Engine & In-Process Execution

| # | Technique | Notes |
|---|-----------|-------|
| 9.1 | COFF BoF loader (CS-compatible) | Parse COFF object, resolve BeaconAPI, execute |
| 9.2 | .NET assembly in-memory (CLR hosting) | ICLRRuntimeHost::ExecuteInDefaultAppDomain |
| 9.3 | PowerShell runspace (in-process) | CLR + System.Management.Automation |
| 9.4 | Fiber-based payload execution | ConvertThreadToFiber → CreateFiber → SwitchToFiber |
| 9.5 | VEH-based local code execution | Trigger AV exception → restore + redirect to shellcode |
| 9.6 | Execution via callback APIs | EnumWindows, SetTimer, EnumChildWindows |
| 9.7 | Custom assembly emission (runtime shellcode) | Generate position-independent shellcode at runtime |

---

## Phase 10 — Anti-Analysis & Expert Evasion

| # | Technique | Notes |
|---|-----------|-------|
| 10.1 | Anti-debug: multi-method | IsDebuggerPresent, NtQueryInformationProcess, heap flag |
| 10.2 | Anti-VM: multi-method | CPUID, RDTSC timing, MAC OUI check, registry artifacts |
| 10.3 | TLS callbacks for anti-debug | Execute before main entry point via TLS |
| 10.4 | Working hours enforcement | Kill if outside configured hours |
| 10.5 | Kill date | Self-destruct after date |
| 10.6 | IP whitelist / domain kill switch | Verify target environment before activating |
| 10.7 | File bloating (entropy reduction) | Append junk to lower file entropy score |
| 10.8 | Compile-time string encryption | XOR key baked in at build time, decrypt at runtime |
| 10.9 | IAT obfuscation (delay + forwarding) | Mask imports, use forwarded export chains |
| 10.10 | BYOVD | RTCore64 / gdrv / WinRing0 for kernel access |
| 10.11 | DLL sideloading | at.exe, Microsoft Teams, OneDrive targets |
| 10.12 | Steganography loader | Extract shellcode from PNG/JPEG pixel data |
| 10.13 | PE packer | Runtime LZ4/zlib compress → decompress + execute |
| 10.14 | Self-signed binary signing | Fake Authenticode cert embedded at build |

---

## Phase 11 — C2 Protocol & Infrastructure Hardening

| # | Technique | Notes |
|---|-----------|-------|
| 11.1 | Malleable HTTP profiles | Mimic OCSP/CDN/Office365 traffic patterns |
| 11.2 | Domain fronting | CDN (Cloudflare/Fastly) front with real host header |
| 11.3 | DNS-over-HTTPS beacon | Covert channel via DoH (Cloudflare/Google) |
| 11.4 | ICMP C2 channel | Data exfil via ICMP echo payload |
| 11.5 | SMB named pipe transport | Lateral movement via \\.\pipe\ |
| 11.6 | SQLite persistence store | Durable encrypted command/result history |
| 11.7 | Multi-operator team server | Shared session state, role-based access |

---

## Technique Count

| Phase | Count | ETA |
|-------|-------|-----|
| 3 EDR Bypass Fundamentals | 9 | **Done** |
| 4 Advanced Injection | 13 | Week 2 |
| 5 Credential Access | 11 | Month 2 |
| 6 Sleep Obfuscation | 6 | Month 2 |
| 7 Syscalls & Unhooking | 8 | Month 3 |
| 8 HWBP Techniques | 6 | Month 3 |
| 9 BOF Engine | 7 | Month 4 |
| 10 Anti-Analysis | 14 | Month 4-5 |
| 11 C2 Protocol | 7 | Month 5-6 |
| **Total** | **81** | — |
