# Architecture

How Taburtuai C2 components connect, how traffic flows, and how the encryption model works.

---

## Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        OPERATOR SIDE                            │
│                                                                 │
│   taburtuai CLI ──────────────┐                                 │
│   Web Dashboard (Vue 3) ──────┤──── REST API (HTTP/JSON) ───┐   │
│   Direct API calls ───────────┘                              │   │
└──────────────────────────────────────────────────────────────│──┘
                                                               │
                                              ┌────────────────▼──────────────────┐
                                              │          Team Server               │
                                              │                                    │
                                              │  ┌─────────────────────────────┐   │
                                              │  │  REST API (Gin framework)   │   │
                                              │  │  50+ endpoints /api/v1/...  │   │
                                              │  └────────────┬────────────────┘   │
                                              │               │                    │
                                              │  ┌────────────▼────────────────┐   │
                                              │  │      Command Queue          │   │
                                              │  │   (per-agent, SQLite)       │   │
                                              │  └────────────┬────────────────┘   │
                                              │               │                    │
                                              │  ┌────────────▼────────────────┐   │
                                              │  │    Agent Monitor            │   │
                                              │  │  online/dormant/offline     │   │
                                              │  └─────────────────────────────┘   │
                                              └─────────────────┬──────────────────┘
                                                                │
                                                  Encrypted beacon
                                                  AES-256-GCM
                                                  over HTTP(S)
                                                                │
                                              ┌─────────────────▼──────────────────┐
                                              │              Agent                  │
                                              │                                     │
                                              │  ┌──────────────────────────────┐   │
                                              │  │       Beacon Loop            │   │
                                              │  │  1. Sleep (masked)           │   │
                                              │  │  2. POST /checkin or /beacon │   │
                                              │  │  3. Decrypt command          │   │
                                              │  │  4. Execute                  │   │
                                              │  │  5. Encrypt result           │   │
                                              │  │  6. POST /result             │   │
                                              │  └──────────────────────────────┘   │
                                              └─────────────────────────────────────┘
```

---

## Beacon Lifecycle

Every beacon cycle on the agent follows this sequence:

1. **Sleep** — wait for `interval ± jitter` seconds. During sleep, if sleep masking is enabled, agent memory pages are marked `PAGE_NOACCESS` and RC4-encrypted.
2. **Wake** — restore page permissions and decrypt memory.
3. **Check timing** — verify kill date and working hours window. If outside window, go back to sleep.
4. **Anti-debug / anti-VM checks** (if OPSEC profile enables them).
5. **Checkin POST** — send `AgentInfo` (hostname, user, OS, PID, etc.) encrypted with the session key. On first checkin, perform ECDH handshake to establish the session key.
6. **Receive command** — server responds with encrypted command JSON (or empty if no pending commands).
7. **Execute command** — dispatch to the appropriate handler.
8. **Submit result** — POST encrypted result JSON back to server.
9. **Repeat.**

---

## Encryption Model

### Phase 1 — Bootstrap (First Checkin)

The agent ships with a static `ENCRYPTION_KEY` baked in at compile time. On first contact:

1. Agent generates an ephemeral ECDH P-256 keypair.
2. Agent sends its public key encrypted with the static AES-256-GCM key.
3. Server generates its own ephemeral ECDH P-256 keypair, responds with server public key.
4. Both sides derive the shared secret via ECDH and run HKDF to produce the session key.
5. The static key is never used again for that session.

### Phase 2 — Session

All subsequent traffic (commands, results, file data) uses the ECDH-derived session key via AES-256-GCM. Each message uses a random 12-byte nonce prepended to the ciphertext.

**Why this matters:** Capturing the static key from the binary does not decrypt captured session traffic. Each session has a unique key derived from ephemeral ECDH material.

---

## Malleable C2 Profiles

The server-side profile controls how agent HTTP requests look to network observers.

```
Agent builds a request:
  URI    : chosen by profile (e.g. /ews/exchange.asmx/agent-uuid for Office365)
  Headers: profile-defined (Accept, Content-Type, User-Agent)
  Body   : AES-GCM ciphertext, base64-encoded

Server routes on URI prefix → dispatches to same handler regardless of profile
```

Profile-specific URI routing means an Office365 profile agent and a default profile agent can both connect to the same server while generating completely different HTTP fingerprints.

---

## Multi-Operator Team Server

The team server supports multiple concurrent operators with collision avoidance:

- **Claim/release** — an operator claims exclusive write access to an agent. Other operators can still read but cannot queue commands until the claim is released.
- **SSE event stream** — operators subscribe to a live event stream (`/api/v1/team/events`) receiving agent check-ins, command completions, and operator broadcast messages.
- **Broadcast** — send notes to all connected operators (e.g. "pivoting through 10.0.0.5 now").

---

## Agent Status

The server's agent monitor tracks each agent's status based on last-seen time:

| Status | Threshold | Commands |
|--------|-----------|---------|
| `online` | Beaconed within `AGENT_DORMANT_SEC` (default 600s) | Accepted and queued |
| `dormant` | 600s – 1800s since last beacon | **Still accepted and queued** — delivered on next wake |
| `offline` | > `AGENT_OFFLINE_SEC` (default 1800s) | Rejected |

Dormant is not dead. A slow-beacon stealth agent beaconing every 5 minutes will appear dormant between beacons — commands queued during that time are delivered on the next check-in.

---

## Storage

SQLite (via `modernc.org/sqlite` — pure Go, no CGo) stores:

| Table | Contents |
|-------|---------|
| `agents` | UUID, hostname, username, OS, last_seen, status |
| `commands` | UUID, agent_id, type, payload, status, result, timestamps |
| `staged_payloads` | token, name, binary, created_at |

Commands survive server restarts. An agent that reconnects after the server rebooted picks up any pending commands from the queue.
