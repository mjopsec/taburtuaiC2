# Agent Management

How to list, inspect, and manage connected agents.

---

## Listing Agents

```
❯ agents list
```

**Output:**
```
[+] Found 3 agent(s)

AGENT ID                             HOSTNAME             USERNAME        STATUS     LAST SEEN           
----------------------------------------------------------------------------------------------------
a1b2c3d4-e5f6-7890-abcd-ef1234567890 WIN-DC01             corp\svc_backup  online     2026-04-25 14:23:01
b2c3d4e5-f6a7-8901-bcde-f01234567890 WORKSTATION-07       corp\jsmith      dormant    2026-04-25 14:15:42
c3d4e5f6-a7b8-9012-cdef-012345678901 FILESERVER-02        corp\admin       online     2026-04-25 14:22:58
```

**Status meanings:**
- `online` — beaconed within the last 10 minutes (configurable via `AGENT_DORMANT_SEC`)
- `dormant` — no beacon for 10–30 minutes; commands still accepted and queued
- `offline` — no beacon for >30 minutes; commands rejected

---

## Agent Details

```
❯ agents info a1b2
```

**Output:**
```
Agent Information
--------------------------------------------------
ID                 a1b2c3d4-e5f6-7890-abcd-ef1234567890
Hostname           WIN-DC01
Username           corp\svc_backup
OS                 windows
Architecture       amd64
Status             online
Last Seen          2026-04-25 14:23:01
First Contact      2026-04-24 09:14:33
Commands Executed  47
--------------------------------------------------
```

Use this to verify the exact context — especially `Username` and `Hostname` — before running privilege-requiring commands like LSASS dump or token steal.

---

## Removing an Agent

```
❯ agents delete a1b2
[+] Agent a1b2c3d4... removed
```

This removes the agent's database record. If the agent binary is still running on the target, it will re-register on its next beacon as a new entry.

**When to use:** Clean up stale offline agents, or remove an agent you've intentionally terminated.

---

## Understanding Agent UUIDs

Each agent generates a UUID on first run from a combination of:
- Hardware identifiers (hostname, MAC address)
- A per-build random salt baked in at compile time

This means:
- Two builds of the same binary on the same machine produce **different** UUIDs (different salts)
- The same binary run twice produces the **same** UUID (same hardware + same salt)
- The agent re-registers with the same UUID after a reboot — the server updates its record rather than creating a duplicate

---

## Working with Dormant Agents

Dormant agents still receive queued commands. Queue a command while an agent is dormant:

```
❯ cmd b2c3 "ipconfig /all" --no-wait
[+] Command queued. Command ID: d4e5f6a7-...
[*] check status: status d4e5f6a7-...
```

When the agent next beacons (at its configured interval), it picks up the command and submits the result. Check the result:

```
❯ status d4e5f6a7
```

---

## Tracking Command History

```
❯ history a1b2
[+] Found 47 command(s) in history.

CMD ID                               TIMESTAMP          STATUS     EXIT  COMMAND
------------------------------------------------------------------------------------------------------------
d4e5f6a7-...                        04-25 14:22:55     completed   0    whoami
e5f6a7b8-...                        04-25 14:21:30     completed   0    ipconfig /all
f6a7b8c9-...                        04-25 13:45:00     failed      1    net user /domain
```

Exit code `-` means the command did not produce a numeric exit code (e.g., file operations, internal commands).

---

## Multi-Agent Operations

Commands that return after queuing (`--no-wait`) let you drive multiple agents concurrently:

```
❯ cmd a1b2 "whoami" --no-wait
[+] Command queued. Command ID: aaa...

❯ cmd b2c3 "whoami" --no-wait
[+] Command queued. Command ID: bbb...

❯ cmd c3d4 "whoami" --no-wait
[+] Command queued. Command ID: ccc...

❯ status aaa
❯ status bbb
❯ status ccc
```
