
# Windows Endpoint Triage Playbook & Secure Security Lab

A comprehensive, low-artifact Incident Response (IR) triage playbook designed to rapidly investigate compromised Windows endpoints, identify active threats, and audit historical security logs using native tools. This repository also contains architectural blueprints for provisioning an isolated, virtualized security lab to safely analyze threats, test penetration tools, and replicate enterprise attack scenarios.

---

## Part 1: The 4-Step Quick Commands (The Live Check)

Run these native commands from an administrative Command Prompt or PowerShell window to quickly assess the volatile state of a suspected Windows endpoint.

### 1. Isolate Unknown Network Traffic
Filters out standard browser noise to isolate unexpected, persistent inbound/outbound connections.
```cmd
netstat -naob | findstr /V/I/C:"chrome" /C:"msedge" /C:"firefox"
```

#### Technical Parameter Breakdown:
(-nab: Shows the network connections and the name of the program (like [cmd.exe]).
-naob: Shows the network connections, the name of the program, AND the unique Process ID (PID) number assigned to that specific running instance of the program.)

* **/V**: Modifies the `findstr` block to perform an **inverted match**, discarding lines containing the browser strings to lower data noise.
* **/I**: Enforces **case-insensitivity**, preventing manual evasion attempts where an attacker might run a process named `ChRoMe.exe`.
* **/C:"..."**: Treats the entire text string inside the quotes as a single literal phrase instead of breaking spaces down into an "OR" logical operator.

### 2. Catch Active Reverse Shells

Instantly isolates common command-line shells actively communicating over live network sockets.

```cmd
netstat -naob | findstr /I/C:"powershell" /C:"cmd.exe"

```

#### Technical Parameter Breakdown:

* Reuses the core execution architecture of the `netstat -naob` parameters detailed above.
* **Analysis Focus:** Directly matches against administrative command interpreters. In standard user environments, `cmd.exe` and `powershell.exe` should virtually never hold open, continuous network sockets to the internet. If discovered, this indicates an active, ongoing reverse shell or staging session.

### 3. View Recent Program Execution History

Queries the Windows Prefetch directory, sorted by date modified, to view a clean chronology of recently executed binaries.

```cmd
dir C:\Windows\Prefetch /O:-D/B

```

#### Technical Parameter Breakdown:

* **C:\Windows\Prefetch**: Targets the core Windows OS performance-optimization directory which caches records of binaries executed over the system's runtime lifespan.
* **/O:-D**: Instructs the output directory list to **sort in reverse chronological order** based on date modified, highlighting the most recent actions.
* **/B**: Forces the command into **Bare format**, returning only plain filenames and dropping system header/footer text to make reading efficient.

### 4. Map a Suspicious PID to Disk

Translates a running Process ID (PID) discovered during network auditing to its absolute location on the file system.

```cmd
wmic process where processid=INSERT_PID_HERE get executablepath

```
### or Using Task Manager (The Visual Way)
```* Press Ctrl + Shift + Esc to open Task Manager.
* Go to the Details tab (or Services tab).
* Click the PID column header to sort the numbers sequentially.
* Scroll down to find (PID).
* Look at the Name and Description columns to see what program it is.
```
### or Using PowerShell (The Deep Dive)
If you want to see the path of the file to make sure it isn't a fake Windows file, run PowerShell as Administrator and type:
```
Get-Process -Id (PID) | Select-Object Name, Path, Description
```


#### Technical Parameter Breakdown:

* **wmic process where processid=**: Leverages the Windows Management Instrumentation framework to isolate system objects matching the explicit number provided.
* **get executablepath**: Tells the system to bypass general information and display only the strict, absolute folder path where that exact binary resides on the physical disk.

---

## Part 2: Incident Response Playbook Checklist

### 1. Active Network Investigation

* **Objective:** Identify unauthorized live network connections and open listening sockets.
* **Analysis & Red Flags:** Look for `ESTABLISHED` connections routing to public IPs on unconventional ports (e.g., `:4444`, `:8080`, `:31337`). Check for unauthorized binaries or command shells maintaining active connections, or unknown applications in a `LISTENING` state. Focus on un-resolvable public IPs or atypical Top-Level Domains (TLDs) like `.xyz` or `.cc`.

### 2. Execution History (Prefetch Diary)

* **Objective:** Audit artifacts of past application executions to establish a timeline of malicious activity.
* **Analysis & Red Flags:** Inspect for `CMD.EXE` or `POWERSHELL.EXE` running during anomalous timeframes when no administration or vulnerability scanning was scheduled. Watch for randomized, high-entropy executable names (e.g., `Z8X9R2.EXE`) at the top of the execution chronology.

### 3. Tracking Suspicious Paths (Pivoting via PID)

* **Objective:** Verify process integrity by cross-referencing running binaries against their disk location.
* **Analysis & Red Flags:** Flag native Windows binaries operating out of non-standard directories (e.g., `svchost.exe` running from a user folder instead of `C:\Windows\System32\`). Investigate any binary executing directly out of volatile space such as `\AppData\Local\Temp\` or `C:\Windows\Temp\`.

### 4. Local Antivirus Triage

* **Objective:** Query Microsoft Defender's database for un-remediated threat signatures.
* **Execution:** Run the following cmdlet inside PowerShell:
```powershell
Get-MpThreatDetection

```


* **Analysis & Red Flags:** Filter closely for log blocks where `ActionSuccess` equals `False`. This explicitly signals that a threat was identified on the machine but the endpoint protection agent failed to successfully isolate, quarantine, or delete the file, necessitating manual containment.

---

## Part 3: The "Big Three" Event Logs for Deep Auditing

When live volatile memory and network states appear clean, historical artifacts within Event Viewer (`eventvwr.msc`) must be interrogated to detect automated actions or hands-on-keyboard attackers who have since disconnected.

| Log Provider | Event ID | Focus Area & Technical Analysis |
| --- | --- | --- |
| **Security Log** | **4624** (Successful Logon) | Audit for **Logon Type 10** (RemoteInteractive / RDP) originating from unexpected, external IP addresses or occurring at anomalous hours (e.g., 3:00 AM). |
| **PowerShell Operational** | **4104** (Script Block Auditing) | Inspect the `Script Block Text` for indicators of obfuscation and egress traffic: `-w hidden`, `-enc`, `DownloadString`, or `Invoke-WebRequest`. |
| **System Log** | **7045 & 1102** (Persistence & Anti-Forensics) | **7045:** New service installations using randomized names or staging out of user temp paths. <br>

<br>**1102:** The Security Audit log was explicitly cleared—a severe indicator of anti-forensics. |

### Technical Interpretation of Event Metrics:

* **Logon Type Classification (ID 4624):** While Logon Type 2 denotes physical keyboard console access and Type 3 denotes standard remote network shares/printers, Type 10 specifically points to interactive remote desktop protocol (RDP) sessions. Broad connections over Type 10 outside typical operational windows indicate an active lateral movement phase.
* **Script Obfuscation Detection (ID 4104):** Attackers often utilize switches like `-w hidden` or `-windowstyle hidden` to prevent a console popup window from alarming local users. The `-enc` or `-EncodedCommand` switch indicates a payload compressed into Base64 blocks to bypass keyword filters. Egress lookups like `DownloadString` or `Invoke-WebRequest` map to active network staging operations.
* **Anti-Forensics & Persistence Markers (ID 7045 / 1102):** Newly initialized services (7045) that direct their `ImagePath` to writeable volatile space like `\AppData\Local\Temp\` show persistence mechanisms. Furthermore, Event ID 1102 logs instances where an administrator or intruder intentionally executes automated log-clearing scripts (e.g., `wevtutil cl`). Legitimate Windows infrastructure does not auto-delete these tables; an isolated 1102 indicates explicit covering of tracks.



```

```
