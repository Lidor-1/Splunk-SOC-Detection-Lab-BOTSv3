# Splunk-SOC-Detection-Lab-BOTSv3
Hands-on SOC analyst simulation using Splunk Enterprise using BOTSv3
dataset (~1.9M events). Covers Tier 1–2 analyst workflows: threat hunting, writing
SPL detection rules, and building a live monitoring dashboard.
## Objective
To simulate a SOC analyst environment by investigating realistic attack scenarios,
writing detection rules that would automatically alert on each threat,
and mapping all findings to MITRE ATT&CK.
 
## Dataset
 
**I used BOTSv3** (~1.9M events, 107 sourcetypes)
 
Key sourcetypes used:
- `wineventlog:security` (46,469 events) — Windows Security logs
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (9,212 events) — Sysmon process telemetry
  
## Investigations & Detections
 
### 1. LOLBin Execution — Living off the Land
**MITRE:** T1218, T1059.003

Tracked suspicious use of built-in Windows tools like reg.exe, WMIC.exe, cmd.exe, and certutil.exe — the kind attackers often use to blend in with normal activity. Noticed machine accounts (ending with $) running these tools interactively, which usually points to malware executing under SYSTEM. The main hosts involved were BSTOLL-L, PCERF-L, and FYODOR-L.
 
**Detection Rule:**
```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688
| eval proc=lower(New_Process_Name)
| where like(proc, "%reg.exe%") OR like(proc, "%wmic.exe%") OR like(proc, "%certutil.exe%") OR like(proc, "%mshta.exe%") OR like(proc, "%rundll32.exe%")
| stats count by Account_Name, New_Process_Name, host
| sort - count
```

![lolbins_query](https://github.com/user-attachments/assets/8a052987-e63c-44b6-bc06-60885f8d1368)

<img width="1920" height="948" alt="lolbins_focused" src="https://github.com/user-attachments/assets/a9e51cc3-5b2b-47e6-805b-52bd35ec04d8" />


<img width="1920" height="950" alt="lolbins_alert" src="https://github.com/user-attachments/assets/d8ffc107-b3d6-4171-a4a4-82baeb4183b0" />


---
 
### 2. Suspicious PowerShell & Active C2 Communication
**MITRE:** T1059.001, T1036.005, T1071.001, T1548.002
 
Used Sysmon EventCode 1 (Process Create) to hunt for malicious PowerShell execution. Identified an active attack chain on host FYODOR-L.
**Sysmon EventCode breakdown — 9,212 events across 11 event types:**

<img width="1920" height="960" alt="sysmon_eventcodes" src="https://github.com/user-attachments/assets/34f37d7f-9783-4cb1-a459-6cf2817a04dd" />

 

**All PowerShell executions — 16 events with suspicious parent processes:**
 
Notable findings on page 1:
- `fodhelper.exe` spawning PowerShell → UAC bypass technique (T1548.002)
- `WmiPrvSE.exe` spawning PowerShell as `NT AUTHORITY\SYSTEM` → WMI-based execution (T1047)
- `browser_broker.exe` spawning PowerShell → browser process abuse
- Dropbox spawning PowerShell for BruceGist → suspicious

  <img width="1920" height="960" alt="powershell_page1" src="https://github.com/user-attachments/assets/8528816f-9522-414a-971d-97363ba9f226" />

  
**62 suspicious encoded/obfuscated commands detected:**
 <img width="1920" height="957" alt="powershell_62results" src="https://github.com/user-attachments/assets/f109ced6-7045-4acf-9418-2f657b588d13" />


**Active C2 attack chain discovered — page 2 of results:**
 
Key findings:
- Fake `iexplorer.exe` (note extra 'r') in `C:\Windows\Temp\unziped\lsof-master\` masquerading as Internet Explorer (T1036.005)
- Active C2 communication to `192.168.9.30:8080/frothlyinventory/showcase.action` — Apache Struts-style exploit URL
- `base64 --decode` operations — live payload decoding
- Linux-style recon commands (`ls -lf /tmp`, `cat /tmp/colonel`, `lsb_release -a`, `uname -a`) running on Windows via the C2 channel
<img width="1920" height="958" alt="powershell_c2_chain" src="https://github.com/user-attachments/assets/b8ca4b77-c7d3-4ff0-81ce-0f91effce66b" />

**Saved Detection Alert:**
![Powershell alert1](https://github.com/user-attachments/assets/bb33cda4-3e8d-4fd6-bdfb-6cc4fdc1b9ca)

 
**Detection Rule (SPL):**
```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "EventID>(?<EventCode>\d+)<"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)<"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)<"
| rex field=_raw "Name='User'>(?<User>[^<]+)<"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)<"
| where EventCode="1"
| eval cmd=lower(CommandLine)
| where like(cmd, "%-enc%") OR like(cmd, "%-encodedcommand%") OR like(cmd, "%bypass%") OR like(cmd, "%iex%") OR like(cmd, "%downloadstring%") OR like(cmd, "%hidden%")
| table _time, host, User, ParentImage, CommandLine
| sort - _time
```

 
> **Note:** Standard field extraction failed on this sourcetype. All fields were extracted manually using `rex`.
---


### 3. Lateral Movement — Explicit Credential Abuse
**MITRE:** T1021, T1550.002
 
Detected lateral movement using EventCode 4648 (explicit credential use). Found accounts authenticating across multiple hosts. Notable finding: `bstoll@froth.ly` using explicit credentials on BSTOLL-L, and service accounts (DWM-1, UMFD-0, UMFD-1) appearing across both BSTOLL-L and PCERF-L simultaneously — consistent with credential theft and reuse.
 
**Explicit credential use across hosts (EventCode 4648):**
<img width="1920" height="952" alt="lateral_movement_4648" src="https://github.com/user-attachments/assets/ab7a16f8-8ecc-483e-afaa-0d21d0e61cb8" />

**Logon type breakdown — all logons are Type 5 (service logons) across multiple hosts:**
<img width="1920" height="953" alt="lateral_logon_types" src="https://github.com/user-attachments/assets/743c0c3a-21aa-482f-85e0-1e588ef73c37" />

 
**Detection Rule (SPL):**
```spl
index=botsv3 sourcetype="wineventlog:security" (EventCode=4648 OR EventCode=4624)
| eval event_type=if(EventCode=4648, "ExplicitCred", "ServiceLogon")
| stats values(event_type) as types, dc(host) as unique_hosts, count by Account_Name
| where mvcount(types) > 1 AND unique_hosts > 1
| sort - unique_hosts
```
 
---

## Lessons Learned

- SPL field extraction isn’t always plug-and-play — Sysmon logs didn’t parse cleanly in my setup, so I had to use `rex` to pull fields from the XML. Reinforced the need to verify extraction before building detections
- Real attack data is messy. Tracing the C2 chain meant pivoting across multiple queries and sourcetypes, not just running one search
- MITRE ATT&CK mapping gets easier once you actually understand what the attacker is doing at each step
- Writing detection rules forces you to think like an attacker — you need to understand the technique before you can catch it
