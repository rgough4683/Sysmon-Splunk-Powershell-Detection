# Detecting Encoded PowerShell Execution with Sysmon + Splunk

## Overview

I built a self-built detection pipeline simulating a SOC analyst workflow. I generated a known attack technique, captured it at the endpoint, and wrote a detection rule to catch it in a SIEM.

**Technique detected:** Encoded PowerShell command execution, also known as a [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/) (Command and Scripting Interpreter: PowerShell)

---

## Architecture

I set up a Windows 11 VM using VM Workstation, and the necessary Sysmon files that would log process creations in Windows Event Viewer.I then downloaded Splunk Enterprise on the VM in order to directly read the Sysmon logs as well as indexes and alerts. 
```
[Windows 11 VM]
   ├── Sysmon (logs process creation → Windows Event Log)
   └── Splunk Enterprise (reads Sysmon log directly, indexes, alerts)
```

**Design note:** Sysmon and Splunk were run on the same VM due to host resource constraints, rather than separating the log source and SIEM onto different machines as would be typical in production. This meant reading the Sysmon Event Log directly via `inputs.conf` instead of using the Universal Forwarder.

---

## Setup Summary

1. Deployed a Windows 11 VM in VMware Workstation Pro, isolated on a host-only network.
2. Installed Sysmon with the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config), a widely-used baseline that filters noise while retaining high-value process, network, and registry events.
3. Installed Splunk Enterprise (free tier) on the same VM.
4. Configured Splunk to ingest the `Microsoft-Windows-Sysmon/Operational` event channel via a manual `inputs.conf` entry (the standard Data Inputs wizard doesn't list non-default Windows Event Log channels).
5. Verified end-to-end ingestion with a baseline search before building any detection logic.

Screenshot: Shows that Sysmon64 is up and running
![alt text](<Log Analysis Screenshots/SOC Analyst Project SS1.jpg>)
---
Screenshot: Shows that Sysmon is creating processes in Windows Event Viewer 
![alt text](<Log Analysis Screenshots/SOC Analyst Project SS2.jpg>)
---

## Generating the Technique

I used an Encoded PowerShell Execution (`powershell.exe -enc <base64>`) because it is a common technique real attackers use to evade simple string-based detection and logging, since the actual command is hidden until decoded. Simulated it with a benign payload:

```powershell
$cmd = 'Write-Host "This is a simulated suspicious command"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -enc $encoded
```
Screenshot: Simulated command in powershell
![alt text](<Log Analysis Screenshots/SOC Analyst Project SS9.jpg>)
---
## Detection Query
This is the query I used and then saved as a Splunk alert:
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*-enc*"
```

Saved as a Splunk alert:
- **Trigger condition:** Number of results > 0, trigger once per scheduled run
- **Schedule:** 
The schedule I ran was over a time range set to "All Time". The alert was set to "*/5 * * * *", which means every 5 minutes. The alert was triggered once everytime the number of results was greater than zero.

Screenshot: Shows the alert configuration
![alt text](<Log Analysis Screenshots/SOC Analyst Project SS7.jpg>)
---
Screenshot: Raw Sysmon event in Event Viewer
![alt text](<Log Analysis Screenshots/SOC Analyst Project SS8.jpg>)
---
Screenshot: Raw Sysmon event as indexed in Splunk
![alt text](<Log Analysis Screenshots/SOC Analyst Project SS4.jpg>)
---
Screenshot: Triggered alert in Activity → Triggered Alerts
![alt text](<SOC Analyst Project SS6.jpg>)
---

## False Positives & Tuning

IT admin scripts, installers, and scheduled tasks also legitimately use -enc, so alerting on CommandLine="*-enc*" alone creates noise. PowerShell itself is a trusted, signed tool, so the real signal isn't the flag, it's whether the ParentImage (what launched it) makes sense. Encoded PowerShell from a known script scheduler is normal, but from Word or a browser is a strong compromise indicator, since attackers often abuse trusted tools already on the machine rather than introduce new malware. A more mature rule would baseline normal parent processes and alert on deviations, and ideally decode the Base64 payload itself, since two -enc commands can carry very different intent.

---

## Debugging Log

| Issue | Diagnosis | Fix |
|---|---|---|
| GitHub "Raw" view didn't download the Sysmon config file | Browser opened the XML as a page instead of downloading | Used `Invoke-WebRequest` in PowerShell to pull the file directly to the target path |
| `.\Sysmon64.exe` not recognized as a command | Wrong working directory | Confirmed actual file location with `ls`/`pwd`, `cd`'d into the correct folder |
| Sysmon channel not listed in Splunk's Data Inputs wizard | Wizard only surfaces a fixed set of standard Windows Event Log channels, not custom ones like Sysmon's | Added the input manually via `inputs.conf` instead of the UI |
| `inputs.conf` silently failed to apply | Notepad had auto-appended `.txt`, so the file wasn't actually named `inputs.conf` | Verified extension in File Explorer with extensions visible; renamed correctly |
| Still no data after fixing filename | Typo in channel name (`Microsoft-Windows-Sysmon-/Operational`, extra hyphen) | Found via Splunk's own internal diagnostic log (`index=_internal sysmon`), which reported the exact malformed channel name it failed to find |
| Saved alert never appeared under Activity → Alerts | Alert never saved in Splunk | Reconfigured the alert from scratch and made sure it saved |

---

## What This Project Demonstrates

- Built a working detection pipeline from source to SIEM, not just used pre-built tools
- Mapped a simulated technique to a real MITRE ATT&CK ID and wrote a rule to detect it
- Diagnosed and resolved configuration failures independently, using the tool's own diagnostic logs rather than guessing
- Considered false-positive tradeoffs, not just detection logic in isolation
