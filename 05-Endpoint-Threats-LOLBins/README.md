# 💻 Endpoint Threats & Living-off-the-Land (LOLBins)

**MITRE ATT&CK Tactics:** Execution (TA0002), Persistence (TA0003), Defence Evasion (TA0005), Discovery (TA0007)  
**Common Techniques:** T1059.001 (PowerShell), T1218 (System Binary Proxy Execution), T1053 (Scheduled Task), T1547 (Boot/Logon Autostart)  
**Severity:** 🔴 High  

---

## 📖 Overview

Living-off-the-Land (LOL) attacks abuse legitimate, built-in Windows/Linux tools and binaries to carry out malicious activities. Because these tools are trusted by the OS and security products, they are highly effective at evading traditional AV detection. This is one of the most common techniques seen in modern APT and ransomware attacks.

**Types commonly seen in SOC alerts:**
- **PowerShell abuse** — Executing encoded/obfuscated payloads, downloading tools, establishing C2
- **WMI (Windows Management Instrumentation)** — Remote execution, persistence, lateral movement
- **Scheduled Tasks / Services** — Persistence via `schtasks.exe`, `sc.exe`, or registry run keys
- **Regsvr32 / Rundll32 / Mshta** — Proxy execution of malicious DLLs or scripts
- **Certutil** — Downloading payloads (`certutil -urlcache -f`), decoding base64
- **Bitsadmin** — File download and persistence via BITS jobs
- **Wscript / Cscript** — Executing VBScript or JScript payloads

---

## ⚔️ Attack Techniques

- Downloading payloads using `certutil`, `bitsadmin`, `curl`, or PowerShell `Invoke-WebRequest`
- Executing malicious code in memory without writing to disk (fileless malware) using `Invoke-Expression` or `IEX`
- Establishing persistence via registry `Run` keys, scheduled tasks, WMI subscriptions, or COM hijacking
- Using `msiexec.exe`, `regsvr32.exe`, or `rundll32.exe` to execute DLLs from remote URLs (bypassing AppLocker in some configs)
- Abusing `mshta.exe` to execute HTML Application (.hta) files from URLs
- Using `wmic.exe` to execute processes remotely on other hosts (lateral movement)
- Encoding payloads in Base64, XOR, or compression to bypass AMSI/script block logging

---

## 🔍 How to Identify in Logs

### Key Log Sources
- Sysmon Event IDs: 1 (Process Create), 3 (Network Connection), 7 (Image Load), 11 (File Create), 13 (Registry)
- Windows Security Event Log: 4688 (Process Creation), 4698 (Scheduled Task Created), 7045 (New Service)
- PowerShell Script Block Logging (Event ID 4104) — Enable this!
- EDR process trees (MDE, CrowdStrike, SentinelOne)

### Indicators to Hunt For
- PowerShell executing with `-EncodedCommand`, `-WindowStyle Hidden`, `-NonInteractive`, `bypass` flags
- `certutil.exe` or `bitsadmin.exe` making outbound HTTP connections
- `regsvr32.exe` or `rundll32.exe` loading DLLs from `%TEMP%` or `%APPDATA%`
- `mshta.exe` spawned from unexpected parent processes
- Scheduled tasks created with random names or pointing to paths in `%TEMP%`
- WMI subscriptions created (`__EventFilter`, `__EventConsumer` objects)
- `wmic.exe` executing commands with remote `/node:` argument

### 🔎 Microsoft Sentinel Queries (KQL)

```kql
// Encoded PowerShell execution
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "FromBase64String", "IEX", "Invoke-Expression", "DownloadString", "DownloadFile")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName

// LOLBin downloading from the internet
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe", "mshta.exe")
| where ProcessCommandLine has_any ("http://", "https://", "ftp://", "urlcache", "-transfer")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Suspicious Regsvr32 / Rundll32 loading from user-writable paths
DeviceProcessEvents
| where FileName in~ ("regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("%temp%", "\\appdata\\", "\\users\\public\\", "http://", "https://", ".dll,")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Scheduled task creation (persistence)
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Alternatively, from Security Event Log
SecurityEvent
| where EventID == 4698
| parse EventData with * '<TaskName>' TaskName '</TaskName>' *
| parse EventData with * '<Command>' Command '</Command>' *
| where Command has_any ("powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "%temp%", "%appdata%")
| project TimeGenerated, Computer, SubjectUserName, TaskName, Command

// WMI process execution
DeviceProcessEvents
| where InitiatingProcessFileName == "wmiprvse.exe"
| where FileName !in~ ("WmiPrvSE.exe", "msiexec.exe") // Exclude normal WMI children
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName

// PowerShell Script Block Logging (Event 4104 - requires PS logging enabled)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where EventData has_any ("IEX", "Invoke-Expression", "DownloadString", "WebClient", "Net.WebClient", "shellcode", "mimikatz")
| project TimeGenerated, Computer, EventData
```

### 🔎 Splunk Queries (SPL)

```spl
// Encoded PowerShell
index=windows EventCode=4688
| where NewProcessName="*powershell.exe*" 
  AND (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*IEX*")
| table _time, ComputerName, SubjectUserName, CommandLine

// Certutil downloading files
index=windows EventCode=4688
| where NewProcessName="*certutil.exe*" AND CommandLine="*urlcache*"
| table _time, ComputerName, CommandLine

// Suspicious child processes from Office apps
index=windows EventCode=4688
| where ParentProcessName IN ("*WINWORD.EXE*","*EXCEL.EXE*","*POWERPNT.EXE*")
  AND NewProcessName IN ("*powershell.exe*","*cmd.exe*","*wscript.exe*","*mshta.exe*")
| table _time, ComputerName, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
```

---

## 🛠️ Remediation Steps

### Immediate Containment
- [ ] **Isolate the endpoint** from the network via EDR
- [ ] **Kill the malicious process** if still running
- [ ] **Remove persistence mechanisms** — Delete scheduled tasks, registry run keys, WMI subscriptions, or rogue services
- [ ] **Collect the payload** for analysis (memory dump, file artefacts from `%TEMP%`)
- [ ] **Revoke credentials** for any accounts used on the machine

### Long-Term Fixes
- Enable **PowerShell Script Block Logging** and **Module Logging** via Group Policy — critical for visibility
- Enable **AMSI (Antimalware Scan Interface)** — blocks malicious script content before execution
- Restrict **PowerShell execution policy** — use `Constrained Language Mode` where possible
- Implement **Application Control** (Windows Defender Application Control / AppLocker) to block unsigned binaries
- Block known LOLBin abuse via **Attack Surface Reduction (ASR) rules** in Microsoft Defender
- Disable or restrict `mshta.exe`, `wscript.exe`, `cscript.exe` if not used in your environment
- Enable **Sysmon** with a comprehensive configuration (SwiftOnSecurity or Olaf Hartong's config)

---

## 👨‍💻 SOC Analyst Actions (Step-by-Step)

1. **Analyse the process tree** — What spawned the LOLBin? Office app? Browser? A service? This reveals the infection vector.
2. **Decode the payload** — Base64-decode PowerShell encoded commands to understand what they executed. Tools: CyberChef.
3. **Check network connections** — Did the LOLBin reach out to any external IP or domain? Extract the C2 indicator.
4. **Look for dropped files** — Check `%TEMP%`, `%APPDATA%`, `C:\ProgramData\` for dropped payloads.
5. **Check persistence** — Review scheduled tasks (`schtasks /query`), registry run keys, WMI subscriptions, and services created around the same timestamp.
6. **Check for privilege escalation** — Did the process run as SYSTEM or a high-privilege account?
7. **Scope the incident** — Hunt for the same command line patterns across all endpoints in your fleet.
8. **Block IOCs** — Domain, IP, file hash — across EDR, proxy, and DNS.
9. **Remediate persistence** — Delete all identified persistence artefacts before reimaging or returning the endpoint.
10. **Document the attack chain** and update your detection rules based on what was observed.

---

## 📚 References

- [LOLBAS Project](https://lolbas-project.github.io/) — Complete list of LOLBins with usage examples
- [MITRE ATT&CK T1218 - Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
- [Sysmon SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [CyberChef - Decode payloads](https://gchq.github.io/CyberChef/)
