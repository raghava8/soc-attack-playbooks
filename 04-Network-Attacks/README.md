# 🌐 Network Attacks (DDoS, MITM, Lateral Movement)

**MITRE ATT&CK Tactics:** Discovery (TA0007), Lateral Movement (TA0008), Exfiltration (TA0010), Impact (TA0040)  
**Common Techniques:** T1498 (Network DoS), T1557 (AiTM - Network Level), T1021 (Remote Services), T1046 (Network Service Scanning)  
**Severity:** 🟠 High  

---

## 📖 Overview

Network-based attacks target the infrastructure layer — routers, switches, firewalls, and network protocols — to disrupt services, intercept traffic, or enable lateral movement across the environment. These attacks are frequently flagged by IDS/IPS, firewall, and NetFlow alerts.

**Types commonly seen in SOC alerts:**
- **DDoS (Distributed Denial of Service)** — Flood of traffic overwhelming services (volumetric, protocol, application layer)
- **Man-in-the-Middle (MITM)** — ARP spoofing, DNS poisoning, SSL stripping to intercept traffic
- **Port Scanning / Network Reconnaissance** — Mapping the internal network using Nmap, Masscan
- **Lateral Movement via SMB/RDP** — Attacker moving from compromised host to other systems
- **DNS Tunnelling** — Encoding C2 traffic in DNS queries to bypass firewalls
- **Network Exfiltration** — Large data transfers to external IPs

---

## ⚔️ Attack Techniques

- Sending SYN floods, UDP floods, ICMP floods to exhaust server resources (DDoS)
- Using botnets or amplification vectors (DNS, NTP, Memcached) for volumetric DDoS
- ARP spoofing to redirect traffic on a LAN segment through an attacker's device
- DNS cache poisoning to redirect users to malicious servers
- Internal port scanning from a compromised host to map live hosts and open ports
- Lateral movement using: PsExec, WMI, SMB shares, RDP, SSH, WinRM
- Data exfiltration via DNS TXT records, ICMP echo packets, or HTTPS to cloud storage

---

## 🔍 How to Identify in Logs

### Key Log Sources
- Firewall/NGFW logs (Palo Alto, Fortinet, Azure Firewall)
- IDS/IPS alerts (Snort, Suricata, Microsoft Defender for Network)
- NetFlow / Traffic Analytics
- DNS logs
- Windows Event Log (4624, 4625, 7045, 5140 for SMB)
- Azure NSG flow logs

### Indicators to Hunt For
- Sudden spike in inbound traffic (Gbps range) from many source IPs — DDoS
- ARP table changes or gratuitous ARP announcements on the network
- High-volume DNS queries to a single domain with random subdomains (DNS tunnelling)
- One internal host scanning many other internal hosts on port 445, 3389, 22, 135
- SMB connections from workstations to other workstations (lateral movement)
- Outbound large data transfers (>1GB) to unknown external IPs
- Connections from endpoints to cloud storage services (S3, Dropbox, OneDrive) not used before

### 🔎 Microsoft Sentinel Queries (KQL)

```kql
// Internal port scanning detection
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize DistinctPorts=dcount(RemotePort), Attempts=count() by DeviceName, RemoteIP, bin(TimeGenerated, 10m)
| where DistinctPorts > 20
| order by DistinctPorts desc

// SMB lateral movement (workstation to workstation)
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| join kind=inner (
    DeviceInfo | where DeviceType == "Workstation" | project RemoteDeviceName=DeviceName
) on $left.RemoteIP == $right.RemoteDeviceName
| project TimeGenerated, DeviceName, RemoteIP, RemotePort
// Filter to exclude known admin machines

// DNS tunnelling - high query rate to single domain with long subdomains
DnsEvents
| where Name matches regex @"^[a-z0-9]{20,}\." // long subdomain pattern
| summarize QueryCount=count(), UniqueSubdomains=dcount(Name) by QueryType, Computer, bin(TimeGenerated, 5m)
| where UniqueSubdomains > 50
| order by UniqueSubdomains desc

// Large outbound data transfer
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize TotalBytes=sum(SentBytes) by DeviceName, RemoteIP, bin(TimeGenerated, 1h)
| where TotalBytes > 500000000 // 500MB threshold
| order by TotalBytes desc

// RDP lateral movement from internal hosts
SecurityEvent
| where EventID == 4624
| where LogonType == 10 // Remote Interactive (RDP)
| where IpAddress matches regex @"^10\.|^192\.168\.|^172\." // internal source
| project TimeGenerated, Computer, TargetUserName, IpAddress, WorkstationName
```

### 🔎 Splunk Queries (SPL)

```spl
// Internal port scan
index=firewall action=denied
| stats dc(dest_port) as unique_ports count as attempts by src_ip, _time span=10m
| where unique_ports > 20
| table _time, src_ip, unique_ports, attempts

// DNS tunnelling detection
index=dns
| eval subdomain_len=len(replace(query,"\\.[^.]+$",""))
| where subdomain_len > 40
| stats count dc(query) as unique_queries by src_ip, _time span=5m
| where unique_queries > 50

// Large data exfiltration
index=firewall action=allowed direction=outbound
| stats sum(bytes_out) as total_out by src_ip, dest_ip, _time span=1h
| where total_out > 500000000
| table _time, src_ip, dest_ip, total_out
```

---

## 🛠️ Remediation Steps

### DDoS
- [ ] Enable **DDoS protection** at the edge (Azure DDoS Standard, Cloudflare, AWS Shield)
- [ ] Work with your ISP/upstream provider to implement **BGP blackholing** for the target IP
- [ ] Implement **rate limiting** and **geo-blocking** for traffic not expected from certain regions
- [ ] Scale up your infrastructure or activate **anycast routing** if using a CDN

### MITM / ARP Poisoning
- [ ] Enable **Dynamic ARP Inspection (DAI)** on managed switches
- [ ] Implement **DHCP snooping** to limit who can act as a DHCP server on VLANs
- [ ] Deploy **802.1X port authentication** to prevent unauthorised devices on the network

### Lateral Movement
- [ ] **Isolate compromised hosts** immediately
- [ ] Block SMB (445) and RDP (3389) between workstations at the firewall/Windows Firewall level
- [ ] Audit and restrict local admin accounts — implement **LAPS** (Local Administrator Password Solution)
- [ ] Enforce **network segmentation** — workstations should not be able to reach other workstations directly

### DNS Tunnelling / Exfiltration
- [ ] Block the identified domain at DNS/proxy layer
- [ ] Implement **DNS filtering** (Cisco Umbrella, Zscaler, Microsoft DNS security) to inspect DNS traffic
- [ ] Review and whitelist cloud storage services; block unapproved ones

---

## 👨‍💻 SOC Analyst Actions (Step-by-Step)

1. **Classify the network alert** — Is this inbound (DDoS/recon), internal (lateral movement), or outbound (exfiltration/C2)?
2. **For DDoS** — Confirm service impact, notify the network/infrastructure team, engage upstream provider if volumetric.
3. **For port scanning from internal hosts** — The scanning host is likely compromised. Treat it as a malware incident. Isolate and investigate.
4. **For lateral movement (RDP/SMB)** — Determine the source host (patient zero) and trace the infection chain. Scope all accessed hosts.
5. **For DNS tunnelling** — Capture sample DNS queries, extract the C2 domain, and block. Check which processes on the host were making the DNS calls.
6. **For large outbound transfers** — Identify what data was sent and where. Classify the data — PII? IP? This may trigger a data breach notification obligation.
7. **Collect network IOCs** — Source/destination IPs, domains, ports, user agents.
8. **Block at all enforcement points** — Firewall, proxy, DNS, EDR.
9. **Escalate** if data exfiltration is confirmed (regulatory notification may be required).
10. **Document** with full packet capture or flow data evidence if available.

---

## 📚 References

- [MITRE ATT&CK T1498 - Network DoS](https://attack.mitre.org/techniques/T1498/)
- [MITRE ATT&CK T1021 - Remote Services](https://attack.mitre.org/techniques/T1021/)
- [CISA DDoS Quick Guide](https://www.cisa.gov/sites/default/files/publications/understanding-and-responding-to-ddos-attacks.pdf)
- [Microsoft - Detect lateral movement with Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/hunting-queries)
- [DNS Tunnelling Detection Techniques](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
