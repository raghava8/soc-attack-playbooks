# Network Attack Detection — Google SecOps / Chronicle

## Log Sources Required

| Chronicle Log Type | Data Source |
|-------------------|------------|
| `PALO_ALTO_FIREWALL` | Palo Alto NGFW traffic and threat logs |
| `FORTINET_FIREWALL` | Fortinet FortiGate logs |
| `AZURE_FIREWALL` | Azure Firewall logs |
| `WINDOWS_DNS` | Windows DNS Server debug logs |
| `INFOBLOX` | Infoblox DNS logs |
| `ZSCALER_WEBPROXY` | Zscaler Internet Access logs |
| `WINDOWS_SYSMON` | Sysmon network connection events (Event ID 3) |
| `MICROSOFT_DEFENDER_ENDPOINT` | MDE network connection telemetry |
| `VPC_FLOW` | AWS VPC Flow Logs / Azure NSG Flow Logs |

---

## YARA-L 2.0 Detection Rules

---

### Rule 1 — Internal Port Scan: One Host Scanning Many Ports

```yaral
rule network_internal_port_scan {
  meta:
    author = "SOC"
    description = "Single internal host generating failed connections to many distinct ports — active port scanning"
    severity = "HIGH"
    mitre_attack_tactic = "Discovery"
    mitre_attack_technique = "T1046"
    false_positives = "Vulnerability scanners (Nessus, Qualys) — whitelist known scanner IPs"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $src
    $e.target.port = $port
    // Source must be internal
    $e.principal.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./

  match:
    $src over 5m

  outcome:
    $unique_ports = count_distinct($port)

  condition:
    $e and $unique_ports > 20
}
```

---

### Rule 2 — Lateral Movement: SMB Connections Between Workstations

```yaral
rule network_lateral_movement_smb {
  meta:
    author = "SOC"
    description = "Workstation initiating SMB connection to another internal host — possible lateral movement"
    severity = "HIGH"
    mitre_attack_technique = "T1021.002"
    false_positives = "Domain controllers, file servers, SCCM servers — whitelist known admin systems as source"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.security_result.action = "ALLOW"
    $e.target.port = 445
    // Source and dest are both internal
    $e.principal.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./
    $e.target.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./
    $e.principal.hostname = $src_host
    $e.target.hostname = $dst_host
    $src_host != $dst_host

  match:
    $src_host over 10m

  outcome:
    $targets = count_distinct($dst_host)

  condition:
    $e and $targets > 3
}
```

---

### Rule 3 — DNS Tunnelling: High-Frequency Queries With Long Subdomains

```yaral
rule network_dns_tunnelling {
  meta:
    author = "SOC"
    description = "Host making high-frequency DNS queries with unusually long subdomain names — DNS tunnelling pattern"
    severity = "HIGH"
    mitre_attack_technique = "T1071.004"
    false_positives = "Some CDN or DGA-based legitimate services — verify domain reputation"

  events:
    $e.metadata.event_type = "NETWORK_DNS"
    $e.principal.ip = $src
    $e.network.dns.questions.name = $qname
    // Long subdomain = > 40 chars before first dot
    re.capture($qname, "^([a-zA-Z0-9\\-]{40,})\\.", "") != ""

  match:
    $src over 5m

  outcome:
    $query_count = count($e.metadata.event_type)
    $unique_domains = count_distinct($qname)

  condition:
    $e and $query_count > 50 and $unique_domains > 20
}
```

---

### Rule 4 — Large Outbound Data Transfer to External IP

```yaral
rule network_large_exfiltration {
  meta:
    author = "SOC"
    description = "Single internal host transferred a large volume of data to an external IP — possible data exfiltration"
    severity = "HIGH"
    mitre_attack_technique = "T1048"
    false_positives = "Legitimate cloud backup or software update processes — verify destination and process"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.security_result.action = "ALLOW"
    $e.principal.ip = $src
    // Source is internal
    $e.principal.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./
    // Dest is external (not RFC1918)
    not $e.target.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./
    $e.network.sent_bytes = $bytes

  match:
    $src over 1h

  outcome:
    $total_bytes = sum($bytes)

  condition:
    $e and $total_bytes > 500000000
}
```

---

### Rule 5 — RDP Lateral Movement From Internal Host

```yaral
rule network_rdp_lateral_movement {
  meta:
    author = "SOC"
    description = "Internal host initiating RDP session to multiple other internal hosts — lateral movement indicator"
    severity = "HIGH"
    mitre_attack_technique = "T1021.001"
    false_positives = "IT admin RDP activity — whitelist known admin jump hosts"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.security_result.action = "ALLOW"
    $e.target.port = 3389
    $e.principal.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./
    $e.target.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./
    $e.principal.hostname = $src

  match:
    $src over 30m

  outcome:
    $rdp_targets = count_distinct($e.target.ip)

  condition:
    $e and $rdp_targets > 3
}
```

---

### Rule 6 — Possible DDoS: High Inbound Traffic Volume From Many Sources

```yaral
rule network_ddos_inbound {
  meta:
    author = "SOC"
    description = "High volume of inbound connections to a single internal target from many distinct sources"
    severity = "HIGH"
    mitre_attack_technique = "T1498"
    false_positives = "Legitimate high-traffic services — baseline normal thresholds first"

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.target.ip = $target
    // Target is internal (your servers)
    $e.target.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./
    $e.principal.ip = $src
    not $e.principal.ip = /^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./

  match:
    $target over 1m

  outcome:
    $unique_sources = count_distinct($src)
    $total_connections = count($e.metadata.event_type)

  condition:
    $e and $unique_sources > 500 and $total_connections > 10000
}
```

---

## UDM Search Queries

Run in **Chronicle > Search (UDM Search)**.

---

### Hunt 1 — Port Scanning From a Specific Internal Host

```
metadata.event_type = "NETWORK_CONNECTION"
AND security_result.action = "BLOCK"
AND principal.ip = "10.0.0.50"
```
> Summarise by `target.port` to see how many ports were probed.

---

### Hunt 2 — All SMB Connections From a Compromised Host

```
metadata.event_type = "NETWORK_CONNECTION"
AND target.port = 445
AND principal.hostname = "INFECTED-HOST"
```

---

### Hunt 3 — DNS Queries With Unusually Long Names

```
metadata.event_type = "NETWORK_DNS"
AND network.dns.questions.name = /.{50,}/
```

---

### Hunt 4 — Outbound Connections on Non-Standard Ports

```
metadata.event_type = "NETWORK_CONNECTION"
AND security_result.action = "ALLOW"
AND NOT target.ip = /^10\.|^192\.168\.|^172\./
AND (target.port = 4444 OR target.port = 9999 OR target.port = 1337 OR target.port = 8888)
```

---

### Hunt 5 — All External Connections From a Specific Host (Last 24h)

```
metadata.event_type = "NETWORK_CONNECTION"
AND principal.hostname = "HOSTNAME"
AND NOT target.ip = /^10\.|^192\.168\.|^172\./
```

---

### Hunt 6 — RDP Connections Between Internal Workstations

```
metadata.event_type = "NETWORK_CONNECTION"
AND target.port = 3389
AND principal.ip = /^10\.|^192\.168\./
AND target.ip = /^10\.|^192\.168\./
```
