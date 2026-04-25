# Web Application Attack Detection — Google SecOps / Chronicle

## Log Sources Required

| Chronicle Log Type | Data Source |
|-------------------|------------|
| `AZURE_WAF` | Azure Front Door / Application Gateway WAF |
| `AWS_WAF` | AWS WAF logs (via S3 or Kinesis to Chronicle) |
| `CLOUDFLARE` | Cloudflare WAF and HTTP logs |
| `PALO_ALTO_FIREWALL` | Palo Alto threat logs for web traffic |
| `APACHE_WEB_SERVER` | Apache access and error logs |
| `NGINX` | Nginx access and error logs |
| `IIS` | Microsoft IIS W3C logs |
| `MOD_SECURITY` | ModSecurity WAF logs |

---

## YARA-L 2.0 Detection Rules

---

### Rule 1 — SQL Injection Attempt Detected

```yaral
rule webapp_sql_injection {
  meta:
    author = "SOC"
    description = "HTTP request contains SQL injection patterns in URL or parameters"
    severity = "HIGH"
    mitre_attack_tactic = "Initial Access"
    mitre_attack_technique = "T1190"
    false_positives = "Security scanners running authorised pen tests — whitelist scanner IPs"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    (
      $e.target.url = /(\%27|\'|\-\-|\%23|#)/i or
      $e.target.url = /(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b)/i or
      $e.target.url = /(\bexec\b|\bexecute\b|\bxp_cmdshell\b|\bsleep\b\()/i or
      $e.network.http.request.body = /(\bunion\b.*\bselect\b|\bor\b\s+1\s*=\s*1|\bdrop\b.*\btable\b)/i
    )
    $e.principal.ip = $src

  condition:
    $e
}
```

---

### Rule 2 — XSS Payload in HTTP Request

```yaral
rule webapp_xss_attempt {
  meta:
    author = "SOC"
    description = "HTTP request contains cross-site scripting payload patterns"
    severity = "HIGH"
    mitre_attack_technique = "T1059.007"
    false_positives = "Security scanners — whitelist known scanner IPs"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    (
      $e.target.url = /(<script|%3Cscript|javascript:|onerror=|onload=|<img.*src.*onerror)/i or
      $e.network.http.request.body = /(<script|%3Cscript|javascript:|onerror\s*=|onload\s*=)/i or
      $e.target.url = /(%22|%27).*(%3E|>)/i
    )
    $e.principal.ip = $src

  condition:
    $e
}
```

---

### Rule 3 — SSRF: Request Targeting Cloud Metadata or Internal IPs

```yaral
rule webapp_ssrf_attempt {
  meta:
    author = "SOC"
    description = "Application received request attempting to trigger SSRF to internal or cloud metadata endpoints"
    severity = "CRITICAL"
    mitre_attack_technique = "T1190"
    false_positives = "Unlikely for metadata IP — treat all as true positive until proven otherwise"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    (
      $e.target.url = /169\.254\.169\.254/i or
      $e.target.url = /metadata\.google\.internal/i or
      $e.target.url = /(127\.0\.0\.1|localhost)/i or
      $e.network.http.request.body = /169\.254\.169\.254|metadata\.google\.internal/i or
      $e.target.url = /file:\/\/\//i
    )
    $e.principal.ip = $src

  condition:
    $e
}
```

---

### Rule 4 — Path Traversal Attempt

```yaral
rule webapp_path_traversal {
  meta:
    author = "SOC"
    description = "HTTP request contains directory traversal sequences attempting to escape the web root"
    severity = "HIGH"
    mitre_attack_technique = "T1083"
    false_positives = "Rare legitimate use — treat as suspicious by default"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    (
      $e.target.url = /(\.\.[\/\\]){2,}/i or
      $e.target.url = /(%2e%2e[%2f%5c]){2,}/i or
      $e.target.url = /(\.\.%2f|\.\.%5c|%2e%2e\/){2,}/i or
      $e.target.url = /(\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini)/i
    )
    $e.principal.ip = $src

  condition:
    $e
}
```

---

### Rule 5 — Known Attack Tool User-Agent Detected

```yaral
rule webapp_attack_tool_useragent {
  meta:
    author = "SOC"
    description = "HTTP request sent with a User-Agent string from a known web attack or scanning tool"
    severity = "HIGH"
    mitre_attack_technique = "T1190"
    false_positives = "Authorised penetration testers — coordinate with security team for scheduled tests"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.network.http.user_agent = /sqlmap|nikto|dirbuster|gobuster|wfuzz|nuclei|masscan|burpsuite|ZAP|w3af|acunetix|nessus/i
    $e.principal.ip = $src

  condition:
    $e
}
```

---

### Rule 6 — Web Shell Access: POST to Unexpected Script File

```yaral
rule webapp_webshell_access {
  meta:
    author = "SOC"
    description = "POST request sent to a script file outside of known application endpoints — possible web shell access"
    severity = "CRITICAL"
    mitre_attack_technique = "T1505.003"
    false_positives = "Legitimate dynamic script endpoints — compare against known application URI whitelist"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.network.http.method = "POST"
    (
      $e.target.url = /\.(php|asp|aspx|jsp|cgi|pl|py|sh)$/i
    )
    // Response indicates success (2xx)
    $e.network.http.response_code >= 200
    $e.network.http.response_code < 300
    $e.principal.ip = $src

  condition:
    $e
}
```

---

### Rule 7 — High Error Rate From Single IP (Fuzzing / Scanning)

```yaral
rule webapp_high_error_rate {
  meta:
    author = "SOC"
    description = "Single source IP generating a high volume of HTTP 4xx/5xx errors — active fuzzing or scanning"
    severity = "MEDIUM"
    mitre_attack_technique = "T1190"
    false_positives = "Misconfigured monitoring tools — verify with network team"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    (
      $e.network.http.response_code >= 400
    )
    $e.principal.ip = $src

  match:
    $src over 5m

  outcome:
    $error_count = count($e.metadata.event_type)

  condition:
    $e and $error_count > 150
}
```

---

### Rule 8 — WAF Block Rule Triggered Repeatedly From Same IP

```yaral
rule webapp_waf_repeated_blocks {
  meta:
    author = "SOC"
    description = "WAF blocked multiple requests from the same IP in a short period — active attack or evasion attempts"
    severity = "HIGH"
    mitre_attack_technique = "T1190"
    false_positives = "Misconfigured client apps — verify source"

  events:
    $e.metadata.event_type = "NETWORK_HTTP"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $src

  match:
    $src over 10m

  outcome:
    $block_count = count($e.metadata.event_type)

  condition:
    $e and $block_count > 20
}
```

---

## UDM Search Queries

Run in **Chronicle > Search (UDM Search)**.

---

### Hunt 1 — All Requests From a Suspicious IP

```
metadata.event_type = "NETWORK_HTTP"
AND principal.ip = "1.2.3.4"
```

---

### Hunt 2 — SQL Injection Patterns in URLs

```
metadata.event_type = "NETWORK_HTTP"
AND target.url = /union.*select|select.*from|drop.*table|xp_cmdshell|or\s+1=1/i
```

---

### Hunt 3 — SSRF Attempts to Metadata Endpoint

```
metadata.event_type = "NETWORK_HTTP"
AND target.url = /169\.254\.169\.254|metadata\.google\.internal/i
```

---

### Hunt 4 — Path Traversal in URL

```
metadata.event_type = "NETWORK_HTTP"
AND target.url = /\.\.[\/\\]|%2e%2e%2f|etc\/passwd|win\.ini/i
```

---

### Hunt 5 — Attack Tool User-Agents in Last 7 Days

```
metadata.event_type = "NETWORK_HTTP"
AND network.http.user_agent = /sqlmap|nikto|dirbuster|nuclei|gobuster|wfuzz/i
```

---

### Hunt 6 — POST Requests to Script Files (Possible Web Shell)

```
metadata.event_type = "NETWORK_HTTP"
AND network.http.method = "POST"
AND target.url = /\.(php|aspx|jsp|cgi)$/i
```

---

### Hunt 7 — WAF Blocks in Last 24 Hours by Source IP

```
metadata.event_type = "NETWORK_HTTP"
AND security_result.action = "BLOCK"
```
> Group by `principal.ip` in Chronicle to find top attacking IPs.

---

### Hunt 8 — Successful Requests After WAF Block From Same IP (Evasion)

```
metadata.event_type = "NETWORK_HTTP"
AND security_result.action = "ALLOW"
AND principal.ip = "1.2.3.4"
```
> Run this after finding a blocked attacker IP — check if any requests got through.

---

## WAF IOC Blocking via Chronicle Reference Lists

```
List name : webapp_attacker_ips
Type      : CIDR

List name : webapp_blocked_useragents
Type      : REGEX

# Example entries for blocked_useragents
sqlmap.*
nikto.*
dirbuster.*
```

**Use in YARA-L:**
```yaral
$e.principal.ip in %webapp_attacker_ips
$e.network.http.user_agent in %webapp_blocked_useragents
```
