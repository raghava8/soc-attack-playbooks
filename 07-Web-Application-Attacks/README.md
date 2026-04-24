# 🕸️ Web Application Attacks (SQLi, XSS, SSRF & More)

**MITRE ATT&CK Tactics:** Initial Access (TA0001), Collection (TA0009), Exfiltration (TA0010)  
**Common Techniques:** T1190 (Exploit Public-Facing Application), T1059 (Command & Scripting Interpreter via web shells), T1505.003 (Web Shell)  
**Severity:** 🟠 High  

---

## 📖 Overview

Web application attacks target vulnerabilities in internet-facing applications to gain unauthorised access, extract data, or execute code on the underlying server. They are frequently flagged by WAF alerts, IDS/IPS, and application logs. Even a single vulnerable parameter can lead to full server compromise or data breach.

**Types commonly seen in SOC alerts:**
- **SQL Injection (SQLi)** — Injecting SQL commands to manipulate the database
- **Cross-Site Scripting (XSS)** — Injecting malicious scripts into web pages viewed by users
- **Server-Side Request Forgery (SSRF)** — Making the server fetch internal resources on the attacker's behalf
- **Path/Directory Traversal** — Accessing files outside the webroot (`../../etc/passwd`)
- **Remote/Local File Inclusion (RFI/LFI)** — Including malicious or local files in web app execution
- **Web Shell Upload** — Uploading a PHP/ASP backdoor to maintain persistent server access
- **Command Injection** — Injecting OS commands through poorly validated input fields
- **Broken Authentication / Session Hijacking** — Stealing session tokens to impersonate users
- **XML External Entity (XXE)** — Exploiting XML parsers to read internal files or SSRF

---

## ⚔️ Attack Techniques

- Appending `' OR '1'='1` or `; DROP TABLE users;--` to URL parameters or form fields
- Using `UNION SELECT` statements to extract data from other database tables
- Injecting `<script>alert(document.cookie)</script>` in stored or reflected contexts
- Using SSRF to reach cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`) and steal cloud credentials
- Path traversal payloads: `../../../../etc/passwd`, `..%2F..%2F..%2F`
- Uploading `.php`, `.aspx`, or `.jsp` files disguised with double extensions (`shell.php.jpg`)
- Exploiting file upload endpoints that don't validate file type server-side
- Using Burp Suite, SQLMap, or Nikto to automate vulnerability discovery and exploitation

---

## 🔍 How to Identify in Logs

### Key Log Sources
- Web Application Firewall (WAF) logs — Azure Front Door WAF, AWS WAF, Cloudflare WAF, ModSecurity
- Web server access logs (IIS, Apache, Nginx)
- Application logs
- Azure Diagnostic Logs / AWS WAF Logs ingested into SIEM

### Indicators to Hunt For
- SQL keywords in URL parameters or POST bodies: `UNION`, `SELECT`, `DROP`, `INSERT`, `EXEC`, `xp_cmdshell`, `'--`, `OR 1=1`
- XSS payloads: `<script>`, `javascript:`, `onerror=`, `onload=`, `%3Cscript%3E` (URL encoded)
- Path traversal sequences: `../`, `%2e%2e%2f`, `..%252f`, `%c0%af`
- SSRF payloads targeting internal IPs: `http://192.168.`, `http://10.`, `http://127.0.0.1`, `http://169.254.169.254`
- Requests returning HTTP 500 errors in rapid succession (fuzzing/probing)
- Unusually large response bodies (data exfiltration via SQLi)
- Requests to `/cmd`, `/shell`, `/upload`, `/admin` paths from external IPs
- User-Agent strings from known attack tools: `sqlmap`, `nikto`, `burpsuite`, `dirbuster`

### 🔎 Microsoft Sentinel Queries (KQL)

```kql
// SQL injection attempts in WAF logs
AzureDiagnostics
| where Category == "FrontdoorWebApplicationFirewallLog"
| where action_s == "Block" or action_s == "Detection"
| where ruleName_s has_any ("SQLi", "SQL", "942", "941") // OWASP rule IDs
| project TimeGenerated, clientIp_s, requestUri_s, ruleName_s, action_s, host_s

// Path traversal attempts
AzureDiagnostics
| where Category == "FrontdoorWebApplicationFirewallLog"
| where requestUri_s has_any ("../", "..%2F", "%2e%2e%2f", "..%252f")
| project TimeGenerated, clientIp_s, requestUri_s, action_s

// SSRF attempts targeting metadata endpoints
AzureDiagnostics
| where Category == "FrontdoorWebApplicationFirewallLog"
| where requestUri_s has_any ("169.254.169.254", "metadata.google.internal", "127.0.0.1", "localhost")
| project TimeGenerated, clientIp_s, requestUri_s, action_s

// High rate of 4xx/5xx from single IP (scanning/fuzzing)
// From IIS/web server logs ingested
W3CIISLog
| where scStatus in (400, 403, 404, 500, 503)
| summarize ErrorCount=count() by cIP, bin(TimeGenerated, 5m)
| where ErrorCount > 100
| order by ErrorCount desc

// Web shell access pattern (POST requests to static-looking files)
W3CIISLog
| where csMethod == "POST"
| where csUriStem has_any (".php", ".asp", ".aspx", ".jsp")
| where csUriStem !in (known_legitimate_endpoints) // Define your app's known POST endpoints
| where csBytes > 0 and scBytes > 0 // Both sent and received data
| project TimeGenerated, cIP, csMethod, csUriStem, scStatus, csBytes, scBytes

// Known attack tool User-Agents
W3CIISLog
| where csUserAgent has_any ("sqlmap", "nikto", "dirbuster", "gobuster", "nuclei", "ZAP", "masscan", "wfuzz")
| project TimeGenerated, cIP, csUriStem, csUserAgent, scStatus
```

### 🔎 Splunk Queries (SPL)

```spl
// SQL injection in web logs
index=web sourcetype=access_combined
| where match(uri_query, "(?i)(union|select|drop|insert|exec|xp_cmdshell|'--|or\s+1=1)")
| stats count by src_ip, uri_path, _time span=5m
| where count > 5

// Path traversal
index=web sourcetype=access_combined
| where match(uri, "(?i)(\.\.\/|\.\.%2F|%2e%2e%2f)")
| table _time, src_ip, uri, status, bytes

// Scanner detection by user-agent
index=web sourcetype=access_combined
| where match(useragent, "(?i)(sqlmap|nikto|burp|dirbuster|gobuster|nuclei)")
| stats count by src_ip, useragent, _time span=1h
| table _time, src_ip, useragent, count

// High error rate (fuzzing)
index=web sourcetype=access_combined status>=400
| stats count as errors by src_ip, _time span=5m
| where errors > 100
```

---

## 🛠️ Remediation Steps

### Immediate Containment
- [ ] **Block the attacking IP** at the WAF and firewall level immediately
- [ ] If SQLi confirmed — **assess data exposure**: what tables/records were accessible? This may trigger a data breach notification
- [ ] If web shell uploaded — **identify and delete the shell**, then check for backdoor accounts or cron jobs created
- [ ] If SSRF exploited to reach metadata endpoint — **rotate any cloud credentials** that may have been exposed
- [ ] **Enable WAF blocking mode** (if previously in detection-only mode)
- [ ] Review recent **file uploads** on the server and quarantine any suspicious files

### Long-Term Fixes
- Implement **parameterised queries / prepared statements** to prevent SQLi at the code level
- Use a **Web Application Firewall (WAF)** in blocking mode with OWASP Core Rule Set
- Validate and **sanitise all user input** on the server side (never trust client-side validation alone)
- Implement **Content Security Policy (CSP)** headers to mitigate XSS
- Restrict **file upload** endpoints — validate file type server-side, store uploads outside the webroot, scan with AV
- Disable **error messages** in production that reveal stack traces or database errors
- Implement **SSRF protections** — block internal IP ranges from being fetched by server-side requests
- Conduct regular **penetration testing** and **DAST scanning** (OWASP ZAP, Burp Suite) on web applications
- Apply the principle of **least privilege** to the web application's database user

---

## 👨‍💻 SOC Analyst Actions (Step-by-Step)

1. **Triage the WAF alert** — Was it blocked or detected only? If detected/allowed, treat as a potential active attack.
2. **Identify the attack type** — SQLi? XSS? SSRF? Path traversal? This determines the potential impact.
3. **Assess if the attack was successful** — Check HTTP response codes and response sizes. A 200 OK with a large response body to a SQLi attempt is concerning. A 500 may indicate a syntax error in injection but could still reveal info.
4. **Scope the attacker's activity** — Pull all requests from the same IP in the past 24 hours. Are they scanning broadly or targeting specific endpoints?
5. **For SQLi** — Determine what the injected query attempted to retrieve. Check DB logs if available.
6. **For web shell** — Search file system logs and web server logs for any `.php`/`.asp` files recently written in the webroot. Check if the shell has been executed.
7. **For SSRF** — Check if requests to internal resources succeeded. Any cloud metadata access? Internal service responses?
8. **Block IOCs** — IP, ASN, user-agent string at WAF.
9. **Notify the application team** to patch the vulnerability identified.
10. **Assess regulatory impact** — If customer data or PII was accessible via the vulnerability, initiate your data breach response process.

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MITRE ATT&CK T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 - Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Azure WAF Rule Sets](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules)
- [SQLMap (for understanding attack tool)](https://sqlmap.org/)
