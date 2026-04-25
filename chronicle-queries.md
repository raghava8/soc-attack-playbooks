# Phishing Detection — Google SecOps / Chronicle

## Log Sources Required

| Chronicle Log Type | Data Source |
|-------------------|------------|
| `WORKSPACE_GMAIL` | Google Workspace Gmail logs |
| `OFFICE_365` | Microsoft 365 email (via Chronicle ingestion) |
| `ZSCALER_WEBPROXY` / `SQUID` | Proxy / Secure Web Gateway |
| `MICROSOFT_DEFENDER_ENDPOINT` | Endpoint telemetry |
| `CS_EDR` | CrowdStrike Falcon |

---

## YARA-L 2.0 Detection Rules

Deploy these rules in **Chronicle > Detection Engine > Rules**.

---

### Rule 1 — Suspicious Email Attachment Delivered (Not Blocked)

Fires when a high-risk attachment type reaches the mailbox without being blocked.

```yaral
rule phishing_risky_attachment_delivered {
  meta:
    author = "SOC"
    description = "Email with high-risk attachment type was delivered to mailbox"
    severity = "HIGH"
    mitre_attack_tactic = "Initial Access"
    mitre_attack_technique = "T1566.001"
    false_positives = "Legitimate ISO files sent by vendors — verify sender domain"

  events:
    $e.metadata.event_type = "EMAIL_TRANSACTION"
    $e.security_result.action = "ALLOW"
    (
      $e.about.file.full_path = /\.(iso|img|lnk|vbs|js|hta|wsf)$/i or
      $e.about.file.full_path = /\.html?$/i
    )
    $e.target.user.email_addresses = $recipient

  condition:
    $e
}
```

---

### Rule 2 — User Clicked Email URL Then Authenticated (Credential Harvest Pivot)

Correlates a proxy hit on a suspicious URL from email with a successful login by the same user within 10 minutes — strong indicator of credential submission.

```yaral
rule phishing_click_then_auth {
  meta:
    author = "SOC"
    description = "User visited a URL from email then authenticated within 10 minutes"
    severity = "CRITICAL"
    mitre_attack_technique = "T1566.002"
    false_positives = "SSO-triggered logins after clicking a legitimate link — verify URL reputation"

  events:
    $click.metadata.event_type = "NETWORK_HTTP"
    $click.principal.user.userid = $user
    $click.target.url = /http/
    $click.metadata.event_timestamp.seconds = $t1

    $login.metadata.event_type = "USER_LOGIN"
    $login.principal.user.userid = $user
    $login.security_result.action = "ALLOW"
    $login.metadata.event_timestamp.seconds > $t1
    $login.metadata.event_timestamp.seconds < ($t1 + 600)

  match:
    $user over 10m

  condition:
    $click and $login
}
```

---

### Rule 3 — BEC: Inbox Forwarding Rule Created to External Address

Detects the creation of an inbox forwarding or redirect rule pointing to an external email address — a top indicator of Business Email Compromise.

```yaral
rule bec_external_forwarding_rule {
  meta:
    author = "SOC"
    description = "Inbox rule created to forward email to external address"
    severity = "CRITICAL"
    mitre_attack_technique = "T1114.003"
    false_positives = "Legitimate out-of-office auto-forward — verify with user"

  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
    (
      $e.target.resource.name = /new-inboxrule|set-inboxrule/i or
      $e.security_result.description = /forwardto|redirectto|forwardasattachment/i
    )
    $e.principal.user.userid = $user

  condition:
    $e
}
```

---

### Rule 4 — AiTM: Impossible Travel After Email-Triggered Login

Fires when the same user account authenticates from two countries within a short window — characteristic of AiTM session token replay.

```yaral
rule phishing_aitm_impossible_travel {
  meta:
    author = "SOC"
    description = "Same user authenticated from two different countries within 30 minutes"
    severity = "CRITICAL"
    mitre_attack_technique = "T1078"
    false_positives = "VPN users, corporate travellers — verify with user"

  events:
    $a.metadata.event_type = "USER_LOGIN"
    $a.security_result.action = "ALLOW"
    $a.principal.user.userid = $user
    $a.principal.location.country_or_region = $country1
    $a.metadata.event_timestamp.seconds = $t1

    $b.metadata.event_type = "USER_LOGIN"
    $b.security_result.action = "ALLOW"
    $b.principal.user.userid = $user
    $b.principal.location.country_or_region = $country2
    $b.metadata.event_timestamp.seconds > $t1
    $b.metadata.event_timestamp.seconds < ($t1 + 1800)

    $country1 != $country2

  match:
    $user over 30m

  condition:
    $a and $b
}
```

---

### Rule 5 — HTML Smuggling: Browser Spawns Suspicious Child Process

Detects a browser spawning a shell or script engine — consistent with an HTML attachment executing a payload via the browser's file handling.

```yaral
rule html_smuggling_browser_child_process {
  meta:
    author = "SOC"
    description = "Browser process spawned a shell or script interpreter"
    severity = "HIGH"
    mitre_attack_technique = "T1027.006"
    false_positives = "Browser-based dev tools in unusual configurations — rare"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.process.file.full_path = /chrome\.exe|msedge\.exe|firefox\.exe|iexplore\.exe/i
    $e.target.process.file.full_path = /powershell\.exe|cmd\.exe|wscript\.exe|mshta\.exe|cscript\.exe/i
    $e.principal.hostname = $host

  condition:
    $e
}
```

---

## UDM Search Queries

Run these directly in **Chronicle > Search (UDM Search)**.

---

### Hunt 1 — All Delivered Emails to a Specific User

```
metadata.event_type = "EMAIL_TRANSACTION"
AND security_result.action = "ALLOW"
AND target.user.email_addresses = "victim@yourdomain.com"
```

---

### Hunt 2 — All Recipients of a Phishing Campaign (by Sender Domain)

```
metadata.event_type = "EMAIL_TRANSACTION"
AND network.email.from = /suspicious-domain\.com/
```

---

### Hunt 3 — Proxy Hits to a Known Phishing Domain

```
metadata.event_type = "NETWORK_HTTP"
AND target.url = /phishingsite\.com/
```

---

### Hunt 4 — Users Who Logged In From an Unexpected Country

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND NOT principal.location.country_or_region = "GB"
```
> Replace `"GB"` with your expected base country.

---

### Hunt 5 — Inbox Rules Created in the Last 24 Hours

```
metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
AND target.resource.name = /inboxrule/i
```

---

### Hunt 6 — Emails With Double-Extension Attachments

```
metadata.event_type = "EMAIL_TRANSACTION"
AND about.file.full_path = /\.(pdf|doc|xls|zip)\.(exe|lnk|vbs|js)$/i
```

---

### Hunt 7 — Sign-ins Using Legacy or Basic Authentication

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND network.application_protocol = "IMAP"
```
> Repeat with `POP3`, `SMTP` to cover all legacy auth protocols.

---

## Chronicle Reference Lists

Add confirmed IOCs to Chronicle Reference Lists for real-time matching in YARA-L rules.

**Create list:** Chronicle > Settings > Reference Lists

```
List name : phishing_domains
Type      : REGEX

# Example entries
malicious-login\.net
microsoftonline-verify\.com
helpdesk-reset-portal\.xyz
```

**Use in YARA-L:**
```yaral
$e.target.url in %phishing_domains
```
