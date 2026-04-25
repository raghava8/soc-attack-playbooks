# Identity & Credential Attack Detection — Google SecOps / Chronicle

## Log Sources Required

| Chronicle Log Type | Data Source |
|-------------------|------------|
| `AZURE_AD` | Azure AD / Entra ID sign-in and audit logs |
| `OKTA` | Okta authentication logs |
| `WORKSPACE_ADMIN` | Google Workspace Admin audit logs |
| `WINDOWS_AD` | Active Directory Security Event Log (4625, 4740, 4768, 4769) |
| `MICROSOFT_DEFENDER_ENDPOINT` | LSASS access events |
| `WINDOWS_SYSMON` | Sysmon Event ID 10 (process access) |

---

## YARA-L 2.0 Detection Rules

---

### Rule 1 — Password Spray: Single IP, Many Accounts, Many Failures

```yaral
rule identity_password_spray {
  meta:
    author = "SOC"
    description = "Single source IP generating authentication failures against many distinct accounts — password spray pattern"
    severity = "HIGH"
    mitre_attack_technique = "T1110.003"
    false_positives = "Misconfigured service accounts or shared IP NAT — verify IP and user list"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip
    $e.principal.user.userid = $user

  match:
    $ip over 1h

  outcome:
    $unique_users = count_distinct($user)

  condition:
    $e and $unique_users > 10
}
```

---

### Rule 2 — Brute Force Success: Many Failures Followed by Login

```yaral
rule identity_brute_force_success {
  meta:
    author = "SOC"
    description = "Account had many failed logins from the same IP followed by a successful authentication"
    severity = "CRITICAL"
    mitre_attack_technique = "T1110.001"
    false_positives = "User mistyping password repeatedly then succeeding — low volume false positives, review manually"

  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.principal.ip = $ip
    $fail.principal.user.userid = $user
    $fail.metadata.event_timestamp.seconds = $t1

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.principal.ip = $ip
    $success.principal.user.userid = $user
    $success.metadata.event_timestamp.seconds > $t1
    $success.metadata.event_timestamp.seconds < ($t1 + 3600)

  match:
    $user, $ip over 1h

  outcome:
    $fail_count = count($fail.metadata.event_type)

  condition:
    $fail and $success and $fail_count >= 10
}
```

---

### Rule 3 — MFA Fatigue: Repeated MFA Denials for Same User

```yaral
rule identity_mfa_fatigue {
  meta:
    author = "SOC"
    description = "User received a high number of MFA prompts or denials in a short window — push bombing / MFA fatigue"
    severity = "HIGH"
    mitre_attack_technique = "T1621"
    false_positives = "User testing MFA repeatedly — contact user to verify"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.security_result.description = /mfa|multi.factor|authenticat/i
    $e.principal.user.userid = $user

  match:
    $user over 15m

  outcome:
    $mfa_denials = count($e.metadata.event_type)

  condition:
    $e and $mfa_denials >= 5
}
```

---

### Rule 4 — Impossible Travel: Login From Two Countries in 30 Minutes

```yaral
rule identity_impossible_travel {
  meta:
    author = "SOC"
    description = "Same user authenticated from two geographically distant locations within 30 minutes"
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

### Rule 5 — Kerberoasting: Multiple TGS Requests for Different Service Accounts

```yaral
rule identity_kerberoasting {
  meta:
    author = "SOC"
    description = "Single user requesting many Kerberos service tickets (TGS) in a short period — Kerberoasting pattern"
    severity = "HIGH"
    mitre_attack_technique = "T1558.003"
    false_positives = "Legitimate service account enumeration by monitoring tools — verify requestor"

  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.metadata.product_name = /active.directory|kerberos/i
    $e.security_result.description = /TGS|service.ticket|kerberos/i
    $e.principal.user.userid = $user
    $e.target.resource.name = $svc

  match:
    $user over 5m

  outcome:
    $ticket_count = count_distinct($svc)

  condition:
    $e and $ticket_count >= 5
}
```

---

### Rule 6 — LSASS Memory Access (Credential Dumping)

```yaral
rule identity_lsass_access {
  meta:
    author = "SOC"
    description = "Non-system process accessed LSASS memory — likely credential dumping via Mimikatz or similar"
    severity = "CRITICAL"
    mitre_attack_technique = "T1003.001"
    false_positives = "AV/EDR processes accessing LSASS for monitoring — whitelist known security tool paths"

  events:
    $e.metadata.event_type = "PROCESS_OPEN"
    $e.target.process.file.full_path = /lsass\.exe/i
    not $e.principal.process.file.full_path = /MsMpEng\.exe|SentinelAgent\.exe|csagent\.exe|CylanceSvc\.exe/i
    $e.principal.hostname = $host

  condition:
    $e
}
```

---

## UDM Search Queries

Run in **Chronicle > Search (UDM Search)**.

---

### Hunt 1 — All Failed Logins From a Suspicious IP

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "BLOCK"
AND principal.ip = "1.2.3.4"
```

---

### Hunt 2 — Successful Logins From a New Country

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND NOT principal.location.country_or_region = "GB"
```

---

### Hunt 3 — Sign-ins Using Legacy Authentication

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND network.application_protocol = /IMAP|POP3|SMTP/i
```

---

### Hunt 4 — MFA Denied Events for a Specific User

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "BLOCK"
AND security_result.description = /mfa|multi.factor/i
AND principal.user.userid = "user@domain.com"
```

---

### Hunt 5 — New Device or Location for a Privileged Account

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND principal.user.userid = "admin@domain.com"
```
> Review results and compare IP/location/device against historical baseline.

---

### Hunt 6 — LSASS Process Access Events Across Fleet

```
metadata.event_type = "PROCESS_OPEN"
AND target.process.file.full_path = /lsass\.exe/i
```
