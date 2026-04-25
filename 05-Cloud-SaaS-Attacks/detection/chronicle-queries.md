# Cloud & SaaS Attack Detection — Google SecOps / Chronicle

## Log Sources Required

| Chronicle Log Type | Data Source |
|-------------------|------------|
| `AZURE_AD` | Azure AD / Entra ID Sign-in and Audit logs |
| `OFFICE_365` | Microsoft 365 Unified Audit Log |
| `WORKSPACE_ADMIN` | Google Workspace Admin Audit |
| `WORKSPACE_GMAIL` | Google Workspace Gmail logs |
| `WORKSPACE_DRIVE` | Google Workspace Drive audit |
| `AWS_CLOUDTRAIL` | AWS CloudTrail API events |
| `GCP_CLOUD_AUDIT` | Google Cloud Audit logs |

---

## YARA-L 2.0 Detection Rules

---

### Rule 1 — OAuth App Granted High-Privilege Consent

```yaral
rule cloud_oauth_high_privilege_consent {
  meta:
    author = "SOC"
    description = "User granted consent to an OAuth application requesting high-privilege permissions"
    severity = "CRITICAL"
    mitre_attack_technique = "T1550.001"
    false_positives = "Legitimate enterprise app deployments — verify app publisher and tenant registration"

  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
    (
      $e.target.resource.name = /consent.to.application|add.oauth2permissiongrant/i or
      $e.security_result.description = /Mail\.Read|Files\.ReadWrite\.All|User\.ReadAll|Directory\.ReadWrite\.All|MailboxSettings\.ReadWrite/i
    )
    $e.principal.user.userid = $user

  condition:
    $e
}
```

---

### Rule 2 — Mass File Download from Cloud Storage

```yaral
rule cloud_mass_file_download {
  meta:
    author = "SOC"
    description = "User downloaded an unusually high number of files from SharePoint, OneDrive, or Drive in a short period"
    severity = "HIGH"
    mitre_attack_technique = "T1530"
    false_positives = "Bulk migration projects — verify with change management"

  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.security_result.action = "ALLOW"
    (
      $e.metadata.product_name = /sharepoint|onedrive|google.drive/i or
      $e.target.resource.type = /file|document/i
    )
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.principal.user.userid = $user

  match:
    $user over 15m

  outcome:
    $download_count = count($e.metadata.event_type)

  condition:
    $e and $download_count > 100
}
```

---

### Rule 3 — External Email Forwarding Rule Created

```yaral
rule cloud_external_forwarding_rule {
  meta:
    author = "SOC"
    description = "User created an inbox rule forwarding all email to an external address"
    severity = "CRITICAL"
    mitre_attack_technique = "T1114.002"
    false_positives = "Legitimate out-of-office forwarding — verify with user"

  events:
    $e.metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
    (
      $e.target.resource.name = /new-inboxrule|set-inboxrule/i or
      $e.security_result.description = /forwardto|redirectto|forwardasattachment|deleteMessage/i
    )
    not $e.security_result.description = /yourdomain\.com/i
    $e.principal.user.userid = $user

  condition:
    $e
}
```

---

### Rule 4 — Privileged Role Assigned to User (Global Admin / Owner)

```yaral
rule cloud_privileged_role_assigned {
  meta:
    author = "SOC"
    description = "A highly privileged role was assigned to a user account — possible persistence or privilege escalation"
    severity = "CRITICAL"
    mitre_attack_technique = "T1098.003"
    false_positives = "Legitimate admin onboarding — verify with IT management"

  events:
    $e.metadata.event_type = "USER_CHANGE_PERMISSIONS"
    (
      $e.security_result.description = /Global Administrator|Company Administrator|Privileged Role Administrator|Owner/i or
      $e.target.resource.name = /Global Administrator|Privileged Role/i
    )
    $e.principal.user.userid = $actor

  condition:
    $e
}
```

---

### Rule 5 — New Application Registration in Cloud Tenant

```yaral
rule cloud_new_app_registration {
  meta:
    author = "SOC"
    description = "New application registered in the cloud tenant — verify legitimacy, especially if followed by API permission grants"
    severity = "MEDIUM"
    mitre_attack_technique = "T1136.003"
    false_positives = "Legitimate developer activity — check with app owner"

  events:
    $e.metadata.event_type = "RESOURCE_CREATION"
    (
      $e.target.resource.type = /application|service.principal/i or
      $e.metadata.product_event_type = /add.application|add.service.principal/i
    )
    $e.principal.user.userid = $actor

  condition:
    $e
}
```

---

### Rule 6 — AWS: New IAM User or Access Key Created From Unusual IP

```yaral
rule cloud_aws_new_iam_user {
  meta:
    author = "SOC"
    description = "New IAM user or access key created in AWS — potential backdoor persistence after credential compromise"
    severity = "CRITICAL"
    mitre_attack_technique = "T1136.003"
    false_positives = "Legitimate IAM provisioning — verify with cloud team"

  events:
    $e.metadata.event_type = "RESOURCE_CREATION"
    $e.metadata.product_name = /aws/i
    (
      $e.metadata.product_event_type = /CreateUser|CreateAccessKey|CreateRole/i
    )
    $e.principal.user.userid = $actor
    $e.principal.ip = $ip

  condition:
    $e
}
```

---

### Rule 7 — Impossible Travel for Cloud Sign-in (30-Minute Window)

```yaral
rule cloud_impossible_travel {
  meta:
    author = "SOC"
    description = "Same cloud account authenticated from two different countries within 30 minutes"
    severity = "CRITICAL"
    mitre_attack_technique = "T1078.004"
    false_positives = "VPN exit nodes, corporate roaming — verify with user"

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

## UDM Search Queries

Run in **Chronicle > Search (UDM Search)**.

---

### Hunt 1 — All Cloud Sign-ins for a User in Last 48h

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND principal.user.userid = "user@yourdomain.com"
```

---

### Hunt 2 — OAuth App Consents in Last 7 Days

```
metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
AND target.resource.name = /consent|oauth2permissiongrant/i
```

---

### Hunt 3 — All Files Downloaded by a Specific User

```
metadata.event_type = "USER_RESOURCE_ACCESS"
AND principal.user.userid = "user@yourdomain.com"
AND target.resource.type = /file/i
```

---

### Hunt 4 — New Admin Role Assignments This Week

```
metadata.event_type = "USER_CHANGE_PERMISSIONS"
AND security_result.description = /Global Administrator|Privileged/i
```

---

### Hunt 5 — Sign-ins to Cloud Admin Portals From External IPs

```
metadata.event_type = "USER_LOGIN"
AND security_result.action = "ALLOW"
AND target.url = /portal\.azure\.com|admin\.microsoft\.com|console\.aws\.amazon\.com/i
AND NOT principal.ip = /^10\.|^192\.168\.|^172\./
```

---

### Hunt 6 — AWS CloudTrail: High-Risk API Calls

```
metadata.event_type = "RESOURCE_CREATION"
AND metadata.product_name = /aws/i
AND metadata.product_event_type = /CreateUser|PutBucketPolicy|DeleteTrail|DisableAlarmActions/i
```

---

### Hunt 7 — External Anonymous Sharing Links Created (SharePoint/Drive)

```
metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
AND security_result.description = /AnonymousLink|SharingLinkCreated|shared.*anyone/i
```
