# ☁️ Cloud & SaaS Attacks

**MITRE ATT&CK Tactics:** Initial Access (TA0001), Persistence (TA0003), Collection (TA0009), Exfiltration (TA0010)  
**Common Techniques:** T1078.004 (Valid Cloud Accounts), T1530 (Data from Cloud Storage), T1537 (Transfer to Cloud Account), T1550.001 (Application Access Token)  
**Severity:** 🔴 Critical  

---

## 📖 Overview

As organisations migrate to cloud and SaaS platforms (Microsoft 365, Azure, AWS, Google Workspace, Salesforce), attackers increasingly target cloud identities and services. Cloud attacks are particularly dangerous because they can grant access to vast amounts of data without touching any endpoint, often evading traditional security controls.

**Types commonly seen in SOC alerts:**
- **Impossible Travel** — Sign-in from two geographically distant locations in a short time
- **OAuth App Abuse** — Malicious third-party apps granted access to user data via consent phishing
- **Cloud Storage Exfiltration** — Mass download or sharing of sensitive files from SharePoint/OneDrive/S3
- **Azure AD / Entra ID Misconfiguration Abuse** — Exploiting overly permissive roles, guest accounts, or app registrations
- **Mailbox Compromise & Email Forwarding** — Attacker reads all email and forwards to external address
- **Service Principal / API Key Abuse** — Compromised Azure service principals or AWS access keys used for persistence
- **Tenant-Wide Attacks** — Adding malicious global admin, creating rogue app registrations

---

## ⚔️ Attack Techniques

- AiTM phishing to steal cloud session tokens, bypassing MFA
- Consenting to a malicious OAuth app that requests `Mail.Read`, `Files.ReadWrite.All`, or `User.ReadAll` permissions
- Registering a new application in the tenant with broad API permissions as a persistence mechanism
- Downloading entire SharePoint document libraries using the Graph API
- Creating inbox forwarding rules to send all emails to an external attacker-controlled address
- Elevating privileges by adding attacker's account to the Global Administrator role
- Exploiting public S3 buckets or Azure Blob containers with misconfigured ACLs
- Using compromised AWS access keys to create new IAM users, spin up EC2 instances, or exfiltrate S3 data

---

## 🔍 How to Identify in Logs

### Key Log Sources
- Azure AD / Entra ID Sign-in Logs and Audit Logs
- Microsoft 365 Unified Audit Log (UAL)
- Microsoft Defender for Cloud Apps (MDCA)
- AWS CloudTrail
- Azure Activity Log / Diagnostic Logs

### Indicators to Hunt For
- Sign-in from two different countries within less than 1–2 hours (impossible travel)
- OAuth app granted high-privilege permissions by a user
- Mass file downloads from SharePoint/OneDrive (>50 files in a short period)
- New inbox rule created to forward/delete emails
- New Global Admin or privileged role assignment
- New application registration with API permissions (especially without admin consent)
- Sign-in to admin portals (Azure Portal, M365 Admin) from unusual IPs or outside business hours
- AWS: IAM user or access key created from a new IP; unusual S3 `GetObject` calls at high volume

### 🔎 Microsoft Sentinel Queries (KQL)

```kql
// Impossible travel detection
let travelThresholdKph = 900; // Speed threshold in km/h
SigninLogs
| where ResultType == 0
| project UserPrincipalName, TimeGenerated, Location, Latitude=toreal(LocationDetails.geoCoordinates.latitude), Longitude=toreal(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| extend PrevTime=prev(TimeGenerated), PrevLat=prev(Latitude), PrevLon=prev(Longitude), PrevUser=prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend TimeDiffHours = datetime_diff('minute', TimeGenerated, PrevTime) / 60.0
| extend DistanceKm = geo_distance_2points(PrevLon, PrevLat, Longitude, Latitude) / 1000
| extend SpeedKph = DistanceKm / TimeDiffHours
| where SpeedKph > travelThresholdKph and TimeDiffHours > 0
| project UserPrincipalName, TimeGenerated, PrevTime, Location, DistanceKm, SpeedKph

// Malicious OAuth app consent
AuditLogs
| where OperationName has_any ("Consent to application", "Add OAuth2PermissionGrant")
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedPermissions = tostring(AdditionalDetails)
| where ConsentedPermissions has_any ("Mail.Read", "Files.ReadWrite.All", "MailboxSettings.ReadWrite", "User.ReadAll", "Directory.ReadWrite.All")
| project TimeGenerated, Identity, AppName, ConsentedPermissions, IPAddress

// Mass file download from SharePoint/OneDrive
OfficeActivity
| where Operation in ("FileDownloaded", "FileAccessed")
| summarize FileCount=count() by UserId, ClientIP, bin(TimeGenerated, 15m)
| where FileCount > 50
| order by FileCount desc

// Inbox forwarding rule created
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, ClientIP, Parameters

// New Global Admin or privileged role assigned
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| where TargetResources[0].modifiedProperties contains "Global Administrator" or TargetResources[0].modifiedProperties contains "Privileged"
| project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), TargetUser=tostring(TargetResources[0].userPrincipalName), RoleName=tostring(TargetResources[0].displayName)

// New application registration with API permissions
AuditLogs
| where OperationName in ("Add application", "Update application – Certificates and secrets management")
| project TimeGenerated, Identity, TargetResources, IPAddress=tostring(AdditionalDetails[0].value)
```

### 🔎 Splunk Queries (SPL)

```spl
// Mass file download O365
index=o365 sourcetype=o365:management:activity Operation IN ("FileDownloaded","FileAccessed")
| stats count as downloads by UserId, ClientIP, _time span=15m
| where downloads > 50
| table _time, UserId, ClientIP, downloads

// Inbox forwarding rule
index=o365 sourcetype=o365:management:activity 
| where Operation IN ("New-InboxRule","Set-InboxRule")
| where Parameters="*ForwardTo*" OR Parameters="*RedirectTo*"
| table _time, UserId, ClientIP, Parameters

// AWS - New IAM user creation
index=aws sourcetype=aws:cloudtrail eventName=CreateUser
| table _time, userAgent, sourceIPAddress, requestParameters.userName, userIdentity.arn
```

---

## 🛠️ Remediation Steps

### Immediate Containment
- [ ] **Revoke all sessions** for the compromised cloud account
- [ ] **Remove malicious OAuth app consent** — Go to Enterprise Applications in Entra ID and delete the app or revoke permissions
- [ ] **Delete inbox forwarding rules** from the compromised mailbox
- [ ] **Remove any newly added admin roles** from the attacker's accounts
- [ ] **Disable any rogue app registrations** or service principals created by the attacker
- [ ] **Rotate API keys / Service Principal secrets** if compromised
- [ ] For AWS: **Disable the compromised IAM access key** and audit what actions were performed with it

### Long-Term Fixes
- Enable **Microsoft Defender for Cloud Apps** to monitor OAuth app consents and alert on suspicious app permissions
- Configure **Admin Consent Workflow** so users cannot self-consent to high-privilege OAuth apps
- Block **external email forwarding** via Exchange transport rules or Defender anti-spam policy
- Implement **Conditional Access** to enforce compliant devices and restrict access from unexpected locations
- Enable **Privileged Identity Management (PIM)** for all privileged Azure AD roles — no standing admin access
- Apply **least privilege** to all service principals and app registrations
- Enable **AWS GuardDuty** for anomaly detection in AWS environments
- Regularly audit **guest accounts** and **external sharing settings** in SharePoint/Teams

---

## 👨‍💻 SOC Analyst Actions (Step-by-Step)

1. **Confirm the alert** — Is the impossible travel a VPN, corporate travel, or genuine compromise? Contact the user.
2. **Assess what was accessed** — Review the user's cloud activity for the past 24–72 hours. Email read? Files downloaded? Admin actions taken?
3. **Check for persistence** — Look for: OAuth app consents, inbox rules, new MFA devices, app registrations, role assignments.
4. **Revoke sessions and reset credentials** — Do not stop at password reset; revoke all refresh tokens.
5. **Remove attacker persistence** — Delete inbox rules, remove OAuth app consents, disable rogue app registrations.
6. **Assess data exposure** — Which files were accessed or downloaded? Is there PII, financial data, or IP involved?
7. **Check for lateral movement** — Did the attacker use the compromised account to access other users' mailboxes, SharePoint sites, or cloud resources?
8. **For AWS incidents** — Review CloudTrail for all API calls made with the compromised key. Check for new IAM users, EC2 instances, or S3 access.
9. **Notify data owners** if sensitive data was accessed — this may trigger GDPR/regulatory obligations.
10. **Escalate** if tenant-wide compromise is suspected (Global Admin compromised, multiple users affected).

---

## 📚 References

- [MITRE ATT&CK - Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Microsoft - Respond to compromised Microsoft 365 account](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account)
- [CISA M365 Security Best Practices](https://www.cisa.gov/microsoft-365-security-best-practices)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [Microsoft Defender for Cloud Apps Documentation](https://learn.microsoft.com/en-us/defender-cloud-apps/)
