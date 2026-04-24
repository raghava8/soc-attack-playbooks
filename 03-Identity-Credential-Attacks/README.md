# 🔑 Identity & Credential Attacks

**MITRE ATT&CK Tactics:** Credential Access (TA0006), Initial Access (TA0001), Persistence (TA0003)  
**Common Techniques:** T1110 (Brute Force), T1621 (MFA Request Generation), T1539 (Steal Web Session Cookie), T1078 (Valid Accounts)  
**Severity:** 🔴 High  

---

## 📖 Overview

Identity-based attacks target user credentials and authentication mechanisms to gain unauthorised access. Since most modern environments rely on cloud identity providers (Azure AD/Entra ID, Okta, Google Workspace), compromising a single account can give attackers access to email, cloud storage, business apps, and internal systems.

**Types commonly seen in SOC alerts:**
- **Password Spray** — One or few passwords tried against many accounts (avoids lockout)
- **Brute Force** — Many passwords tried against one account
- **Credential Stuffing** — Leaked username/password pairs tested across services
- **MFA Fatigue (Push Bombing)** — Repeated MFA prompts sent until the user approves
- **Adversary-in-the-Middle (AiTM)** — Real-time session token theft bypassing MFA (Evilginx2, Modlishka)
- **Pass-the-Hash / Pass-the-Ticket** — Reusing credential hashes/Kerberos tickets without knowing the password
- **Kerberoasting** — Requesting service tickets for offline cracking

---

## ⚔️ Attack Techniques

- Spraying common passwords (`Winter2024!`, `Company@123`, `Welcome1`) across all Active Directory accounts
- Using legitimate Microsoft/Okta APIs to spray without triggering traditional lockout policies
- Deploying AiTM phishing proxies (EvilProxy, Evilginx2) to capture session tokens post-MFA
- Registering attacker-controlled MFA devices on compromised accounts for persistence
- Extracting NTLM hashes from LSASS memory using Mimikatz or Task Manager dump
- Using `Rubeus` or `Impacket` for Kerberos attacks (AS-REP Roasting, Kerberoasting)
- Abusing OAuth consent grants to maintain persistent access even after password reset

---

## 🔍 How to Identify in Logs

### Key Log Sources
- Azure AD / Entra ID Sign-in Logs
- Active Directory Security Event Log (4625, 4740, 4768, 4769, 4771)
- MFA logs (Entra ID, Okta, Duo)
- Endpoint logs (4624, 4648, Sysmon Event 10 for LSASS access)

### Indicators to Hunt For
- Single IP authenticating against many different accounts in a short period (spray)
- Many failed logins followed by one success (brute force)
- User receiving many MFA push notifications they didn't initiate
- Sign-in from a country/IP the user has never used before
- New MFA device registered immediately after sign-in
- LSASS process accessed by non-system processes
- Service account tickets requested for high-privilege accounts (Kerberoasting)
- Sign-in using Legacy Authentication protocols (IMAP, SMTP, POP3) that bypass MFA

### 🔎 Microsoft Sentinel Queries (KQL)

```kql
// Password spray - one IP, many users, many failures
SigninLogs
| where ResultType != "0"
| summarize FailedAccounts=dcount(UserPrincipalName), FailedAttempts=count() by IPAddress, bin(TimeGenerated, 1h)
| where FailedAccounts > 10
| order by FailedAccounts desc

// Successful sign-in after many failures (brute force success)
let failures = SigninLogs
    | where ResultType != "0"
    | summarize FailCount=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h);
SigninLogs
| where ResultType == "0"
| join kind=inner failures on UserPrincipalName, IPAddress
| where FailCount > 5
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, FailCount

// MFA fatigue - user received many MFA prompts in short time
AADNonInteractiveUserSignInLogs
| union SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType in ("50074","50076","500121") // MFA required / denied codes
| summarize MFAPrompts=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where MFAPrompts > 5
| order by MFAPrompts desc

// AiTM - token replay from unusual location after MFA success
SigninLogs
| where AuthenticationDetails has "MFA" and ResultType == "0"
| summarize Locations=dcount(Location), IPs=dcount(IPAddress) by UserPrincipalName, CorrelationId
| where Locations > 1 or IPs > 1

// New MFA method registered on account
AuditLogs
| where OperationName has_any ("Register security info", "User registered security info", "Authentication method registered")
| project TimeGenerated, Identity, OperationName, TargetResources, IPAddress=tostring(parse_json(tostring(AdditionalDetails))[0].value)

// Legacy authentication (bypasses MFA)
SigninLogs
| where ClientAppUsed in ("IMAP", "POP3", "SMTP Auth", "Exchange ActiveSync", "Basic Auth")
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, Location

// LSASS access (credential dumping on endpoint)
// Requires Sysmon Event ID 10
SecurityEvent
| where EventID == 10
| where TargetImage has "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
| where SourceImage !has_any ("AV vendor processes", "MicrosoftEdgeUpdate.exe")
| project TimeGenerated, Computer, SourceImage, GrantedAccess
```

### 🔎 Splunk Queries (SPL)

```spl
// Password spray detection
index=azure sourcetype=azure:aad:signin ResultType!=0
| stats dc(UserPrincipalName) as unique_users count as attempts by IPAddress, _time span=1h
| where unique_users > 10
| table _time, IPAddress, unique_users, attempts

// Kerberoasting detection (multiple TGS requests)
index=windows EventCode=4769 TicketEncryptionType=0x17
| stats count by SubjectUserName, ServiceName, _time span=5m
| where count > 5
| table _time, SubjectUserName, ServiceName, count
```

---

## 🛠️ Remediation Steps

### Immediate Containment
- [ ] **Block the attacking IP(s)** at firewall and Conditional Access Policy
- [ ] **Disable the compromised account** temporarily while investigating
- [ ] **Revoke all active sessions** — Azure: `Revoke-AzureADUserAllRefreshToken` / Entra: Revoke Sessions
- [ ] **Reset the password** to something strong and unique
- [ ] **Remove unknown MFA devices** registered on the account
- [ ] **Check and remove** any OAuth app consents or inbox rules created by the attacker
- [ ] If credential dumping occurred on an endpoint — **rotate all service account passwords** and Kerberos accounts (especially KRBTGT for golden ticket risk)

### Long-Term Fixes
- Enforce **Phishing-Resistant MFA** (FIDO2/passkeys, Certificate-Based Auth) — not push/SMS
- Block **Legacy Authentication** protocols globally via Conditional Access
- Enable **Identity Protection** / UEBA to baseline and detect anomalous sign-ins
- Apply **Conditional Access** policies: block sign-in from non-compliant/unmanaged devices
- Implement **Password Protection** (ban common passwords) in AD and Entra ID
- Enable **LSASS Protection** (RunAsPPL) and Credential Guard
- Disable **unconstrained Kerberos delegation** and ensure service accounts have strong passwords

---

## 👨‍💻 SOC Analyst Actions (Step-by-Step)

1. **Identify the attack type** — Is this a spray (many accounts), brute force (one account), or post-MFA token theft?
2. **Determine if there was a successful login** — A failed spray is lower urgency; a successful sign-in is an active compromise.
3. **For successful logins** — Check what the attacker accessed: email (Graph API), SharePoint, cloud apps.
4. **Check for persistence** — New MFA device? OAuth consent? Mail forwarding rule? New app registered?
5. **Review sign-in location and device** — Compare to the user's baseline. Impossible travel? Unknown device?
6. **If token theft (AiTM)** — Password reset alone is NOT enough. All refresh tokens must be revoked.
7. **Notify the user** — Ask them to confirm whether they approved any MFA prompts they didn't initiate.
8. **Block IOCs** — Attacker IP, ASN if cloud VPN/proxy, malicious OAuth app ID.
9. **Scan for lateral movement** — Did the attacker use the compromised account to access other systems or send internal phishing?
10. **Escalate** if privileged accounts (Global Admin, Domain Admin) were compromised.

---

## 📚 References

- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1621 - MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
- [Microsoft - Investigate compromised accounts](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account)
- [Detecting AiTM Phishing with Sentinel](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/what-s-new-detect-adversary-in-the-middle-aitm-phishing/ba-p/3290171)
- [CISA Guidance on MFA](https://www.cisa.gov/mfa)
