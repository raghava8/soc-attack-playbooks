# 📧 Phishing & Email-Based Attacks

**MITRE ATT&CK Tactics:** Initial Access (TA0001), Execution (TA0002)  
**Common Techniques:** T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link), T1078 (Valid Accounts)  
**Severity:** 🔴 High  

---

## 📖 Overview

Phishing is one of the most common initial access vectors used by threat actors. Attackers send deceptive emails impersonating trusted entities (banks, IT helpdesk, Microsoft, HR) to trick users into clicking malicious links, downloading malware-laced attachments, or submitting credentials on fake login pages.

**Types of phishing seen in SOC daily alerts:**
- **Spearphishing** — Targeted attacks against specific individuals or departments
- **Business Email Compromise (BEC)** — Impersonation of executives to authorise wire transfers or data disclosure
- **Credential Harvesting** — Fake login portals (O365, VPN, Outlook Web Access)
- **Malicious Attachments** — Office macros, ISO files, PDFs with embedded links
- **QR Code Phishing (Quishing)** — QR codes in emails bypassing URL scanners

---

## ⚔️ Attack Techniques

- Sending emails from lookalike domains (e.g., `micros0ft.com`, `support-helpdesk[.]net`)
- Embedding malicious URLs behind legitimate-looking hyperlinks or redirectors
- Using compromised legitimate accounts to send phishing at scale (harder to detect)
- Attaching `.html` files that open a credential-harvesting page locally (bypasses email gateway URL scanning)
- Exploiting open redirects on trusted domains (Google, LinkedIn) to proxy phishing URLs
- HTML smuggling — embedding malware inside HTML attachments decoded in the browser

---

## 🔍 How to Identify in Logs

### Key Log Sources
- Email gateway logs (Microsoft Defender for Office 365, Proofpoint, Mimecast)
- Azure AD / Entra ID Sign-in logs
- Endpoint logs (MDE, Sysmon)
- Proxy/DNS logs

### Indicators to Hunt For
- Emails with mismatched `From:` vs `Reply-To:` headers
- Newly registered domains (< 30 days old) in email sender or URLs
- Emails with `.html`, `.htm`, `.iso`, `.img`, `.lnk` attachments
- User clicked a URL that redirected through multiple hops
- Successful sign-in from an unusual country immediately after a phishing email landed
- Mass identical emails sent to multiple users within minutes

### 🔎 Microsoft Sentinel Queries (KQL)

```kql
// Detect emails with suspicious attachment types
EmailAttachmentInfo
| where FileType in ("html", "htm", "iso", "img", "lnk", "vbs", "js")
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction != "Blocked"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, DeliveryAction

// Users who clicked a phishing URL and then signed in
EmailUrlInfo
| where UrlDomain !in (trusted_domains)  // Define your trusted domain list
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| project NetworkMessageId, RecipientEmailAddress, Url, UrlDomain
| join kind=inner (
    AADSignInLogs
    | where ResultType == 0
    | project UserPrincipalName, SignInTime=TimeGenerated, IPAddress, Location
) on $left.RecipientEmailAddress == $right.UserPrincipalName

// BEC - Inbox rule created to forward/delete emails (post-compromise)
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData contains "ForwardTo" or RawEventData contains "DeleteMessage"
| project Timestamp, AccountDisplayName, IPAddress, RawEventData
```

### 🔎 Splunk Queries (SPL)

```spl
// Suspicious attachment delivery
index=email sourcetype=o365:management:activity 
| where Operation="MessageReceived" AND Attachment_Extension IN ("html","htm","iso","img","lnk","vbs")
| table _time, SenderAddress, RecipientAddress, Subject, Attachment_Name

// Sign-in after phishing email delivery
index=azure sourcetype=azure:aad:signin 
ResultType=0 
| stats count by UserPrincipalName, IPAddress, Location, _time
| join UserPrincipalName [
    search index=email sourcetype=o365:management:activity Operation=MessageReceived
    | table RecipientAddress
    | rename RecipientAddress as UserPrincipalName
]
```

---

## 🛠️ Remediation Steps

### Immediate Containment
- [ ] **Soft-delete** the phishing email from all affected mailboxes using `Search-Mailbox` or Purge in Microsoft Defender
- [ ] **Block the sender domain** and IP at the email gateway
- [ ] **Block the malicious URL** at the proxy/firewall
- [ ] If credentials were submitted — **reset the user's password immediately** and revoke all active sessions (`Revoke-AzureADUserAllRefreshToken`)
- [ ] If MFA is not enrolled, enforce it immediately on the affected account
- [ ] **Isolate the endpoint** if the user executed an attachment

### Long-Term Fixes
- Enable **Safe Links** and **Safe Attachments** in Microsoft Defender for Office 365
- Configure **DMARC, DKIM, and SPF** for your own domain to prevent spoofing
- Block **auto-forwarding rules** to external domains at the tenant level
- Deploy **attack simulation training** (Microsoft Attack Simulator / KnowBe4) regularly
- Enable **MFA** for all users, especially those with access to finance/HR systems

---

## 👨‍💻 SOC Analyst Actions (Step-by-Step)

1. **Triage the alert** — Confirm the email was delivered (not just flagged). Check DeliveryAction in email logs.
2. **Scope the campaign** — Search for all recipients of the same email (same sender, same subject, same attachment hash or URL).
3. **Check for user interaction** — Did anyone click the link or open the attachment? Check proxy logs and endpoint telemetry.
4. **Assess credential exposure** — If a credential-harvesting page was involved, check for sign-ins from unusual IPs/locations in the 30 minutes after the click.
5. **Hunt for persistence** — If a user ran an attachment, check for new scheduled tasks, autorun entries, or inbox rules created by the account.
6. **Purge the email** from all mailboxes.
7. **Notify the user** and advise them not to use their password until it's reset.
8. **Raise a ticket / escalate** if compromise is confirmed (account takeover or malware execution).
9. **Block IOCs** — domain, IP, URL, file hash — across email gateway, proxy, and EDR.
10. **Document findings** in your SIEM/SOAR case with timeline and evidence.

---

## 📚 References

- [MITRE ATT&CK T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- [Microsoft - Investigate phishing attacks](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/investigate-malicious-email-that-was-delivered)
- [CISA Phishing Guidance](https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing)
- [HTML Smuggling explained](https://www.microsoft.com/en-us/security/blog/2021/11/11/html-smuggling-surges-highly-evasive-loader-technique-increasingly-used-in-banking-malware-payloads/)
