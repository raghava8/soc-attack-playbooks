# 🛡️ SOC Analyst Attack Playbooks

> A structured knowledge base of cyber attacks encountered in daily SOC operations — covering detection, investigation, and remediation for each threat type.

**Maintained by:** [@raghava8](https://github.com/raghava8)  
**Purpose:** Reference guide for SOC analysts handling real-world alerts and incidents  
**SIEM Coverage:** Microsoft Sentinel · Splunk · Generic/Agnostic

---

## 📁 Repository Index

| # | Attack Category | Common Alerts | Severity |
|---|----------------|---------------|----------|
| 01 | [Phishing & Email Attacks](./01-Phishing-Email-Attacks/) | Suspicious email, malicious link click, attachment execution | 🔴 High |
| 02 | [Malware & Ransomware](./02-Malware-Ransomware/) | AV alert, file encryption, C2 communication | 🔴 Critical |
| 03 | [Identity & Credential Attacks](./03-Identity-Credential-Attacks/) | Brute force, password spray, MFA bypass, token theft | 🔴 High |
| 04 | [Network Attacks (DDoS, MITM)](./04-Network-Attacks/) | Traffic spike, ARP spoofing, lateral movement | 🟠 High |
| 05 | [Endpoint Threats & LOLBins](./05-Endpoint-Threats-LOLBins/) | PowerShell abuse, WMI persistence, living-off-the-land | 🔴 High |
| 06 | [Cloud & SaaS Attacks](./06-Cloud-SaaS-Attacks/) | Impossible travel, OAuth abuse, storage exfiltration | 🔴 Critical |
| 07 | [Web Application Attacks](./07-Web-Application-Attacks/) | SQLi, XSS, SSRF, path traversal | 🟠 High |

---

## 🧭 How to Use This Repo

Each folder contains a `README.md` with the following structure:

1. **Overview** — What the attack is and how it works
2. **Attack Techniques** — Specific TTPs (mapped to MITRE ATT&CK where applicable)
3. **How to Identify in Logs** — Log sources, key indicators, SIEM queries
4. **Remediation Steps** — Immediate containment + long-term fixes
5. **SOC Analyst Actions** — Step-by-step response workflow
6. **References** — MITRE ATT&CK, vendor advisories, CVEs

---

## 🔖 MITRE ATT&CK Coverage

This repo maps to the [MITRE ATT&CK Enterprise Framework](https://attack.mitre.org/). Each playbook includes relevant Tactic and Technique IDs.

---

*Contributions welcome. If you work in SOC and want to add a new attack type or improve detection logic, feel free to open a PR.*
