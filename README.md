# 🛡️ SOC Analyst Attack Playbooks

> Operational knowledge base of cyber attacks encountered in daily SOC work — built for analysts who need fast, reliable guidance during live incidents.

**Maintained by:** [@raghava8](https://github.com/raghava8)  
**SIEM:** Google SecOps / Chronicle (YARA-L 2.0 + UDM Search)  
**Framework:** MITRE ATT&CK Enterprise  

---

## 📁 Repository Index

| # | Attack Category | Severity | MITRE Tactics |
|---|----------------|----------|---------------|
| [01](./01-Phishing-Email-Attacks/) | Phishing & Email Attacks | 🔴 High | Initial Access · Execution |
| [02](./02-Malware-Ransomware/) | Malware & Ransomware | 🔴 Critical | Execution · Persistence · Impact |
| [03](./03-Identity-Credential-Attacks/) | Identity & Credential Attacks | 🔴 High | Credential Access · Persistence |
| [04](./04-Network-Attacks/) | Network Attacks (DDoS, MITM) | 🟠 High | Discovery · Lateral Movement · Impact |
| [05](./05-Cloud-SaaS-Attacks/) | Cloud & SaaS Attacks | 🔴 Critical | Initial Access · Collection · Exfiltration |
| [06](./06-Web-Application-Attacks/) | Web Application Attacks | 🟠 High | Initial Access · Execution |

---

## 📂 Each Playbook Structure

```
attack-category/
├── README.md                        ← Overview, MITRE mapping, quick reference
├── description/
│   └── overview.md                  ← How the attack works, variants, threat actor TTPs
├── detection/
│   └── chronicle-queries.md         ← Google SecOps YARA-L 2.0 rules + UDM hunt queries
├── remediation/
│   └── steps.md                     ← Immediate containment + long-term hardening
└── analyst-actions/
    └── workflow.md                  ← Step-by-step SOC response checklist
```

---

## 🔎 SIEM: Google SecOps / Chronicle

All detection content in this repo uses:

| Query Type | Purpose |
|------------|---------|
| **YARA-L 2.0** | Persistent detection rules that generate alerts in Chronicle |
| **UDM Search** | Ad-hoc hunting in the Chronicle UI using normalised fields |

### Core UDM Fields Referenced Across Playbooks

| UDM Field | Description |
|-----------|-------------|
| `metadata.event_type` | Event category (USER_LOGIN, NETWORK_HTTP, PROCESS_LAUNCH, etc.) |
| `principal.user.userid` | Acting user account |
| `principal.ip` | Source IP address |
| `principal.hostname` | Source hostname |
| `target.hostname` | Destination hostname |
| `target.url` | Full URL accessed |
| `target.user.email_addresses` | Recipient email address |
| `network.email.from` | Sender email address |
| `network.application_protocol` | Protocol (HTTP, DNS, SMTP, etc.) |
| `security_result.action` | ALLOW / BLOCK / UNKNOWN |
| `src.process.command_line` | Process command line arguments |
| `src.process.file.full_path` | Process executable path |
| `principal.process.parent_process.file.full_path` | Parent process path |

---

## 🧭 How to Use During an Incident

1. **Active alert** → Open `analyst-actions/workflow.md` first
2. **Proactive hunting** → Run queries from `detection/chronicle-queries.md` in Chronicle UDM Search
3. **Containment** → Follow `remediation/steps.md`
4. **Context** → Read `description/overview.md`

---

*Contributions welcome — open a PR to add attack types, improve YARA-L rules, or update remediation steps.*
