# Endpoint Threat Detection + Incident Response Lab

A home SOC lab built on real macOS and Ubuntu endpoints using **Wazuh**. 

Wazuh ships a built-in SSH brute-force rule - but it only detects attacks that guess **non-existent usernames**. 
An attacker guessing passwords against a **real, valid account** (the more dangerous and realistic scenario) slips past it entirely.
I found this gap, wrote a custom two-stage correlation rule to close it, and validated it end-to-end against live attack traffic. 
Full writeup: [`incidents/INC-001-ssh/`](incidents/INC-001-ssh/)

---

## Environment

| | |
|---|---|
| **SIEM** | Wazuh (manager + ruleset, running on Ubuntu) |
| **Monitored endpoints** | macOS, Ubuntu (`pvee-device`) — real machines, not disposable VMs |
| **Telemetry sources** | journald, FIM/Syscheck, PAM, system inventory, SCA |
| **Detection logic** | Custom Wazuh rules ([`wazuh-rules/`](wazuh-rules/)) |

---

## Skills demonstrated

| Skill | Where it shows up |
|---|---|
| Log analysis & SIEM investigation | Every incident's evidence/timeline section |
| Detection engineering (custom rule writing) | [`wazuh-rules/local_rules.xml`](wazuh-rules/local_rules.xml) |
| MITRE ATT&CK mapping | Every incident's MITRE section |
| Incident response workflow | Alert → Triage → Evidence → Root Cause → Containment in every writeup |
| Identifying gaps in default tooling | INC-001 (SSH brute-force correlation gap) |

---

## Incidents

| # | Incident | Status | Summary |
|---|---|---|---|
| 001 | [SSH Brute Force → Account Compromise](incidents/INC-001-ssh/) | ✅ Complete | Found & closed a gap in Wazuh's default brute-force detection for valid-username attacks |
| 002 | Privilege Escalation | 🔲 Planned | Detecting suspicious sudo usage and mapping to MITRE privilege escalation techniques |
| 003 | Persistence Mechanism | 🔲 Planned | Detecting a cron/systemd persistence mechanism via File Integrity Monitoring |
| 004 | File Integrity Violation | 🔲 Planned | Investigating unauthorized modification of sensitive files |
| 005 | Suspicious Process Investigation | 🔲 Planned | Tracing a suspicious process to parent, command line, and network activity |
| 006 | macOS Endpoint Investigation | 🔲 Planned | What Wazuh can and cannot see on macOS — documented visibility gaps |

Each incident folder follows the same structure: **Summary → Attack Simulation → Detection Gap (if any) → Custom Rule (if any) → Validation Evidence → MITRE Mapping → Root Cause → Containment & Remediation.**

---

## Repository structure

```
endpoint-soc-lab/
├── README.md
├── wazuh-rules/
│   └── local_rules.xml          ← all custom detection rules
├── incidents/
│   ├── INC-001-ssh/
│   │   ├── README.md
│   │   └── screenshots/
│   ├── INC-002-privilege-escalation/
│   ├── INC-003-persistence/
│   ├── INC-004-file-tampering/
│   ├── INC-005-suspicious-process/
│   └── INC-006-macos/
├── mitre/
│   └── coverage-matrix.md       ← all techniques covered, across incidents
└── detection-gaps/
    └── findings.md              ← gaps found in default tooling, across incidents
```
