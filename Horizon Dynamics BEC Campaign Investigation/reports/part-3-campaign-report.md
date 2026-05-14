# Part 3 — Phishing Campaign Analysis Report

> One-page campaign report covering both emails from the Horizon Dynamics BEC investigation.  
> Audience: SOC lead.

---

## Executive Summary

This report analyzes a phishing campaign targeting Horizon Dynamics employees using a lookalike domain (`horizondynarnics.com`) to impersonate internal departments.

The attacker used social engineering techniques, including urgency and payroll-related themes, to trick users into interacting with malicious links and attachments. The second email escalated the attack by delivering a macro-enabled document designed to execute hidden code and steal sensitive information.

The current risk is **High**, as the payload was successfully delivered and is capable of execution, although no confirmed user interaction or data exfiltration has been observed.

---

## Technical Analysis

The attack began with a phishing email impersonating company leadership, using a malicious link and QR code to trick the user into interacting with payroll-related content.

In the second stage, the attacker escalates the attack by delivering a macro-enabled document that executes a hidden PowerShell script. The script is obfuscated using Base64 encoding and further payload components are hidden using steganography techniques.

Upon execution, the malware attempts to communicate with an external attacker-controlled domain to facilitate data exfiltration. The objective of the campaign is to steal sensitive payroll and financial information from the targeted users.

---

## Risk Rating

🟠 **High**

The attack chain is fully capable of execution:

- The malicious attachment was successfully delivered
- The document contains a hidden payload
- Macro execution can trigger encoded PowerShell
- External C2 infrastructure is present

No confirmed user interaction or data exfiltration has been observed at this stage.

---

## Remediations

### Contain

- Block sender domain `horizondynarnics.com`
- Block secondary domain `horizondynamics-support.net`
- Block sending IP `185.234.72.19` at the perimeter firewall
- Sinkhole the C2 / exfiltration domain `cdn-horizondynamics.net`
- Quarantine all emails containing `Payroll_Verification_Form.docm`

### Eradicate

- Hunt across endpoints for:
  - `Payroll_Verification_Form.docm`
  - `logo.png`
  - `%APPDATA%\payroll_creds.txt`
- Detect:
  - `winword.exe` spawning `powershell.exe -enc`
- Isolate infected hosts
- Capture memory and re-image affected systems
- Reset credentials for impacted users

### Recover

- Restore connectivity only after EDR validation
- Verify SPF / DKIM / DMARC configuration
- Ensure DMARC is configured with `p=reject`
- Notify affected employees
- Deploy SIEM detections for:
  - Office → PowerShell execution
  - Outbound traffic to lookalike domains

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Email | `it.support@horizondynarnics.com` | Typosquatted sender impersonating IT Support |
| Email | `bounce-3291@mail.horizondynarnics.com` | Malicious return-path infrastructure |
| Domain | `horizondynarnics.com` | Lookalike phishing domain |
| IP | `185.234.72.19` | Suspicious origin mail server |
| Other | `SPF=fail`, `DKIM=none`, `DMARC=fail` | Authentication failures |
| Email | `helpdesk@horizondynamics-support.net` | Secondary malicious support domain |
| Filename | `Payroll_Verification_Form.docm` | Macro-enabled payload |
| Filename | `logo.png` | Steganography carrier image |
| Other | `%APPDATA%\payroll_creds.txt` | Credential harvesting target |
| Domain | `cdn-horizondynamics.net` | C2 / exfiltration infrastructure |

Full IOC list available at:

[`../iocs/iocs.md`](../iocs/iocs.md)

---

## Takeaways from the Full Campaign

### 1. IOC vs. TTP is not academic

Block-list rows are IOCs, while behavioral patterns are TTPs. The distinction repeatedly appears in real SOC documentation and incident-response workflows.

### 2. Campaign analysis ≠ email analysis

Analyzing a single email is triage. Identifying shared infrastructure, pretext, and targeting across multiple emails is what turns the investigation into campaign analysis.

### 3. Defense in depth matters

The attacker uses multiple obfuscation layers:

- Base64 encoding
- Steganography
- Macro execution

Each layer bypasses different defensive controls. The strongest detection point is behavioral correlation:

> Office spawning encoded PowerShell that extracts hidden content and transmits data externally.

### 4. DMARC does not stop typosquatting

`p=reject` protects against direct spoofing of legitimate domains but does not prevent attackers from registering lookalike domains such as:

`horizondynarnics.com`

Brand-domain monitoring and lookalike-domain detection remain critical defensive controls.

---

## Future Improvements

Potential future extensions for this investigation:

- MITRE ATT&CK mapping
- Enterprise-scale telemetry hunting
- Steganography detection methods
- PowerShell hardening
  - Constrained Language Mode
  - Script Block Logging
  - AMSI enforcement
- Additional SIEM detections and correlation rules
