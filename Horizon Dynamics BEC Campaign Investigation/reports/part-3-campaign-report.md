# Part 3: Phishing Campaign Analysis Report

> One-page campaign report covering both emails from the Horizon Dynamics BEC investigation.<br>
> Audience: SOC lead.

---

## Executive Summary

This report analyzes a phishing campaign targeting Horizon Dynamics employees using a lookalike domain (`horizondynarnics.com`) to impersonate internal departments. The attacker used social engineering techniques, including urgency and payroll-related themes, to trick users into interacting with malicious links and attachments. The second email escalated the attack by delivering a macro-enabled document designed to execute hidden code and steal sensitive information.

The current risk is **High**, as the payload was successfully delivered and is capable of execution, although no confirmed user interaction or data exfiltration has been observed.

---

## Technical Analysis

The attack began with a phishing email impersonating company leadership, using a malicious link and QR code to trick the user into interacting with payroll-related content. In the second stage, the attacker escalates the attack by delivering a macro-enabled document that executes a hidden PowerShell script. The script is obfuscated using Base64 encoding and further payload components are hidden using steganography techniques.

Upon execution, the malware attempts to communicate with an external attacker-controlled domain to facilitate data exfiltration. The objective of the campaign is to steal sensitive payroll and financial information from the targeted users.

---

## Risk Rating

🟠 **High**

The attack chain is fully capable of execution: the malicious attachment was successfully delivered and contains a hidden payload. No confirmed user interaction or data exfiltration has been observed, but macro-based code execution and external C2 infrastructure represent a significant risk.

---

## Remediations

### Contain
- Block sender domain `horizondynarnics.com` and secondary domain `horizondynamics-support.net` at the email gateway.
- Block sending IP `185.234.72.19` at the perimeter firewall.
- Sinkhole the C2 / exfiltration domain `cdn-horizondynamics.net` at DNS and proxy level.
- Quarantine all emails containing `Payroll_Verification_Form.docm` and purge from user mailboxes.

### Eradicate
- Hunt across endpoints for `Payroll_Verification_Form.docm`, the steganography carrier `logo.png`, and the credential file `%APPDATA%\payroll_creds.txt`.
- Detect macro-based execution: `winword.exe` spawning `powershell.exe -enc`.
- Isolate any host with hits, capture memory, and re-image rather than clean.
- Reset credentials for any user with a created or modified `payroll_creds.txt`.

### Recover
- Restore network access only after EDR validation.
- Verify SPF / DKIM / DMARC for `horizondynamics.com` is set to `p=reject` to block future spoofing.
- Notify affected employees and confirm no payroll data was submitted via the fraudulent portal.
- Deploy SIEM rule for outbound traffic to lookalike domains and for Office → PowerShell.

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Email | `it.support@horizondynarnics.com` | Typosquatted sender impersonating IT Support |
| Email | `bounce-3291@mail.horizondynarnics.com` | Malicious return-path infrastructure |
| Domain | `horizondynarnics.com` | Lookalike domain used for phishing |
| IP | `185.234.72.19` | Suspicious origin mail server |
| Other | `SPF=fail`, `DKIM=none`, `DMARC=fail` | Email authentication failure (spoofed sender) |
| Email | `helpdesk@horizondynamics-support.net` | Secondary malicious support domain |
| Filename | `Payroll_Verification_Form.docm` | Macro-enabled payload delivery document |
| Filename | `logo.png` | Steganography carrier image |
| Other | `%APPDATA%\payroll_creds.txt` | Credential harvesting target |
| Domain | `cdn-horizondynamics.net` | C2 / exfiltration infrastructure |

Full IOC list (with all Part 1 + Part 2 entries) at [`../iocs/iocs.md`](../iocs/iocs.md).

---

## Takeaways from the full campaign

A few principles this investigation reinforced:

1. **IOC vs. TTP is not academic.** Block-list rows are IOCs, behavior descriptions are TTPs. The distinction shows up again and again in every SOC document.
2. **Campaign analysis ≠ email analysis.** Looking at one email is triage; looking at two and noticing they share infrastructure, pretext, and targeting is what makes it a campaign. That mindset shift is the actual job.
3. **Defense in depth is real.** The attacker uses three obfuscation layers (Base64, steganography, macro) — each defeats a different control. The cleanest detection is at the *behavior chain* layer (Office spawning encoded PowerShell that reads pixels and POSTs data), not at any single obfuscation layer.
4. **DMARC doesn't stop typosquats.** `p=reject` on your own domain stops attackers spoofing *your* domain — it does nothing about an attacker registering a lookalike like `horizondynarnics.com`. Brand-domain monitoring is the missing piece in most stacks.

Next directions to extend this work: MITRE ATT&CK classification of the chain, telemetry hunting at scale across enterprise logs, steganography detection theory, and deeper PowerShell hardening (Constrained Language Mode, Script-Block Logging, AMSI enforcement). These will likely appear in future projects in this repo.
