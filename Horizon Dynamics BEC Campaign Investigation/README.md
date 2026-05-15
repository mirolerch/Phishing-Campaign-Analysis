# Horizon Dynamics BEC Campaign Investigation

> **Scenario:** Multi-stage Business Email Compromise (BEC) campaign targeting a fictional company, "Horizon Dynamics" <br>
> **Role simulated:** New SOC analyst doing first-pass triage and campaign-level write-up <br>
> **Output:** 3-part investigation — initial triage, deeper payload analysis, final one-page campaign report <br>

---

## TL;DR

A threat actor sent two coordinated phishing emails to Horizon Dynamics over April 7–9, 2026.

1. **Email #1 - wide-net CEO impersonation.** Spoofed "Sarah Chen, CEO" sends an all-staff payroll-update lure with an embedded QR code and a lookalike "secure payroll portal" link. The sender domain is a typosquat: `horizondynarnics.com` (note `rn` substituted for `m`).
2. **Email #2 — targeted spearphishing follow-up.** Two days later, the same actor sends a tailored "IT Support" email to a single user (`j.martinez`) with a macro-enabled Word attachment. The macro launches a Base64-encoded PowerShell stager that reads a steganographically modified `logo.png` and exfiltrates `%APPDATA%\payroll_creds.txt` to `cdn-horizondynamics[.]net`.

**Final risk rating:** 🟠 **High** — full attack chain delivered and executable; no confirmed user interaction at report time.

---

## The Attack Chain

```
┌──────────────────────────────────────────────────────────────────────────┐
│   PART 1 — Wide-net phishing                                             │
│   Spoofed CEO → all-staff → QR + lookalike payroll portal URL            │
│                                                                          │
│              ↓ no bites → actor pivots                                   │
│                                                                          │
│   PART 2 — Targeted spearphishing                                        │
│   IT-Support spoof → single user → .docm attachment                      │
│                                                                          │
│              ↓ user enables macros                                       │
│                                                                          │
│   powershell.exe -enc <Base64>                                           │
│                                                                          │
│              ↓ decoded with CyberChef                                    │
│                                                                          │
│   Loader reads logo.png pixels → LSB steganography extraction            │
│                                                                          │
│              ↓ reconstructed command                                     │
│                                                                          │
│   Invoke-WebRequest POST to cdn-horizondynamics[.]net/exfil              │
│   (sends contents of %APPDATA%\payroll_creds.txt)                        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## How to read this case study

| File | Content |
|---|---|
| [`reports/part-1-spot-the-bait.md`](reports/part-1-spot-the-bait.md) | Email #1 analysis — IOCs and technical summary |
| [`reports/part-2-the-bait-gets-sharper.md`](reports/part-2-the-bait-gets-sharper.md) | Email #2 analysis — IOCs, header analysis, CyberChef walkthrough (Base64 + LSB) |
| [`reports/part-3-campaign-report.md`](reports/part-3-campaign-report.md) | Final one-page campaign report with risk rating and remediations |
| [`iocs/iocs.md`](iocs/iocs.md) | Consolidated IOC list across all three parts (defanged) |
| [`iocs/iocs.csv`](iocs/iocs.csv) | Same list as CSV for SIEM / block-list import |
| [`evidence/`](evidence/) | CyberChef screenshots from the Base64 decode and LSB extract |

---

## Tools used

| Tool | Used for |
|---|---|
| **CyberChef** | Decoding the Base64 PowerShell stager (`From Base64` + UTF-16LE decode); extracting the hidden command from `logo.png` (`Extract LSB` recipe with R/G/B channels, Row pixel order, Bit 0) |
| **Manual email-header review** | SPF / DKIM / DMARC verdict, Return-Path mismatch, originating-IP identification |
| **Visual / lexical inspection** | Spotting the `rn`/`m` typosquat in the sender domain |

---

## What I learned

The biggest single takeaway: an **IOC** and a **TTP** are not the same thing.

Behavioral signals like "urgency language", "embedded QR code", and "sensitive-data request via email" are real red flags but they are *Tactics, Techniques, and Procedures* — not IOCs. An IOC is something a SIEM rule can match on with `equals` ("if sender domain == X, block"); a TTP is a behavior that needs analytic logic to detect. Both belong in a SOC report, but in different sections. The IOC tables in all three reports are restricted to technical, machine-actionable data only.

Other takeaways are at the end of [`part-3-campaign-report.md`](reports/part-3-campaign-report.md).

---

## About this project

The scenario, victim company, and threat actor in this case study are fictional. The TTPs and the technical content (typosquat domains, Base64 PowerShell stagers, LSB steganography, BEC pretexting) are realistic and modeled on contemporary BEC campaigns tracked by the FBI IC3 and CISA.

The findings, IOCs, decoded payloads, technical analyses, and the final campaign report are my own work.

