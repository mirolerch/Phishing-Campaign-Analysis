# Part 1: Spot the Bait

> Stage 1 of the campaign: a wide-net BEC lure impersonating the CEO of Horizon Dynamics. <br>
> First-pass triage: what does a SOC analyst notice in the first 30 seconds?

---

## Campaign context

I am the new SOC analyst at Horizon Dynamics. This is the first email in a suspected phishing campaign from a single threat actor. It just landed in the company inbox and was flagged by a user who thought something felt off.

> **A "campaign"** is a coordinated, multi-step attack. Threat actors use multiple emails, tactics, delivery methods, and payloads across a campaign to increase the chance that at least one attempt succeeds.

---

## Email under investigation

```
From: Sarah Chen <sarah.chen@horizondynarnics.com>
To: all-staff@horizondynamics.com
Subject: Urgent: Payroll Direct Deposit Update Required Before Tomorrow's Run
Date: Mon, 7 Apr 2026 09:14:32 -0400

Hi Team,

I hope this finds you well.

Due to our migration to the new payroll platform, all employees must
update their direct deposit information immediately.

Please scan the QR code below or click the secure link to complete
the update before 3:00 PM tomorrow or your next paycheck may be delayed.

[QR Code Embedded in Email]

Secure Payroll Portal:
https://horizondynamics-payroll.co/update

Thank you for handling this right away.

Best regards,
Sarah Chen
CEO, Horizon Dynamics
```

**Analyst workstation note:** the embedded QR code was scanned in a sandboxed environment and resolves to `hxxps://horizondynamics-payroll[.]co/update`.

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Email | `sarah.chen@horizondynarnics.com` | Misspelled domain |
| Domain | `horizondynarnics.com` | Mismatch between sender and legitimate company domain |
| URL | `https://horizondynamics-payroll.co/update` | External domain (.co), not the official company domain |

---

## Short technical summary

This email is a phishing attempt impersonating Horizon Dynamics, using a lookalike domain (`horizondynarnics.com`) to deceive recipients. The message contains urgency language and directs users to an external domain (`horizondynamics-payroll.co`) to update sensitive payroll information, which is not standard business practice. The inclusion of a QR code further obscures the malicious destination.

**Recommended action:** Block the sender domain and URL, report the email as phishing, warn users not to interact with the link or QR code, and verify any payroll updates through official internal channels.

---

## IOCs vs. TTPs

The IOC table above is restricted to **technical, machine-actionable data**: IPs, domains, URLs, email addresses, file hashes — anything a SIEM rule can match with `equals`. Behavioral signals like *urgency language*, *unexpected payroll request*, and *embedded QR code* are real red flags but they are **TTPs** (Tactics, Techniques, Procedures), not IOCs. They belong in the technical summary and the remediation reasoning, not in a block-list table.

This distinction matters operationally:

- An **IOC** can power a fire-and-forget block-list: "if sender domain == `horizondynarnics.com`, alert."
- A **TTP** needs analytic logic to detect: "alert when an email contains urgency keywords *and* a financial-data request *and* a QR code."

Both belong in a SOC report, but in different sections.
