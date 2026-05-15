# Evidence

CyberChef screenshots captured during the Part 2 payload analysis.

## Screenshots

| Filename | What it shows |
|---|---|
| `cyberchef-base64-decode.png` | CyberChef `From Base64` recipe used to decode the macro's PowerShell stager. Demonstrates how `powershell -enc <Base64>` reverses into a cleartext loader. |
| `cyberchef-lsb-extract.png` | CyberChef `Extract LSB` recipe (R / G / B channels, Row pixel order, Bit 0) applied to `logo.png`. Output reveals the hidden `Invoke-WebRequest` exfiltration command pointing at `cdn-horizondynamics[.]net/exfil`. |

Both screenshots are referenced from [`../reports/part-2-the-bait-gets-sharper.md`](../reports/part-2-the-bait-gets-sharper.md).

## Why steganography is invisible to the eye

Both the benign `logo.png` and the LSB-modified version look pixel-identical to a human reviewer. LSB encoding only flips the least significant bit of each color channel — a change of `1` on a `0–255` scale per channel — which is far below the human eye's color-discrimination threshold. That is exactly why CyberChef's `Extract LSB` recipe (or any equivalent stego decoder) is necessary: visual inspection cannot detect this technique.
