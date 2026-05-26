# ⚛ RonwayScanner

> **"Know your quantum risk before it knows you."**

---

## What It Does

RonwayScanner connects to any domain over TLS and inspects its cryptographic posture against NIST post-quantum standards (FIPS 203/204/205). It identifies cipher suites, key exchange algorithms, and certificate signatures that are vulnerable to quantum computers — then scores the target 0–100 and generates reports for both engineering teams and executive leadership.

---

## Why This Matters Now

Quantum computers capable of breaking RSA and elliptic-curve cryptography are expected within the decade. The threat, however, is active **today**: adversaries are harvesting encrypted traffic now, storing it, and will decrypt it retroactively once quantum hardware is available. This is called **harvest now, decrypt later (HNDL)**.

Every session secured with RSA or ECDHE key exchange is a candidate for future decryption — including financial transactions, health records, and government communications. NIST finalized the first post-quantum standards in 2024 (ML-KEM, ML-DSA, SLH-DSA). The window to migrate before quantum computers arrive is closing.

---

## Installation

```bash
cargo install --path .
```

Or build the release binary directly:

```bash
cargo build --release
# binary at: target/release/ronway
```

**Windows prerequisite:** requires Visual Studio 2022 Build Tools (C++ workload).

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --silent --override "--passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

---

## Quick Start

```bash
# Scan a single domain
ronway scan --target bsp.gov.ph

# Generate a JSON report
ronway scan --target bsp.gov.ph --output json --out-file report.json

# Generate an HTML report (technical teams)
ronway scan --target bsp.gov.ph --output html --out-file report.html

# Generate a PDF report (CISO / board presentation)
ronway scan --target bsp.gov.ph --output pdf --out-file report.pdf

# Scan from a list of domains
ronway bulk --targets domains.txt

# Continuous monitoring (once per day by default)
ronway monitor --target bsp.gov.ph --interval 1440
```

---

## CLI Reference

```
ronway scan
  --target <domain>       Domain to scan (required)
  --port <port>           Default: 443
  --output <format>       terminal (default) | json | html | pdf
  --out-file <path>       Output file path
  --audience <type>       technical (default) | ciso
  --timeout <seconds>     Default: 10
  --verbose               Show debug output

ronway bulk
  --targets <file>        Text file, one domain per line
  --output <format>       terminal | json
  --out-dir <path>        Directory for individual reports
  --concurrency <n>       Default: 10

ronway monitor
  --target <domain>
  --interval <minutes>    Default: 1440 (once per day)
  --alert-score <n>       Alert if score exceeds threshold (default: 60)

ronway version
```

**CI/CD integration:** `ronway scan` exits with code `1` if the risk score is ≥ 60, making it drop-in compatible with any pipeline that fails on non-zero exit codes.

---

## What It Detects

| Vulnerability                 | Why It's a Problem              | Replace With                        |
| ----------------------------- | ------------------------------- | ----------------------------------- |
| RSA key exchange              | Broken by Shor's Algorithm      | X25519MLKEM768 hybrid (FIPS 203)    |
| ECDHE key exchange            | Broken by Shor's Algorithm      | X25519MLKEM768 hybrid (FIPS 203)    |
| RSA certificate               | Quantum vulnerable signature    | ML-DSA-65 (FIPS 204)                |
| ECDSA certificate             | Quantum vulnerable signature    | ML-DSA-65 (FIPS 204)                |
| TLS 1.2 or below              | Allows vulnerable cipher suites | TLS 1.3 only                        |
| CBC mode ciphers              | BEAST / POODLE attack surface   | AES-256-GCM or ChaCha20-Poly1305    |
| RC4 / 3DES / NULL             | Classically broken              | Disable immediately                 |
| No HSTS                       | Protocol downgrade vector       | max-age=31536000; includeSubDomains |
| Server header leaking version | Information disclosure          | Strip or genericise header          |

---

## Interpreting Results

Scores are additive penalty points capped at 100. Higher is worse.

| Score  | Level        | Meaning                                        |
| ------ | ------------ | ---------------------------------------------- |
| 80–100 | **Critical** | Immediate PQC migration required               |
| 60–79  | **High**     | Urgent — plan migration within 90 days         |
| 40–59  | **Medium**   | Schedule migration within 6 months             |
| 20–39  | **Low**      | Monitor and plan                               |
| 0–19   | **Pass**     | Meets current post-quantum readiness standards |

The **harvest risk** flag is raised whenever RSA, ECDH, ECDHE, or DH key exchange is detected. This indicates that past sessions are at risk of future decryption regardless of when migration happens.

---

## Sample Terminal Output

```
══════════════════════════════════════════════
 RonwayScanner — Post-Quantum Security Report
══════════════════════════════════════════════

Target:     bsp.gov.ph (202.90.136.10)
Scanned:    2026-07-15 09:42:18 UTC
Duration:   1.24 seconds

┌─ Risk Score ──────────────────────────────┐
│  87/100  CRITICAL                          │
│  Immediate PQC migration required          │
└────────────────────────────────────────────┘

Vulnerabilities Found: 6

✗ CRITICAL  RSA key exchange detected — harvest now decrypt later risk
✗ CRITICAL  RSA-2048 certificate — quantum vulnerable
✗ HIGH      TLS 1.2 accepted — allows vulnerable cipher suites
✗ HIGH      CBC mode cipher suite enabled
⚠ MEDIUM    No HSTS header
⚠ LOW       Server header leaking version info

Top Recommendations:
1. Replace RSA key exchange with ML-KEM-768 hybrid (2 weeks effort)
2. Replace RSA-2048 certificate with ML-DSA-65 (4 weeks effort)
3. Disable TLS 1.2 — enable TLS 1.3 only (1 week effort)

Run with --output pdf to generate a board-ready report.
══════════════════════════════════════════════
```

---

## Enterprise Audits

RonwayScanner v1 covers remote TLS/certificate scanning. For full internal infrastructure audits — including filesystem key scanning, dependency analysis, database encryption review, and end-to-end migration implementation — contact BPxAI.

**bpxai.com/quantum**

---

## Built By

**Koleen Baes Paunon** — BPxAI
[bpxai.com](https://bpxai.com) · [@KBPsystem](https://x.com/KBPsystem) · [GitHub](https://github.com/KBPsystem777)

Named for **Ronnie** and **Liway**.

---

© 2026 BPxAI. All rights reserved. Proprietary software — not for redistribution.
