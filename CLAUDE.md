# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Identity

- **Binary name:** `ronway`
- **Crate name:** `ronway-scanner`
- **Tagline:** "Know your quantum risk before it knows you."
- **Named for:** Ronnie (dad) and Liway (mom) — Built by Koleen Baes Paunon / BPxAI
- **License:** Proprietary / All Rights Reserved — do NOT add MIT or open-source license headers

RonwayScanner is a post-quantum cryptographic vulnerability scanner and the core commercial product of BPxAI. It connects to remote targets over TLS, inspects their cipher suites, X.509 certificates, and HTTP security headers, then scores them against NIST PQC guidance (FIPS 203/204/205) and generates reports for developers and CISOs.

**v1 scope: remote scan only.** Local filesystem scanning is v2. Do not build v2 features.

---

## Build Requirements (Windows)

**This project requires a C/C++ linker.** Neither MSVC nor MinGW-w64 tools ship with Rust itself.

To compile on Windows, install one of:

```powershell
# Option A — MSVC Build Tools (recommended, ~2–4 GB)
winget install Microsoft.VisualStudio.2022.BuildTools --silent --override "--passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

# Option B — MinGW-w64 via winlibs.com (~150 MB)
# Download from https://winlibs.com, extract, add bin\ to PATH
# Then use: cargo +stable-x86_64-pc-windows-gnu build
```

After installing, reopen the terminal before building.

---

## Common Commands

```bash
cargo build              # debug build (requires linker tools above)
cargo build --release    # release binary → target/release/ronway.exe
cargo test               # run unit tests only
cargo test -- --ignored  # also run integration tests (makes real network calls)
cargo test classifier    # run a single test module by name filter
cargo clippy             # lint (all warnings should be clean)
cargo fmt                # format code
```

**Manual smoke tests after build:**

```bash
./target/release/ronway version
./target/release/ronway scan --target example.com
./target/release/ronway scan --target example.com --output json
./target/release/ronway scan --target example.com --output html --out-file /tmp/test.html
```

Exit code convention: `0` if risk score < 60, `1` if score ≥ 60 (enables CI/CD gate).

---

## Architecture Overview

```
CLI (main.rs)
    └── RonwayScanner::scan (lib.rs) ← orchestrator
            ├── tokio::join! ─── TlsScanner::scan     (scanner/tls.rs)
            │                ─── CertScanner::scan    (scanner/cert.rs)
            │                └── HttpScanner::scan    (scanner/http.rs)
            │
            ├── VulnerabilityDatabase::build_vulnerabilities (classifier/algorithms.rs)
            ├── RiskScorer::calculate                        (classifier/scoring.rs)
            └── RecommendationEngine::generate               (classifier/recommendations.rs)
                    │
                    └── ScanReport ──► JsonReporter  (report/json.rs)
                                  ──► HtmlReporter   (report/html.rs)
                                  └─► PdfReporter    (report/pdf.rs)
```

### Data flow

1. `main.rs` parses CLI args with clap and calls `RonwayScanner::scan(target)`.
2. The orchestrator in `lib.rs` resolves DNS, then fires all three scanners concurrently via `tokio::join!`. Individual scanner failures are caught and stored as `None` fields — they do not abort the full scan.
3. Raw findings (`TlsFinding`, `CertFinding`, `HttpFinding`) are passed to `VulnerabilityDatabase::build_vulnerabilities` to produce a `Vec<Vulnerability>`.
4. `RiskScorer::calculate` walks the vulnerability list, accumulates weighted penalty points (capped at 100), and returns a `RiskScore`.
5. `RecommendationEngine::generate` maps each vulnerability ID to a prioritised `Recommendation`.
6. Everything is assembled into a `ScanReport` and dispatched to the appropriate reporter.

### Module responsibilities

| Module | Responsibility |
|---|---|
| `scanner/tls.rs` | Opens a rustls connection, extracts TLS version and cipher suite |
| `scanner/cert.rs` | Extracts the server's DER certificate from the TLS connection and parses it with x509-parser |
| `scanner/http.rs` | Fetches HTTP headers with reqwest; checks HSTS, CSP, Server leakage |
| `classifier/algorithms.rs` | Pure lookup functions: is this key exchange / signature / cipher quantum-vulnerable? |
| `classifier/scoring.rs` | Deterministic weighted scoring (0–100); sets `harvest_risk` flag |
| `classifier/recommendations.rs` | Maps vulnerability IDs → prioritised remediation actions |
| `models/risk.rs` | `RiskLevel` enum (`Critical/High/Medium/Low/Pass`) and `RiskScore` |
| `models/finding.rs` | `TlsFinding`, `CertFinding`, `HttpFinding`, `Vulnerability`, `Recommendation` structs |
| `models/report.rs` | `ScanTarget` and `ScanReport` (the root output type) |

---

## Key Design Constraints

- **Use `rustls` only — never `openssl`/`native-tls`.** `reqwest` is configured with `default-features = false, features = ["rustls-tls", "json"]` for the same reason.
- **`AlgorithmClassifier` functions must be pure** (no I/O, no side effects) so the classifier is fully unit-testable.
- **10-second timeout** on all outbound connections (`tokio::time::timeout`).
- Integration tests that make real network calls are marked `#[ignore]` and live in `tests/integration/`. Run them explicitly with `cargo test -- --ignored`.
- HTML templates in `templates/` must be **self-contained** (no external CDN) so PDF rendering works offline.

---

## Risk Scoring Weights

The scoring model is additive (penalties sum, capped at 100):

| Finding | Points |
|---|---|
| RSA key exchange | +35 |
| ECDH/ECDHE key exchange | +30 |
| DH key exchange | +25 |
| NULL cipher suite | +40 |
| EXPORT cipher suite | +30 |
| TLS 1.0/1.1 enabled | +20 |
| RSA certificate signature | +25 |
| ECDSA certificate signature | +20 |
| RC4 cipher | +20 |
| Certificate expired | +20 |
| ECDSA certificate | +20 |
| 3DES cipher | +15 |
| SHA-1 in chain | +15 |
| CBC mode cipher | +10 |
| TLS 1.2 as highest version | +10 |
| Self-signed certificate | +10 |
| No HSTS | +5 |
| Server header leaks version | +5 |

`harvest_risk` is `true` when any RSA / ECDH / ECDHE / DH key exchange is detected (store-now-decrypt-later threat).

---

## NIST PQC Algorithm Mapping

| Vulnerable | Replace With | NIST Standard |
|---|---|---|
| RSA / ECDHE key exchange | X25519MLKEM768 hybrid | FIPS 203 (ML-KEM) |
| RSA certificate | ML-DSA-65 | FIPS 204 (ML-DSA) |
| ECDSA certificate | ML-DSA-65 | FIPS 204 (ML-DSA) |
| AES-CBC | AES-256-GCM or ChaCha20-Poly1305 | NIST SP 800-38D |
