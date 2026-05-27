# RonwayScanner — Build Progress

> Status as of 2026-05-27. This document tracks what is built, what is stubbed,
> and how to verify the work on a clean checkout.

---

## Phase progress

| Phase | Title | Status |
|------:|---|---|
| 1 | Project scaffold | Done |
| 2 | Data models | Done |
| 3 | Vulnerability classification database | Done |
| 4 | Risk scoring engine + unit tests | Done |
| 5 | Remediation recommendations engine | Not started |
| 6 | TLS scanner core | Stub |
| 7 | Certificate parser | Stub |
| 8 | HTTP headers scanner | Stub |
| 9 | Main scanner orchestrator (`RonwayScanner::scan`) | Stub |
| 10 | Report generators (JSON / HTML / PDF) | Stub |
| 11 | CLI polish (`bulk`, `monitor`, output modes) | Stub |
| 12 | Tests + README | Partial (unit tests only) |
| 13 | Final build verification | Pending Phase 5+ |

---

## What works right now

### Phase 1 — Scaffold

- `cargo build` and `cargo check` succeed against the full dependency tree
  (tokio, rustls, reqwest, x509-parser, clap, etc.).
- Binary skeleton: `ronway scan --target <domain>` parses CLI args and
  prints `Scanning <domain>...` — no real scan yet.

### Phase 2 — Data models

| File | Types |
|---|---|
| [src/models/risk.rs](../src/models/risk.rs) | `RiskLevel` enum, `RiskScore` struct |
| [src/models/finding.rs](../src/models/finding.rs) | `TlsFinding`, `CertFinding`, `HttpFinding`, `Vulnerability`, `Recommendation` |
| [src/models/report.rs](../src/models/report.rs) | `ScanTarget`, `ScanReport` |

All types derive `Serialize` + `Deserialize` so they can be emitted to JSON in
Phase 10 without rework. `RiskLevel::from_score` maps the 0–100 scale to the
five risk levels per the spec.

### Phase 3 — Classifier

[src/classifier/algorithms.rs](../src/classifier/algorithms.rs) exposes two
pure (side-effect-free) types:

- **`AlgorithmClassifier`** — answers four questions about a string:
  - `is_tls_version_vulnerable(&str) -> bool`
  - `is_key_exchange_vulnerable(&str) -> (bool, &'static str)`
  - `is_signature_algorithm_vulnerable(&str) -> (bool, &'static str)`
  - `is_cipher_suite_vulnerable(&str) -> (bool, &'static str)`
- **`VulnerabilityDatabase::build_vulnerabilities`** — takes
  `Option<&TlsFinding>`, `Option<&CertFinding>`, `Option<&HttpFinding>`
  (any scanner may fail) and emits `Vec<Vulnerability>` with stable IDs:
  `RSA_KEY_EXCHANGE`, `ECDHE_KEY_EXCHANGE`, `DH_KEY_EXCHANGE`,
  `TLS_LEGACY_VERSION`, `TLS_VERSION_VULNERABLE`,
  `NULL_CIPHER`, `EXPORT_CIPHER`, `RC4_CIPHER`, `TRIPLE_DES_CIPHER`, `CBC_CIPHER`,
  `RSA_CERTIFICATE`, `ECDSA_CERTIFICATE`, `RSA_SIGNATURE`, `ECDSA_SIGNATURE`,
  `SHA1_IN_CHAIN`, `CERT_EXPIRED`, `CERT_SELF_SIGNED`,
  `NO_HSTS`, `SERVER_HEADER_LEAK`,
  plus sentinels `TLS_SCAN_FAILED` / `CERT_SCAN_FAILED`.

The cipher classifier checks vulnerable patterns **before** safe ones, so
`AES_128_CBC` correctly flags as CBC-vulnerable rather than being mis-labeled
safe by the AES_128 rule.

Nine inline `#[cfg(test)]` tests cover positive and negative cases for each
classifier function.

### Phase 4 — Scoring

[src/classifier/scoring.rs](../src/classifier/scoring.rs) exposes
`RiskScorer` with:

- `RiskScorer::calculate(&[Vulnerability]) -> RiskScore` — sums per-ID
  penalty weights (saturating, capped at 100). Weights match the table in
  [CLAUDE.md](../CLAUDE.md) exactly (RSA KX +35, ECDHE +30, NULL cipher +40, etc.).
- `RiskScorer::harvest_risk_present(&[Vulnerability]) -> bool` — true if any
  RSA / ECDHE / DH key exchange vulnerability is present.
- `RiskScorer::generate_summary(&RiskScore, target) -> String` — produces the
  executive-style summary sentence used in reports.

[tests/unit/scoring_test.rs](../tests/unit/scoring_test.rs) — eleven tests
covering empty inputs, individual weights, the harvest-risk flag, every
`RiskLevel::from_score` boundary, the 100-point cap, and the summary string.
Wired into [Cargo.toml](../Cargo.toml) via an explicit `[[test]]` target since
Cargo does not auto-discover tests under `tests/<subdir>/`.

---

## What is still a stub

- [src/scanner/tls.rs](../src/scanner/tls.rs),
  [src/scanner/cert.rs](../src/scanner/cert.rs),
  [src/scanner/http.rs](../src/scanner/http.rs),
  [src/scanner/dns.rs](../src/scanner/dns.rs) — module skeletons only.
- [src/classifier/recommendations.rs](../src/classifier/recommendations.rs) —
  empty stub.
- [src/report/](../src/report/) — JSON / HTML / PDF reporters not implemented.
- [src/lib.rs](../src/lib.rs) — orchestrator `RonwayScanner::scan` does not exist yet.
- [src/main.rs](../src/main.rs) — only the `scan --target` arg is wired; no
  `--output`, `--out-file`, `bulk`, `monitor`, or `version` commands yet.

---

## How to test on this machine

### Prerequisites

The project needs a C/C++ linker. On this workstation that is **MSVC Build
Tools v14.44.35207** + **Windows SDK 10.0.26100.0**, already installed at:

```
C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\
C:\Program Files (x86)\Windows Kits\10\
```

#### Linker shadowing — fixed

`cargo` invokes `link.exe` by bare name. Git for Windows ships its own GNU
`link` at `C:\Program Files\Git\usr\bin\link.exe`, which appears earlier on
PATH and breaks builds with errors like:

```
error: linking with `link.exe` failed: exit code: 1
  = note: link: extra operand 'C:\\Users\\Kolee\\...\\build_script_build.exe'
```

This is fixed in [.cargo/config.toml](../.cargo/config.toml), which pins the
MSVC linker by absolute path:

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\link.exe"
```

If MSVC is updated and the `14.44.35207` directory disappears, update the
version number — or run `cargo` from the **"x64 Native Tools Command Prompt
for VS 2022"** (Start menu), which sets PATH so MSVC's `link.exe` wins on its
own. Either approach works.

### Step-by-step verification

Run each command from the project root
(`C:\Users\Kolee\proj\ronway-scanner`).

1. **Confirm the toolchain is alive.**

   ```powershell
   cargo --version
   rustc --version
   ```

   Should report Cargo and rustc from the active toolchain
   (currently `nightly-x86_64-pc-windows-msvc`).

2. **Compile without linking the test binaries** (fast feedback loop).

   ```powershell
   cargo check
   ```

   Expected: `Finished 'dev' profile ... in <N>s`. No errors.

3. **Run the unit tests** (this is the main thing to verify Phase 3 and 4).

   ```powershell
   cargo test
   ```

   Expected output ends with:

   ```
   running 9 tests
   ... 9 passed; 0 failed (classifier)
   running 11 tests
   ... 11 passed; 0 failed (scoring_test)
   ```

   20 tests total across the library unit tests and the integration test
   file. All must pass.

4. **Lint and format checks** (CLAUDE.md asks for clean output).

   ```powershell
   cargo fmt --check
   cargo clippy --all-targets
   ```

   `cargo fmt --check` exits 0 if formatting is clean; if not, run
   `cargo fmt` to fix.

5. **Release build** — confirms the binary still links.

   ```powershell
   cargo build --release
   ```

   Produces `target\release\ronway.exe`.

6. **Smoke-test the CLI stub.** Phase 1 only prints a placeholder string;
   real scanning lands in Phase 6+.

   ```powershell
   .\target\release\ronway.exe scan --target example.com
   ```

   Expected: `Scanning example.com...` and exit code 0.

### Running a single test by name

```powershell
cargo test score_is_capped_at_100
cargo test classifier::algorithms
```

### What is **not** runnable yet

These will exist once their phases land — do not try them until then:

```powershell
# Phase 6+ — real TLS scan
ronway scan --target bsp.gov.ph

# Phase 10 — output formats
ronway scan --target bsp.gov.ph --output json
ronway scan --target bsp.gov.ph --output pdf --out-file report.pdf

# Phase 11 — bulk and monitor
ronway bulk --targets domains.txt
ronway monitor --target example.com --interval 1440
```

---

## Troubleshooting

### `cargo test` fails with `link: extra operand ...`

PATH is being read before `.cargo/config.toml` for some reason, or the file
is missing/typoed. Verify:

```powershell
Test-Path .cargo\config.toml
Get-Content .cargo\config.toml
```

If it exists, double-check that the linker path in it points to a real
`link.exe`. If MSVC has been updated, the `14.44.35207` directory may have
been renamed; update the path or run from a Developer Command Prompt.

### `cargo test` is slow

First build after `cargo clean` recompiles ~280 dependency crates (~1 min on
this machine). Subsequent runs reuse cached artifacts and finish in seconds.

### `cargo check` fails on a fresh clone

The `.cargo/config.toml` file is committed, so the fix travels with the repo.
But the path inside it is workstation-specific — anyone else cloning this
project will need to update the path (or use a Developer Command Prompt).
This is fine for now since the project is single-developer; revisit before
publishing.

---

## Next phase

**Phase 5 — Remediation recommendations engine.** Implement
[src/classifier/recommendations.rs](../src/classifier/recommendations.rs)
to map vulnerability IDs (the ones emitted in Phase 3) to prioritised
`Recommendation` structs (already defined in Phase 2). This unblocks
the orchestrator in Phase 9 and lets the JSON report show real
remediation guidance.
