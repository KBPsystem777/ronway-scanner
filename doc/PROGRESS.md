# RonwayScanner — Build Progress

> Status as of 2026-05-28. The v1 remote-scan product is feature complete:
> TLS / certificate / HTTP scanning, NIST-PQC classification, additive
> risk scoring, prioritised remediation, four output formats, and the
> `scan` / `bulk` / `monitor` / `serve` / `version` CLI surface — all wired
> into a single `ronway` binary. The `serve` command exposes the same
> scan engine as a hardened JSON HTTP API for the BPxAI landing page.
>
> **New since the last update:** Phase 14 — the HTTP API server
> ([src/server.rs](../src/server.rs)) with SSRF-safe target validation,
> per-IP rate limiting, and a restricted CORS allowlist.
>
> See [USAGE.md](USAGE.md) for the full local terminal walkthrough.

---

## Phase progress

| Phase | Title | Status |
|------:|---|---|
| 1 | Project scaffold | Done |
| 2 | Data models | Done |
| 3 | Vulnerability classification database | Done |
| 4 | Risk scoring engine + unit tests | Done |
| 5 | Remediation recommendations engine | Done |
| 6 | TLS scanner core | Done |
| 7 | Certificate parser | Done |
| 8 | HTTP headers scanner | Done |
| 9 | Main scanner orchestrator (`RonwayScanner::scan`) | Done |
| 10 | Report generators (JSON / HTML / PDF) | Done |
| 11 | CLI polish (`scan`, `bulk`, `monitor`, `version`, output modes) | Done |
| 12 | Tests + README | Done |
| 13 | Final build verification | Done |
| 14 | HTTP API server (`serve`: `/api/scan`, `/api/health`) | Done |

---

## What works right now

### Library entry point — `RonwayScanner::scan`

[src/lib.rs](../src/lib.rs) exposes a single async orchestrator:

```rust
let report: ScanReport = RonwayScanner::scan("bsp.gov.ph").await;
// or
let report = RonwayScanner::scan_with_port("bsp.gov.ph", 8443).await;
```

The orchestrator:

1. fires the TLS and HTTP scanners concurrently via `tokio::join!`;
2. derives the `CertFinding` from the TLS scan's `peer_cert_der` (single
   handshake — no second round-trip to the target);
3. wraps individual scanner failures into `Option` fields, so a partial
   scan still produces a coherent `ScanReport` annotated with
   `TLS_SCAN_FAILED` / `CERT_SCAN_FAILED` sentinels;
4. classifies, scores, and assembles a prioritised `Vec<Recommendation>`;
5. flips `quantum_ready` on only when TLS 1.3, a PQC-safe cipher, a PQC
   key exchange, and a non-quantum-vulnerable cert all line up.

### Phase 6 — TLS scanner core

[src/scanner/tls.rs](../src/scanner/tls.rs) — `TlsScanner::scan(host, port)`
opens a `tokio-rustls` connection (10-second timeout, permissive cert
verifier so broken targets still complete the handshake) and returns
`TlsScanResult { finding, peer_cert_der }`. `TlsScanError` is a typed
enum (`Timeout` / `InvalidHostname` / `TcpConnect` / `Handshake`).
Cipher-suite names are normalised to the IANA form
(`TLS13_AES_256_GCM_SHA384` → `TLS_AES_256_GCM_SHA384`).

### Phase 7 — Certificate parser

[src/scanner/cert.rs](../src/scanner/cert.rs) — `CertScanner::parse_der`
consumes the DER bytes from Phase 6 and produces a fully populated
`CertFinding`: subject / issuer, key algorithm (`RSA-{bits}` / `EC {curve}`
/ `Ed25519` / `ML-DSA-{level}`), signature algorithm (OID → human name),
validity window with `days_remaining` / `is_expired`, `is_self_signed`,
and the `ct_logged` flag from SCT extension OID
`1.3.6.1.4.1.11129.2.4.2`.

### Phase 8 — HTTP headers scanner

[src/scanner/http.rs](../src/scanner/http.rs) — `HttpScanner::scan(host, port)`
issues one GET via reqwest (rustls-tls backend, 10-second timeout,
`danger_accept_invalid_certs` so broken certs don't block the header
scan — they're already graded by Phase 7) and extracts:
`Strict-Transport-Security` (with `max-age` parsed out), `Content-Security-Policy`
presence, `X-Frame-Options` value, `Server` value.

### Phase 10 — Report generators

| Reporter | Output |
|---|---|
| [`JsonReporter`](../src/report/json.rs) | Pretty-printed JSON (one-shot `serde_json::to_string_pretty`). |
| [`HtmlReporter`](../src/report/html.rs) | Self-contained HTML — inline CSS, no JavaScript, no external URLs. |
| [`PdfReporter`](../src/report/pdf.rs) | A4 portrait PDF built with `printpdf` and Helvetica built-ins. Greedy word-wrap, automatic page breaks. |

### Phase 11 — CLI

[src/main.rs](../src/main.rs) — clap-derived `Cli` with four subcommands:

| Command | What it does |
|---|---|
| `scan --target T [--port P] [--output text\|json\|html\|pdf] [--out-file F]` | Single scan. PDF mode requires `--out-file`. |
| `bulk --targets FILE [--output text\|json] [--concurrency N]` | Reads `host` / `host:port` per line, scans concurrently (default 8 in flight), prints per-target summary. |
| `monitor --target T [--port P] [--interval MIN]` | Re-scans on an interval and prints when the risk score changes. |
| `serve [--port P]` | Starts the HTTP API server (default `0.0.0.0:3001`). |
| `version` | Prints the binary version. |

Exit codes: `0` if the (worst) risk score is `< 60`, `1` if `>= 60`,
`2` for setup errors (missing file, bad CLI args, etc.). This matches
the CI-gate convention in [CLAUDE.md](../CLAUDE.md).

### Phase 14 — HTTP API server

[src/server.rs](../src/server.rs) — `ronway serve` boots an axum server that
exposes the same scan engine over JSON, so the BPxAI landing page can run
scans from the browser without shelling out to the binary.

| Endpoint | Behaviour |
|---|---|
| `GET /api/health` | `200` with `{ "status": "ok", "service": "ronway-scanner", "version": "…" }`. |
| `POST /api/scan` | Body `{ "target": "example.com", "port": 443 }` → full `ScanReport` JSON (same shape the reporters serialise). |

Server-side guard rails (not negotiable by the client):

- **SSRF defence.** `validate_target` strips any scheme/path, then rejects
  private, loopback, link-local, CGNAT, and reserved IP ranges plus
  internal-looking hostnames (`localhost`, `*.local`, `*.internal`,
  `*.lan`, `*.home`, `*.corp`) so the API can't be pointed at internal
  infrastructure.
- **Rate limiting.** A per-IP sliding window — 10 scans / 60 s — backed by
  an in-memory `RateLimiter`, pruned by a background task every 120 s.
- **30-second wall-clock cap** on each scan (`ApiError::ScanTimeout` → `504`).
- **CORS allowlist** restricted to the bpxai.com production origins plus
  the `localhost:3000` / `localhost:5173` dev ports.

On startup it prints a banner (listening URL + endpoints) and then a
morgan-style coloured log line per request — `METHOD PATH STATUS LATENCY IP`
— emitted at INFO so it's visible by default. `init_tracing` now defaults
to `warn,ronway_scanner=info` (still overridable via `RUST_LOG`).

---

## Testing

Every phase ships inline unit tests plus dedicated integration files
that drive the public API against an in-process rustls server:

| File | Coverage |
|---|---|
| `src/**/*.rs` `#[cfg(test)]` modules | Pure helpers (classifier, scoring, recommendations, TLS group/cipher mapping, HTTP parsing, HTML escaping, PDF text-wrap, etc.). |
| [tests/unit/scoring_test.rs](../tests/unit/scoring_test.rs) | Risk scoring boundaries, harvest-risk flag, 100-point cap, summary text. |
| [tests/unit/cert_test.rs](../tests/unit/cert_test.rs) | DER parsing across ECDSA-P256, ECDSA-P384, Ed25519, expired certs, malformed input. |
| [tests/unit/tls_test.rs](../tests/unit/tls_test.rs) | Real TLS 1.3 handshake against an in-process rcgen server; verifies the DER bytes are passed through to Phase 7. |
| [tests/unit/http_test.rs](../tests/unit/http_test.rs) | In-process HTTPS server serving controlled response headers. |
| [tests/unit/orchestrator_test.rs](../tests/unit/orchestrator_test.rs) | Full pipeline against a local HTTPS server + failure-sentinel path. |
| [tests/unit/report_test.rs](../tests/unit/report_test.rs) | JSON / HTML / PDF rendering of a representative `ScanReport`. |
| [tests/unit/server_test.rs](../tests/unit/server_test.rs) | In-process axum server: `/api/health`, CORS allow/block, SSRF rejections (localhost / private IP / empty), malformed-JSON `400`, rate-limit `429` after 10 hits. The real-target shape contract is `#[ignore]`d. |
| [tests/integration/tls_scan_test.rs](../tests/integration/tls_scan_test.rs) | `#[ignore]`d real-network sanity against `example.com`. Run with `cargo test -- --ignored`. |

### How to verify on a fresh checkout

```powershell
cargo build --release
cargo test
cargo clippy --all-targets
cargo fmt --check
```

End-to-end smoke tests (require outbound HTTPS):

```powershell
./target/release/ronway.exe version
./target/release/ronway.exe scan --target example.com
./target/release/ronway.exe scan --target example.com --output json
./target/release/ronway.exe scan --target example.com --output html --out-file report.html
./target/release/ronway.exe scan --target example.com --output pdf  --out-file report.pdf

# API server (in a second terminal):
./target/release/ronway.exe serve --port 3001
# then:  curl http://localhost:3001/api/health
```

---

## What is intentionally **not** in v1

- **Filesystem / dependency scanning.** Per [CLAUDE.md](../CLAUDE.md),
  local-source scanning is v2.
- **DNS-record analysis** (CAA / TLSA / DNSSEC).
  [src/scanner/dns.rs](../src/scanner/dns.rs) is reserved for v2.
- **OCSP / CRL freshness checks** beyond the `is_expired` flag.
- **Cipher-suite enumeration** beyond the one selected by the server.
  RonwayScanner reports what the server *picks*, not the full menu.

---

## Troubleshooting

### `cargo test` fails with `link: extra operand ...`

PATH is being read before `.cargo/config.toml`, or the file is missing.
See [.cargo/config.toml](../.cargo/config.toml) — it pins the MSVC linker
to an absolute path. If MSVC has been updated, the `14.44.35207`
directory may have been renamed; update the path or run from a
**x64 Native Tools Command Prompt for VS 2022**.

### `cargo check` fails on a fresh clone

The committed `.cargo/config.toml` linker path is workstation-specific.
Update it or use a Developer Command Prompt. This is fine for now since
the project is single-developer; revisit before publishing.
