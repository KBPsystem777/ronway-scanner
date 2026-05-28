# RonwayScanner v1 — Complete Build Plan

## Post-Quantum Cryptographic Vulnerability Scanner

---

> **How to use this document:**
> Open this file alongside Claude Code.
> Work through each phase sequentially.
> Paste the prompt under each task directly into Claude Code.
> Do not skip phases. Each one builds on the previous.

---

## Project Identity

```
Name:        RonwayScanner
Binary:      ronway
Crate name:  ronway-scanner
GitHub:      github.com/kbpsystem777/ronway-scanner
Website:     ronway-api.bpxai.com
Tagline:     "Know your quantum risk before it knows you."
License:     MIT (OSS core) + Commercial (SaaS tier)
```

---

## v1 Scope — What We Ship

RonwayScanner v1 is the remote scan mode only.
Local scan mode is v2. Do not build it now. Ship v1 first.

**v1 ships:**

- CLI binary: `ronway scan <domain>`
- TLS handshake inspector
- X.509 certificate analyzer
- Quantum vulnerability classifier
- Risk scorer (0 to 100)
- JSON output for developers
- HTML report output for technical teams
- PDF report output for CISO/board presentation
- Bulk scan from text file
- Continuous monitoring daemon mode (basic)

**v1 does NOT ship:**

- Local filesystem scan (v2)
- SaaS dashboard (v2 or separate project)
- Subdomain enumeration (v1.1)
- Database scanning (v2)
- Dependency scanning (v2)

---

## Tech Stack

```toml
# Cargo.toml dependencies

[dependencies]
# Async runtime — the foundation of everything
tokio = { version = "1", features = ["full"] }

# TLS inspection — core scanner engine
rustls = { version = "0.23", features = ["ring"] }
rustls-native-certs = "0.7"
webpki-roots = "0.26"

# HTTP client — connectivity checks and cert fetching
reqwest = { version = "0.12", features = ["rustls-tls", "json"] }

# X.509 certificate parsing
x509-parser = "0.16"

# CLI interface
clap = { version = "4", features = ["derive"] }

# Serialization — JSON output
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
anyhow = "1"
thiserror = "1"

# Parallel processing for bulk scans
rayon = "1"

# HTML report templating
tera = "1"

# PDF generation
headless_chrome = "1"   # calls Chrome/Chromium to render PDF from HTML
# Alternative if Chrome not available:
# printpdf = "0.7"

# Terminal output and progress bars
colored = "2"
indicatif = "0.17"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Date and time
chrono = { version = "0.4", features = ["serde"] }

# DNS resolution
hickory-resolver = "0.24"
```

---

## Project Structure

```
ronway-scanner/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── .gitignore
│
├── src/
│   ├── main.rs                  # CLI entry point — clap commands
│   ├── lib.rs                   # Public library API
│   │
│   ├── scanner/
│   │   ├── mod.rs               # Scanner module exports
│   │   ├── tls.rs               # TLS handshake inspector
│   │   ├── cert.rs              # X.509 certificate parser
│   │   ├── http.rs              # HTTP security headers checker
│   │   └── dns.rs               # DNS resolution and connectivity
│   │
│   ├── classifier/
│   │   ├── mod.rs               # Classifier module exports
│   │   ├── algorithms.rs        # Quantum vulnerability database
│   │   ├── scoring.rs           # Risk scoring engine
│   │   └── recommendations.rs   # Remediation recommendation engine
│   │
│   ├── report/
│   │   ├── mod.rs               # Report module exports
│   │   ├── json.rs              # JSON output formatter
│   │   ├── html.rs              # HTML report generator
│   │   └── pdf.rs               # PDF report generator
│   │
│   └── models/
│       ├── mod.rs               # Model exports
│       ├── finding.rs           # ScanFinding struct
│       ├── report.rs            # ScanReport struct
│       └── risk.rs              # RiskLevel enum and scoring types
│
├── templates/
│   ├── report.html              # Tera HTML report template
│   └── report_ciso.html         # Executive/board-friendly template
│
├── assets/
│   └── ronway_logo.svg          # Logo for reports
│
└── tests/
    ├── integration/
    │   ├── tls_scan_test.rs     # Integration tests against known endpoints
    │   └── cert_parse_test.rs   # Certificate parsing tests
    └── unit/
        ├── classifier_test.rs   # Vulnerability classification tests
        └── scoring_test.rs      # Risk scoring tests
```

---

## Phase 1 — Project Scaffold

**Time estimate: 30 minutes**
**Goal: Working project that compiles with all dependencies**

### Claude Code Prompt — Phase 1:

```
Create a new Rust project called ronway-scanner.

Set up the complete project structure:

1. Create Cargo.toml with these exact dependencies:
   - tokio 1 with full features
   - rustls 0.23 with ring feature
   - rustls-native-certs 0.7
   - webpki-roots 0.26
   - reqwest 0.12 with rustls-tls and json features
   - x509-parser 0.16
   - clap 4 with derive feature
   - serde 1 with derive feature
   - serde_json 1
   - anyhow 1
   - thiserror 1
   - rayon 1
   - colored 2
   - indicatif 0.17
   - tracing 0.1
   - tracing-subscriber 0.3
   - chrono 0.4 with serde feature
   - hickory-resolver 0.24

2. Create this directory structure:
   src/main.rs
   src/lib.rs
   src/scanner/mod.rs
   src/scanner/tls.rs
   src/scanner/cert.rs
   src/scanner/http.rs
   src/scanner/dns.rs
   src/classifier/mod.rs
   src/classifier/algorithms.rs
   src/classifier/scoring.rs
   src/classifier/recommendations.rs
   src/report/mod.rs
   src/report/json.rs
   src/report/html.rs
   src/report/pdf.rs
   src/models/mod.rs
   src/models/finding.rs
   src/models/report.rs
   src/models/risk.rs
   templates/report.html
   templates/report_ciso.html

3. Populate each file with a stub (empty mod with a comment describing its purpose)
   so the project compiles without errors.

4. In main.rs set up a basic clap CLI with one subcommand:
   ronway scan --target <domain>
   that prints "Scanning <domain>..." to stdout.

Make it compile with: cargo build
```

---

## Phase 2 — Data Models

**Time estimate: 45 minutes**
**Goal: All structs and enums defined. The skeleton of every data type.**

### Claude Code Prompt — Phase 2:

```
In the ronway-scanner project, implement all data models.

In src/models/risk.rs create:

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Critical,   // score 80-100: immediate migration required
    High,       // score 60-79: urgent attention needed
    Medium,     // score 40-59: plan migration within 6 months
    Low,        // score 20-39: monitor and plan
    Pass,       // score 0-19: meets current standards
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self { ... }
    pub fn label(&self) -> &str { ... }
    pub fn color_code(&self) -> &str { ... }  // hex colors for report
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub value: u8,           // 0-100
    pub level: RiskLevel,
    pub summary: String,
    pub harvest_risk: bool,  // true if RSA/ECC key exchange detected
}

---

In src/models/finding.rs create:

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFinding {
    pub protocol_version: String,       // "TLSv1.2", "TLSv1.3"
    pub protocol_vulnerable: bool,
    pub cipher_suite: String,
    pub cipher_vulnerable: bool,
    pub key_exchange: String,           // "RSA", "ECDHE", "ML-KEM-768"
    pub key_exchange_vulnerable: bool,
    pub compression: String,
    pub compression_vulnerable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertFinding {
    pub subject: String,
    pub issuer: String,
    pub key_algorithm: String,          // "RSA-2048", "ECDSA-256", "ML-DSA-65"
    pub key_algorithm_vulnerable: bool,
    pub signature_algorithm: String,
    pub signature_algorithm_vulnerable: bool,
    pub valid_from: String,
    pub valid_until: String,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub ct_logged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFinding {
    pub hsts_enabled: bool,
    pub hsts_max_age: Option<u64>,
    pub csp_present: bool,
    pub x_frame_options: Option<String>,
    pub server_header: Option<String>,   // detect if leaking server info
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,             // e.g., "RSA_KEY_EXCHANGE"
    pub title: String,
    pub description: String,
    pub severity: RiskLevel,
    pub nist_reference: String, // e.g., "NIST SP 800-131A Rev 2"
    pub cvss_equivalent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: u8,           // 1 = highest priority
    pub action: String,
    pub current: String,        // what they have now
    pub replace_with: String,   // what to use instead
    pub effort_weeks: u8,
    pub nist_algorithm: String, // the NIST PQC standard algorithm
}

---

In src/models/report.rs create:

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub domain: String,
    pub ip_address: Option<String>,
    pub port: u16,
    pub scanned_at: String,        // ISO 8601 datetime
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: ScanTarget,
    pub risk_score: RiskScore,
    pub tls: Option<TlsFinding>,
    pub certificate: Option<CertFinding>,
    pub http: Option<HttpFinding>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub recommendations: Vec<Recommendation>,
    pub summary: String,           // one paragraph plain English summary
    pub quantum_ready: bool,       // true only if zero quantum-vulnerable findings
}

impl ScanReport {
    pub fn is_critical(&self) -> bool { ... }
    pub fn vulnerability_count(&self) -> usize { ... }
    pub fn has_harvest_risk(&self) -> bool { ... }
}

---

Make all models derive Serialize and Deserialize.
Import everything correctly in src/models/mod.rs.
Make the project compile after these additions.
```

---

## Phase 3 — Vulnerability Classification Database

**Time estimate: 1 hour**
**Goal: Complete lookup table of every algorithm rated against NIST PQC guidance**

### Claude Code Prompt — Phase 3:

```
In src/classifier/algorithms.rs implement the complete quantum
vulnerability classification database for RonwayScanner.

Create an AlgorithmClassifier struct with these methods:

pub fn is_tls_version_vulnerable(version: &str) -> bool
  - "TLSv1.0" -> true  (deprecated, enables downgrade attacks)
  - "TLSv1.1" -> true  (deprecated)
  - "TLSv1.2" -> true  (vulnerable, allows RSA key exchange)
  - "TLSv1.3" -> false (safe, only forward-secret ciphers allowed)
  - "SSLv3"   -> true  (broken)

pub fn is_key_exchange_vulnerable(algorithm: &str) -> (bool, &str)
  Returns (is_vulnerable, reason)
  - "RSA"          -> (true, "Broken by Shor's Algorithm on quantum computers")
  - "DH"           -> (true, "Discrete log problem solved by Shor's Algorithm")
  - "DHE"          -> (true, "Discrete log problem solved by Shor's Algorithm")
  - "ECDH"         -> (true, "Elliptic curve discrete log solved by Shor's Algorithm")
  - "ECDHE"        -> (true, "Elliptic curve discrete log solved by Shor's Algorithm")
  - "ML-KEM-512"   -> (false, "NIST FIPS 203 post-quantum key encapsulation")
  - "ML-KEM-768"   -> (false, "NIST FIPS 203 post-quantum key encapsulation")
  - "ML-KEM-1024"  -> (false, "NIST FIPS 203 post-quantum key encapsulation")
  - "X25519MLKEM768" -> (false, "Hybrid classical+PQC — recommended transition")
  - "X25519"       -> (false, "Classical only but forward secret — transitionally safe")
  - "X448"         -> (false, "Classical only but forward secret — transitionally safe")

pub fn is_signature_algorithm_vulnerable(algorithm: &str) -> (bool, &str)
  - "sha1WithRSAEncryption"    -> (true, "SHA-1 collision vulnerable + RSA quantum vulnerable")
  - "sha256WithRSAEncryption"  -> (true, "RSA quantum vulnerable via Shor's Algorithm")
  - "sha384WithRSAEncryption"  -> (true, "RSA quantum vulnerable via Shor's Algorithm")
  - "sha512WithRSAEncryption"  -> (true, "RSA quantum vulnerable via Shor's Algorithm")
  - "ecdsa-with-SHA256"        -> (true, "ECDSA quantum vulnerable via Shor's Algorithm")
  - "ecdsa-with-SHA384"        -> (true, "ECDSA quantum vulnerable via Shor's Algorithm")
  - "id-dsa-with-sha1"         -> (true, "DSA broken classically and quantum vulnerable")
  - "id-ML-DSA-44"             -> (false, "NIST FIPS 204 ML-DSA post-quantum signature")
  - "id-ML-DSA-65"             -> (false, "NIST FIPS 204 ML-DSA post-quantum signature")
  - "id-ML-DSA-87"             -> (false, "NIST FIPS 204 ML-DSA post-quantum signature")
  - "id-slh-dsa-sha2-128s"     -> (false, "NIST FIPS 205 SLH-DSA post-quantum signature")
  - "Ed25519"                  -> (false, "Classical only — transitionally safe")
  - "Ed448"                    -> (false, "Classical only — transitionally safe")

pub fn is_cipher_suite_vulnerable(cipher: &str) -> (bool, &str)
  - Anything containing "RC4"       -> (true, "RC4 stream cipher broken")
  - Anything containing "3DES"      -> (true, "64-bit block cipher, SWEET32 vulnerable")
  - Anything containing "DES"       -> (true, "56-bit key, classically broken")
  - Anything containing "NULL"      -> (true, "No encryption")
  - Anything containing "EXPORT"    -> (true, "Export-grade intentionally weak crypto")
  - Anything containing "MD5"       -> (true, "MD5 collision vulnerable")
  - Anything containing "SHA1"      -> (true, "SHA-1 collision vulnerable (not SHA-256/384/512)")
  - Anything containing "_CBC"      -> (true, "CBC mode vulnerable to BEAST/POODLE attacks")
  - Anything containing "AES_128"   -> (false, "AES-128 safe (Grover halves to 64-bit but still safe)")
  - Anything containing "AES_256"   -> (false, "AES-256 quantum safe (Grover reduces to 128-bit)")
  - Anything containing "CHACHA20"  -> (false, "ChaCha20-Poly1305 quantum safe")

Also create a VulnerabilityDatabase struct with a method:
pub fn build_vulnerabilities(tls: &TlsFinding, cert: &CertFinding) -> Vec<Vulnerability>
  That takes scan findings and returns a Vec<Vulnerability> with:
  - A unique ID for each vulnerability found
  - Human-readable title and description
  - NIST reference
  - Severity level

Make all functions pure (no side effects) for easy testing.
```

---

## Phase 4 — Risk Scoring Engine

**Time estimate: 30 minutes**
**Goal: Deterministic risk score from vulnerability list**

### Claude Code Prompt — Phase 4:

```
In src/classifier/scoring.rs implement the RonwayScanner risk scoring engine.

The scoring model:

Base score starts at 0. Each vulnerability adds points. Max score is 100.

Vulnerability weights:
  RSA key exchange detected:        +35 points  (harvest now decrypt later)
  ECDH/ECDHE key exchange:          +30 points  (harvest now decrypt later)
  DH key exchange:                  +25 points  (harvest now decrypt later)
  TLS 1.0 or 1.1 enabled:          +20 points  (protocol downgrade risk)
  TLS 1.2 as highest version:       +10 points  (allows vulnerable key exchange)
  RSA certificate signature:        +25 points  (quantum vulnerable)
  ECDSA certificate signature:      +20 points  (quantum vulnerable)
  SHA-1 in certificate chain:       +15 points  (collision vulnerable)
  Self-signed certificate:          +10 points  (no CA validation)
  CBC mode cipher suite:            +10 points  (BEAST/POODLE)
  RC4 cipher suite:                 +20 points  (broken stream cipher)
  3DES cipher suite:                +15 points  (SWEET32)
  NULL cipher suite:                +40 points  (no encryption)
  EXPORT cipher suite:              +30 points  (intentionally weak)
  Certificate expired:              +20 points  (immediate issue)
  No HSTS:                          +5  points  (downgrade attack vector)
  Server header leaking version:    +5  points  (information disclosure)

Score is capped at 100.

Harvest risk flag is set to true if ANY of these are present:
  - RSA key exchange
  - ECDH or ECDHE key exchange
  - DH key exchange

Create:

pub struct RiskScorer;

impl RiskScorer {
    pub fn calculate(vulnerabilities: &[Vulnerability]) -> RiskScore
    pub fn harvest_risk_present(vulnerabilities: &[Vulnerability]) -> bool
    pub fn generate_summary(score: &RiskScore, target: &str) -> String
      Returns a 2-3 sentence plain English summary suitable for an executive report.
}

The generate_summary method should produce output like:
  "bsp.gov.ph scored 87/100 (Critical) on the RonwayScanner post-quantum
  assessment. RSA key exchange was detected, meaning past encrypted sessions
  are at risk of future decryption by quantum computers (harvest now, decrypt
  later). Immediate migration to ML-KEM-768 hybrid key exchange and ML-DSA-65
  certificate signatures is recommended."

Write unit tests for the scoring logic in tests/unit/scoring_test.rs
```

---

## Phase 5 — Remediation Recommendations Engine

**Time estimate: 45 minutes**
**Goal: Actionable recommendations for every vulnerability found**

### Claude Code Prompt — Phase 5:

```
In src/classifier/recommendations.rs implement the remediation
recommendation engine for RonwayScanner.

Create a RecommendationEngine struct with:

pub fn generate(vulnerabilities: &[Vulnerability]) -> Vec<Recommendation>

The function maps each vulnerability ID to a concrete recommendation.
Recommendations are sorted by priority (1 = do this first).

Implement recommendations for each vulnerability:

"RSA_KEY_EXCHANGE" -> Recommendation {
    priority: 1,
    action: "Replace RSA key exchange with ML-KEM-768 hybrid",
    current: "RSA key exchange (quantum vulnerable)",
    replace_with: "X25519MLKEM768 hybrid key exchange (NIST FIPS 203)",
    effort_weeks: 2,
    nist_algorithm: "ML-KEM-768 (FIPS 203)",
}

"ECDHE_KEY_EXCHANGE" -> Recommendation {
    priority: 1,
    action: "Add ML-KEM-768 hybrid alongside ECDHE",
    current: "ECDHE only (quantum vulnerable)",
    replace_with: "X25519MLKEM768 hybrid — ML-KEM-768 + X25519",
    effort_weeks: 2,
    nist_algorithm: "ML-KEM-768 (FIPS 203)",
}

"TLS_VERSION_VULNERABLE" -> Recommendation {
    priority: 2,
    action: "Disable TLS 1.0, 1.1, 1.2. Enable TLS 1.3 only",
    current: "TLS 1.2 or below (allows vulnerable cipher suites)",
    replace_with: "TLS 1.3 only configuration",
    effort_weeks: 1,
    nist_algorithm: "TLS 1.3 (RFC 8446)",
}

"RSA_CERTIFICATE" -> Recommendation {
    priority: 3,
    action: "Replace RSA certificate with ML-DSA-65 certificate",
    current: "RSA-2048 or RSA-4096 certificate (quantum vulnerable)",
    replace_with: "ML-DSA-65 certificate from PQC-ready CA",
    effort_weeks: 4,
    nist_algorithm: "ML-DSA-65 (FIPS 204)",
}

"ECDSA_CERTIFICATE" -> Recommendation {
    priority: 3,
    action: "Replace ECDSA certificate with ML-DSA-65",
    current: "ECDSA certificate (quantum vulnerable)",
    replace_with: "ML-DSA-65 certificate or Ed25519 as interim",
    effort_weeks: 4,
    nist_algorithm: "ML-DSA-65 (FIPS 204)",
}

"CBC_CIPHER" -> Recommendation {
    priority: 4,
    action: "Disable CBC mode cipher suites",
    current: "AES-CBC mode (BEAST/POODLE vulnerable)",
    replace_with: "AES-256-GCM or ChaCha20-Poly1305",
    effort_weeks: 1,
    nist_algorithm: "AES-256-GCM (NIST SP 800-38D)",
}

"NO_HSTS" -> Recommendation {
    priority: 5,
    action: "Enable HTTP Strict Transport Security",
    current: "No HSTS header (allows protocol downgrade)",
    replace_with: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    effort_weeks: 1,
    nist_algorithm: "N/A — defense in depth",
}

Remove duplicate recommendations if the same vulnerability
appears multiple times. Keep highest priority version.

Sort final recommendations by priority ascending (1 first).
```

---

## Phase 6 — TLS Scanner Core

**Time estimate: 2 hours**
**Goal: Working TLS handshake inspection against real domains**

### Claude Code Prompt — Phase 6:

```
In src/scanner/tls.rs implement the TLS handshake inspector
for RonwayScanner. This is the core scanner engine.

Use the rustls crate to initiate TLS connections.

Create:

pub struct TlsScanner;

impl TlsScanner {
    pub async fn scan(host: &str, port: u16) -> Result<TlsFinding>
}

The scan method should:

1. Attempt a TLS 1.3 connection first using rustls ClientConfig
   Record: negotiated protocol version, negotiated cipher suite
   Record: key exchange group if available from connection info

2. Attempt a TLS 1.2 connection separately
   Record: whether server accepts TLS 1.2
   Record: cipher suite negotiated under TLS 1.2

3. Build a TlsFinding from the observed parameters:
   - protocol_version: the highest TLS version the server supports
   - protocol_vulnerable: true if server accepts TLS 1.2 or below
   - cipher_suite: the negotiated cipher suite name
   - cipher_vulnerable: pass to AlgorithmClassifier::is_cipher_suite_vulnerable
   - key_exchange: detected key exchange algorithm
   - key_exchange_vulnerable: pass to AlgorithmClassifier::is_key_exchange_vulnerable
   - compression: "none" (TLS 1.3 has no compression) or detected value

4. Handle these error cases gracefully:
   - Connection refused -> return an error with clear message
   - DNS resolution failure -> return error with "domain not found"
   - TLS handshake rejected -> return error with "TLS handshake failed"
   - Timeout after 10 seconds -> return error with "connection timed out"

Use tokio::time::timeout for the 10 second timeout.
Use anyhow::Result for error handling throughout.
Add tracing::debug! calls at each step for debugging.

Do NOT use unsafe code anywhere in this file.
```

---

## Phase 7 — Certificate Parser

**Time estimate: 1.5 hours**
**Goal: Complete X.509 certificate analysis**

### Claude Code Prompt — Phase 7:

```
In src/scanner/cert.rs implement the X.509 certificate analyzer
for RonwayScanner.

Use the x509-parser crate and reqwest to fetch and parse certificates.

Create:

pub struct CertScanner;

impl CertScanner {
    pub async fn scan(host: &str, port: u16) -> Result<CertFinding>
    fn parse_certificate(cert_der: &[u8]) -> Result<CertFinding>
    fn detect_key_algorithm(cert: &X509Certificate) -> String
    fn detect_signature_algorithm(cert: &X509Certificate) -> String
    fn days_until_expiry(cert: &X509Certificate) -> i64
    fn is_self_signed(cert: &X509Certificate) -> bool
}

The scan method should:

1. Open a TLS connection using rustls
2. Extract the server certificate from the connection
3. Pass it to parse_certificate
4. Return a populated CertFinding

The parse_certificate method should extract:

subject: the CN of the subject distinguished name
issuer: the CN of the issuer distinguished name
key_algorithm: detect from SubjectPublicKeyInfo:
  - RSA key -> format as "RSA-{bits}" e.g. "RSA-2048"
  - ECDSA key -> format as "ECDSA-{curve}" e.g. "ECDSA-P256"
  - ML-DSA key -> format as "ML-DSA-{level}" e.g. "ML-DSA-65"
  - Ed25519 -> "Ed25519"
  - Unknown -> "Unknown"

key_algorithm_vulnerable: pass to AlgorithmClassifier::is_signature_algorithm_vulnerable

signature_algorithm: the signature algorithm OID mapped to human name:
  - 1.2.840.113549.1.1.11 -> "sha256WithRSAEncryption"
  - 1.2.840.113549.1.1.12 -> "sha384WithRSAEncryption"
  - 1.2.840.10045.4.3.2   -> "ecdsa-with-SHA256"
  - etc.

valid_from: ISO 8601 formatted not-before date
valid_until: ISO 8601 formatted not-after date
days_remaining: positive if valid, negative if expired
is_expired: true if days_remaining < 0
is_self_signed: true if subject == issuer
ct_logged: check for the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)
           true if the extension is present

Handle parse errors gracefully — if any field cannot be parsed,
use a sensible default value rather than returning an error.

Log the raw certificate subject and issuer at tracing::debug level.
```

---

## Phase 8 — HTTP Headers Scanner

**Time estimate: 45 minutes**
**Goal: Check HTTP security headers that affect crypto posture**

### Claude Code Prompt — Phase 8:

```
In src/scanner/http.rs implement the HTTP security headers scanner
for RonwayScanner.

Use reqwest to fetch the headers.

Create:

pub struct HttpScanner;

impl HttpScanner {
    pub async fn scan(host: &str) -> Result<HttpFinding>
}

The scan method should:

1. Make a GET request to https://{host}/ with reqwest
   Set a 10 second timeout
   Do NOT follow redirects (inspect headers of the initial response)
   Set User-Agent: "RonwayScanner/1.0 (security assessment)"

2. Extract and analyze these headers:

   Strict-Transport-Security (HSTS):
     hsts_enabled: true if header present
     hsts_max_age: parse max-age value from header (e.g., 31536000)
     If max-age < 31536000 (1 year) note it as suboptimal

   Content-Security-Policy:
     csp_present: true if header present
     Do not parse the full policy — just check presence

   X-Frame-Options:
     x_frame_options: Some("DENY") or Some("SAMEORIGIN") or None

   Server:
     server_header: Some(value) if present
     This is an information disclosure finding if it reveals
     software version (e.g., "Apache/2.4.51" leaks version)

3. Return populated HttpFinding

Handle request errors gracefully:
  - If the HTTP request fails, return an HttpFinding with all
    fields set to their safe defaults (hsts_enabled: false, etc.)
  - Log the error at tracing::warn level but do not propagate it
    since HTTP headers are a secondary scan, not primary
```

---

## Phase 9 — Main Scanner Orchestrator

**Time estimate: 1 hour**
**Goal: Coordinate all scanners into one complete ScanReport**

### Claude Code Prompt — Phase 9:

```
In src/lib.rs implement the main RonwayScanner orchestrator
that coordinates all scan modules into a complete ScanReport.

Create:

pub struct RonwayScanner;

impl RonwayScanner {
    pub async fn scan(target: &str) -> Result<ScanReport>
    pub async fn scan_bulk(targets: Vec<String>) -> Vec<Result<ScanReport>>
    fn parse_target(target: &str) -> (String, u16)
      Extracts host and port from input like:
        "bsp.gov.ph"        -> ("bsp.gov.ph", 443)
        "bsp.gov.ph:8443"   -> ("bsp.gov.ph", 8443)
        "https://bsp.gov.ph" -> ("bsp.gov.ph", 443)
}

The scan method should:

1. Record start time with chrono::Utc::now()

2. Resolve the IP address of the target using hickory-resolver
   Store in ScanTarget.ip_address

3. Run TlsScanner::scan, CertScanner::scan, and HttpScanner::scan
   Run them concurrently using tokio::join! for speed
   Handle individual scanner failures gracefully:
     If TLS scan fails, record tls: None and add a critical vulnerability
     If cert scan fails, record certificate: None and add a critical vulnerability
     If HTTP scan fails, record http: None (non-critical)

4. Pass all findings to VulnerabilityDatabase::build_vulnerabilities
   to get the Vec<Vulnerability>

5. Pass vulnerabilities to RiskScorer::calculate to get RiskScore

6. Pass vulnerabilities to RecommendationEngine::generate to get Vec<Recommendation>

7. Generate plain English summary with RiskScorer::generate_summary

8. Record scan duration: chrono::Utc::now() - start_time milliseconds

9. Build and return ScanReport with all fields populated

For scan_bulk:
  Use rayon to parallelize across multiple targets
  Return a Vec of Results — individual scan failures do not stop others
  Print a progress bar using indicatif

Add these display methods to ScanReport:
  pub fn print_terminal(&self)
    Prints a formatted, colored terminal output using the colored crate
    Shows: target, risk score with color, key findings, top 3 recommendations

Example terminal output format:

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

  Run with --output pdf to generate board-ready report.
  ══════════════════════════════════════════════
```

---

## Phase 10 — Report Generation

**Time estimate: 1.5 hours**
**Goal: JSON, HTML, and PDF report output**

### Claude Code Prompt — Phase 10:

```
Implement the three report generators for RonwayScanner.

--- src/report/json.rs ---

Create:
pub struct JsonReporter;
impl JsonReporter {
    pub fn generate(report: &ScanReport) -> Result<String>
      Uses serde_json::to_string_pretty to serialize the full ScanReport
      Returns formatted JSON string
}

--- src/report/html.rs ---

Create a Tera HTML template at templates/report.html with:
- RonwayScanner branding header
- Risk score displayed as a large colored number
- Color coding: red for Critical/High, orange for Medium, green for Pass
- Vulnerabilities table: ID, title, severity, description
- Recommendations table: priority, action, current, replace_with, effort
- Certificate details section
- TLS configuration section
- Footer: "Generated by RonwayScanner — ronwayscanner.com"

Create:
pub struct HtmlReporter;
impl HtmlReporter {
    pub fn generate(report: &ScanReport) -> Result<String>
      Uses tera to render the template with the report data
      Returns the rendered HTML string as a String
}

--- src/report/pdf.rs ---

Create:
pub struct PdfReporter;
impl PdfReporter {
    pub async fn generate(report: &ScanReport, output_path: &str) -> Result<()>
      1. Generate HTML using HtmlReporter::generate
      2. Write to a temp file
      3. Use headless_chrome to open the HTML and print to PDF
      4. Save PDF to output_path
      5. Remove the temp file
      If headless_chrome fails (Chrome not installed),
      fall back to saving the HTML file and inform the user.
}

--- templates/report.html ---

Build a complete professional HTML report template with:
- Dark color scheme: #0a0a0f background, white text
- Purple accent color: #9333ea (RonwayScanner brand)
- Logo placeholder at top: "⚛ RonwayScanner"
- Target domain and scan date
- Large risk score number colored by severity
- Harvest risk warning box (shown only if harvest_risk is true):
  "⚠ HARVEST NOW DECRYPT LATER RISK DETECTED
   Encrypted data transmitted to this host is at risk of future
   decryption by quantum computers."
- Vulnerabilities section with severity badges
- Recommendations section with priority numbers
- Certificate details in a clean table
- TLS configuration in a clean table
- Page footer with scan timestamp and RonwayScanner version
- Print-friendly CSS: @media print { background: white; color: black; }

Make the HTML self-contained — no external CDN dependencies.
All CSS inline in <style> tags so PDF renders correctly offline.
```

---

## Phase 11 — CLI Polish and Commands

**Time estimate: 1 hour**
**Goal: Complete CLI with all user-facing commands**

### Claude Code Prompt — Phase 11:

```
Implement the complete CLI for RonwayScanner in src/main.rs.

Use clap derive macros to define this command structure:

ronway <COMMAND>

Commands:

  scan       Scan a single domain
    --target <domain>           Required. Domain to scan.
    --port <port>               Optional. Default 443.
    --output <format>           Optional. "terminal" (default), "json", "html", "pdf"
    --out-file <path>           Optional. Output file path. Required for json/html/pdf.
    --audience <type>           Optional. "technical" (default) or "ciso"
                                ciso generates executive-friendly language
    --timeout <seconds>         Optional. Default 10.
    --verbose                   Optional. Show debug output.

  bulk       Scan multiple domains from a file
    --targets <file>            Required. Path to text file with one domain per line.
    --output <format>           Optional. "terminal" (default) or "json"
    --out-dir <path>            Optional. Directory to write individual reports.
    --concurrency <n>           Optional. Default 10 concurrent scans.

  monitor    Continuously monitor a domain (basic daemon mode v1)
    --target <domain>           Required.
    --interval <minutes>        Optional. Default 1440 (once per day).
    --alert-score <threshold>   Optional. Alert if score exceeds this. Default 60.

  version    Print version information

Implement these behaviors:

For `scan`:
  1. Show a spinner using indicatif while scanning
  2. On completion, print terminal output by default
  3. If --output pdf and no --out-file given, auto-name as {domain}_{date}.pdf
  4. If --audience ciso, use more executive language in summary
  5. Exit with code 0 if score < 60, exit code 1 if score >= 60
     This allows CI/CD pipeline integration: fail the build if vulnerable

For `bulk`:
  1. Read target file, strip empty lines and comments (#)
  2. Show progress bar for all scans
  3. Print summary table when complete:
     Domain | Score | Level | Key Finding
  4. Write individual JSON reports to --out-dir if specified

For `monitor`:
  Basic v1: run scan once, sleep for interval, repeat
  Print result each time with timestamp
  This is expanded in v2 to a proper daemon with alerts

For `version`:
  Print: RonwayScanner v1.0.0
         Post-Quantum Cryptographic Scanner
         Built by BPxAI — bpxai.com
         Named for Ronnie and Liway
         github.com/pilipinas-rs/ronway-scanner

Add a startup banner for interactive use (suppress with --quiet):
  ⚛ RonwayScanner v1.0.0 — Post-Quantum Security Assessment
  Named for Ronnie and Liway — Built by BPxAI
```

---

## Phase 12 — Tests and README

**Time estimate: 1 hour**
**Goal: Tests passing, README complete, ready for GitHub**

### Claude Code Prompt — Phase 12:

````
Complete RonwayScanner v1 with tests and documentation.

--- Tests ---

In tests/unit/classifier_test.rs write unit tests for:
  - is_key_exchange_vulnerable("RSA") returns (true, _)
  - is_key_exchange_vulnerable("ML-KEM-768") returns (false, _)
  - is_signature_algorithm_vulnerable("sha256WithRSAEncryption") returns (true, _)
  - is_cipher_suite_vulnerable("TLS_RSA_WITH_3DES_EDE_CBC_SHA") returns (true, _)
  - is_cipher_suite_vulnerable("TLS_AES_256_GCM_SHA384") returns (false, _)

In tests/unit/scoring_test.rs write unit tests for:
  - RiskScore with RSA_KEY_EXCHANGE vulnerability scores >= 35
  - RiskScore with no vulnerabilities scores 0
  - harvest_risk_present returns true when RSA_KEY_EXCHANGE present
  - harvest_risk_present returns false with no key exchange vulnerabilities
  - RiskLevel::from_score(87) returns RiskLevel::Critical
  - RiskLevel::from_score(15) returns RiskLevel::Pass

In tests/integration/tls_scan_test.rs write integration tests:
  Note: These make real network calls. Mark with #[ignore] so they
  only run when explicitly called with: cargo test -- --ignored

  - scan("example.com") returns Ok(TlsFinding)
  - scan("expired.badssl.com") detects an expired certificate
  - scan("tls-v1-0.badssl.com") detects TLS 1.0

Run: cargo test
All unit tests must pass.

--- README.md ---

Write a complete README.md for the GitHub repository:

# ⚛ RonwayScanner

> Post-quantum cryptographic vulnerability scanner for Philippine institutions.
> Named for Ronnie and Liway.

## What It Does
[Explain remote scan mode in 3 sentences]

## Why Post-Quantum Security Matters Now
[2 paragraph explanation of harvest now decrypt later in plain language]

## Installation
```bash
cargo install ronway-scanner
````

## Quick Start

```bash
# Scan a domain
ronway scan --target bsp.gov.ph

# Generate PDF report
ronway scan --target bsp.gov.ph --output pdf --out-file report.pdf

# Scan multiple domains
ronway bulk --targets domains.txt
```

## What It Detects

[Table of vulnerable algorithms and their replacements]

## Interpreting Results

[Explain the 0-100 risk score and what each level means]

## Enterprise Audits

For full internal infrastructure audits including filesystem scanning,
dependency analysis, and migration implementation:
bpxai.com/quantum

## Built By

[Your name, BPxAI, link to bpxai.com]

## License

MIT for OSS CLI. Enterprise features require commercial license.
See bpxai.com/quantum for enterprise pricing.

```

---

## Phase 13 — Final Build Verification

**Time estimate: 30 minutes**
**Goal: Everything compiles, tests pass, binary runs**

### Claude Code Prompt — Phase 13:

```

Final verification of RonwayScanner v1.

Run these commands and fix any errors:

1. cargo fmt — format all code
2. cargo clippy — fix all linter warnings (treat warnings as errors)
3. cargo test — all unit tests must pass
4. cargo build --release — release binary must compile

Then test the binary manually:

./target/release/ronway version
Must print version banner

./target/release/ronway scan --target example.com
Must complete without panic and print terminal output

./target/release/ronway scan --target example.com --output json
Must print valid JSON that parses correctly

./target/release/ronway scan --target example.com --output html --out-file /tmp/test.html
Must create a valid HTML file

If any of these fail, fix the root cause before declaring v1 complete.

After all checks pass, create a git tag:
git add .
git commit -m "feat: RonwayScanner v1.0.0 — remote scan mode"
git tag v1.0.0
git push origin main --tags

RonwayScanner v1 is shipped.

```

---

## Total Build Timeline

| Phase | Task | Estimated Time |
|-------|------|---------------|
| 1 | Project scaffold | 30 min |
| 2 | Data models | 45 min |
| 3 | Vulnerability database | 60 min |
| 4 | Risk scoring engine | 30 min |
| 5 | Recommendations engine | 45 min |
| 6 | TLS scanner core | 120 min |
| 7 | Certificate parser | 90 min |
| 8 | HTTP headers scanner | 45 min |
| 9 | Main orchestrator | 60 min |
| 10 | Report generation | 90 min |
| 11 | CLI polish | 60 min |
| 12 | Tests and README | 60 min |
| 13 | Final verification | 30 min |
| **Total** | | **~12 hours** |

**Realistic schedule with Claude Code: 2 full weekends.**

Weekend 1: Phases 1 to 7 (foundation + core scanner)
Weekend 2: Phases 8 to 13 (reports + CLI + ship)

---

## After v1 Ships — What v2 Adds

```

v1.1 (2 weeks after v1)

- Subdomain enumeration via crt.sh certificate transparency
- Batch PDF report for bulk scans
- GitHub Actions integration example

v2.0 (Month 3)

- Local scan mode: filesystem, keys, configs, dependencies, database
- This is the enterprise audit product
- Requires authorization workflow built into the CLI

v2.1 (Month 4)

- SaaS dashboard: Next.js + Supabase + PayMongo
- Scan job queue
- Continuous monitoring with email alerts
- White-label reports for enterprise clients

```

---

## Domain and Brand

Register immediately:
- ronwayscanner.com
- github.com/kbpsystem777/ronway-scanner
- crates.io: ronway-scanner

First post on X after v1 ships:
```

Shipped RonwayScanner v1.0.0.

Post-quantum cryptographic vulnerability scanner for Philippine institutions.

Named for my parents: Ronnie and Liway.

ronway scan --target [any domain]

github.com/kbpsystem777/ronway-scanner

🇵🇭 ⚛

```

That tweet gets retweeted by the Philippine dev community.
That is your launch.
```

---

_RonwayScanner — Built by Koleen Baes Paunon_ for _BPxAI — bpxai.com — @KBPsystem_
