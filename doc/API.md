# RonwayScanner API Reference

**Base URL:** `https://ronway-api.bpxai.com`

**Rate limit:** 10 requests/min per IP (sliding window)  
**CORS allowed origins:** `https://bpxai.com`, `https://www.bpxai.com`, `http://localhost:3000`, `http://localhost:5173`

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Service health check |
| `POST` | `/api/scan` | Run a quantum-risk scan |
| `GET` | `/api/scans` | List all scan history |
| `GET` | `/api/scans/:domain` | Scan history for a single domain |
| `GET` | `/api/sites` | Per-site scan rollup |

---

## GET /api/health

Returns the service status and version. No authentication required.

**Response `200`**
```json
{
  "status": "ok",
  "service": "ronway-scanner",
  "version": "0.1.0"
}
```

---

## POST /api/scan

Run a post-quantum cryptography risk scan against a public target. Analyzes TLS configuration, X.509 certificate, and HTTP security headers, then scores against NIST PQC guidance (FIPS 203/204/205).

**Request body** (`Content-Type: application/json`)

```json
{
  "target": "example.com",
  "port": 443
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | yes | Public domain or IP literal. Schemes (`https://`) and paths are stripped automatically. Inline port (`example.com:8443`) is supported. |
| `port` | number | no | Override the port. Inline port in `target` takes precedence over this field. Defaults to `443`. |

**Target validation rules**
- Must be a public hostname or public IPv4/IPv6 literal
- Max 253 characters
- Private, loopback, link-local, CGNAT, and reserved IPs are rejected (SSRF protection)
- Private TLDs are rejected: `.local`, `.internal`, `.lan`, `.home`, `.corp`, `localhost`
- IPv6 literals are not supported in v1

**Response `200`**

```json
{
  "target": {
    "domain": "koleenbp.com",
    "ip_address": null,
    "port": 443,
    "scanned_at": "2026-05-28T10:33:18.708768848+00:00",
    "scan_duration_ms": 26
  },
  "risk_score": {
    "value": 50,
    "level": "Medium",
    "summary": "koleenbp.com scored 50/100 (Medium) on the RonwayScanner post-quantum assessment. Plan a post-quantum migration within the next 6 months.",
    "harvest_risk": false
  },
  "quantum_ready": false,
  "summary": "koleenbp.com scored 50/100 (Medium) on the RonwayScanner post-quantum assessment. Plan a post-quantum migration within the next 6 months.",
  "tls": {
    "protocol_version": "TLSv1.3",
    "protocol_vulnerable": false,
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "cipher_vulnerable": false,
    "key_exchange": "X25519",
    "key_exchange_vulnerable": false,
    "compression": "NULL",
    "compression_vulnerable": false
  },
  "certificate": {
    "subject": "CN=koleenbp.com",
    "issuer": "C=US, O=Let's Encrypt, CN=R12",
    "key_algorithm": "RSA 2048-bit",
    "key_algorithm_vulnerable": true,
    "signature_algorithm": "sha256WithRSAEncryption",
    "signature_algorithm_vulnerable": true,
    "valid_from": "2026-04-22T15:40:23+00:00",
    "valid_until": "2026-07-21T15:40:22+00:00",
    "days_remaining": 54,
    "is_expired": false,
    "is_self_signed": false,
    "ct_logged": true
  },
  "http": {
    "hsts_enabled": true,
    "hsts_max_age": 63072000,
    "csp_present": false,
    "x_frame_options": null,
    "server_header": "Vercel"
  },
  "vulnerabilities": [
    {
      "id": "RSA_CERTIFICATE",
      "title": "RSA certificate detected (RSA 2048-bit)",
      "description": "RSA certificates are broken by Shor's Algorithm on a sufficiently large quantum computer. Plan migration to ML-DSA-65.",
      "severity": "High",
      "nist_reference": "NIST FIPS 204 (ML-DSA)",
      "cvss_equivalent": 7.4
    },
    {
      "id": "RSA_SIGNATURE",
      "title": "RSA signature algorithm (sha256WithRSAEncryption)",
      "description": "RSA quantum vulnerable via Shor's Algorithm",
      "severity": "High",
      "nist_reference": "NIST FIPS 204 (ML-DSA)",
      "cvss_equivalent": 7.4
    }
  ],
  "recommended_actions": [
    "Replace RSA certificate with ML-DSA-65 certificate"
  ],
  "additional_recommendations": 0,
  "upgrade": {
    "message": "Full PQC migration roadmap — exact configurations, rollout sequencing, and effort estimates — is delivered via a BPxAI engagement.",
    "url": "https://bpxai.com/quantum"
  }
}
```

**Response field reference**

| Field | Type | Notes |
|-------|------|-------|
| `target.domain` | string | Normalized hostname or IP |
| `target.ip_address` | string \| null | Resolved IPv4/v6 address, or `null` if resolution was skipped |
| `target.port` | number | Port that was scanned |
| `target.scanned_at` | string (ISO 8601) | Timestamp with timezone offset |
| `target.scan_duration_ms` | number | Wall-clock milliseconds for the full scan |
| `risk_score.value` | number | 0–100 additive penalty score |
| `risk_score.level` | string | `Pass` / `Low` / `Medium` / `High` / `Critical` / `Incomplete` |
| `risk_score.harvest_risk` | boolean | `true` when RSA, ECDH, ECDHE, or DH key exchange is detected (store-now-decrypt-later threat) |
| `quantum_ready` | boolean | `true` only when score is 0 and no vulnerable algorithms were found |
| `tls` | object \| null | `null` if the TLS handshake failed entirely |
| `certificate` | object \| null | `null` if the certificate could not be parsed |
| `http` | object \| null | `null` if the HTTP probe failed |
| `http.x_frame_options` | string \| null | Header value, or `null` if absent |
| `http.server_header` | string \| null | Server banner, or `null` if not sent |
| `vulnerabilities` | array | Full finding list — all severities included |
| `recommended_actions` | array | Up to 3 de-duplicated action headlines (free tier) |
| `additional_recommendations` | number | Count of additional actions not shown in the free tier |
| `upgrade.url` | string | BPxAI engagement page for the full remediation roadmap |

**Error responses**

| Status | `error` code | Reason |
|--------|-------------|--------|
| `400` | `invalid_target` | Empty, private/loopback/reserved IP, unsupported IPv6 literal, or malformed hostname |
| `429` | `rate_limited` | More than 10 requests/min from this IP |
| `504` | `scan_timeout` | Scan exceeded the 30-second limit |
| `500` | `internal_error` | Server fault |

```json
{
  "error": "invalid_target",
  "message": "target 192.168.1.1 is a private / reserved address"
}
```

**Example curl**

```bash
curl -X POST https://ronway-api.bpxai.com/api/scan \
  -H 'Content-Type: application/json' \
  -d '{ "target": "example.com" }'
```

---

## GET /api/scans

Returns all scan history, newest first.

**Query parameters**

| Param | Type | Default | Max | Description |
|-------|------|---------|-----|-------------|
| `limit` | number | 50 | 500 | Rows to return |
| `offset` | number | 0 | — | Rows to skip (pagination) |

**Response `200`**

```json
[
  {
    "id": 42,
    "scanned_at": "2026-05-28T10:33:18+00:00",
    "target_domain": "koleenbp.com",
    "target_port": 443,
    "risk_score": 50,
    "risk_level": "Medium",
    "harvest_risk": false,
    "quantum_ready": false,
    "vulnerability_count": 2,
    "created_at": "2026-05-28T10:33:19+00:00"
  }
]
```

**Example curl**

```bash
curl 'https://ronway-api.bpxai.com/api/scans?limit=20&offset=0'
```

---

## GET /api/scans/:domain

Returns scan history for a single domain, newest first.

**Path parameter**

| Param | Description |
|-------|-------------|
| `domain` | The exact domain to filter by (e.g. `example.com`) |

**Query parameters**

| Param | Type | Default | Max | Description |
|-------|------|---------|-----|-------------|
| `limit` | number | 50 | 500 | Rows to return |

**Response `200`** — same shape as `GET /api/scans`

**Example curl**

```bash
curl 'https://ronway-api.bpxai.com/api/scans/koleenbp.com'
```

---

## GET /api/sites

Per-site rollup ordered by scan count descending. Useful for a dashboard showing which domains have been scanned most and their latest risk posture.

**Query parameters**

| Param | Type | Default | Max | Description |
|-------|------|---------|-----|-------------|
| `limit` | number | 50 | 500 | Sites to return |

**Response `200`**

```json
[
  {
    "target_domain": "koleenbp.com",
    "scan_count": 3,
    "first_scanned": "2026-05-01T08:00:00+00:00",
    "last_scanned": "2026-05-28T10:33:18+00:00",
    "latest_risk_score": 50,
    "latest_risk_level": "Medium"
  }
]
```

**Example curl**

```bash
curl 'https://ronway-api.bpxai.com/api/sites?limit=10'
```

---

## Risk levels

| Level | Score range | Meaning |
|-------|-------------|---------|
| `Pass` | 0–9 | No significant quantum risk detected |
| `Low` | 10–29 | Minor issues, low urgency |
| `Medium` | 30–59 | Addressable within normal upgrade cycles |
| `High` | 60–79 | Prioritise remediation |
| `Critical` | 80–100 | Immediate action required |
| `Incomplete` | — | Scan could not complete one or more checks |

`harvest_risk: true` means RSA, ECDH, ECDHE, or DH key exchange was detected — the target is vulnerable to store-now-decrypt-later attacks where ciphertext captured today can be decrypted once a cryptographically relevant quantum computer exists.

---

## NIST PQC migration targets

| Vulnerable algorithm | Replace with | Standard |
|---------------------|-------------|----------|
| RSA / ECDHE key exchange | X25519MLKEM768 hybrid | FIPS 203 (ML-KEM) |
| RSA certificate | ML-DSA-65 | FIPS 204 (ML-DSA) |
| ECDSA certificate | ML-DSA-65 | FIPS 204 (ML-DSA) |
| AES-CBC | AES-256-GCM or ChaCha20-Poly1305 | NIST SP 800-38D |
