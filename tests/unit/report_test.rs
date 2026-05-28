//! Phase 10 end-to-end tests: build a representative ScanReport, push it
//! through each reporter, and assert the output is well-formed.

use ronway_scanner::models::finding::{
    CertFinding, HttpFinding, Recommendation, TlsFinding, Vulnerability,
};
use ronway_scanner::models::report::{ScanReport, ScanTarget};
use ronway_scanner::models::risk::{RiskLevel, RiskScore};
use ronway_scanner::report::html::HtmlReporter;
use ronway_scanner::report::json::JsonReporter;
use ronway_scanner::report::pdf::PdfReporter;

fn sample_report() -> ScanReport {
    ScanReport {
        target: ScanTarget {
            domain: "bsp.gov.ph".into(),
            ip_address: Some("203.0.113.10".into()),
            port: 443,
            scanned_at: "2026-05-28T08:00:00+00:00".into(),
            scan_duration_ms: 482,
        },
        risk_score: RiskScore {
            value: 78,
            level: RiskLevel::High,
            summary: "bsp.gov.ph scored 78/100 (High) on the RonwayScanner post-quantum \
                      assessment. A quantum-vulnerable key exchange was detected, meaning \
                      past encrypted sessions are at risk of future decryption."
                .into(),
            harvest_risk: true,
        },
        tls: Some(TlsFinding {
            protocol_version: "TLSv1.3".into(),
            protocol_vulnerable: false,
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            cipher_vulnerable: false,
            key_exchange: "ECDHE".into(),
            key_exchange_vulnerable: true,
            compression: "NULL".into(),
            compression_vulnerable: false,
        }),
        certificate: Some(CertFinding {
            subject: "CN=bsp.gov.ph".into(),
            issuer: "CN=DigiCert TLS RSA SHA256 2020 CA1".into(),
            key_algorithm: "RSA 2048-bit".into(),
            key_algorithm_vulnerable: true,
            signature_algorithm: "sha256WithRSAEncryption".into(),
            signature_algorithm_vulnerable: true,
            valid_from: "2026-01-15T00:00:00+00:00".into(),
            valid_until: "2027-02-14T23:59:59+00:00".into(),
            days_remaining: 262,
            is_expired: false,
            is_self_signed: false,
            ct_logged: true,
        }),
        http: Some(HttpFinding {
            hsts_enabled: false,
            hsts_max_age: None,
            csp_present: false,
            x_frame_options: Some("SAMEORIGIN".into()),
            server_header: Some("nginx/1.25.3".into()),
        }),
        vulnerabilities: vec![
            Vulnerability {
                id: "ECDHE_KEY_EXCHANGE".into(),
                title: "Quantum-vulnerable key exchange: ECDHE".into(),
                description: "Elliptic curve discrete log is solved by Shor's Algorithm. \
                              Encrypted traffic is exposed to harvest-now-decrypt-later."
                    .into(),
                severity: RiskLevel::Critical,
                nist_reference: "NIST FIPS 203 (ML-KEM)".into(),
                cvss_equivalent: 8.1,
            },
            Vulnerability {
                id: "RSA_CERTIFICATE".into(),
                title: "RSA certificate detected (RSA 2048-bit)".into(),
                description: "RSA certificates are broken by Shor's Algorithm.".into(),
                severity: RiskLevel::High,
                nist_reference: "NIST FIPS 204 (ML-DSA)".into(),
                cvss_equivalent: 7.4,
            },
            Vulnerability {
                id: "NO_HSTS".into(),
                title: "HSTS not enabled".into(),
                description: "Strict-Transport-Security header is missing.".into(),
                severity: RiskLevel::Low,
                nist_reference: "RFC 6797".into(),
                cvss_equivalent: 3.7,
            },
        ],
        recommendations: vec![
            Recommendation {
                priority: 1,
                action: "Add ML-KEM-768 hybrid alongside ECDHE".into(),
                current: "ECDHE only (quantum vulnerable)".into(),
                replace_with: "X25519MLKEM768 hybrid — ML-KEM-768 + X25519".into(),
                effort_weeks: 2,
                nist_algorithm: "ML-KEM-768 (FIPS 203)".into(),
            },
            Recommendation {
                priority: 3,
                action: "Replace RSA certificate with ML-DSA-65".into(),
                current: "RSA-2048 (quantum vulnerable)".into(),
                replace_with: "ML-DSA-65 certificate from PQC-ready CA".into(),
                effort_weeks: 4,
                nist_algorithm: "ML-DSA-65 (FIPS 204)".into(),
            },
        ],
        summary: "bsp.gov.ph scored 78/100 (High).".into(),
        quantum_ready: false,
    }
}

#[test]
fn json_reporter_round_trips_through_serde() {
    let json = JsonReporter::render(&sample_report()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["target"]["domain"], "bsp.gov.ph");
    assert_eq!(parsed["risk_score"]["value"], 78);
    assert_eq!(parsed["vulnerabilities"].as_array().unwrap().len(), 3);
    assert_eq!(parsed["recommendations"][0]["priority"], 1);
}

#[test]
fn html_reporter_includes_key_data_and_no_external_refs() {
    let html = HtmlReporter::render(&sample_report());
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("bsp.gov.ph"));
    assert!(html.contains("78"));
    assert!(html.contains("ECDHE_KEY_EXCHANGE"));
    assert!(html.contains("ML-KEM-768"));
    // self-contained
    assert!(!html.contains("http://"));
    assert!(!html.contains("https://"));
}

#[test]
fn pdf_reporter_writes_a_pdf_to_disk() {
    let tmp = std::env::temp_dir().join("ronway_test_report.pdf");
    let _ = std::fs::remove_file(&tmp);

    PdfReporter::render(&sample_report(), &tmp).expect("PDF render");

    let bytes = std::fs::read(&tmp).expect("read PDF");
    assert!(bytes.starts_with(b"%PDF-"), "missing PDF magic header");
    assert!(
        bytes.len() > 1000,
        "PDF unexpectedly small: {} bytes",
        bytes.len()
    );

    let _ = std::fs::remove_file(&tmp);
}
