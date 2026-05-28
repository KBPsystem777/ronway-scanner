//! Phase 10: JSON reporter — serialises a `ScanReport` to a stable,
//! pretty-printed JSON document suitable for CI pipelines, dashboards,
//! and machine-to-machine ingestion.

use anyhow::{Context, Result};

use crate::models::report::ScanReport;

pub struct JsonReporter;

impl JsonReporter {
    pub fn render(report: &ScanReport) -> Result<String> {
        serde_json::to_string_pretty(report).context("failed to serialise ScanReport to JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{
        CertFinding, HttpFinding, Recommendation, TlsFinding, Vulnerability,
    };
    use crate::models::report::{ScanReport, ScanTarget};
    use crate::models::risk::{RiskLevel, RiskScore};

    fn sample_report() -> ScanReport {
        ScanReport {
            target: ScanTarget {
                domain: "example.com".into(),
                ip_address: Some("93.184.216.34".into()),
                port: 443,
                scanned_at: "2026-05-28T12:00:00+00:00".into(),
                scan_duration_ms: 1234,
            },
            risk_score: RiskScore {
                value: 50,
                level: RiskLevel::Medium,
                summary: "test summary".into(),
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
                subject: "CN=example.com".into(),
                issuer: "CN=Let's Encrypt".into(),
                key_algorithm: "RSA 2048-bit".into(),
                key_algorithm_vulnerable: true,
                signature_algorithm: "sha256WithRSAEncryption".into(),
                signature_algorithm_vulnerable: true,
                valid_from: "2026-01-01T00:00:00+00:00".into(),
                valid_until: "2026-12-31T00:00:00+00:00".into(),
                days_remaining: 200,
                is_expired: false,
                is_self_signed: false,
                ct_logged: true,
            }),
            http: Some(HttpFinding {
                hsts_enabled: false,
                hsts_max_age: None,
                csp_present: false,
                x_frame_options: None,
                server_header: Some("nginx/1.25.3".into()),
            }),
            vulnerabilities: vec![Vulnerability {
                id: "ECDHE_KEY_EXCHANGE".into(),
                title: "ECDHE key exchange".into(),
                description: "vulnerable to Shor".into(),
                severity: RiskLevel::Critical,
                nist_reference: "FIPS 203".into(),
                cvss_equivalent: 8.1,
            }],
            recommendations: vec![Recommendation {
                priority: 1,
                action: "Switch to ML-KEM-768 hybrid".into(),
                current: "ECDHE".into(),
                replace_with: "X25519MLKEM768".into(),
                effort_weeks: 2,
                nist_algorithm: "ML-KEM-768".into(),
            }],
            summary: "test summary".into(),
            quantum_ready: false,
        }
    }

    #[test]
    fn render_produces_valid_json() {
        let json = JsonReporter::render(&sample_report()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["target"]["domain"], "example.com");
        assert_eq!(parsed["risk_score"]["value"], 50);
        assert_eq!(parsed["vulnerabilities"][0]["id"], "ECDHE_KEY_EXCHANGE");
    }

    #[test]
    fn render_is_pretty_printed() {
        let json = JsonReporter::render(&sample_report()).unwrap();
        assert!(json.contains('\n'));
        assert!(json.contains("  "));
    }
}
