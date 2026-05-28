//! RonwayScanner — post-quantum TLS / certificate / HTTP vulnerability scanner.
//!
//! The library entry point is [`RonwayScanner::scan`], which fires the TLS
//! and HTTP probes concurrently, derives the certificate finding from the
//! TLS handshake's peer DER, classifies everything against NIST PQC
//! guidance, scores it, and assembles a [`ScanReport`].

pub mod classifier;
pub mod models;
pub mod report;
pub mod scanner;
pub mod server;
pub mod store;

use std::time::Instant;

use chrono::Utc;
use tracing::{debug, warn};

use crate::classifier::algorithms::VulnerabilityDatabase;
use crate::classifier::recommendations::RecommendationEngine;
use crate::classifier::scoring::RiskScorer;
use crate::models::finding::{CertFinding, HttpFinding, TlsFinding};
use crate::models::report::{ScanReport, ScanTarget};
use crate::models::risk::RiskLevel;
use crate::scanner::cert::CertScanner;
use crate::scanner::http::HttpScanner;
use crate::scanner::tls::{TlsScanError, TlsScanner};

/// Default TLS port. Phase 9 supports remote HTTPS scanning only.
pub const DEFAULT_PORT: u16 = 443;

/// Top-level orchestrator. The struct is a marker — all behaviour lives in
/// the associated `scan` function.
pub struct RonwayScanner;

impl RonwayScanner {
    /// Scan `target` on the default HTTPS port (443).
    pub async fn scan(target: &str) -> ScanReport {
        Self::scan_with_port(target, DEFAULT_PORT).await
    }

    /// Scan `target:port`. Always returns a `ScanReport` — individual
    /// scanner failures are recorded as `None` fields and surfaced as
    /// `TLS_SCAN_FAILED` / `CERT_SCAN_FAILED` sentinels in the vuln list.
    pub async fn scan_with_port(target: &str, port: u16) -> ScanReport {
        let started_at = Utc::now();
        let timer = Instant::now();

        let (tls_outcome, http_finding) =
            tokio::join!(TlsScanner::scan(target, port), run_http_scan(target, port),);

        let (tls_finding, cert_finding) = split_tls_outcome(tls_outcome);

        let vulnerabilities = VulnerabilityDatabase::build_vulnerabilities(
            tls_finding.as_ref(),
            cert_finding.as_ref(),
            http_finding.as_ref(),
        );

        let mut risk_score = RiskScorer::calculate(&vulnerabilities);
        if tls_finding.is_none() && cert_finding.is_none() && http_finding.is_none() {
            // Nothing answered — this is an operational failure, not a
            // security grade. Mark it Unknown so it can never be read as a
            // passing posture, and explain why.
            risk_score.value = 0;
            risk_score.level = RiskLevel::Unknown;
            risk_score.harvest_risk = false;
            risk_score.summary = format!(
                "RonwayScanner could not reach {target} on port {port}, so its \
                 post-quantum posture could not be assessed. Confirm the host is \
                 online and serving TLS on that port, then re-scan."
            );
        } else {
            // The per-vuln-count summary is fine for logs, but reports prefer
            // the executive narrative that includes the target name.
            risk_score.summary = RiskScorer::generate_summary(&risk_score, target);
        }

        let recommendations = RecommendationEngine::generate(&vulnerabilities);
        let summary = risk_score.summary.clone();
        let quantum_ready = is_quantum_ready(&tls_finding, &cert_finding);

        let target_record = ScanTarget {
            domain: target.to_string(),
            ip_address: None,
            port,
            scanned_at: started_at.to_rfc3339(),
            scan_duration_ms: timer.elapsed().as_millis() as u64,
        };

        ScanReport {
            target: target_record,
            risk_score,
            tls: tls_finding,
            certificate: cert_finding,
            http: http_finding,
            vulnerabilities,
            recommendations,
            summary,
            quantum_ready,
        }
    }
}

async fn run_http_scan(target: &str, port: u16) -> Option<HttpFinding> {
    match HttpScanner::scan(target, port).await {
        Ok(f) => Some(f),
        Err(e) => {
            warn!("HTTP scan for {}:{} failed: {}", target, port, e);
            None
        }
    }
}

/// Unpack the TLS scan outcome into separate `TlsFinding` and `CertFinding`
/// options. If the TLS handshake failed, both come back `None` and the
/// classifier inserts the appropriate failure sentinels.
fn split_tls_outcome(
    outcome: Result<crate::scanner::tls::TlsScanResult, TlsScanError>,
) -> (Option<TlsFinding>, Option<CertFinding>) {
    match outcome {
        Ok(result) => {
            let cert =
                result
                    .peer_cert_der
                    .as_deref()
                    .and_then(|der| match CertScanner::parse_der(der) {
                        Ok(f) => Some(f),
                        Err(e) => {
                            warn!("certificate parse failed: {}", e);
                            None
                        }
                    });
            (Some(result.finding), cert)
        }
        Err(e) => {
            debug!("TLS scan failed cleanly: {}", e);
            (None, None)
        }
    }
}

/// "Quantum-ready" means TLS 1.3 negotiated, no quantum-vulnerable
/// key exchange / cipher, and (if a cert was retrieved) a PQC-safe key
/// and signature.
fn is_quantum_ready(tls: &Option<TlsFinding>, cert: &Option<CertFinding>) -> bool {
    let Some(tls) = tls.as_ref() else {
        return false;
    };
    if tls.protocol_vulnerable || tls.cipher_vulnerable || tls.key_exchange_vulnerable {
        return false;
    }
    match cert {
        Some(c) => {
            !c.key_algorithm_vulnerable && !c.signature_algorithm_vulnerable && !c.is_expired
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{CertFinding, HttpFinding, TlsFinding};

    fn safe_tls() -> TlsFinding {
        TlsFinding {
            protocol_version: "TLSv1.3".into(),
            protocol_vulnerable: false,
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            cipher_vulnerable: false,
            key_exchange: "X25519MLKEM768".into(),
            key_exchange_vulnerable: false,
            compression: "NULL".into(),
            compression_vulnerable: false,
        }
    }

    fn safe_cert() -> CertFinding {
        CertFinding {
            subject: "CN=safe".into(),
            issuer: "CN=safe-ca".into(),
            key_algorithm: "ML-DSA-65".into(),
            key_algorithm_vulnerable: false,
            signature_algorithm: "id-ML-DSA-65".into(),
            signature_algorithm_vulnerable: false,
            valid_from: "2026-01-01T00:00:00+00:00".into(),
            valid_until: "2027-01-01T00:00:00+00:00".into(),
            days_remaining: 200,
            is_expired: false,
            is_self_signed: false,
            ct_logged: true,
        }
    }

    #[test]
    fn quantum_ready_true_for_pqc_tls_and_cert() {
        assert!(is_quantum_ready(&Some(safe_tls()), &Some(safe_cert())));
    }

    #[test]
    fn quantum_ready_false_when_kx_is_vulnerable() {
        let mut tls = safe_tls();
        tls.key_exchange = "ECDHE".into();
        tls.key_exchange_vulnerable = true;
        assert!(!is_quantum_ready(&Some(tls), &Some(safe_cert())));
    }

    #[test]
    fn quantum_ready_false_when_cert_missing() {
        assert!(!is_quantum_ready(&Some(safe_tls()), &None));
    }

    #[test]
    fn quantum_ready_false_when_tls_missing() {
        assert!(!is_quantum_ready(&None, &Some(safe_cert())));
    }

    #[test]
    fn split_tls_outcome_drops_cert_when_der_unparseable() {
        let result = crate::scanner::tls::TlsScanResult {
            finding: safe_tls(),
            peer_cert_der: Some(b"not-a-real-cert".to_vec()),
        };
        let (tls, cert) = split_tls_outcome(Ok(result));
        assert!(tls.is_some());
        assert!(cert.is_none());
    }

    #[allow(dead_code)]
    fn _http_finding_compiles() -> HttpFinding {
        HttpFinding {
            hsts_enabled: false,
            hsts_max_age: None,
            csp_present: false,
            x_frame_options: None,
            server_header: None,
        }
    }
}
