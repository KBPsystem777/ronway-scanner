//! Phase 9 integration: drive RonwayScanner::scan against an in-process
//! HTTPS server with a self-signed ECDSA cert and assert the full pipeline
//! returns a coherent ScanReport.

use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use ronway_scanner::models::risk::RiskLevel;
use ronway_scanner::RonwayScanner;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Spin up a server that:
/// - serves a self-signed ECDSA P-256 cert (Phase 7 will flag it ECDSA +
///   self-signed)
/// - answers any request with a 200 that *does* set HSTS
async fn spawn_server() -> u16 {
    ensure_crypto_provider();

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(30);
    let cert = params.self_signed(&key).unwrap();
    let cert_der: Vec<u8> = cert.der().to_vec();
    let key_der = key.serialize_der();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // The orchestrator does TWO connections in parallel — one for TLS scan,
    // one for HTTP — so loop and serve each.
    tokio::spawn(async move {
        for _ in 0..4 {
            let (tcp, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let response = "HTTP/1.1 200 OK\r\n\
                                    Strict-Transport-Security: max-age=31536000\r\n\
                                    Server: ronway-test/0.1\r\n\
                                    Content-Length: 2\r\n\
                                    Connection: close\r\n\
                                    \r\n\
                                    ok";
                    let _ = tls.write_all(response.as_bytes()).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });

    port
}

#[tokio::test]
async fn full_scan_pipeline_against_local_https_server() {
    let port = spawn_server().await;

    let report = RonwayScanner::scan_with_port("127.0.0.1", port).await;

    // Target metadata
    assert_eq!(report.target.domain, "127.0.0.1");
    assert_eq!(report.target.port, port);
    assert!(report.target.scan_duration_ms < 30_000);

    // TLS scan succeeded
    let tls = report.tls.as_ref().expect("TLS finding");
    assert_eq!(tls.protocol_version, "TLSv1.3");
    assert!(!tls.protocol_vulnerable);

    // Cert was extracted from the same handshake
    let cert = report.certificate.as_ref().expect("cert finding");
    assert!(cert.is_self_signed);
    assert_eq!(cert.signature_algorithm, "ecdsa-with-SHA256");

    // HTTP scan worked
    let http = report.http.as_ref().expect("HTTP finding");
    assert!(http.hsts_enabled);
    assert_eq!(http.hsts_max_age, Some(31_536_000));

    // Classifier picked up the self-signed + ECDSA vulnerabilities
    let ids: Vec<&str> = report
        .vulnerabilities
        .iter()
        .map(|v| v.id.as_str())
        .collect();
    assert!(ids.contains(&"CERT_SELF_SIGNED"), "ids = {:?}", ids);
    assert!(ids.contains(&"ECDSA_CERTIFICATE"), "ids = {:?}", ids);
    assert!(ids.contains(&"ECDSA_SIGNATURE"), "ids = {:?}", ids);

    // Recommendations are sorted by priority asc and non-empty
    assert!(!report.recommendations.is_empty());
    let priorities: Vec<u8> = report.recommendations.iter().map(|r| r.priority).collect();
    let mut sorted = priorities.clone();
    sorted.sort();
    assert_eq!(priorities, sorted);

    // Score sanity
    assert!(report.risk_score.value > 0);
    assert!(report.summary.contains("127.0.0.1"));
    assert!(!report.quantum_ready, "ECDSA cert is not PQC-safe");
}

#[tokio::test]
async fn scan_against_unreachable_host_is_not_graded() {
    let report = RonwayScanner::scan_with_port("127.0.0.1", 1).await;

    assert!(report.tls.is_none());
    assert!(report.certificate.is_none());
    assert!(report.http.is_none());
    assert!(report.is_unreachable());

    // A scan that never connected is an operational failure, not a
    // vulnerability — it must not be graded as a risk score.
    assert!(
        report.vulnerabilities.is_empty(),
        "unreachable scan should produce no vulnerabilities, got {:?}",
        report
            .vulnerabilities
            .iter()
            .map(|v| v.id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(report.risk_score.value, 0);
    assert_eq!(report.risk_score.level, RiskLevel::Unknown);
    assert!(!report.risk_score.harvest_risk);
    assert!(!report.quantum_ready);
}
