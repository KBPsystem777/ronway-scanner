//! Phase 6/7 integration: spin up an in-process rustls server and confirm
//! `TlsScanner::scan` returns a populated finding + peer cert DER that
//! `CertScanner::parse_der` can consume.

use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use ronway_scanner::scanner::cert::CertScanner;
use ronway_scanner::scanner::tls::{TlsScanError, TlsScanner};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn spawn_localhost_tls_server() -> (u16, Vec<u8>) {
    ensure_crypto_provider();

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("CertificateParams::new");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(30);
    let cert = params.self_signed(&key).expect("self_signed");
    let cert_der: Vec<u8> = cert.der().to_vec();
    let key_der_bytes = key.serialize_der();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes)),
        )
        .expect("server config");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = [0u8; 16];
                let _ = tls.read(&mut buf).await;
            }
        }
    });

    (port, cert_der)
}

#[tokio::test]
async fn scans_local_tls_server_and_extracts_finding() {
    let (port, expected_cert_der) = spawn_localhost_tls_server().await;

    let result = TlsScanner::scan("127.0.0.1", port)
        .await
        .expect("scan should succeed");

    let finding = &result.finding;

    assert_eq!(finding.protocol_version, "TLSv1.3");
    assert!(!finding.protocol_vulnerable);
    assert!(
        finding.cipher_suite.starts_with("TLS_AES_")
            || finding.cipher_suite.starts_with("TLS_CHACHA20_"),
        "expected a TLS 1.3 AEAD cipher suite, got {}",
        finding.cipher_suite
    );
    assert!(!finding.cipher_vulnerable);
    assert!(matches!(
        finding.key_exchange.as_str(),
        "X25519" | "X25519MLKEM768" | "ECDHE"
    ));
    assert_eq!(finding.compression, "NULL");

    let peer = result.peer_cert_der.expect("peer cert DER present");
    assert_eq!(peer, expected_cert_der);
}

#[tokio::test]
async fn cert_scanner_consumes_tls_scanner_output() {
    let (port, _) = spawn_localhost_tls_server().await;

    let tls_result = TlsScanner::scan("127.0.0.1", port).await.unwrap();
    let peer_der = tls_result.peer_cert_der.expect("DER from TLS handshake");

    let cert_finding = CertScanner::parse_der(&peer_der).expect("cert parse");
    assert!(cert_finding.subject.contains("localhost"));
    assert_eq!(cert_finding.signature_algorithm, "ecdsa-with-SHA256");
    assert!(cert_finding.is_self_signed);
    assert!(!cert_finding.is_expired);
}

#[tokio::test]
async fn scan_to_unreachable_port_errors_cleanly() {
    let res = TlsScanner::scan("127.0.0.1", 1).await;
    assert!(matches!(res, Err(TlsScanError::TcpConnect { .. })));
}

#[tokio::test]
async fn scan_with_invalid_hostname_returns_invalid_hostname_error() {
    let res = TlsScanner::scan("has spaces in it", 443).await;
    assert!(matches!(res, Err(TlsScanError::InvalidHostname(_))));
}
