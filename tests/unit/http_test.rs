//! Phase 8 integration tests.
//!
//! Spin up an in-process HTTPS server with a self-signed cert that emits a
//! controlled set of response headers, then assert `HttpScanner::scan`
//! extracts them faithfully. The scanner's `danger_accept_invalid_certs`
//! flag is what allows the self-signed cert to work here.

use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use ronway_scanner::scanner::http::HttpScanner;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Spin up a one-shot HTTPS server on 127.0.0.1 that always answers with
/// the given response (including the headers under test) and exits.
async fn spawn_https_server(response: &'static str) -> u16 {
    ensure_crypto_provider();

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
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

    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                // Read just enough of the request to keep the client happy,
                // then write the canned response and close.
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            }
        }
    });

    port
}

#[tokio::test]
async fn extracts_all_security_headers() {
    let response = "HTTP/1.1 200 OK\r\n\
                    Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n\
                    Content-Security-Policy: default-src 'self'\r\n\
                    X-Frame-Options: DENY\r\n\
                    Server: nginx/1.25.3\r\n\
                    Content-Length: 2\r\n\
                    Connection: close\r\n\
                    \r\n\
                    ok";

    let port = spawn_https_server(response).await;
    let finding = HttpScanner::scan("127.0.0.1", port).await.unwrap();

    assert!(finding.hsts_enabled);
    assert_eq!(finding.hsts_max_age, Some(63_072_000));
    assert!(finding.csp_present);
    assert_eq!(finding.x_frame_options.as_deref(), Some("DENY"));
    assert_eq!(finding.server_header.as_deref(), Some("nginx/1.25.3"));
}

#[tokio::test]
async fn reports_missing_security_headers() {
    let response = "HTTP/1.1 200 OK\r\n\
                    Content-Length: 2\r\n\
                    Connection: close\r\n\
                    \r\n\
                    ok";

    let port = spawn_https_server(response).await;
    let finding = HttpScanner::scan("127.0.0.1", port).await.unwrap();

    assert!(!finding.hsts_enabled);
    assert!(finding.hsts_max_age.is_none());
    assert!(!finding.csp_present);
    assert!(finding.x_frame_options.is_none());
    assert!(finding.server_header.is_none());
}

#[tokio::test]
async fn unreachable_port_errors() {
    let res = HttpScanner::scan("127.0.0.1", 1).await;
    assert!(res.is_err());
}
