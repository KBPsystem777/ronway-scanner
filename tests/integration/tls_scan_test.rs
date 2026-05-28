//! Real-world TLS handshake against example.com. `#[ignore]`d so it does
//! not run as part of the standard test suite.

use ronway_scanner::scanner::tls::{TlsScanError, TlsScanner};

#[tokio::test]
#[ignore = "makes real network connection; run with `cargo test -- --ignored`"]
async fn example_com_returns_finding() {
    let result = TlsScanner::scan("example.com", 443)
        .await
        .expect("scan should succeed against example.com");

    let finding = &result.finding;
    assert!(finding.protocol_version.starts_with("TLSv1."));
    assert!(!finding.cipher_suite.is_empty());
    assert!(!finding.key_exchange.is_empty());
    assert!(
        result.peer_cert_der.is_some(),
        "leaf cert DER must be exposed"
    );
}

#[tokio::test]
#[ignore = "makes real network connection; run with `cargo test -- --ignored`"]
async fn unreachable_port_errors_cleanly() {
    let res = TlsScanner::scan("example.com", 1).await;
    assert!(matches!(
        res,
        Err(TlsScanError::TcpConnect { .. } | TlsScanError::Timeout { .. })
    ));
}
