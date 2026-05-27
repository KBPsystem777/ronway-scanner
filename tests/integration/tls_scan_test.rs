use ronway_scanner::scanner::tls::TlsScanner;

#[tokio::test]
#[ignore = "makes real network connection; run with `cargo test -- --ignored`"]
async fn example_com_returns_finding() {
    let finding = TlsScanner::scan("example.com", 443)
        .await
        .expect("TLS scan should succeed against example.com");

    assert!(
        finding.protocol_version.starts_with("TLSv1."),
        "expected TLS version, got {}",
        finding.protocol_version
    );
    assert!(
        !finding.cipher_suite.is_empty(),
        "cipher suite must be populated"
    );
    assert!(
        !finding.key_exchange.is_empty(),
        "key exchange must be populated"
    );
}

#[tokio::test]
#[ignore = "makes real network connection; run with `cargo test -- --ignored`"]
async fn unreachable_port_errors_cleanly() {
    let result = TlsScanner::scan("example.com", 1).await;
    assert!(result.is_err(), "scanning a closed port should error");
}
