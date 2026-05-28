//! Phase 6: TLS scanner core.
//!
//! Opens a rustls connection to a remote target with a 10-second timeout,
//! extracts the negotiated protocol version / cipher suite / key exchange,
//! and exposes the peer's leaf-certificate DER bytes so `CertScanner`
//! (Phase 7) can analyse the same handshake without a second connection.
//!
//! Certificate verification is intentionally bypassed — the scanner exists
//! to *find* expired or self-signed certs, so the handshake must succeed
//! against deliberately broken targets. Trust decisions are reported via
//! the `CertFinding` instead.

use std::sync::{Arc, Once};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, NamedGroup, ProtocolVersion,
    SignatureScheme, SupportedCipherSuite,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::classifier::algorithms::AlgorithmClassifier;
use crate::models::finding::TlsFinding;

pub const DEFAULT_PORT: u16 = 443;
pub const TIMEOUT_SECS: u64 = 10;

#[derive(Debug, thiserror::Error)]
pub enum TlsScanError {
    #[error("connection to {host}:{port} timed out after {secs}s")]
    Timeout { host: String, port: u16, secs: u64 },

    #[error("invalid hostname for SNI: {0}")]
    InvalidHostname(String),

    #[error("TCP connect to {host}:{port} failed: {source}")]
    TcpConnect {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },

    #[error("TLS handshake with {host}:{port} failed: {source}")]
    Handshake {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct TlsScanResult {
    pub finding: TlsFinding,
    pub peer_cert_der: Option<Vec<u8>>,
}

pub struct TlsScanner;

impl TlsScanner {
    pub async fn scan(host: &str, port: u16) -> Result<TlsScanResult, TlsScanError> {
        ensure_crypto_provider();

        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| TlsScanError::InvalidHostname(host.to_string()))?;

        let timeout = Duration::from_secs(TIMEOUT_SECS);

        let tcp = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| TlsScanError::Timeout {
                host: host.to_string(),
                port,
                secs: TIMEOUT_SECS,
            })?
            .map_err(|source| TlsScanError::TcpConnect {
                host: host.to_string(),
                port,
                source,
            })?;

        let config = build_permissive_client_config();
        let connector = TlsConnector::from(Arc::new(config));

        let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
            .await
            .map_err(|_| TlsScanError::Timeout {
                host: host.to_string(),
                port,
                secs: TIMEOUT_SECS,
            })?
            .map_err(|source| TlsScanError::Handshake {
                host: host.to_string(),
                port,
                source,
            })?;

        let (_, conn) = tls.get_ref();
        Ok(inspect_connection(conn))
    }
}

fn inspect_connection(conn: &ClientConnection) -> TlsScanResult {
    let protocol_version = format_protocol_version(conn.protocol_version());
    let protocol_vulnerable = AlgorithmClassifier::is_tls_version_vulnerable(&protocol_version);

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(cipher_suite_name)
        .unwrap_or_else(|| "unknown".to_string());
    let (cipher_vulnerable, _) = AlgorithmClassifier::is_cipher_suite_vulnerable(&cipher_suite);

    let key_exchange = conn
        .negotiated_key_exchange_group()
        .map(|g| kx_group_name(g.name()))
        .unwrap_or_else(|| derive_kx_from_cipher(&cipher_suite));
    let (key_exchange_vulnerable, _) =
        AlgorithmClassifier::is_key_exchange_vulnerable(&key_exchange);

    let peer_cert_der = conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|cert| cert.as_ref().to_vec());

    let finding = TlsFinding {
        protocol_version,
        protocol_vulnerable,
        cipher_suite,
        cipher_vulnerable,
        key_exchange,
        key_exchange_vulnerable,
        compression: "NULL".to_string(),
        compression_vulnerable: false,
    };

    TlsScanResult {
        finding,
        peer_cert_der,
    }
}

fn format_protocol_version(v: Option<ProtocolVersion>) -> String {
    match v {
        Some(ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
        Some(ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
        Some(ProtocolVersion::TLSv1_1) => "TLSv1.1".to_string(),
        Some(ProtocolVersion::TLSv1_0) => "TLSv1.0".to_string(),
        Some(ProtocolVersion::SSLv3) => "SSLv3".to_string(),
        Some(ProtocolVersion::SSLv2) => "SSLv2".to_string(),
        Some(other) => format!("{:?}", other),
        None => "unknown".to_string(),
    }
}

fn cipher_suite_name(suite: SupportedCipherSuite) -> String {
    let cs = suite.suite();
    let raw = cs
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| format!("{:?}", cs));
    // rustls names its TLS 1.3 suites `TLS13_AES_128_GCM_SHA256` etc.,
    // but the IANA registry calls them `TLS_AES_128_GCM_SHA256`. Reports
    // and CVE lookups expect the IANA form, so normalise here.
    if let Some(rest) = raw.strip_prefix("TLS13_") {
        format!("TLS_{}", rest)
    } else {
        raw
    }
}

fn kx_group_name(group: NamedGroup) -> String {
    match group {
        NamedGroup::X25519 => "X25519".to_string(),
        NamedGroup::secp256r1 | NamedGroup::secp384r1 | NamedGroup::secp521r1 => {
            "ECDHE".to_string()
        }
        NamedGroup::FFDHE2048
        | NamedGroup::FFDHE3072
        | NamedGroup::FFDHE4096
        | NamedGroup::FFDHE6144
        | NamedGroup::FFDHE8192 => "DHE".to_string(),
        NamedGroup::X25519MLKEM768 => "X25519MLKEM768".to_string(),
        NamedGroup::secp256r1MLKEM768 => "secp256r1MLKEM768".to_string(),
        other => other
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| format!("{:?}", other)),
    }
}

fn derive_kx_from_cipher(cipher: &str) -> String {
    let u = cipher.to_ascii_uppercase();
    if u.contains("ECDHE") {
        "ECDHE".to_string()
    } else if u.contains("ECDH_") {
        "ECDH".to_string()
    } else if u.contains("DHE") {
        "DHE".to_string()
    } else if u.contains("_DH_") {
        "DH".to_string()
    } else if u.starts_with("TLS_RSA") {
        "RSA".to_string()
    } else {
        "unknown".to_string()
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn build_permissive_client_config() -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

static CRYPTO_INIT: Once = Once::new();

fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_protocol_version_known_versions() {
        assert_eq!(
            format_protocol_version(Some(ProtocolVersion::TLSv1_3)),
            "TLSv1.3"
        );
        assert_eq!(
            format_protocol_version(Some(ProtocolVersion::TLSv1_2)),
            "TLSv1.2"
        );
        assert_eq!(
            format_protocol_version(Some(ProtocolVersion::TLSv1_0)),
            "TLSv1.0"
        );
        assert_eq!(
            format_protocol_version(Some(ProtocolVersion::SSLv3)),
            "SSLv3"
        );
    }

    #[test]
    fn format_protocol_version_none_is_unknown() {
        assert_eq!(format_protocol_version(None), "unknown");
    }

    #[test]
    fn derive_kx_recognises_ecdhe() {
        assert_eq!(
            derive_kx_from_cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            "ECDHE"
        );
    }

    #[test]
    fn derive_kx_recognises_dhe() {
        assert_eq!(
            derive_kx_from_cipher("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
            "DHE"
        );
    }

    #[test]
    fn derive_kx_recognises_rsa_only() {
        assert_eq!(derive_kx_from_cipher("TLS_RSA_WITH_AES_128_CBC_SHA"), "RSA");
    }

    #[test]
    fn derive_kx_unknown_for_tls13_cipher_names() {
        assert_eq!(derive_kx_from_cipher("TLS_AES_256_GCM_SHA384"), "unknown");
        assert_eq!(
            derive_kx_from_cipher("TLS_CHACHA20_POLY1305_SHA256"),
            "unknown"
        );
    }

    #[test]
    fn kx_group_x25519_classifies_as_safe() {
        let name = kx_group_name(NamedGroup::X25519);
        assert_eq!(name, "X25519");
        let (vuln, _) = AlgorithmClassifier::is_key_exchange_vulnerable(&name);
        assert!(!vuln);
    }

    #[test]
    fn kx_group_p256_classifies_as_ecdhe_vulnerable() {
        let name = kx_group_name(NamedGroup::secp256r1);
        assert_eq!(name, "ECDHE");
        let (vuln, _) = AlgorithmClassifier::is_key_exchange_vulnerable(&name);
        assert!(vuln);
    }

    #[test]
    fn kx_group_ffdhe_classifies_as_dhe_vulnerable() {
        let name = kx_group_name(NamedGroup::FFDHE2048);
        assert_eq!(name, "DHE");
        let (vuln, _) = AlgorithmClassifier::is_key_exchange_vulnerable(&name);
        assert!(vuln);
    }

    #[test]
    fn kx_group_pq_hybrid_classifies_as_safe() {
        let name = kx_group_name(NamedGroup::X25519MLKEM768);
        assert_eq!(name, "X25519MLKEM768");
        let (vuln, _) = AlgorithmClassifier::is_key_exchange_vulnerable(&name);
        assert!(!vuln);
    }

    #[tokio::test]
    async fn scan_invalid_hostname_returns_error() {
        let res = TlsScanner::scan("invalid hostname with spaces", 443).await;
        assert!(matches!(res, Err(TlsScanError::InvalidHostname(_))));
    }
}
