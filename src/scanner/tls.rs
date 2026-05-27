use std::io::ErrorKind;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::classifier::algorithms::AlgorithmClassifier;
use crate::models::finding::TlsFinding;

const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TlsScanner;

impl TlsScanner {
    pub async fn scan(host: &str, port: u16) -> Result<TlsFinding> {
        debug!("starting TLS scan for {}:{}", host, port);

        let tls13 = run_attempt(host.to_string(), port, AttemptVersion::Tls13).await;
        let tls12 = run_attempt(host.to_string(), port, AttemptVersion::Tls12).await;

        match (tls13, tls12) {
            (Ok(r13), Ok(_)) => Ok(build_finding(&r13, true)),
            (Ok(r13), Err(e12)) => {
                debug!("TLS 1.2 attempt failed (may be TLS 1.3 only): {}", e12);
                Ok(build_finding(&r13, false))
            }
            (Err(e13), Ok(r12)) => {
                debug!("TLS 1.3 attempt failed, server only offers TLS 1.2: {}", e13);
                Ok(build_finding(&r12, true))
            }
            (Err(e13), Err(e12)) => {
                warn!("both TLS attempts failed (1.3: {} | 1.2: {})", e13, e12);
                Err(e13)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum AttemptVersion {
    Tls13,
    Tls12,
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&TLS13];
static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&TLS12];

impl AttemptVersion {
    fn versions(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match self {
            Self::Tls13 => TLS13_ONLY,
            Self::Tls12 => TLS12_ONLY,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Tls13 => "TLS 1.3",
            Self::Tls12 => "TLS 1.2",
        }
    }
}

struct HandshakeResult {
    protocol_version: String,
    cipher_suite: String,
    key_exchange: String,
}

async fn run_attempt(
    host: String,
    port: u16,
    version: AttemptVersion,
) -> Result<HandshakeResult> {
    let label = version.label();
    let join = tokio::task::spawn_blocking(move || perform_handshake(&host, port, version));

    let inner = timeout(SCAN_TIMEOUT, join)
        .await
        .map_err(|_| anyhow!("{} connection timed out", label))?
        .map_err(|e| anyhow!("{} task failed: {}", label, e))?;

    inner.with_context(|| format!("{} attempt failed", label))
}

fn perform_handshake(
    host: &str,
    port: u16,
    version: AttemptVersion,
) -> Result<HandshakeResult> {
    debug!("attempting {} handshake with {}:{}", version.label(), host, port);

    let provider = ensure_default_provider();
    let verifier = Arc::new(AcceptAnyServerCert {
        provider: provider.clone(),
    });

    let config = ClientConfig::builder_with_protocol_versions(version.versions())
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow!("invalid hostname '{}': {}", host, e))?;

    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .context("failed to construct TLS client")?;

    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| anyhow!("domain not found: {}: {}", host, e))?
        .next()
        .ok_or_else(|| anyhow!("domain not found: {}: no addresses resolved", host))?;

    let mut sock = TcpStream::connect_timeout(&addr, SCAN_TIMEOUT).map_err(|e| match e.kind() {
        ErrorKind::ConnectionRefused => anyhow!("connection refused: {}:{}", host, port),
        ErrorKind::TimedOut => anyhow!("connection timed out: {}:{}", host, port),
        _ => anyhow!("connection failed: {}: {}", host, e),
    })?;
    sock.set_read_timeout(Some(SCAN_TIMEOUT))?;
    sock.set_write_timeout(Some(SCAN_TIMEOUT))?;

    conn.complete_io(&mut sock).map_err(|e| match e.kind() {
        ErrorKind::TimedOut => anyhow!("TLS handshake timed out"),
        _ => anyhow!("TLS handshake failed: {}", e),
    })?;

    let protocol_version = conn
        .protocol_version()
        .map(format_protocol_version)
        .ok_or_else(|| anyhow!("no protocol version negotiated"))?;

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .ok_or_else(|| anyhow!("no cipher suite negotiated"))?;

    let key_exchange = match conn.negotiated_key_exchange_group() {
        Some(g) => named_group_to_kx(&format!("{:?}", g.name())).to_string(),
        None => key_exchange_from_cipher(&cipher_suite).to_string(),
    };

    debug!(
        "{} handshake ok: {} / {} / kx={}",
        version.label(),
        protocol_version,
        cipher_suite,
        key_exchange
    );

    Ok(HandshakeResult {
        protocol_version,
        cipher_suite,
        key_exchange,
    })
}

fn ensure_default_provider() -> Arc<CryptoProvider> {
    if let Some(p) = CryptoProvider::get_default() {
        return p.clone();
    }
    let provider = rustls::crypto::ring::default_provider();
    let _ = provider.install_default();
    CryptoProvider::get_default()
        .expect("crypto provider installed above")
        .clone()
}

fn format_protocol_version(v: rustls::ProtocolVersion) -> String {
    use rustls::ProtocolVersion;
    match v {
        ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        ProtocolVersion::TLSv1_1 => "TLSv1.1".to_string(),
        ProtocolVersion::TLSv1_0 => "TLSv1.0".to_string(),
        ProtocolVersion::SSLv3 => "SSLv3".to_string(),
        ProtocolVersion::SSLv2 => "SSLv2".to_string(),
        other => format!("{:?}", other),
    }
}

fn named_group_to_kx(name: &str) -> &'static str {
    let upper = name.to_ascii_uppercase();
    if upper.contains("MLKEM") {
        "X25519MLKEM768"
    } else if upper.starts_with("X25519")
        || upper.starts_with("X448")
        || upper.starts_with("SECP")
        || upper.starts_with("BRAINPOOL")
    {
        "ECDHE"
    } else if upper.starts_with("FFDHE") {
        "DHE"
    } else {
        "ECDHE"
    }
}

fn key_exchange_from_cipher(cipher: &str) -> &'static str {
    let c = cipher.to_ascii_uppercase();
    let is_tls13 = c.starts_with("TLS13_")
        || c.starts_with("TLS_AES_")
        || c.starts_with("TLS_CHACHA20_");

    if is_tls13 || c.contains("ECDHE") {
        "ECDHE"
    } else if c.contains("_ECDH_") {
        "ECDH"
    } else if c.contains("DHE") {
        "DHE"
    } else if c.contains("_DH_") {
        "DH"
    } else if c.starts_with("TLS_RSA_") {
        "RSA"
    } else {
        "UNKNOWN"
    }
}

fn build_finding(primary: &HandshakeResult, accepts_tls12: bool) -> TlsFinding {
    let protocol_vulnerable = accepts_tls12
        || AlgorithmClassifier::is_tls_version_vulnerable(&primary.protocol_version);
    let (cipher_vulnerable, _) =
        AlgorithmClassifier::is_cipher_suite_vulnerable(&primary.cipher_suite);
    let (kx_vulnerable, _) =
        AlgorithmClassifier::is_key_exchange_vulnerable(&primary.key_exchange);

    TlsFinding {
        protocol_version: primary.protocol_version.clone(),
        protocol_vulnerable,
        cipher_suite: primary.cipher_suite.clone(),
        cipher_vulnerable,
        key_exchange: primary.key_exchange.clone(),
        key_exchange_vulnerable: kx_vulnerable,
        compression: "none".to_string(),
        compression_vulnerable: false,
    }
}

#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_formats_tls13() {
        assert_eq!(
            format_protocol_version(rustls::ProtocolVersion::TLSv1_3),
            "TLSv1.3"
        );
    }

    #[test]
    fn named_group_x25519_maps_to_ecdhe() {
        assert_eq!(named_group_to_kx("X25519"), "ECDHE");
    }

    #[test]
    fn named_group_mlkem_maps_to_hybrid() {
        assert_eq!(named_group_to_kx("X25519MLKEM768"), "X25519MLKEM768");
    }

    #[test]
    fn named_group_ffdhe_maps_to_dhe() {
        assert_eq!(named_group_to_kx("FFDHE2048"), "DHE");
    }

    #[test]
    fn cipher_tls13_implies_ecdhe() {
        assert_eq!(key_exchange_from_cipher("TLS_AES_256_GCM_SHA384"), "ECDHE");
    }

    #[test]
    fn cipher_tls_rsa_implies_rsa() {
        assert_eq!(
            key_exchange_from_cipher("TLS_RSA_WITH_AES_128_CBC_SHA"),
            "RSA"
        );
    }

    #[test]
    fn cipher_ecdhe_extracted() {
        assert_eq!(
            key_exchange_from_cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            "ECDHE"
        );
    }
}
