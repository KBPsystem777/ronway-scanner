use crate::models::finding::{CertFinding, HttpFinding, TlsFinding, Vulnerability};
use crate::models::risk::RiskLevel;

pub struct AlgorithmClassifier;

impl AlgorithmClassifier {
    pub fn is_tls_version_vulnerable(version: &str) -> bool {
        let v = version.trim().to_ascii_uppercase().replace(' ', "");
        matches!(
            v.as_str(),
            "SSLV2" | "SSLV3" | "TLSV1" | "TLSV1.0" | "TLSV1.1" | "TLSV1.2"
        )
    }

    pub fn is_key_exchange_vulnerable(algorithm: &str) -> (bool, &'static str) {
        let a = algorithm.trim().to_ascii_uppercase();
        match a.as_str() {
            "RSA" => (true, "Broken by Shor's Algorithm on quantum computers"),
            "DH" => (true, "Discrete log problem solved by Shor's Algorithm"),
            "DHE" => (true, "Discrete log problem solved by Shor's Algorithm"),
            "ECDH" => (
                true,
                "Elliptic curve discrete log solved by Shor's Algorithm",
            ),
            "ECDHE" => (
                true,
                "Elliptic curve discrete log solved by Shor's Algorithm",
            ),
            "ML-KEM-512" => (false, "NIST FIPS 203 post-quantum key encapsulation"),
            "ML-KEM-768" => (false, "NIST FIPS 203 post-quantum key encapsulation"),
            "ML-KEM-1024" => (false, "NIST FIPS 203 post-quantum key encapsulation"),
            "X25519MLKEM768" => (false, "Hybrid classical+PQC — recommended transition"),
            "X25519" => (
                false,
                "Classical only but forward secret — transitionally safe",
            ),
            "X448" => (
                false,
                "Classical only but forward secret — transitionally safe",
            ),
            _ => (
                false,
                "Unknown key exchange algorithm — manual review required",
            ),
        }
    }

    pub fn is_signature_algorithm_vulnerable(algorithm: &str) -> (bool, &'static str) {
        match algorithm.trim() {
            "sha1WithRSAEncryption" => {
                (true, "SHA-1 collision vulnerable + RSA quantum vulnerable")
            }
            "sha256WithRSAEncryption" => (true, "RSA quantum vulnerable via Shor's Algorithm"),
            "sha384WithRSAEncryption" => (true, "RSA quantum vulnerable via Shor's Algorithm"),
            "sha512WithRSAEncryption" => (true, "RSA quantum vulnerable via Shor's Algorithm"),
            "ecdsa-with-SHA256" => (true, "ECDSA quantum vulnerable via Shor's Algorithm"),
            "ecdsa-with-SHA384" => (true, "ECDSA quantum vulnerable via Shor's Algorithm"),
            "ecdsa-with-SHA512" => (true, "ECDSA quantum vulnerable via Shor's Algorithm"),
            "id-dsa-with-sha1" => (true, "DSA broken classically and quantum vulnerable"),
            "id-ML-DSA-44" => (false, "NIST FIPS 204 ML-DSA post-quantum signature"),
            "id-ML-DSA-65" => (false, "NIST FIPS 204 ML-DSA post-quantum signature"),
            "id-ML-DSA-87" => (false, "NIST FIPS 204 ML-DSA post-quantum signature"),
            "id-slh-dsa-sha2-128s" => (false, "NIST FIPS 205 SLH-DSA post-quantum signature"),
            "Ed25519" => (false, "Classical only — transitionally safe"),
            "Ed448" => (false, "Classical only — transitionally safe"),
            _ => (
                false,
                "Unknown signature algorithm — manual review required",
            ),
        }
    }

    pub fn is_cipher_suite_vulnerable(cipher: &str) -> (bool, &'static str) {
        let c = cipher.to_ascii_uppercase();

        if c.contains("NULL") {
            return (true, "No encryption");
        }
        if c.contains("EXPORT") {
            return (true, "Export-grade intentionally weak crypto");
        }
        if c.contains("RC4") {
            return (true, "RC4 stream cipher broken");
        }
        if c.contains("3DES") {
            return (true, "64-bit block cipher, SWEET32 vulnerable");
        }
        if c.contains("DES") {
            return (true, "56-bit key, classically broken");
        }
        if c.contains("MD5") {
            return (true, "MD5 collision vulnerable");
        }
        if c.contains("SHA1") {
            return (true, "SHA-1 collision vulnerable (not SHA-256/384/512)");
        }
        if c.contains("_CBC") {
            return (true, "CBC mode vulnerable to BEAST/POODLE attacks");
        }
        if c.contains("CHACHA20") {
            return (false, "ChaCha20-Poly1305 quantum safe");
        }
        if c.contains("AES_256") {
            return (false, "AES-256 quantum safe (Grover reduces to 128-bit)");
        }
        if c.contains("AES_128") {
            return (
                false,
                "AES-128 safe (Grover halves to 64-bit but still safe)",
            );
        }

        (false, "Unknown cipher suite — manual review required")
    }
}

pub struct VulnerabilityDatabase;

impl VulnerabilityDatabase {
    pub fn build_vulnerabilities(
        tls: Option<&TlsFinding>,
        cert: Option<&CertFinding>,
        http: Option<&HttpFinding>,
    ) -> Vec<Vulnerability> {
        let mut vulns: Vec<Vulnerability> = Vec::new();

        // A probe that didn't return a finding is an *operational* failure
        // (host down, port closed, not TLS), not a cryptographic weakness —
        // so it is intentionally NOT recorded as a vulnerability and does not
        // contribute to the risk score. The orchestrator flags a fully
        // unreachable scan as `RiskLevel::Unknown` instead.
        if let Some(t) = tls {
            Self::collect_tls(t, &mut vulns);
        }
        if let Some(c) = cert {
            Self::collect_cert(c, &mut vulns);
        }
        if let Some(h) = http {
            Self::collect_http(h, &mut vulns);
        }

        vulns
    }

    fn collect_tls(t: &TlsFinding, vulns: &mut Vec<Vulnerability>) {
        if AlgorithmClassifier::is_tls_version_vulnerable(&t.protocol_version) {
            let upper = t.protocol_version.to_ascii_uppercase();
            if upper.contains("1.0") || upper.contains("1.1") || upper.contains("SSL") {
                vulns.push(Vulnerability {
                    id: "TLS_LEGACY_VERSION".into(),
                    title: format!("Legacy TLS/SSL version negotiated ({})", t.protocol_version),
                    description:
                        "TLS 1.0, TLS 1.1, and all SSL versions are deprecated and enable \
                         downgrade and oracle-style attacks. They must be disabled."
                            .into(),
                    severity: RiskLevel::High,
                    nist_reference: "NIST SP 800-52 Rev 2".into(),
                    cvss_equivalent: 7.4,
                });
            } else {
                vulns.push(Vulnerability {
                    id: "TLS_VERSION_VULNERABLE".into(),
                    title: format!(
                        "TLS 1.2 accepted as highest version ({})",
                        t.protocol_version
                    ),
                    description: "TLS 1.2 permits RSA key exchange and other quantum-vulnerable \
                         primitives. TLS 1.3 should be the only enabled version."
                        .into(),
                    severity: RiskLevel::Medium,
                    nist_reference: "RFC 8446 (TLS 1.3)".into(),
                    cvss_equivalent: 5.3,
                });
            }
        }

        let (kx_vuln, kx_reason) = AlgorithmClassifier::is_key_exchange_vulnerable(&t.key_exchange);
        if kx_vuln {
            let kx_upper = t.key_exchange.to_ascii_uppercase();
            let id = match kx_upper.as_str() {
                "RSA" => "RSA_KEY_EXCHANGE",
                "ECDH" | "ECDHE" => "ECDHE_KEY_EXCHANGE",
                "DH" | "DHE" => "DH_KEY_EXCHANGE",
                _ => "VULNERABLE_KEY_EXCHANGE",
            };
            vulns.push(Vulnerability {
                id: id.into(),
                title: format!("Quantum-vulnerable key exchange: {}", t.key_exchange),
                description: format!(
                    "{} Encrypted traffic is exposed to the harvest-now-decrypt-later threat.",
                    kx_reason
                ),
                severity: RiskLevel::Critical,
                nist_reference: "NIST FIPS 203 (ML-KEM)".into(),
                cvss_equivalent: 8.1,
            });
        }

        let (cs_vuln, cs_reason) = AlgorithmClassifier::is_cipher_suite_vulnerable(&t.cipher_suite);
        if cs_vuln {
            let cs_upper = t.cipher_suite.to_ascii_uppercase();
            let (id, severity, cvss) = if cs_upper.contains("NULL") {
                ("NULL_CIPHER", RiskLevel::Critical, 9.1)
            } else if cs_upper.contains("EXPORT") {
                ("EXPORT_CIPHER", RiskLevel::Critical, 8.6)
            } else if cs_upper.contains("RC4") {
                ("RC4_CIPHER", RiskLevel::High, 7.5)
            } else if cs_upper.contains("3DES") {
                ("TRIPLE_DES_CIPHER", RiskLevel::High, 6.5)
            } else if cs_upper.contains("_CBC") {
                ("CBC_CIPHER", RiskLevel::Medium, 5.9)
            } else if cs_upper.contains("MD5") {
                ("MD5_CIPHER", RiskLevel::High, 7.0)
            } else if cs_upper.contains("SHA1") {
                ("SHA1_CIPHER", RiskLevel::Medium, 5.3)
            } else {
                ("VULNERABLE_CIPHER", RiskLevel::Medium, 5.0)
            };
            vulns.push(Vulnerability {
                id: id.into(),
                title: format!("Vulnerable cipher suite: {}", t.cipher_suite),
                description: cs_reason.into(),
                severity,
                nist_reference: "NIST SP 800-52 Rev 2".into(),
                cvss_equivalent: cvss,
            });
        }
    }

    fn collect_cert(c: &CertFinding, vulns: &mut Vec<Vulnerability>) {
        if c.is_expired {
            vulns.push(Vulnerability {
                id: "CERT_EXPIRED".into(),
                title: "Certificate has expired".into(),
                description: format!(
                    "Certificate expired on {} ({} days ago). \
                     Clients will reject this connection.",
                    c.valid_until,
                    c.days_remaining.abs()
                ),
                severity: RiskLevel::Critical,
                nist_reference: "RFC 5280".into(),
                cvss_equivalent: 7.5,
            });
        }

        if c.is_self_signed {
            vulns.push(Vulnerability {
                id: "CERT_SELF_SIGNED".into(),
                title: "Self-signed certificate".into(),
                description:
                    "The certificate is not chained to a trusted CA. There is no third-party \
                     identity validation, exposing clients to impersonation attacks."
                        .into(),
                severity: RiskLevel::Medium,
                nist_reference: "RFC 5280".into(),
                cvss_equivalent: 5.0,
            });
        }

        let key_upper = c.key_algorithm.to_ascii_uppercase();
        if key_upper.starts_with("RSA") {
            vulns.push(Vulnerability {
                id: "RSA_CERTIFICATE".into(),
                title: format!("RSA certificate detected ({})", c.key_algorithm),
                description: "RSA certificates are broken by Shor's Algorithm on a sufficiently \
                     large quantum computer. Plan migration to ML-DSA-65."
                    .into(),
                severity: RiskLevel::High,
                nist_reference: "NIST FIPS 204 (ML-DSA)".into(),
                cvss_equivalent: 7.4,
            });
        } else if key_upper.starts_with("ECDSA") || key_upper.starts_with("EC ") {
            vulns.push(Vulnerability {
                id: "ECDSA_CERTIFICATE".into(),
                title: format!("ECDSA certificate detected ({})", c.key_algorithm),
                description: "ECDSA signatures are broken by Shor's Algorithm. Plan migration to \
                     ML-DSA-65 from FIPS 204."
                    .into(),
                severity: RiskLevel::High,
                nist_reference: "NIST FIPS 204 (ML-DSA)".into(),
                cvss_equivalent: 7.0,
            });
        }

        let (sig_vuln, sig_reason) =
            AlgorithmClassifier::is_signature_algorithm_vulnerable(&c.signature_algorithm);
        if sig_vuln {
            let sig_lc = c.signature_algorithm.to_ascii_lowercase();
            if sig_lc.contains("sha1") {
                vulns.push(Vulnerability {
                    id: "SHA1_IN_CHAIN".into(),
                    title: "SHA-1 signature in certificate".into(),
                    description: sig_reason.into(),
                    severity: RiskLevel::High,
                    nist_reference: "NIST SP 800-131A Rev 2".into(),
                    cvss_equivalent: 7.4,
                });
            } else if sig_lc.starts_with("ecdsa") {
                vulns.push(Vulnerability {
                    id: "ECDSA_SIGNATURE".into(),
                    title: format!("ECDSA signature algorithm ({})", c.signature_algorithm),
                    description: sig_reason.into(),
                    severity: RiskLevel::High,
                    nist_reference: "NIST FIPS 204 (ML-DSA)".into(),
                    cvss_equivalent: 7.0,
                });
            } else {
                vulns.push(Vulnerability {
                    id: "RSA_SIGNATURE".into(),
                    title: format!("RSA signature algorithm ({})", c.signature_algorithm),
                    description: sig_reason.into(),
                    severity: RiskLevel::High,
                    nist_reference: "NIST FIPS 204 (ML-DSA)".into(),
                    cvss_equivalent: 7.4,
                });
            }
        }
    }

    fn collect_http(h: &HttpFinding, vulns: &mut Vec<Vulnerability>) {
        if !h.hsts_enabled {
            vulns.push(Vulnerability {
                id: "NO_HSTS".into(),
                title: "HSTS not enabled".into(),
                description:
                    "Strict-Transport-Security header is missing. Clients may be downgraded \
                     to plaintext HTTP by an active network attacker."
                        .into(),
                severity: RiskLevel::Low,
                nist_reference: "RFC 6797".into(),
                cvss_equivalent: 3.7,
            });
        }

        if let Some(server) = &h.server_header {
            if Self::server_header_leaks_version(server) {
                vulns.push(Vulnerability {
                    id: "SERVER_HEADER_LEAK".into(),
                    title: "Server header leaks software version".into(),
                    description: format!(
                        "Server header reveals software version information ({}). \
                         This aids attackers in fingerprinting and CVE matching.",
                        server
                    ),
                    severity: RiskLevel::Low,
                    nist_reference: "OWASP ASVS V14.4".into(),
                    cvss_equivalent: 3.1,
                });
            }
        }
    }

    fn server_header_leaks_version(server: &str) -> bool {
        server.chars().any(|c| c.is_ascii_digit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_key_exchange_is_vulnerable() {
        let (vuln, _) = AlgorithmClassifier::is_key_exchange_vulnerable("RSA");
        assert!(vuln);
    }

    #[test]
    fn ml_kem_768_is_safe() {
        let (vuln, _) = AlgorithmClassifier::is_key_exchange_vulnerable("ML-KEM-768");
        assert!(!vuln);
    }

    #[test]
    fn x25519_mlkem768_hybrid_is_safe() {
        let (vuln, _) = AlgorithmClassifier::is_key_exchange_vulnerable("X25519MLKEM768");
        assert!(!vuln);
    }

    #[test]
    fn rsa_sha256_signature_is_vulnerable() {
        let (vuln, _) =
            AlgorithmClassifier::is_signature_algorithm_vulnerable("sha256WithRSAEncryption");
        assert!(vuln);
    }

    #[test]
    fn ml_dsa_65_signature_is_safe() {
        let (vuln, _) = AlgorithmClassifier::is_signature_algorithm_vulnerable("id-ML-DSA-65");
        assert!(!vuln);
    }

    #[test]
    fn cipher_3des_is_vulnerable() {
        let (vuln, _) =
            AlgorithmClassifier::is_cipher_suite_vulnerable("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
        assert!(vuln);
    }

    #[test]
    fn cipher_tls13_aes_256_gcm_is_safe() {
        let (vuln, _) = AlgorithmClassifier::is_cipher_suite_vulnerable("TLS_AES_256_GCM_SHA384");
        assert!(!vuln);
    }

    #[test]
    fn tls12_is_flagged_vulnerable() {
        assert!(AlgorithmClassifier::is_tls_version_vulnerable("TLSv1.2"));
    }

    #[test]
    fn tls13_is_safe() {
        assert!(!AlgorithmClassifier::is_tls_version_vulnerable("TLSv1.3"));
    }
}
