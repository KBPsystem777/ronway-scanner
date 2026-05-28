//! Phase 7: X.509 certificate parser.
//!
//! Takes a DER-encoded leaf certificate (typically pulled from the TLS
//! handshake in Phase 6) and returns a fully populated `CertFinding`
//! with subject/issuer, validity window, key & signature algorithms,
//! self-signed status, and the CT-log flag.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use x509_parser::der_parser::oid::Oid;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::classifier::algorithms::AlgorithmClassifier;
use crate::models::finding::CertFinding;

const SCT_EXTENSION_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

pub struct CertScanner;

impl CertScanner {
    pub fn parse_der(der: &[u8]) -> Result<CertFinding> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|e| anyhow!("X.509 DER parse failed: {}", e))?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let is_self_signed = subject == issuer;

        let signature_algorithm = signature_algorithm_name(&cert.signature_algorithm.algorithm);
        let (signature_algorithm_vulnerable, _) =
            AlgorithmClassifier::is_signature_algorithm_vulnerable(&signature_algorithm);

        let (key_algorithm, key_algorithm_vulnerable) = describe_public_key(&cert);

        let validity = cert.validity();
        let not_after = DateTime::<Utc>::from_timestamp(validity.not_after.timestamp(), 0)
            .ok_or_else(|| anyhow!("not_after timestamp out of range"))?;
        let not_before = DateTime::<Utc>::from_timestamp(validity.not_before.timestamp(), 0)
            .ok_or_else(|| anyhow!("not_before timestamp out of range"))?;

        let now = Utc::now();
        let days_remaining = (not_after - now).num_days();
        let is_expired = not_after < now;

        let ct_logged = cert
            .extensions()
            .iter()
            .any(|ext| ext.oid.to_id_string() == SCT_EXTENSION_OID);

        Ok(CertFinding {
            subject,
            issuer,
            key_algorithm,
            key_algorithm_vulnerable,
            signature_algorithm,
            signature_algorithm_vulnerable,
            valid_from: not_before.to_rfc3339(),
            valid_until: not_after.to_rfc3339(),
            days_remaining,
            is_expired,
            is_self_signed,
            ct_logged,
        })
    }
}

fn signature_algorithm_name(oid: &Oid) -> String {
    let dotted = oid.to_id_string();
    match dotted.as_str() {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".to_string(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_string(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".to_string(),
        "1.2.840.10040.4.3" => "id-dsa-with-sha1".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        // NIST FIPS 204 ML-DSA OIDs (post-quantum, safe)
        "2.16.840.1.101.3.4.3.17" => "id-ML-DSA-44".to_string(),
        "2.16.840.1.101.3.4.3.18" => "id-ML-DSA-65".to_string(),
        "2.16.840.1.101.3.4.3.19" => "id-ML-DSA-87".to_string(),
        _ => dotted,
    }
}

fn describe_public_key(cert: &X509Certificate) -> (String, bool) {
    let spki = cert.public_key();
    let alg_oid = spki.algorithm.algorithm.to_id_string();

    match alg_oid.as_str() {
        // RSA
        "1.2.840.113549.1.1.1" => {
            let label = match spki.parsed() {
                Ok(PublicKey::RSA(rsa)) => {
                    let bits = rsa_modulus_bits(rsa.modulus);
                    if bits > 0 {
                        format!("RSA {}-bit", bits)
                    } else {
                        "RSA".to_string()
                    }
                }
                _ => "RSA".to_string(),
            };
            (label, true)
        }
        // EC
        "1.2.840.10045.2.1" => {
            let curve = ec_curve_name(spki).unwrap_or("unknown-curve");
            (format!("EC {}", curve), true)
        }
        "1.3.101.112" => ("Ed25519".to_string(), false),
        "1.3.101.113" => ("Ed448".to_string(), false),
        // NIST FIPS 204 ML-DSA (post-quantum)
        "2.16.840.1.101.3.4.3.17" => ("ML-DSA-44".to_string(), false),
        "2.16.840.1.101.3.4.3.18" => ("ML-DSA-65".to_string(), false),
        "2.16.840.1.101.3.4.3.19" => ("ML-DSA-87".to_string(), false),
        other => (other.to_string(), false),
    }
}

fn rsa_modulus_bits(modulus: &[u8]) -> usize {
    let trimmed = if modulus.first() == Some(&0) {
        &modulus[1..]
    } else {
        modulus
    };
    trimmed.len() * 8
}

fn ec_curve_name(spki: &SubjectPublicKeyInfo) -> Option<&'static str> {
    let params = spki.algorithm.parameters.as_ref()?;
    let oid = params.as_oid().ok()?;
    match oid.to_id_string().as_str() {
        "1.2.840.10045.3.1.7" => Some("P-256"),
        "1.3.132.0.34" => Some("P-384"),
        "1.3.132.0.35" => Some("P-521"),
        "1.3.132.0.10" => Some("secp256k1"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_modulus_bits_strips_leading_zero() {
        let mut modulus = vec![0u8];
        modulus.extend(std::iter::repeat_n(0xFFu8, 256));
        assert_eq!(rsa_modulus_bits(&modulus), 2048);
    }

    #[test]
    fn rsa_modulus_bits_without_pad() {
        let modulus = vec![0x80u8; 256];
        assert_eq!(rsa_modulus_bits(&modulus), 2048);
    }

    #[test]
    fn signature_name_maps_known_oids() {
        let oid = x509_parser::der_parser::oid!(1.2.840 .113549 .1 .1 .11);
        assert_eq!(signature_algorithm_name(&oid), "sha256WithRSAEncryption");

        let oid = x509_parser::der_parser::oid!(1.2.840 .10045 .4 .3 .2);
        assert_eq!(signature_algorithm_name(&oid), "ecdsa-with-SHA256");

        let oid = x509_parser::der_parser::oid!(1.3.101 .112);
        assert_eq!(signature_algorithm_name(&oid), "Ed25519");

        let oid = x509_parser::der_parser::oid!(2.16.840 .1 .101 .3 .4 .3 .18);
        assert_eq!(signature_algorithm_name(&oid), "id-ML-DSA-65");
    }

    #[test]
    fn signature_name_falls_back_to_oid_string() {
        let oid = x509_parser::der_parser::oid!(1.2.3 .4 .5);
        assert_eq!(signature_algorithm_name(&oid), "1.2.3.4.5");
    }

    #[test]
    fn malformed_der_returns_error() {
        let bytes = b"not actually a certificate";
        assert!(CertScanner::parse_der(bytes).is_err());
    }
}
