//! Phase 7 unit tests for the X.509 certificate parser.
//!
//! Generates real DER certificates with rcgen at test time, then asserts
//! that `CertScanner::parse_der` extracts the right fields. Covers ECDSA
//! P-256/P-384, Ed25519, self-signed status, expiry, and malformed input.

use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
};
use ronway_scanner::scanner::cert::CertScanner;
use time::{Duration, OffsetDateTime};

fn make_params(common_name: &str) -> CertificateParams {
    let mut params =
        CertificateParams::new(vec![common_name.to_string()]).expect("CertificateParams::new");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(90);
    params
}

fn self_signed_der(params: CertificateParams, key_pair: &KeyPair) -> Vec<u8> {
    params
        .self_signed(key_pair)
        .expect("self_signed")
        .der()
        .to_vec()
}

#[test]
fn parses_ecdsa_p256_self_signed_certificate() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let der = self_signed_der(make_params("ecdsa-p256.test"), &key);

    let finding = CertScanner::parse_der(&der).expect("parse_der");

    assert!(
        finding.key_algorithm.starts_with("EC P-256"),
        "expected EC P-256, got {}",
        finding.key_algorithm
    );
    assert!(finding.key_algorithm_vulnerable);
    assert_eq!(finding.signature_algorithm, "ecdsa-with-SHA256");
    assert!(finding.signature_algorithm_vulnerable);
    assert!(finding.is_self_signed);
    assert!(!finding.is_expired);
    assert!(finding.days_remaining > 0);
    assert!(finding.subject.contains("ecdsa-p256.test"));
    assert_eq!(finding.subject, finding.issuer);
    assert!(!finding.ct_logged);
}

#[test]
fn parses_ecdsa_p384_certificate() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let der = self_signed_der(make_params("ecdsa-p384.test"), &key);

    let finding = CertScanner::parse_der(&der).expect("parse_der");

    assert_eq!(finding.key_algorithm, "EC P-384");
    assert_eq!(finding.signature_algorithm, "ecdsa-with-SHA384");
    assert!(finding.signature_algorithm_vulnerable);
}

#[test]
fn parses_ed25519_certificate_as_safe() {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let der = self_signed_der(make_params("ed25519.test"), &key);

    let finding = CertScanner::parse_der(&der).expect("parse_der");

    assert_eq!(finding.key_algorithm, "Ed25519");
    assert!(
        !finding.key_algorithm_vulnerable,
        "Ed25519 keys are transitionally safe"
    );
    assert_eq!(finding.signature_algorithm, "Ed25519");
    assert!(!finding.signature_algorithm_vulnerable);
}

#[test]
fn detects_expired_certificate() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = make_params("expired.test");
    params.not_before = OffsetDateTime::now_utc() - Duration::days(400);
    params.not_after = OffsetDateTime::now_utc() - Duration::days(30);
    let der = self_signed_der(params, &key);

    let finding = CertScanner::parse_der(&der).expect("parse_der");

    assert!(finding.is_expired);
    assert!(finding.days_remaining < 0);
}

#[test]
fn self_signed_flag_set_when_subject_equals_issuer() {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let der = self_signed_der(make_params("selfsigned.test"), &key);

    let finding = CertScanner::parse_der(&der).expect("parse_der");
    assert!(finding.is_self_signed);
    assert_eq!(finding.subject, finding.issuer);
}

#[test]
fn valid_from_and_until_are_rfc3339_strings() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let der = self_signed_der(make_params("dates.test"), &key);

    let finding = CertScanner::parse_der(&der).expect("parse_der");

    assert!(finding.valid_from.contains('T'));
    assert!(finding.valid_until.contains('T'));
    assert!(finding.valid_from.len() >= 19);
    assert!(finding.valid_until.len() >= 19);
}

#[test]
fn malformed_der_returns_error() {
    assert!(CertScanner::parse_der(b"not a certificate").is_err());
}

#[test]
fn empty_input_returns_error() {
    assert!(CertScanner::parse_der(&[]).is_err());
}
