use ronway_scanner::classifier::scoring::RiskScorer;
use ronway_scanner::models::finding::Vulnerability;
use ronway_scanner::models::risk::RiskLevel;

fn vuln(id: &str) -> Vulnerability {
    Vulnerability {
        id: id.to_string(),
        title: id.to_string(),
        description: String::new(),
        severity: RiskLevel::Medium,
        nist_reference: String::new(),
        cvss_equivalent: 0.0,
    }
}

#[test]
fn empty_findings_score_zero() {
    let score = RiskScorer::calculate(&[]);
    assert_eq!(score.value, 0);
    assert_eq!(score.level, RiskLevel::Pass);
    assert!(!score.harvest_risk);
}

#[test]
fn rsa_key_exchange_contributes_at_least_35() {
    let score = RiskScorer::calculate(&[vuln("RSA_KEY_EXCHANGE")]);
    assert!(
        score.value >= 35,
        "expected RSA_KEY_EXCHANGE to add >= 35 points, got {}",
        score.value
    );
}

#[test]
fn harvest_risk_set_when_rsa_key_exchange_present() {
    let score = RiskScorer::calculate(&[vuln("RSA_KEY_EXCHANGE")]);
    assert!(score.harvest_risk);
}

#[test]
fn harvest_risk_unset_with_no_key_exchange_vulnerability() {
    let score = RiskScorer::calculate(&[vuln("NO_HSTS"), vuln("CBC_CIPHER")]);
    assert!(!score.harvest_risk);
}

#[test]
fn harvest_risk_present_helper_detects_ecdhe() {
    let vulns = vec![vuln("ECDHE_KEY_EXCHANGE")];
    assert!(RiskScorer::harvest_risk_present(&vulns));
}

#[test]
fn harvest_risk_present_false_for_unrelated_ids() {
    let vulns = vec![vuln("NO_HSTS"), vuln("SERVER_HEADER_LEAK")];
    assert!(!RiskScorer::harvest_risk_present(&vulns));
}

#[test]
fn risk_level_from_score_critical_at_87() {
    assert_eq!(RiskLevel::from_score(87), RiskLevel::Critical);
}

#[test]
fn risk_level_from_score_pass_at_15() {
    assert_eq!(RiskLevel::from_score(15), RiskLevel::Pass);
}

#[test]
fn risk_level_from_score_boundaries() {
    assert_eq!(RiskLevel::from_score(80), RiskLevel::Critical);
    assert_eq!(RiskLevel::from_score(60), RiskLevel::High);
    assert_eq!(RiskLevel::from_score(40), RiskLevel::Medium);
    assert_eq!(RiskLevel::from_score(20), RiskLevel::Low);
    assert_eq!(RiskLevel::from_score(0), RiskLevel::Pass);
}

#[test]
fn score_is_capped_at_100() {
    let many = vec![
        vuln("RSA_KEY_EXCHANGE"),
        vuln("RSA_CERTIFICATE"),
        vuln("NULL_CIPHER"),
        vuln("EXPORT_CIPHER"),
        vuln("TLS_LEGACY_VERSION"),
        vuln("CERT_EXPIRED"),
    ];
    let score = RiskScorer::calculate(&many);
    assert_eq!(score.value, 100);
    assert_eq!(score.level, RiskLevel::Critical);
}

#[test]
fn generate_summary_includes_target_and_score() {
    let score = RiskScorer::calculate(&[vuln("RSA_KEY_EXCHANGE"), vuln("RSA_CERTIFICATE")]);
    let summary = RiskScorer::generate_summary(&score, "bsp.gov.ph");
    assert!(summary.contains("bsp.gov.ph"));
    assert!(summary.contains(&score.value.to_string()));
    assert!(summary.contains("harvest now, decrypt later"));
}
