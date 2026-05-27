use crate::models::finding::Vulnerability;
use crate::models::risk::{RiskLevel, RiskScore};

pub struct RiskScorer;

impl RiskScorer {
    pub fn calculate(vulnerabilities: &[Vulnerability]) -> RiskScore {
        let mut score: u16 = 0;

        for v in vulnerabilities {
            score = score.saturating_add(Self::weight_for(&v.id));
        }

        let value: u8 = score.min(100) as u8;
        let level = RiskLevel::from_score(value);
        let harvest_risk = Self::harvest_risk_present(vulnerabilities);
        let summary = Self::compose_summary(value, &level, harvest_risk, vulnerabilities.len());

        RiskScore {
            value,
            level,
            summary,
            harvest_risk,
        }
    }

    pub fn harvest_risk_present(vulnerabilities: &[Vulnerability]) -> bool {
        vulnerabilities.iter().any(|v| {
            matches!(
                v.id.as_str(),
                "RSA_KEY_EXCHANGE" | "ECDHE_KEY_EXCHANGE" | "DH_KEY_EXCHANGE"
            )
        })
    }

    pub fn generate_summary(score: &RiskScore, target: &str) -> String {
        let level_text = score.level.label();
        let harvest_clause = if score.harvest_risk {
            " A quantum-vulnerable key exchange was detected, meaning past encrypted \
             sessions are at risk of future decryption by quantum computers \
             (harvest now, decrypt later)."
        } else {
            ""
        };

        let action_clause = match score.level {
            RiskLevel::Critical => {
                " Immediate migration to ML-KEM-768 hybrid key exchange and ML-DSA-65 \
                 certificate signatures is recommended."
            }
            RiskLevel::High => {
                " Urgent migration to NIST post-quantum primitives (FIPS 203/204) \
                 should be scheduled."
            }
            RiskLevel::Medium => {
                " Plan a post-quantum migration within the next 6 months."
            }
            RiskLevel::Low => {
                " Monitor cryptographic posture and prepare a migration plan."
            }
            RiskLevel::Pass => {
                " The endpoint meets current post-quantum readiness guidance."
            }
        };

        format!(
            "{} scored {}/100 ({}) on the RonwayScanner post-quantum assessment.{}{}",
            target, score.value, level_text, harvest_clause, action_clause
        )
    }

    fn compose_summary(
        value: u8,
        level: &RiskLevel,
        harvest_risk: bool,
        vuln_count: usize,
    ) -> String {
        let harvest_clause = if harvest_risk {
            " Harvest-now-decrypt-later risk detected."
        } else {
            ""
        };
        format!(
            "Risk score {}/100 ({}). {} vulnerabilit{} found.{}",
            value,
            level.label(),
            vuln_count,
            if vuln_count == 1 { "y" } else { "ies" },
            harvest_clause
        )
    }

    fn weight_for(id: &str) -> u16 {
        match id {
            // TLS protocol
            "TLS_LEGACY_VERSION" => 20,
            "TLS_VERSION_VULNERABLE" => 10,

            // Key exchange (harvest now, decrypt later)
            "RSA_KEY_EXCHANGE" => 35,
            "ECDHE_KEY_EXCHANGE" => 30,
            "DH_KEY_EXCHANGE" => 25,

            // Cipher suites
            "NULL_CIPHER" => 40,
            "EXPORT_CIPHER" => 30,
            "RC4_CIPHER" => 20,
            "TRIPLE_DES_CIPHER" => 15,
            "CBC_CIPHER" => 10,
            "MD5_CIPHER" => 15,
            "SHA1_CIPHER" => 10,
            "VULNERABLE_CIPHER" => 10,

            // Certificate
            "RSA_CERTIFICATE" => 25,
            "ECDSA_CERTIFICATE" => 20,
            "RSA_SIGNATURE" => 25,
            "ECDSA_SIGNATURE" => 20,
            "SHA1_IN_CHAIN" => 15,
            "CERT_EXPIRED" => 20,
            "CERT_SELF_SIGNED" => 10,

            // HTTP
            "NO_HSTS" => 5,
            "SERVER_HEADER_LEAK" => 5,

            // Scan-pipeline failures (treated as evidence of misconfiguration)
            "TLS_SCAN_FAILED" => 40,
            "CERT_SCAN_FAILED" => 30,

            _ => 0,
        }
    }
}
