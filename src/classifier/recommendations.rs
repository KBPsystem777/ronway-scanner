use crate::models::finding::{Recommendation, Vulnerability};

pub struct RecommendationEngine;

impl RecommendationEngine {
    pub fn generate(vulnerabilities: &[Vulnerability]) -> Vec<Recommendation> {
        let mut seen: Vec<(String, Recommendation)> = Vec::new();

        for vuln in vulnerabilities {
            let Some(rec) = Self::map(&vuln.id) else {
                continue;
            };

            if let Some(existing) = seen.iter_mut().find(|(id, _)| id == &vuln.id) {
                if rec.priority < existing.1.priority {
                    existing.1 = rec;
                }
            } else {
                seen.push((vuln.id.clone(), rec));
            }
        }

        let mut recs: Vec<Recommendation> = seen.into_iter().map(|(_, r)| r).collect();
        recs.sort_by_key(|r| r.priority);
        recs
    }

    fn map(id: &str) -> Option<Recommendation> {
        let rec = match id {
            "RSA_KEY_EXCHANGE" => Recommendation {
                priority: 1,
                action: "Replace RSA key exchange with ML-KEM-768 hybrid".into(),
                current: "RSA key exchange (quantum vulnerable)".into(),
                replace_with: "X25519MLKEM768 hybrid key exchange (NIST FIPS 203)".into(),
                effort_weeks: 2,
                nist_algorithm: "ML-KEM-768 (FIPS 203)".into(),
            },

            "ECDHE_KEY_EXCHANGE" => Recommendation {
                priority: 1,
                action: "Add ML-KEM-768 hybrid alongside ECDHE".into(),
                current: "ECDHE only (quantum vulnerable)".into(),
                replace_with: "X25519MLKEM768 hybrid — ML-KEM-768 + X25519".into(),
                effort_weeks: 2,
                nist_algorithm: "ML-KEM-768 (FIPS 203)".into(),
            },

            "DH_KEY_EXCHANGE" => Recommendation {
                priority: 1,
                action: "Replace finite-field Diffie-Hellman with ML-KEM-768 hybrid".into(),
                current: "DH/DHE key exchange (quantum vulnerable)".into(),
                replace_with: "X25519MLKEM768 hybrid key exchange (NIST FIPS 203)".into(),
                effort_weeks: 2,
                nist_algorithm: "ML-KEM-768 (FIPS 203)".into(),
            },

            "VULNERABLE_KEY_EXCHANGE" => Recommendation {
                priority: 1,
                action: "Replace key exchange with NIST PQC primitive".into(),
                current: "Unknown / non-PQC key exchange".into(),
                replace_with: "X25519MLKEM768 hybrid key exchange (NIST FIPS 203)".into(),
                effort_weeks: 2,
                nist_algorithm: "ML-KEM-768 (FIPS 203)".into(),
            },

            "TLS_LEGACY_VERSION" => Recommendation {
                priority: 2,
                action: "Disable SSL, TLS 1.0, and TLS 1.1. Enable TLS 1.3 only".into(),
                current: "Legacy SSL/TLS version negotiated".into(),
                replace_with: "TLS 1.3 only configuration".into(),
                effort_weeks: 1,
                nist_algorithm: "TLS 1.3 (RFC 8446)".into(),
            },

            "TLS_VERSION_VULNERABLE" => Recommendation {
                priority: 2,
                action: "Disable TLS 1.0, 1.1, 1.2. Enable TLS 1.3 only".into(),
                current: "TLS 1.2 or below (allows vulnerable cipher suites)".into(),
                replace_with: "TLS 1.3 only configuration".into(),
                effort_weeks: 1,
                nist_algorithm: "TLS 1.3 (RFC 8446)".into(),
            },

            "RSA_CERTIFICATE" | "RSA_SIGNATURE" => Recommendation {
                priority: 3,
                action: "Replace RSA certificate with ML-DSA-65 certificate".into(),
                current: "RSA-2048 or RSA-4096 certificate (quantum vulnerable)".into(),
                replace_with: "ML-DSA-65 certificate from PQC-ready CA".into(),
                effort_weeks: 4,
                nist_algorithm: "ML-DSA-65 (FIPS 204)".into(),
            },

            "ECDSA_CERTIFICATE" | "ECDSA_SIGNATURE" => Recommendation {
                priority: 3,
                action: "Replace ECDSA certificate with ML-DSA-65".into(),
                current: "ECDSA certificate (quantum vulnerable)".into(),
                replace_with: "ML-DSA-65 certificate or Ed25519 as interim".into(),
                effort_weeks: 4,
                nist_algorithm: "ML-DSA-65 (FIPS 204)".into(),
            },

            "SHA1_IN_CHAIN" => Recommendation {
                priority: 3,
                action: "Reissue certificate without SHA-1 in the chain".into(),
                current: "SHA-1 signature in certificate (collision vulnerable)".into(),
                replace_with: "SHA-256 or stronger; plan for ML-DSA-65 at next renewal".into(),
                effort_weeks: 2,
                nist_algorithm: "ML-DSA-65 (FIPS 204)".into(),
            },

            "CERT_EXPIRED" => Recommendation {
                priority: 1,
                action: "Renew the expired certificate immediately".into(),
                current: "Certificate is past its not-after date".into(),
                replace_with: "Valid certificate from a trusted CA; prefer ML-DSA-65 if available"
                    .into(),
                effort_weeks: 1,
                nist_algorithm: "ML-DSA-65 (FIPS 204)".into(),
            },

            "CERT_SELF_SIGNED" => Recommendation {
                priority: 4,
                action: "Replace self-signed certificate with one from a trusted CA".into(),
                current: "Self-signed certificate (no third-party validation)".into(),
                replace_with: "Publicly trusted CA-issued certificate".into(),
                effort_weeks: 1,
                nist_algorithm: "N/A — trust anchor hygiene".into(),
            },

            "NULL_CIPHER" => Recommendation {
                priority: 1,
                action: "Disable NULL cipher suites immediately".into(),
                current: "NULL cipher suite enabled (no encryption)".into(),
                replace_with: "TLS 1.3 AEAD cipher suites only (AES-256-GCM, ChaCha20-Poly1305)"
                    .into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "EXPORT_CIPHER" => Recommendation {
                priority: 1,
                action: "Disable EXPORT-grade cipher suites".into(),
                current: "Export-grade cipher suite enabled (intentionally weak)".into(),
                replace_with: "TLS 1.3 AEAD cipher suites only".into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "RC4_CIPHER" => Recommendation {
                priority: 2,
                action: "Disable RC4 cipher suites".into(),
                current: "RC4 stream cipher enabled (broken)".into(),
                replace_with: "AES-256-GCM or ChaCha20-Poly1305".into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "TRIPLE_DES_CIPHER" => Recommendation {
                priority: 2,
                action: "Disable 3DES cipher suites".into(),
                current: "3DES cipher suite enabled (SWEET32 vulnerable)".into(),
                replace_with: "AES-256-GCM or ChaCha20-Poly1305".into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "MD5_CIPHER" => Recommendation {
                priority: 2,
                action: "Disable cipher suites that use MD5".into(),
                current: "MD5 in cipher suite (collision vulnerable)".into(),
                replace_with: "TLS 1.3 AEAD cipher suites (SHA-256/384 PRF)".into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "SHA1_CIPHER" => Recommendation {
                priority: 3,
                action: "Disable cipher suites that use SHA-1".into(),
                current: "SHA-1 in cipher suite (collision vulnerable)".into(),
                replace_with: "TLS 1.3 AEAD cipher suites (SHA-256/384 PRF)".into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "CBC_CIPHER" => Recommendation {
                priority: 4,
                action: "Disable CBC mode cipher suites".into(),
                current: "AES-CBC mode (BEAST/POODLE vulnerable)".into(),
                replace_with: "AES-256-GCM or ChaCha20-Poly1305".into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "VULNERABLE_CIPHER" => Recommendation {
                priority: 4,
                action: "Restrict cipher suites to TLS 1.3 AEAD set".into(),
                current: "Unknown / non-standard cipher suite".into(),
                replace_with: "AES-256-GCM or ChaCha20-Poly1305".into(),
                effort_weeks: 1,
                nist_algorithm: "AES-256-GCM (NIST SP 800-38D)".into(),
            },

            "NO_HSTS" => Recommendation {
                priority: 5,
                action: "Enable HTTP Strict Transport Security".into(),
                current: "No HSTS header (allows protocol downgrade)".into(),
                replace_with: "Strict-Transport-Security: max-age=31536000; includeSubDomains"
                    .into(),
                effort_weeks: 1,
                nist_algorithm: "N/A — defense in depth".into(),
            },

            "SERVER_HEADER_LEAK" => Recommendation {
                priority: 5,
                action: "Strip version information from the Server response header".into(),
                current: "Server header leaks software version".into(),
                replace_with: "Generic Server header (e.g., \"nginx\" with no version)".into(),
                effort_weeks: 1,
                nist_algorithm: "N/A — information disclosure hardening".into(),
            },

            _ => return None,
        };

        Some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::risk::RiskLevel;

    fn vuln(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            title: id.into(),
            description: String::new(),
            severity: RiskLevel::High,
            nist_reference: String::new(),
            cvss_equivalent: 0.0,
        }
    }

    #[test]
    fn rsa_key_exchange_maps_to_priority_1() {
        let recs = RecommendationEngine::generate(&[vuln("RSA_KEY_EXCHANGE")]);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].priority, 1);
        assert!(recs[0].nist_algorithm.contains("ML-KEM-768"));
    }

    #[test]
    fn no_hsts_maps_to_low_priority() {
        let recs = RecommendationEngine::generate(&[vuln("NO_HSTS")]);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].priority, 5);
    }

    #[test]
    fn duplicates_are_deduplicated() {
        let recs =
            RecommendationEngine::generate(&[vuln("RSA_KEY_EXCHANGE"), vuln("RSA_KEY_EXCHANGE")]);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn results_are_sorted_by_priority_ascending() {
        let recs = RecommendationEngine::generate(&[
            vuln("NO_HSTS"),
            vuln("RSA_KEY_EXCHANGE"),
            vuln("TLS_VERSION_VULNERABLE"),
            vuln("RSA_CERTIFICATE"),
        ]);
        assert_eq!(recs.len(), 4);
        let priorities: Vec<u8> = recs.iter().map(|r| r.priority).collect();
        let mut sorted = priorities.clone();
        sorted.sort();
        assert_eq!(priorities, sorted);
        assert_eq!(recs[0].priority, 1);
    }

    #[test]
    fn unknown_vulnerability_is_skipped() {
        let recs = RecommendationEngine::generate(&[vuln("SOMETHING_NOT_MAPPED")]);
        assert!(recs.is_empty());
    }
}
