use serde::{Deserialize, Serialize};

use crate::models::finding::{CertFinding, HttpFinding, Recommendation, TlsFinding, Vulnerability};
use crate::models::risk::{RiskLevel, RiskScore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub domain: String,
    pub ip_address: Option<String>,
    pub port: u16,
    pub scanned_at: String,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: ScanTarget,
    pub risk_score: RiskScore,
    pub tls: Option<TlsFinding>,
    pub certificate: Option<CertFinding>,
    pub http: Option<HttpFinding>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub recommendations: Vec<Recommendation>,
    pub summary: String,
    pub quantum_ready: bool,
}

impl ScanReport {
    pub fn is_critical(&self) -> bool {
        matches!(
            self.risk_score.level,
            RiskLevel::Critical | RiskLevel::High
        )
    }

    pub fn vulnerability_count(&self) -> usize {
        self.vulnerabilities.len()
    }

    pub fn has_harvest_risk(&self) -> bool {
        self.risk_score.harvest_risk
    }
}
