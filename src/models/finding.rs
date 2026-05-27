use serde::{Deserialize, Serialize};

use crate::models::risk::RiskLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFinding {
    pub protocol_version: String,
    pub protocol_vulnerable: bool,
    pub cipher_suite: String,
    pub cipher_vulnerable: bool,
    pub key_exchange: String,
    pub key_exchange_vulnerable: bool,
    pub compression: String,
    pub compression_vulnerable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertFinding {
    pub subject: String,
    pub issuer: String,
    pub key_algorithm: String,
    pub key_algorithm_vulnerable: bool,
    pub signature_algorithm: String,
    pub signature_algorithm_vulnerable: bool,
    pub valid_from: String,
    pub valid_until: String,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub ct_logged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFinding {
    pub hsts_enabled: bool,
    pub hsts_max_age: Option<u64>,
    pub csp_present: bool,
    pub x_frame_options: Option<String>,
    pub server_header: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: RiskLevel,
    pub nist_reference: String,
    pub cvss_equivalent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: u8,
    pub action: String,
    pub current: String,
    pub replace_with: String,
    pub effort_weeks: u8,
    pub nist_algorithm: String,
}
