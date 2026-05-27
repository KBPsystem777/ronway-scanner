use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Pass,
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            80..=u8::MAX => RiskLevel::Critical,
            60..=79 => RiskLevel::High,
            40..=59 => RiskLevel::Medium,
            20..=39 => RiskLevel::Low,
            _ => RiskLevel::Pass,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            RiskLevel::Critical => "Critical",
            RiskLevel::High => "High",
            RiskLevel::Medium => "Medium",
            RiskLevel::Low => "Low",
            RiskLevel::Pass => "Pass",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            RiskLevel::Critical => "#dc2626",
            RiskLevel::High => "#ea580c",
            RiskLevel::Medium => "#ca8a04",
            RiskLevel::Low => "#65a30d",
            RiskLevel::Pass => "#16a34a",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub value: u8,
    pub level: RiskLevel,
    pub summary: String,
    pub harvest_risk: bool,
}
