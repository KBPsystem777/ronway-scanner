//! Scan-history persistence.
//!
//! Every completed scan served by the API is recorded in a local SQLite
//! database so submissions can be reviewed later. Persistence is
//! best-effort: a write failure is logged but never fails the scan
//! response, and a store can be `disabled()` (used by tests) so no database
//! file is touched.

use std::net::IpAddr;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use tracing::{info, warn};

use crate::models::report::ScanReport;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS scans (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at          TEXT    NOT NULL,
    client_ip           TEXT    NOT NULL,
    target_domain       TEXT    NOT NULL,
    target_port         INTEGER NOT NULL,
    risk_score          INTEGER NOT NULL,
    risk_level          TEXT    NOT NULL,
    harvest_risk        INTEGER NOT NULL,
    quantum_ready       INTEGER NOT NULL,
    vulnerability_count INTEGER NOT NULL,
    report_json         TEXT    NOT NULL,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scans_domain     ON scans(target_domain);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
";

/// Handle to the scan-history database. Cheap to clone (the pool is
/// reference-counted internally).
#[derive(Clone)]
pub struct ScanStore {
    pool: Option<SqlitePool>,
}

impl ScanStore {
    /// A no-op store that records nothing. Used in tests and when the API
    /// is run without a configured database.
    pub fn disabled() -> Self {
        Self { pool: None }
    }

    /// Open (creating if necessary) a SQLite database at `path` and ensure
    /// the schema exists.
    pub async fn connect(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .with_context(|| format!("failed to open scan database at {path}"))?;
        sqlx::query(SCHEMA)
            .execute(&pool)
            .await
            .context("failed to initialise scan-history schema")?;
        info!("recording scan history to {}", path);
        Ok(Self { pool: Some(pool) })
    }

    /// Persist one completed scan. Best-effort: errors are logged, not
    /// propagated, so capturing history never breaks the API response.
    pub async fn record(&self, client_ip: IpAddr, report: &ScanReport) {
        let Some(pool) = &self.pool else {
            return;
        };
        let report_json = match serde_json::to_string(report) {
            Ok(j) => j,
            Err(e) => {
                warn!("could not serialise scan for persistence: {}", e);
                return;
            }
        };
        let result = sqlx::query(
            "INSERT INTO scans \
             (scanned_at, client_ip, target_domain, target_port, risk_score, \
              risk_level, harvest_risk, quantum_ready, vulnerability_count, report_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&report.target.scanned_at)
        .bind(client_ip.to_string())
        .bind(&report.target.domain)
        .bind(report.target.port as i64)
        .bind(report.risk_score.value as i64)
        .bind(report.risk_score.level.label())
        .bind(report.risk_score.harvest_risk as i64)
        .bind(report.quantum_ready as i64)
        .bind(report.vulnerabilities.len() as i64)
        .bind(report_json)
        .execute(pool)
        .await;

        if let Err(e) = result {
            warn!(
                "failed to persist scan of {}: {}",
                report.target.domain, e
            );
        }
    }
}
