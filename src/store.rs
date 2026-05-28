//! Scan-history persistence.
//!
//! Every completed scan served by the API is recorded in a local SQLite
//! database so submissions can be reviewed later. Persistence is
//! best-effort: a write failure is logged but never fails the scan
//! response, and a store can be `disabled()` (used by tests) so no database
//! file is touched.

use std::net::IpAddr;

use anyhow::{Context, Result};
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::FromRow;
use tracing::{info, warn};

use crate::models::report::ScanReport;

/// One row of scan history, without the bulky full-report JSON or the
/// client IP (the IP is stored but never exposed through the public API).
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ScanSummary {
    pub id: i64,
    pub scanned_at: String,
    pub target_domain: String,
    pub target_port: i64,
    pub risk_score: i64,
    pub risk_level: String,
    pub harvest_risk: bool,
    pub quantum_ready: bool,
    pub vulnerability_count: i64,
    pub created_at: String,
}

/// Per-site rollup: how many times a domain has been scanned and how it
/// looked most recently. Powers the historical "how often / how risky" view.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct SiteAggregate {
    pub target_domain: String,
    pub scan_count: i64,
    pub first_scanned: String,
    pub last_scanned: String,
    pub latest_risk_score: i64,
    pub latest_risk_level: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::report::{ScanReport, ScanTarget};
    use crate::models::risk::{RiskLevel, RiskScore};
    use std::net::Ipv4Addr;

    fn report(domain: &str, score: u8) -> ScanReport {
        ScanReport {
            target: ScanTarget {
                domain: domain.into(),
                ip_address: None,
                port: 443,
                scanned_at: "2026-05-28T00:00:00+00:00".into(),
                scan_duration_ms: 100,
            },
            risk_score: RiskScore {
                value: score,
                level: RiskLevel::from_score(score),
                summary: "test".into(),
                harvest_risk: true,
            },
            tls: None,
            certificate: None,
            http: None,
            vulnerabilities: Vec::new(),
            recommendations: Vec::new(),
            summary: "test".into(),
            quantum_ready: false,
        }
    }

    async fn temp_store() -> (ScanStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("ronway_store_test_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = ScanStore::connect(path.to_str().unwrap()).await.unwrap();
        (store, path)
    }

    #[tokio::test]
    async fn records_and_lists_scans_with_history_and_aggregates() {
        let (store, path) = temp_store().await;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // koleenbp.com scanned twice (history), example.com once.
        store.record(ip, &report("koleenbp.com", 50)).await;
        store.record(ip, &report("koleenbp.com", 30)).await;
        store.record(ip, &report("example.com", 45)).await;

        let all = store.list_scans(10, 0).await.unwrap();
        assert_eq!(all.len(), 3);
        // bool round-trips through the INTEGER column.
        assert!(all[0].harvest_risk);
        assert!(!all[0].quantum_ready);

        let history = store.list_scans_for_domain("koleenbp.com", 10).await.unwrap();
        assert_eq!(history.len(), 2);

        let sites = store.site_aggregates(10).await.unwrap();
        let koleen = sites
            .iter()
            .find(|s| s.target_domain == "koleenbp.com")
            .unwrap();
        assert_eq!(koleen.scan_count, 2);
        // Most-scanned first.
        assert_eq!(sites[0].target_domain, "koleenbp.com");

        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn disabled_store_returns_empty() {
        let store = ScanStore::disabled();
        assert!(store.list_scans(10, 0).await.unwrap().is_empty());
        assert!(store.site_aggregates(10).await.unwrap().is_empty());
    }
}

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

    /// All scans, newest first. `limit`/`offset` paginate. Returns an empty
    /// list when persistence is disabled.
    pub async fn list_scans(&self, limit: i64, offset: i64) -> Result<Vec<ScanSummary>> {
        let Some(pool) = &self.pool else {
            return Ok(Vec::new());
        };
        let rows = sqlx::query_as::<_, ScanSummary>(
            "SELECT id, scanned_at, target_domain, target_port, risk_score, risk_level, \
                    harvest_risk, quantum_ready, vulnerability_count, created_at \
             FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .context("failed to list scans")?;
        Ok(rows)
    }

    /// Scan history for a single domain, newest first.
    pub async fn list_scans_for_domain(
        &self,
        domain: &str,
        limit: i64,
    ) -> Result<Vec<ScanSummary>> {
        let Some(pool) = &self.pool else {
            return Ok(Vec::new());
        };
        let rows = sqlx::query_as::<_, ScanSummary>(
            "SELECT id, scanned_at, target_domain, target_port, risk_score, risk_level, \
                    harvest_risk, quantum_ready, vulnerability_count, created_at \
             FROM scans WHERE target_domain = ? ORDER BY id DESC LIMIT ?",
        )
        .bind(domain)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("failed to list scans for domain")?;
        Ok(rows)
    }

    /// Per-site rollup: scan count, first/last seen, and the latest score —
    /// ordered by most-scanned first.
    pub async fn site_aggregates(&self, limit: i64) -> Result<Vec<SiteAggregate>> {
        let Some(pool) = &self.pool else {
            return Ok(Vec::new());
        };
        let rows = sqlx::query_as::<_, SiteAggregate>(
            "SELECT \
                target_domain, \
                COUNT(*) AS scan_count, \
                MIN(created_at) AS first_scanned, \
                MAX(created_at) AS last_scanned, \
                (SELECT risk_score FROM scans s2 WHERE s2.target_domain = s1.target_domain \
                    ORDER BY s2.id DESC LIMIT 1) AS latest_risk_score, \
                (SELECT risk_level FROM scans s2 WHERE s2.target_domain = s1.target_domain \
                    ORDER BY s2.id DESC LIMIT 1) AS latest_risk_level \
             FROM scans s1 \
             GROUP BY target_domain \
             ORDER BY scan_count DESC, last_scanned DESC \
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("failed to aggregate sites")?;
        Ok(rows)
    }
}
