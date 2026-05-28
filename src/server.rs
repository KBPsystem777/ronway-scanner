//! Phase 14: HTTP server exposing the scanner as a JSON API.
//!
//! Endpoints:
//! - `GET  /api/health` → `200 OK` with `{"status":"ok",...}`
//! - `POST /api/scan`   `{ "target": "example.com" }` → full `ScanReport` JSON
//!
//! Hard limits enforced server-side (not negotiable by the client):
//! - 10 scans per minute, per remote IP
//! - 30-second wall clock per scan
//! - Targets must be public hostnames or public IP literals — private,
//!   loopback, link-local, and reserved ranges are rejected so the API
//!   can't be coerced into scanning internal infrastructure (SSRF-class
//!   abuse).
//!
//! CORS is restricted to the bpxai.com production origins and local dev
//! ports. The browser will reject any other origin — calls from `curl`,
//! the CLI, or server-to-server hits aren't affected because they don't
//! send an `Origin` header.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::models::finding::{CertFinding, HttpFinding, TlsFinding, Vulnerability};
use crate::models::report::{ScanReport, ScanTarget};
use crate::models::risk::RiskScore;
use crate::store::ScanStore;
use crate::RonwayScanner;

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX_REQUESTS: usize = 10;
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(120);
/// Maximum number of scans running simultaneously across all clients.
/// Prevents a LinkedIn-style traffic spike from exhausting outbound connections.
const MAX_CONCURRENT_SCANS: usize = 20;
/// How long a cached scan result is served without re-scanning the target.
const SCAN_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes
/// Maximum request body accepted by the scan endpoint.
/// A valid payload is well under 300 bytes; 4 KB is generous headroom.
const MAX_BODY_BYTES: usize = 4096;
/// Global ceiling: maximum scan requests accepted per minute across ALL IPs.
/// A botnet with 1000 IPs each within their per-IP budget would otherwise
/// generate 10 000 req/min — this hard-caps the total server load.
const GLOBAL_SCAN_CEILING: usize = 120;
/// How many times an IP must hit the per-IP rate limit before it is
/// temporarily blocked entirely.
const REPEAT_OFFENDER_THRESHOLD: usize = 3;
/// How long a repeat-offender IP stays blocked.
const REPEAT_OFFENDER_BAN_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// Browser origins permitted to call the API. Production origins + the
/// two common Next.js / Vite dev ports.
const ALLOWED_ORIGINS: &[&str] = &[
    "https://bpxai.com",
    "https://www.bpxai.com",
    "https://ronway-api.bpxai.com",
    "http://localhost:3000",
    "http://localhost:5173",
];

/// In-memory scan cache entry.
struct CacheEntry {
    report: Arc<PublicScanReport>,
    inserted_at: Instant,
}

/// Shared server state.
#[derive(Clone)]
pub struct AppState {
    limiter: Arc<Mutex<RateLimiter>>,
    scan_slots: Arc<Semaphore>,
    /// Global scan request counter, reset every minute by a background task.
    /// Caps total load regardless of how many distinct IPs are involved.
    global_scan_count: Arc<AtomicUsize>,
    /// IPs temporarily blocked for repeatedly exhausting their rate limit.
    blocked_ips: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    /// Short-lived cache keyed by (host, port). Serves repeat scans of the
    /// same target without opening new TLS connections.
    scan_cache: Arc<Mutex<HashMap<(String, u16), CacheEntry>>>,
    /// Token required for admin endpoints. Read from `RONWAY_ADMIN_TOKEN` at
    /// startup. `None` means the env var was not set — admin endpoints return
    /// 401 until the operator configures it.
    admin_token: Option<Arc<str>>,
    store: ScanStore,
}

impl AppState {
    /// State with scan-history persistence disabled (used by tests).
    pub fn new() -> Self {
        Self {
            limiter: Arc::new(Mutex::new(RateLimiter::new(
                RATE_LIMIT_MAX_REQUESTS,
                RATE_LIMIT_WINDOW,
            ))),
            scan_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
            global_scan_count: Arc::new(AtomicUsize::new(0)),
            blocked_ips: Arc::new(Mutex::new(HashMap::new())),
            scan_cache: Arc::new(Mutex::new(HashMap::new())),
            admin_token: None,
            store: ScanStore::disabled(),
        }
    }

    /// State with a hardcoded admin token — use in tests only.
    pub fn with_test_token(token: &str) -> Self {
        let mut state = Self::new();
        state.admin_token = Some(Arc::from(token));
        state
    }

    /// State that records every completed scan to `store`.
    pub fn with_store(store: ScanStore) -> Self {
        let admin_token = std::env::var("RONWAY_ADMIN_TOKEN")
            .ok()
            .map(|t| Arc::from(t.as_str()));
        if admin_token.is_none() {
            warn!("RONWAY_ADMIN_TOKEN is not set — admin endpoints (/api/scans, /api/sites) will return 401");
        }
        Self {
            limiter: Arc::new(Mutex::new(RateLimiter::new(
                RATE_LIMIT_MAX_REQUESTS,
                RATE_LIMIT_WINDOW,
            ))),
            scan_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
            global_scan_count: Arc::new(AtomicUsize::new(0)),
            blocked_ips: Arc::new(Mutex::new(HashMap::new())),
            scan_cache: Arc::new(Mutex::new(HashMap::new())),
            admin_token,
            store,
        }
    }
}

/// Constant-time token comparison — prevents timing-oracle attacks where an
/// attacker could infer prefix matches by measuring response latency.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Check that the request carries a valid `Authorization: Bearer <token>`
/// header matching the server's configured admin token.
fn require_admin(headers: &HeaderMap, token: &Option<Arc<str>>) -> Result<(), ApiError> {
    let Some(expected) = token else {
        // Token not configured — treat as disabled rather than open.
        return Err(ApiError::Unauthorized);
    };
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if constant_time_eq(provided, expected) {
        Ok(())
    } else {
        warn!("admin endpoint: invalid or missing token");
        Err(ApiError::Unauthorized)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}


/// Build the axum `Router` without binding to a port. Useful for tests
/// that want to drive the server in-process.
pub fn router(state: AppState) -> Router {
    let origins: Vec<HeaderValue> = ALLOWED_ORIGINS
        .iter()
        .map(|o| HeaderValue::from_static(o))
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/scan", post(scan_handler))
        .route("/api/scans", get(list_scans_handler))
        .route("/api/scans/:domain", get(scans_by_domain_handler))
        .route("/api/sites", get(sites_handler))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(
            // `log_requests` is outermost so it records every request —
            // including CORS preflights short-circuited by the cors layer.
            ServiceBuilder::new()
                .layer(middleware::from_fn(log_requests))
                .layer(cors),
        )
        .with_state(state)
}

/// Resolve the real client IP.
///
/// Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are **only trusted when the
/// TCP connection itself came from loopback** — meaning the request arrived
/// through the local Nginx reverse proxy, not directly from the internet.
/// If someone bypasses Nginx and connects straight to port 3001, the socket
/// IP is used as-is and any spoofed proxy headers are ignored.
fn client_ip(headers: &HeaderMap, socket: IpAddr) -> IpAddr {
    let from_local_proxy = match socket {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if from_local_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(ip) = xff.split(',').next().and_then(|s| s.trim().parse().ok()) {
                return ip;
            }
        }
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
        {
            return ip;
        }
    }
    socket
}

/// Morgan-style per-request logger: one coloured line per request with
/// method, path, status, latency, and client IP. Emitted at INFO so it
/// shows by default when running `ronway serve`.
async fn log_requests(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let ip = client_ip(req.headers(), addr.ip());
    let started = Instant::now();

    let response = next.run(req).await;

    let status = response.status();
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    let code = status.as_u16();
    let status_str = code.to_string();
    let status_colored = if status.is_success() {
        status_str.green().bold()
    } else if status.is_redirection() {
        status_str.cyan().bold()
    } else if status.is_client_error() {
        status_str.yellow().bold()
    } else {
        status_str.red().bold()
    };

    info!(
        "{} {} {} {} {}",
        method.as_str().magenta().bold(),
        path,
        status_colored,
        format!("{:.1}ms", elapsed_ms).dimmed(),
        ip.to_string().dimmed(),
    );

    response
}

/// Bind to `0.0.0.0:port` and serve until the process is killed. Also
/// spawns a background task that prunes the rate-limit window every
/// `RATE_LIMIT_CLEANUP_INTERVAL`.
pub async fn serve(port: u16) -> anyhow::Result<()> {
    // Where to record submitted scans. Defaults to a file in the working
    // directory; in the container image this is /data/ronway.db on a volume.
    let db_path = std::env::var("RONWAY_DB_PATH").unwrap_or_else(|_| "ronway.db".to_string());
    let store = ScanStore::connect(&db_path).await?;

    let state = AppState::with_store(store);
    spawn_cleanup_task(
        state.limiter.clone(),
        state.global_scan_count.clone(),
        state.blocked_ips.clone(),
    );

    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        anyhow::anyhow!(
            "could not bind {}: {} (is another `ronway serve` still running on this port?)",
            addr,
            e
        )
    })?;

    // Always-visible banner — even if logging is turned down, the operator
    // needs to see the server came up and where to reach it.
    println!("{}", "RonwayScanner API".bold());
    println!("  listening   http://localhost:{}", port);
    println!("  health      GET  /api/health");
    println!("  scan        POST /api/scan");
    println!("  {}", "press Ctrl-C to stop".dimmed());

    info!("RonwayScanner API listening on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn spawn_cleanup_task(
    limiter: Arc<Mutex<RateLimiter>>,
    global_count: Arc<AtomicUsize>,
    blocked_ips: Arc<Mutex<HashMap<IpAddr, Instant>>>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RATE_LIMIT_CLEANUP_INTERVAL);
        tick.tick().await; // skip immediate first tick
        loop {
            tick.tick().await;
            let now = Instant::now();
            limiter.lock().await.prune(now);
            // Reset global counter — it tracks req/min so a per-minute reset is correct.
            global_count.store(0, Ordering::Relaxed);
            // Evict expired temp-bans.
            blocked_ips
                .lock()
                .await
                .retain(|_, banned_at| banned_at.elapsed() < REPEAT_OFFENDER_BAN_DURATION);
        }
    });
}

// ─── Handlers ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn health_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, ApiError> {
    let ip = client_ip(&headers, addr.ip());
    let mut guard = state.limiter.lock().await;
    if !guard.check_and_record(ip, Instant::now()) {
        return Err(ApiError::RateLimited);
    }
    Ok(Json(HealthResponse {
        status: "ok",
        service: "ronway-scanner",
        version: env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    #[serde(default)]
    port: Option<u16>,
}

async fn scan_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ScanRequest>,
) -> Result<Json<PublicScanReport>, ApiError> {
    let client_ip = client_ip(&headers, addr.ip());

    // Temp-ban check — IPs that repeatedly exhaust their per-IP budget.
    {
        let blocks = state.blocked_ips.lock().await;
        if let Some(banned_at) = blocks.get(&client_ip) {
            if banned_at.elapsed() < REPEAT_OFFENDER_BAN_DURATION {
                warn!("blocked ip attempt: {}", client_ip);
                return Err(ApiError::RateLimited);
            }
            // Ban expired — falls through; stale entry cleaned up by background task.
        }
    }

    // Global ceiling — caps total scan load regardless of how many IPs are involved.
    let prev = state
        .global_scan_count
        .fetch_add(1, Ordering::Relaxed);
    if prev >= GLOBAL_SCAN_CEILING {
        state.global_scan_count.fetch_sub(1, Ordering::Relaxed);
        warn!("global ceiling hit: {} req/min", GLOBAL_SCAN_CEILING);
        return Err(ApiError::ServerBusy);
    }

    // Per-IP rate limit — checked after global ceiling to avoid mutex contention
    // from requests that would be rejected globally anyway.
    {
        let mut guard = state.limiter.lock().await;
        if !guard.check_and_record(client_ip, Instant::now()) {
            state.global_scan_count.fetch_sub(1, Ordering::Relaxed);
            let hits = guard.throttle_count(&client_ip);
            warn!("rate limit hit: {} (throttled {} times)", client_ip, hits);
            if hits >= REPEAT_OFFENDER_THRESHOLD {
                drop(guard);
                let mut blocks = state.blocked_ips.lock().await;
                blocks.entry(client_ip).or_insert_with(Instant::now);
                warn!("temp-banned repeat offender: {}", client_ip);
            }
            return Err(ApiError::RateLimited);
        }
    }

    let (host, port) = validate_target(&req.target, req.port)?;

    // Cache check — serve a recent result without burning a TLS connection.
    // This is the primary defence against repeated scans of the same target
    // (e.g. 500 people scanning bsp.gov.ph after a LinkedIn post).
    {
        let cache = state.scan_cache.lock().await;
        if let Some(entry) = cache.get(&(host.clone(), port)) {
            if entry.inserted_at.elapsed() < SCAN_CACHE_TTL {
                info!("cache hit {} -> {}:{}", client_ip, host, port);
                return Ok(Json((*entry.report).clone()));
            }
        }
    }

    // Acquire a scan slot — rejects immediately if MAX_CONCURRENT_SCANS are
    // already running. try_acquire avoids queuing callers behind a busy server.
    let _slot = state
        .scan_slots
        .try_acquire()
        .map_err(|_| ApiError::ServerBusy)?;

    info!("scan request {} -> {}:{}", client_ip, host, port);

    let scan = RonwayScanner::scan_with_port(&host, port);
    let scan_result = tokio::time::timeout(SCAN_TIMEOUT, scan).await;
    state.global_scan_count.fetch_sub(1, Ordering::Relaxed);
    let report = scan_result.map_err(|_| ApiError::ScanTimeout)?;

    // Persist the FULL report server-side (best-effort) before trimming it
    // down to the free-tier view returned to the public caller.
    state.store.record(client_ip, &report).await;

    let public = Arc::new(PublicScanReport::from_report(&report));

    // Populate cache for subsequent requests within the TTL window.
    {
        let mut cache = state.scan_cache.lock().await;
        cache.insert(
            (host, port),
            CacheEntry {
                report: Arc::clone(&public),
                inserted_at: Instant::now(),
            },
        );
    }

    Ok(Json((*public).clone()))
}

// ─── Scan history / aggregation ─────────────────────────────────────────────

/// Default and ceiling for how many rows a history endpoint will return.
const HISTORY_DEFAULT_LIMIT: i64 = 50;
const HISTORY_MAX_LIMIT: i64 = 500;

#[derive(Deserialize)]
struct ListParams {
    limit: Option<i64>,
    offset: Option<i64>,
}

fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(HISTORY_DEFAULT_LIMIT).clamp(1, HISTORY_MAX_LIMIT)
}

/// `GET /api/scans?limit=&offset=` — every scan, newest first.
/// Requires `Authorization: Bearer <RONWAY_ADMIN_TOKEN>`.
async fn list_scans_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<crate::store::ScanSummary>>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let limit = clamp_limit(params.limit);
    let offset = params.offset.unwrap_or(0).max(0);
    let scans = state
        .store
        .list_scans(limit, offset)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(scans))
}

/// `GET /api/scans/:domain` — scan history for one site, newest first.
/// Requires `Authorization: Bearer <RONWAY_ADMIN_TOKEN>`.
async fn scans_by_domain_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<crate::store::ScanSummary>>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let limit = clamp_limit(params.limit);
    let scans = state
        .store
        .list_scans_for_domain(&domain, limit)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(scans))
}

/// `GET /api/sites?limit=` — per-site rollup (scan count, first/last seen,
/// latest score), most-scanned first.
/// Requires `Authorization: Bearer <RONWAY_ADMIN_TOKEN>`.
async fn sites_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<crate::store::SiteAggregate>>, ApiError> {
    require_admin(&headers, &state.admin_token)?;
    let limit = clamp_limit(params.limit);
    let sites = state
        .store
        .site_aggregates(limit)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(sites))
}

/// Maximum number of remediation-action headlines exposed in the free tier.
const FREE_TIER_ACTION_PREVIEW: usize = 3;

/// The public, free-tier projection of a [`ScanReport`].
///
/// It includes the full assessment a visitor needs to understand their risk —
/// findings with descriptions, the observed TLS/cert/HTTP facts, the score —
/// but deliberately omits the detailed remediation roadmap (exact target
/// configs, rollout sequencing, effort estimates). Those fields are the BPxAI
/// consulting deliverable, so the API exposes only de-duplicated action
/// headlines plus a count and an upgrade pointer.
#[derive(Clone, Serialize)]
struct PublicScanReport {
    target: ScanTarget,
    risk_score: RiskScore,
    quantum_ready: bool,
    summary: String,
    tls: Option<TlsFinding>,
    certificate: Option<CertFinding>,
    http: Option<HttpFinding>,
    vulnerabilities: Vec<Vulnerability>,
    recommended_actions: Vec<String>,
    additional_recommendations: usize,
    upgrade: Upgrade,
}

#[derive(Clone, Serialize)]
struct Upgrade {
    message: &'static str,
    url: &'static str,
}

impl PublicScanReport {
    fn from_report(report: &ScanReport) -> Self {
        // De-duplicate recommendation action headlines, preserving priority order.
        let mut seen = std::collections::HashSet::new();
        let distinct_actions: Vec<String> = report
            .recommendations
            .iter()
            .filter(|r| seen.insert(r.action.clone()))
            .map(|r| r.action.clone())
            .collect();

        let recommended_actions: Vec<String> = distinct_actions
            .iter()
            .take(FREE_TIER_ACTION_PREVIEW)
            .cloned()
            .collect();
        let additional_recommendations =
            distinct_actions.len().saturating_sub(recommended_actions.len());

        Self {
            target: report.target.clone(),
            risk_score: report.risk_score.clone(),
            quantum_ready: report.quantum_ready,
            summary: report.summary.clone(),
            tls: report.tls.clone(),
            certificate: report.certificate.clone(),
            http: report.http.clone(),
            vulnerabilities: report.vulnerabilities.clone(),
            recommended_actions,
            additional_recommendations,
            upgrade: Upgrade {
                message: "Full PQC migration roadmap — exact configurations, rollout \
                          sequencing, and effort estimates — is delivered via a BPxAI engagement.",
                url: "https://bpxai.com/quantum",
            },
        }
    }
}

// ─── Input validation ─────────────────────────────────────────────────────

/// Normalise a user-supplied target into `(host, port)`. Strips an
/// optional `http://` / `https://` scheme and any trailing path, then
/// rejects anything that resolves to a private / loopback / link-local /
/// reserved IP — the API must not become an SSRF gadget.
pub fn validate_target(raw: &str, port_override: Option<u16>) -> Result<(String, u16), ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::InvalidTarget("target is required".into()));
    }
    if trimmed.len() > 253 {
        return Err(ApiError::InvalidTarget(
            "target exceeds 253 characters".into(),
        ));
    }

    // Strip scheme.
    let stripped = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);

    // Cut off path / query / fragment.
    let host_port = stripped
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(stripped)
        .trim();

    if host_port.is_empty() {
        return Err(ApiError::InvalidTarget("target host is empty".into()));
    }

    // Split host:port. IPv6 literals would need brackets — we don't
    // support those in v1 to keep the parser simple, and rejecting them
    // here is consistent with the bulk-file format.
    let (host, parsed_port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        if h.contains(':') {
            return Err(ApiError::InvalidTarget(
                "IPv6 literals not supported in v1".into(),
            ));
        }
        let port: u16 = p
            .parse()
            .map_err(|_| ApiError::InvalidTarget(format!("invalid port: {}", p)))?;
        if port == 0 {
            return Err(ApiError::InvalidTarget("port must be > 0".into()));
        }
        (h.to_string(), Some(port))
    } else {
        (host_port.to_string(), None)
    };

    if !is_valid_hostname_or_ip(&host) {
        return Err(ApiError::InvalidTarget(format!(
            "invalid host: {}",
            host
        )));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_disallowed_ip(&ip) {
            return Err(ApiError::InvalidTarget(format!(
                "target {} is a private / reserved address",
                ip
            )));
        }
    } else if is_disallowed_hostname(&host) {
        return Err(ApiError::InvalidTarget(format!(
            "hostname {} resolves to a private network",
            host
        )));
    }

    let port = port_override.or(parsed_port).unwrap_or(443);
    Ok((host, port))
}

/// Cheap DNS-name-or-IP-literal sanity check. Doesn't actually resolve
/// — the scanner will do that when it connects.
fn is_valid_hostname_or_ip(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    // Labels split by '.', each 1–63 chars, letters/digits/hyphens only,
    // not starting or ending with a hyphen.
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Hostnames that obviously resolve to the local machine or non-routable
/// space. We don't do live DNS resolution here — the scanner will, and
/// will fail naturally on internal-only names. This list is the cheap
/// belt-and-braces check against the easy mistakes.
fn is_disallowed_hostname(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "ip6-localhost"
            | "ip6-loopback"
            | "broadcasthost"
    ) || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".lan")
        || lower.ends_with(".home")
        || lower.ends_with(".corp")
}

fn is_disallowed_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10 CGNAT
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                // 169.254.0.0/16 already covered by is_link_local
                // 192.0.0.0/24 IETF protocol assignments
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15 benchmarking
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18)
                // 240.0.0.0/4 reserved future use
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique-local addresses
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
        }
    }
}

// ─── Rate limiter ──────────────────────────────────────────────────────────

/// Sliding-window per-IP rate limiter. In-memory — fine for a single
/// instance. Behind a load balancer you'd swap this for Redis or
/// IP-hash-routing.
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    hits: HashMap<IpAddr, Vec<Instant>>,
    /// How many times each IP has been rejected within the current window.
    throttle_count: HashMap<IpAddr, usize>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            hits: HashMap::new(),
            throttle_count: HashMap::new(),
        }
    }

    /// Record a request from `ip` at `now`. Returns `true` if the request is
    /// within the budget, `false` if it should be rejected.
    /// Also increments the throttle counter so callers can detect repeat offenders.
    pub fn check_and_record(&mut self, ip: IpAddr, now: Instant) -> bool {
        let entry = self.hits.entry(ip).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() >= self.max_requests {
            *self.throttle_count.entry(ip).or_default() += 1;
            return false;
        }
        entry.push(now);
        true
    }

    /// How many times `ip` has been throttled since the last prune.
    pub fn throttle_count(&self, ip: &IpAddr) -> usize {
        self.throttle_count.get(ip).copied().unwrap_or(0)
    }

    /// Drop every IP whose most recent hit fell outside the window.
    pub fn prune(&mut self, now: Instant) {
        self.hits.retain(|_, hits| {
            hits.retain(|t| now.duration_since(*t) < self.window);
            !hits.is_empty()
        });
        self.throttle_count.clear();
    }

    #[cfg(test)]
    pub fn tracked_ips(&self) -> usize {
        self.hits.len()
    }
}

// ─── Error type ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ApiError {
    InvalidTarget(String),
    Unauthorized,
    RateLimited,
    ServerBusy,
    ScanTimeout,
    Internal(String),
}

impl ApiError {
    /// Map an internal error to a 500 without leaking details to the client.
    fn internal(e: impl std::fmt::Display) -> Self {
        warn!("internal error: {}", e);
        ApiError::Internal("internal server error".into())
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::InvalidTarget(m) => (StatusCode::BAD_REQUEST, "invalid_target", m),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "valid Authorization: Bearer <token> header required".into(),
            ),
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                format!(
                    "rate limit: {} requests per {} seconds",
                    RATE_LIMIT_MAX_REQUESTS,
                    RATE_LIMIT_WINDOW.as_secs()
                ),
            ),
            ApiError::ServerBusy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "server_busy",
                format!(
                    "server is handling {} concurrent scans; retry shortly",
                    MAX_CONCURRENT_SCANS
                ),
            ),
            ApiError::ScanTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "scan_timeout",
                format!("scan exceeded {} seconds", SCAN_TIMEOUT.as_secs()),
            ),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", m),
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ─── validate_target ──────────────────────────────────────────

    #[test]
    fn validate_target_accepts_plain_domain() {
        let (host, port) = validate_target("example.com", None).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn validate_target_strips_https_scheme() {
        let (host, port) = validate_target("https://example.com", None).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn validate_target_strips_path_and_query() {
        let (host, _) = validate_target("https://example.com/foo?q=1", None).unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn validate_target_parses_inline_port() {
        let (host, port) = validate_target("example.com:8443", None).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn validate_target_port_override_wins() {
        let (_, port) = validate_target("example.com:8443", Some(9000)).unwrap();
        assert_eq!(port, 9000);
    }

    #[test]
    fn validate_target_rejects_empty() {
        assert!(matches!(
            validate_target("", None),
            Err(ApiError::InvalidTarget(_))
        ));
        assert!(matches!(
            validate_target("   ", None),
            Err(ApiError::InvalidTarget(_))
        ));
    }

    #[test]
    fn validate_target_rejects_localhost() {
        assert!(matches!(
            validate_target("localhost", None),
            Err(ApiError::InvalidTarget(_))
        ));
        assert!(matches!(
            validate_target("https://localhost:8080", None),
            Err(ApiError::InvalidTarget(_))
        ));
    }

    #[test]
    fn validate_target_rejects_mdns_and_internal_tlds() {
        for h in [
            "printer.local",
            "server.internal",
            "host.lan",
            "router.home",
            "host.corp",
            "foo.localhost",
        ] {
            assert!(
                matches!(validate_target(h, None), Err(ApiError::InvalidTarget(_))),
                "should reject: {}",
                h
            );
        }
    }

    #[test]
    fn validate_target_rejects_private_ipv4() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.5.1",
            "192.168.1.1",
            "169.254.169.254", // AWS / link-local
            "100.64.1.1",      // CGNAT
            "0.0.0.0",
            "255.255.255.255",
            "240.0.0.1",
            "198.18.0.1",
        ] {
            assert!(
                matches!(validate_target(ip, None), Err(ApiError::InvalidTarget(_))),
                "should reject {}",
                ip
            );
        }
    }

    #[test]
    fn validate_target_rejects_private_ipv6() {
        for ip in ["::1", "fc00::1", "fe80::1", "::"] {
            assert!(
                matches!(validate_target(ip, None), Err(ApiError::InvalidTarget(_))),
                "should reject {}",
                ip
            );
        }
    }

    #[test]
    fn validate_target_accepts_public_ipv4() {
        let (host, _) = validate_target("8.8.8.8", None).unwrap();
        assert_eq!(host, "8.8.8.8");
    }

    #[test]
    fn validate_target_rejects_garbage_characters() {
        for bad in [
            "example.com space",
            "exam ple.com",
            "host with spaces",
            "-leading.hyphen.com",
            "trailing-.com",
            "exa$mple.com",
        ] {
            assert!(
                matches!(validate_target(bad, None), Err(ApiError::InvalidTarget(_))),
                "should reject: {}",
                bad
            );
        }
    }

    #[test]
    fn validate_target_rejects_huge_input() {
        let huge = "a".repeat(300);
        assert!(matches!(
            validate_target(&huge, None),
            Err(ApiError::InvalidTarget(_))
        ));
    }

    #[test]
    fn validate_target_rejects_ipv6_literal() {
        // IPv6 in host:port form would need brackets — explicitly rejected.
        assert!(matches!(
            validate_target("2001:db8::1:443", None),
            Err(ApiError::InvalidTarget(_))
        ));
    }

    // ─── client IP resolution ─────────────────────────────────────

    #[test]
    fn client_ip_prefers_x_forwarded_for() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        let socket = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            client_ip(&h, socket),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn client_ip_falls_back_to_x_real_ip_then_socket() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.9".parse().unwrap());
        let socket = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            client_ip(&h, socket),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))
        );

        // No proxy headers → socket peer.
        let empty = HeaderMap::new();
        assert_eq!(client_ip(&empty, socket), socket);
    }

    // ─── rate limiter ─────────────────────────────────────────────

    fn ip(v: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, v))
    }

    #[test]
    fn rate_limiter_allows_up_to_max() {
        let mut rl = RateLimiter::new(3, Duration::from_secs(60));
        let now = Instant::now();
        assert!(rl.check_and_record(ip(1), now));
        assert!(rl.check_and_record(ip(1), now));
        assert!(rl.check_and_record(ip(1), now));
        assert!(!rl.check_and_record(ip(1), now));
    }

    #[test]
    fn rate_limiter_buckets_per_ip() {
        let mut rl = RateLimiter::new(1, Duration::from_secs(60));
        let now = Instant::now();
        assert!(rl.check_and_record(ip(1), now));
        assert!(rl.check_and_record(ip(2), now));
        // ip(1) is exhausted, but ip(2) and ip(3) are fine.
        assert!(!rl.check_and_record(ip(1), now));
        assert!(rl.check_and_record(ip(3), now));
    }

    #[test]
    fn rate_limiter_releases_after_window() {
        let mut rl = RateLimiter::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check_and_record(ip(1), t0));
        assert!(rl.check_and_record(ip(1), t0));
        assert!(!rl.check_and_record(ip(1), t0));

        let t1 = t0 + Duration::from_secs(61);
        assert!(
            rl.check_and_record(ip(1), t1),
            "old hits should have aged out"
        );
    }

    #[test]
    fn rate_limiter_prune_drops_empty_ips() {
        let mut rl = RateLimiter::new(5, Duration::from_secs(60));
        let t0 = Instant::now();
        rl.check_and_record(ip(1), t0);
        rl.check_and_record(ip(2), t0);
        assert_eq!(rl.tracked_ips(), 2);

        rl.prune(t0 + Duration::from_secs(120));
        assert_eq!(rl.tracked_ips(), 0);
    }
}
