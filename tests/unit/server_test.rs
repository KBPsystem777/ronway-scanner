//! Integration tests for the REST API.
//!
//! Boots the axum server on a kernel-allocated port, exercises the
//! public endpoints with reqwest, and asserts the JSON shape the
//! bpxai-landing-page frontend relies on.

use std::net::SocketAddr;
use std::time::Duration;

use ronway_scanner::server::{router, AppState};
use serde_json::{json, Value};
use tokio::net::TcpListener;

/// Bind on 127.0.0.1:0, spawn the server, and return the base URL.
async fn spawn_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(AppState::new()).into_make_service_with_connect_info::<SocketAddr>();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    format!("http://{}", addr)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap()
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let base = spawn_server().await;
    let resp = client()
        .get(format!("{}/api/health", base))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "ronway-scanner");
    assert!(body["version"].is_string());
}

#[tokio::test]
async fn cors_allows_bpxai_origin() {
    let base = spawn_server().await;
    let resp = client()
        .request(reqwest::Method::OPTIONS, format!("{}/api/scan", base))
        .header("Origin", "https://bpxai.com")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .await
        .unwrap();

    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(allow_origin, "https://bpxai.com");
}

#[tokio::test]
async fn cors_allows_localhost_dev_origin() {
    let base = spawn_server().await;
    let resp = client()
        .request(reqwest::Method::OPTIONS, format!("{}/api/scan", base))
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .await
        .unwrap();

    let allow_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(allow_origin, "http://localhost:3000");
}

#[tokio::test]
async fn cors_blocks_unknown_origin() {
    let base = spawn_server().await;
    let resp = client()
        .request(reqwest::Method::OPTIONS, format!("{}/api/scan", base))
        .header("Origin", "https://evil.example.com")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .await
        .unwrap();

    // tower-http omits the allow-origin header entirely when the origin
    // is not on the allowlist — the browser then refuses the request.
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn scan_rejects_localhost_target() {
    let base = spawn_server().await;
    let resp = client()
        .post(format!("{}/api/scan", base))
        .json(&json!({ "target": "localhost" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target");
}

#[tokio::test]
async fn scan_rejects_private_ip_target() {
    let base = spawn_server().await;
    let resp = client()
        .post(format!("{}/api/scan", base))
        .json(&json!({ "target": "192.168.1.1" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target");
}

#[tokio::test]
async fn scan_rejects_empty_target() {
    let base = spawn_server().await;
    let resp = client()
        .post(format!("{}/api/scan", base))
        .json(&json!({ "target": "" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn scan_rejects_malformed_json() {
    let base = spawn_server().await;
    let resp = client()
        .post(format!("{}/api/scan", base))
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .unwrap();

    // axum's Json extractor returns 400 for malformed bodies.
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn scan_rate_limit_kicks_in_after_10_requests() {
    let base = spawn_server().await;
    let c = client();

    // 10 requests hitting invalid_target (cheap, never reaches scanner).
    // Validation happens *after* rate-limit accounting, so each call
    // consumes one slot from the bucket.
    for i in 0..10 {
        let resp = c
            .post(format!("{}/api/scan", base))
            .json(&json!({ "target": "localhost" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "request {} should still be allowed", i);
    }

    let resp = c
        .post(format!("{}/api/scan", base))
        .json(&json!({ "target": "localhost" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "11th request should be throttled");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "rate_limited");
}

#[tokio::test]
async fn history_endpoints_return_empty_array_when_store_disabled() {
    let base = spawn_server().await;
    let c = client();

    for path in ["/api/scans", "/api/sites", "/api/scans/example.com"] {
        let resp = c.get(format!("{}{}", base, path)).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{} should be 200", path);
        let body: Value = resp.json().await.unwrap();
        assert!(body.is_array(), "{} should return a JSON array", path);
        assert_eq!(
            body.as_array().unwrap().len(),
            0,
            "{} should be empty with persistence disabled",
            path
        );
    }
}

#[tokio::test]
#[ignore = "makes real outbound HTTPS connection; run with `cargo test -- --ignored`"]
async fn scan_returns_full_report_for_real_target() {
    let base = spawn_server().await;
    let resp = client()
        .post(format!("{}/api/scan", base))
        .json(&json!({ "target": "example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    // Free-tier shape contract the frontend relies on.
    assert_eq!(body["target"]["domain"], "example.com");
    assert!(body["risk_score"]["value"].is_number());
    assert!(body["risk_score"]["level"].is_string());
    assert!(body["vulnerabilities"].is_array());
    assert!(body["tls"].is_object());
    // Free tier exposes action headlines + an upgrade pointer, NOT the
    // detailed remediation roadmap.
    assert!(body["recommended_actions"].is_array());
    assert!(body["additional_recommendations"].is_number());
    assert!(body["upgrade"]["url"].is_string());
    assert!(body.get("recommendations").is_none());
}
