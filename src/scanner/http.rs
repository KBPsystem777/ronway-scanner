//! Phase 8: HTTP security headers scanner.
//!
//! Issues a single GET to `https://host:port/` with a 10-second timeout
//! and a permissive TLS verifier (the cert is graded by Phase 7, not us),
//! then inspects the response headers for:
//!
//! - **Strict-Transport-Security** — present? `max-age` value?
//! - **Content-Security-Policy** — present?
//! - **X-Frame-Options** — value, if any
//! - **Server** — full header value, if any
//!
//! The output is an `HttpFinding` that the classifier later turns into
//! `NO_HSTS` and `SERVER_HEADER_LEAK` vulnerabilities.

use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::header::{
    HeaderMap, CONTENT_SECURITY_POLICY, SERVER, STRICT_TRANSPORT_SECURITY, X_FRAME_OPTIONS,
};
use reqwest::{Client, ClientBuilder};
use tracing::debug;

use crate::models::finding::HttpFinding;

const TIMEOUT_SECS: u64 = 10;
const USER_AGENT: &str = concat!("RonwayScanner/", env!("CARGO_PKG_VERSION"));

pub struct HttpScanner;

impl HttpScanner {
    pub async fn scan(host: &str, port: u16) -> Result<HttpFinding> {
        let url = format!("https://{}:{}/", host, port);
        debug!("HTTP scan starting: {}", url);

        let client = build_client()?;
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("HTTP request to {} failed: {}", url, e))?;

        Ok(parse_headers(response.headers()))
    }
}

fn build_client() -> Result<Client> {
    ClientBuilder::new()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(TIMEOUT_SECS))
        .user_agent(USER_AGENT)
        // The scanner must reach servers with broken certs — Phase 7 grades
        // the cert separately, so we don't reject the connection here.
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        // Follow redirects but don't loop forever.
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| anyhow!("failed to build HTTP client: {}", e))
}

fn parse_headers(headers: &HeaderMap) -> HttpFinding {
    let hsts_value = header_str(headers, STRICT_TRANSPORT_SECURITY.as_str());
    let hsts_enabled = hsts_value.is_some();
    let hsts_max_age = hsts_value.as_deref().and_then(parse_hsts_max_age);

    HttpFinding {
        hsts_enabled,
        hsts_max_age,
        csp_present: headers.contains_key(CONTENT_SECURITY_POLICY),
        x_frame_options: header_str(headers, X_FRAME_OPTIONS.as_str()),
        server_header: header_str(headers, SERVER.as_str()),
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// Parse the `max-age=N` directive out of an HSTS header value. Returns
/// `None` if the directive is missing or unparseable. Quoted values
/// (`max-age="31536000"`) are tolerated.
fn parse_hsts_max_age(value: &str) -> Option<u64> {
    for part in value.split(';') {
        let part = part.trim();
        let lower = part.to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("max-age") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let raw = rest.trim().trim_matches('"');
        if let Ok(n) = raw.parse::<u64>() {
            return Some(n);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderName, HeaderValue};

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            let name = HeaderName::from_bytes(k.as_bytes()).unwrap();
            h.insert(name, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn parse_hsts_max_age_basic() {
        assert_eq!(parse_hsts_max_age("max-age=31536000"), Some(31_536_000));
    }

    #[test]
    fn parse_hsts_max_age_with_directives() {
        assert_eq!(
            parse_hsts_max_age("max-age=63072000; includeSubDomains; preload"),
            Some(63_072_000)
        );
    }

    #[test]
    fn parse_hsts_max_age_quoted() {
        assert_eq!(parse_hsts_max_age("max-age=\"3600\""), Some(3_600));
    }

    #[test]
    fn parse_hsts_max_age_case_insensitive_directive() {
        assert_eq!(parse_hsts_max_age("Max-Age=600"), Some(600));
    }

    #[test]
    fn parse_hsts_max_age_missing_returns_none() {
        assert_eq!(parse_hsts_max_age("includeSubDomains"), None);
    }

    #[test]
    fn parse_hsts_max_age_unparseable_returns_none() {
        assert_eq!(parse_hsts_max_age("max-age=forever"), None);
    }

    #[test]
    fn parse_headers_full_security_set() {
        let headers = make_headers(&[
            (
                "strict-transport-security",
                "max-age=31536000; includeSubDomains",
            ),
            ("content-security-policy", "default-src 'self'"),
            ("x-frame-options", "DENY"),
            ("server", "nginx/1.25.3"),
        ]);
        let finding = parse_headers(&headers);
        assert!(finding.hsts_enabled);
        assert_eq!(finding.hsts_max_age, Some(31_536_000));
        assert!(finding.csp_present);
        assert_eq!(finding.x_frame_options.as_deref(), Some("DENY"));
        assert_eq!(finding.server_header.as_deref(), Some("nginx/1.25.3"));
    }

    #[test]
    fn parse_headers_no_security_headers() {
        let finding = parse_headers(&HeaderMap::new());
        assert!(!finding.hsts_enabled);
        assert!(finding.hsts_max_age.is_none());
        assert!(!finding.csp_present);
        assert!(finding.x_frame_options.is_none());
        assert!(finding.server_header.is_none());
    }

    #[test]
    fn parse_headers_hsts_without_max_age() {
        let headers = make_headers(&[("strict-transport-security", "includeSubDomains")]);
        let finding = parse_headers(&headers);
        assert!(finding.hsts_enabled);
        assert!(finding.hsts_max_age.is_none());
    }
}
