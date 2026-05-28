//! Phase 10: PDF reporter.
//!
//! Produces a CISO-ready PDF using `printpdf`'s built-in Helvetica fonts —
//! no external font files, no shell-outs, no headless browsers. The output
//! contains the executive summary, the risk score, the TLS/cert/HTTP
//! findings, the vulnerability list, and the prioritised recommendations.

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use printpdf::{
    BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference,
};

use crate::models::finding::{CertFinding, HttpFinding, Recommendation, TlsFinding, Vulnerability};
use crate::models::report::ScanReport;
use crate::models::risk::RiskLevel;

// A4 portrait, in millimetres.
const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_X_MM: f32 = 15.0;
const MARGIN_TOP_MM: f32 = 20.0;
const MARGIN_BOTTOM_MM: f32 = 18.0;

// Font sizing rules of thumb — Helvetica is roughly 0.5em advance per
// character, so 90 chars at 10pt fits the 180mm content width with margin.
const CHARS_PER_LINE_BODY: usize = 95;
const CHARS_PER_LINE_TITLE: usize = 60;

pub struct PdfReporter;

impl PdfReporter {
    pub fn render(report: &ScanReport, out_path: &Path) -> Result<()> {
        let (doc, page1, layer1) = PdfDocument::new(
            format!("RonwayScanner — {}", report.target.domain),
            Mm(PAGE_WIDTH_MM),
            Mm(PAGE_HEIGHT_MM),
            "Layer 1",
        );

        let regular = doc
            .add_builtin_font(BuiltinFont::Helvetica)
            .map_err(|e| anyhow!("failed to add Helvetica: {}", e))?;
        let bold = doc
            .add_builtin_font(BuiltinFont::HelveticaBold)
            .map_err(|e| anyhow!("failed to add Helvetica-Bold: {}", e))?;

        let fonts = Fonts {
            regular: regular.clone(),
            bold: bold.clone(),
        };

        let mut cursor = Cursor::new(&doc, page1, layer1);
        write_report(&mut cursor, &fonts, report);

        let file = File::create(out_path)
            .with_context(|| format!("failed to create PDF at {}", out_path.display()))?;
        doc.save(&mut BufWriter::new(file))
            .map_err(|e| anyhow!("failed to write PDF: {}", e))?;
        Ok(())
    }
}

struct Fonts {
    regular: IndirectFontRef,
    bold: IndirectFontRef,
}

/// Lays out lines top-down, starting a new page when we run out of room.
struct Cursor<'a> {
    doc: &'a PdfDocumentReference,
    layer: PdfLayerReference,
    y_mm: f32,
}

impl<'a> Cursor<'a> {
    fn new(
        doc: &'a PdfDocumentReference,
        page: printpdf::PdfPageIndex,
        layer: printpdf::PdfLayerIndex,
    ) -> Self {
        let layer = doc.get_page(page).get_layer(layer);
        Self {
            doc,
            layer,
            y_mm: PAGE_HEIGHT_MM - MARGIN_TOP_MM,
        }
    }

    fn ensure_room(&mut self, needed_mm: f32) {
        if self.y_mm - needed_mm < MARGIN_BOTTOM_MM {
            let (new_page, new_layer) =
                self.doc
                    .add_page(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), "Layer 1");
            self.layer = self.doc.get_page(new_page).get_layer(new_layer);
            self.y_mm = PAGE_HEIGHT_MM - MARGIN_TOP_MM;
        }
    }

    fn write_line(
        &mut self,
        text: &str,
        font: &IndirectFontRef,
        size_pt: f32,
        line_height_mm: f32,
    ) {
        self.ensure_room(line_height_mm);
        self.layer.use_text(
            sanitize(text),
            size_pt,
            Mm(MARGIN_X_MM),
            Mm(self.y_mm),
            font,
        );
        self.y_mm -= line_height_mm;
    }

    fn write_wrapped(
        &mut self,
        text: &str,
        font: &IndirectFontRef,
        size_pt: f32,
        line_height_mm: f32,
        chars_per_line: usize,
    ) {
        for raw_line in text.split('\n') {
            if raw_line.is_empty() {
                self.y_mm -= line_height_mm * 0.5;
                continue;
            }
            for line in wrap_line(raw_line, chars_per_line) {
                self.write_line(&line, font, size_pt, line_height_mm);
            }
        }
    }

    fn vskip(&mut self, mm: f32) {
        self.y_mm -= mm;
    }
}

fn write_report(cursor: &mut Cursor, fonts: &Fonts, report: &ScanReport) {
    // Cover header
    cursor.write_line("RonwayScanner", &fonts.bold, 22.0, 9.0);
    cursor.write_line(
        "Post-Quantum Cryptographic Vulnerability Report",
        &fonts.regular,
        11.0,
        6.0,
    );
    cursor.vskip(3.0);

    // Target block
    cursor.write_line(
        &format!("Target:   {}:{}", report.target.domain, report.target.port),
        &fonts.bold,
        11.0,
        5.5,
    );
    cursor.write_line(
        &format!(
            "Scanned:  {}    Duration: {} ms",
            report.target.scanned_at, report.target.scan_duration_ms
        ),
        &fonts.regular,
        10.0,
        5.0,
    );
    cursor.vskip(3.0);

    // Risk score block
    let score_line = if report.risk_score.level == RiskLevel::Unknown {
        "RISK SCORE: N/A  (scan incomplete — endpoint not assessed)".to_string()
    } else {
        format!(
            "RISK SCORE: {}/100  ({})",
            report.risk_score.value,
            report.risk_score.level.label()
        )
    };
    cursor.write_line(&score_line, &fonts.bold, 14.0, 7.0);
    if report.risk_score.harvest_risk {
        cursor.write_line(
            "[!] Harvest-now-decrypt-later risk detected.",
            &fonts.bold,
            10.0,
            5.0,
        );
    }
    cursor.write_line(
        &format!(
            "Quantum-ready: {}",
            if report.quantum_ready { "YES" } else { "NO" }
        ),
        &fonts.regular,
        10.0,
        5.0,
    );
    cursor.vskip(2.0);

    section_header(cursor, fonts, "Executive summary");
    cursor.write_wrapped(
        &report.summary,
        &fonts.regular,
        10.0,
        5.0,
        CHARS_PER_LINE_BODY,
    );
    cursor.vskip(2.0);

    write_tls(cursor, fonts, &report.tls);
    write_cert(cursor, fonts, &report.certificate);
    write_http(cursor, fonts, &report.http);
    write_vulns(cursor, fonts, &report.vulnerabilities);
    write_recs(cursor, fonts, &report.recommendations);

    cursor.vskip(4.0);
    cursor.write_line(
        &format!(
            "Generated by RonwayScanner v{} — BPxAI — All Rights Reserved",
            env!("CARGO_PKG_VERSION")
        ),
        &fonts.regular,
        8.0,
        4.0,
    );
}

fn section_header(cursor: &mut Cursor, fonts: &Fonts, title: &str) {
    cursor.vskip(1.5);
    cursor.write_line(title, &fonts.bold, 12.0, 6.0);
    cursor.write_line(
        "-----------------------------------------------------------------------",
        &fonts.regular,
        9.0,
        3.5,
    );
}

fn write_tls(cursor: &mut Cursor, fonts: &Fonts, tls: &Option<TlsFinding>) {
    section_header(cursor, fonts, "TLS");
    match tls {
        Some(t) => {
            kv(
                cursor,
                fonts,
                "Protocol",
                &flag_str(&t.protocol_version, t.protocol_vulnerable),
            );
            kv(
                cursor,
                fonts,
                "Cipher suite",
                &flag_str(&t.cipher_suite, t.cipher_vulnerable),
            );
            kv(
                cursor,
                fonts,
                "Key exchange",
                &flag_str(&t.key_exchange, t.key_exchange_vulnerable),
            );
            kv(cursor, fonts, "Compression", &t.compression);
        }
        None => cursor.write_line("(TLS scan failed)", &fonts.regular, 10.0, 5.0),
    }
}

fn write_cert(cursor: &mut Cursor, fonts: &Fonts, cert: &Option<CertFinding>) {
    section_header(cursor, fonts, "Certificate");
    match cert {
        Some(c) => {
            kv(cursor, fonts, "Subject", &c.subject);
            kv(cursor, fonts, "Issuer", &c.issuer);
            kv(
                cursor,
                fonts,
                "Key",
                &flag_str(&c.key_algorithm, c.key_algorithm_vulnerable),
            );
            kv(
                cursor,
                fonts,
                "Signature",
                &flag_str(&c.signature_algorithm, c.signature_algorithm_vulnerable),
            );
            kv(cursor, fonts, "Valid from", &c.valid_from);
            kv(cursor, fonts, "Valid until", &c.valid_until);
            kv(
                cursor,
                fonts,
                "Days remaining",
                &format!(
                    "{}{}",
                    c.days_remaining,
                    if c.is_expired { " (EXPIRED)" } else { "" }
                ),
            );
            kv(
                cursor,
                fonts,
                "Self-signed",
                if c.is_self_signed { "yes" } else { "no" },
            );
            kv(
                cursor,
                fonts,
                "CT logged",
                if c.ct_logged { "yes" } else { "no" },
            );
        }
        None => cursor.write_line("(Certificate scan failed)", &fonts.regular, 10.0, 5.0),
    }
}

fn write_http(cursor: &mut Cursor, fonts: &Fonts, http: &Option<HttpFinding>) {
    section_header(cursor, fonts, "HTTP headers");
    match http {
        Some(h) => {
            let hsts = if h.hsts_enabled {
                match h.hsts_max_age {
                    Some(n) => format!("enabled (max-age = {} s)", n),
                    None => "enabled (no max-age)".into(),
                }
            } else {
                "MISSING".into()
            };
            kv(cursor, fonts, "HSTS", &hsts);
            kv(
                cursor,
                fonts,
                "CSP",
                if h.csp_present { "present" } else { "missing" },
            );
            kv(
                cursor,
                fonts,
                "X-Frame-Options",
                h.x_frame_options.as_deref().unwrap_or("-"),
            );
            kv(
                cursor,
                fonts,
                "Server header",
                h.server_header.as_deref().unwrap_or("-"),
            );
        }
        None => cursor.write_line("(HTTP scan failed)", &fonts.regular, 10.0, 5.0),
    }
}

fn write_vulns(cursor: &mut Cursor, fonts: &Fonts, vulns: &[Vulnerability]) {
    section_header(cursor, fonts, &format!("Vulnerabilities ({})", vulns.len()));
    if vulns.is_empty() {
        cursor.write_line("None detected.", &fonts.regular, 10.0, 5.0);
        return;
    }
    for v in vulns {
        cursor.vskip(1.0);
        cursor.write_line(
            &format!("[{}] {} — {}", severity_label(&v.severity), v.id, v.title),
            &fonts.bold,
            10.5,
            5.0,
        );
        cursor.write_wrapped(
            &v.description,
            &fonts.regular,
            9.5,
            4.5,
            CHARS_PER_LINE_BODY,
        );
        cursor.write_line(
            &format!(
                "    NIST: {} | CVSS-equivalent: {:.1}",
                v.nist_reference, v.cvss_equivalent
            ),
            &fonts.regular,
            9.0,
            4.5,
        );
    }
}

fn write_recs(cursor: &mut Cursor, fonts: &Fonts, recs: &[Recommendation]) {
    section_header(cursor, fonts, &format!("Recommendations ({})", recs.len()));
    if recs.is_empty() {
        cursor.write_line("None required.", &fonts.regular, 10.0, 5.0);
        return;
    }
    for r in recs {
        cursor.vskip(1.0);
        cursor.write_line(
            &format!("P{}. {}", r.priority, r.action),
            &fonts.bold,
            10.5,
            5.0,
        );
        cursor.write_wrapped(
            &format!("    Current:      {}", r.current),
            &fonts.regular,
            9.5,
            4.5,
            CHARS_PER_LINE_BODY,
        );
        cursor.write_wrapped(
            &format!("    Replace with: {}", r.replace_with),
            &fonts.regular,
            9.5,
            4.5,
            CHARS_PER_LINE_BODY,
        );
        cursor.write_line(
            &format!(
                "    Effort: {} weeks | NIST: {}",
                r.effort_weeks, r.nist_algorithm
            ),
            &fonts.regular,
            9.0,
            4.5,
        );
    }
}

fn kv(cursor: &mut Cursor, fonts: &Fonts, key: &str, value: &str) {
    let line = format!("{:<18}{}", key, value);
    cursor.write_wrapped(&line, &fonts.regular, 10.0, 5.0, CHARS_PER_LINE_TITLE + 30);
}

fn flag_str(value: &str, vulnerable: bool) -> String {
    if vulnerable {
        format!("{}  [VULNERABLE]", value)
    } else {
        value.to_string()
    }
}

fn severity_label(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "CRIT",
        RiskLevel::High => "HIGH",
        RiskLevel::Medium => "MED ",
        RiskLevel::Low => "LOW ",
        RiskLevel::Pass => "PASS",
        RiskLevel::Unknown => "N/A ",
    }
}

/// printpdf writes WinAnsi by default — strip characters outside that
/// range so non-ASCII subject lines don't crash the writer.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if (c as u32) <= 0xFF { c } else { '?' })
        .collect()
}

/// Greedy word-wrap by character count. Words longer than the limit are
/// hard-broken so we never emit an over-long line.
fn wrap_line(text: &str, max_chars: usize) -> Vec<String> {
    if text.len() <= max_chars {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if word.len() > max_chars {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            for chunk in word.as_bytes().chunks(max_chars) {
                lines.push(String::from_utf8_lossy(chunk).into_owned());
            }
            continue;
        }
        let projected = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };
        if projected > max_chars {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        } else {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_line_short_returns_single_line() {
        assert_eq!(
            wrap_line("hello world", 80),
            vec!["hello world".to_string()]
        );
    }

    #[test]
    fn wrap_line_breaks_at_word_boundaries() {
        let lines = wrap_line("one two three four five", 9);
        assert_eq!(lines, vec!["one two", "three", "four five"]);
    }

    #[test]
    fn wrap_line_hard_breaks_long_words() {
        let lines = wrap_line("aaaaaaaaaa", 4);
        assert_eq!(lines, vec!["aaaa", "aaaa", "aa"]);
    }

    #[test]
    fn sanitize_strips_high_codepoints() {
        let s = sanitize("hello \u{1F600} world");
        assert_eq!(s, "hello ? world");
    }

    #[test]
    fn sanitize_keeps_latin1() {
        assert_eq!(sanitize("café"), "café");
    }
}
