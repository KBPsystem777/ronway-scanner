//! Phase 11: command-line interface for the `ronway` binary.
//!
//! Subcommands:
//! - `scan`     run a single scan and emit text / JSON / HTML / PDF
//! - `bulk`     scan a newline-delimited list of targets concurrently
//! - `monitor`  re-scan a target on an interval and print risk deltas
//! - `version`  print the binary version
//!
//! Exit codes (per CLAUDE.md):
//! - `0` — top-level risk score < 60 (or any non-scan command succeeded)
//! - `1` — risk score >= 60 (intended as a CI/CD gate)

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use futures::stream::{FuturesUnordered, StreamExt};
use ronway_scanner::models::report::ScanReport;
use ronway_scanner::models::risk::RiskLevel;
use ronway_scanner::report::html::HtmlReporter;
use ronway_scanner::report::json::JsonReporter;
use ronway_scanner::report::pdf::PdfReporter;
use ronway_scanner::RonwayScanner;
use tokio::sync::Semaphore;
use tracing::warn;

const FAIL_SCORE: u8 = 60;
const DEFAULT_BULK_CONCURRENCY: usize = 8;

#[derive(Parser)]
#[command(
    name = "ronway",
    version,
    about = "Post-quantum cryptographic vulnerability scanner",
    long_about = "RonwayScanner — Know your quantum risk before it knows you.\n\
                  Scans remote HTTPS targets for TLS / certificate / HTTP weaknesses \
                  and grades them against NIST PQC guidance (FIPS 203/204/205)."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a single target.
    Scan {
        #[arg(long, short)]
        target: String,

        #[arg(long, default_value_t = 443)]
        port: u16,

        #[arg(long, value_enum, default_value_t = OutputMode::Text)]
        output: OutputMode,

        /// Write the rendered report to this file instead of stdout.
        /// Required for `--output pdf`.
        #[arg(long)]
        out_file: Option<PathBuf>,
    },

    /// Scan many targets in parallel from a newline-delimited file.
    Bulk {
        /// Path to a file with one `host` or `host:port` per line.
        /// Lines starting with `#` are ignored.
        #[arg(long)]
        targets: PathBuf,

        /// Output mode for the per-target summary.
        #[arg(long, value_enum, default_value_t = OutputMode::Text)]
        output: OutputMode,

        /// Maximum concurrent scans.
        #[arg(long, default_value_t = DEFAULT_BULK_CONCURRENCY)]
        concurrency: usize,
    },

    /// Re-scan a target on a fixed interval and report when the score changes.
    Monitor {
        #[arg(long, short)]
        target: String,

        #[arg(long, default_value_t = 443)]
        port: u16,

        /// Interval between scans, in minutes.
        #[arg(long, default_value_t = 1440)]
        interval: u64,
    },

    /// Run the HTTP API server (POST /api/scan, GET /api/health).
    Serve {
        /// Port to bind on. Binds 0.0.0.0:<port>.
        #[arg(long, default_value_t = 3001)]
        port: u16,
    },

    /// Print the binary version.
    Version,
}

#[derive(Copy, Clone, ValueEnum, Debug, PartialEq)]
enum OutputMode {
    Text,
    Json,
    Html,
    Pdf,
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();
    let Some(command) = cli.command else {
        print_welcome();
        return ExitCode::SUCCESS;
    };
    match command {
        Commands::Scan {
            target,
            port,
            output,
            out_file,
        } => match run_scan(&target, port, output, out_file.as_deref()).await {
            // An unreachable target is an operational failure, not a risk
            // verdict — surface it as a setup error (exit 2), not a gate fail.
            Ok(report) if report.is_unreachable() => ExitCode::from(2),
            Ok(report) => exit_for_score(report.risk_score.value),
            Err(e) => {
                eprintln!("{} {:#}", "error:".red().bold(), e);
                ExitCode::from(2)
            }
        },
        Commands::Bulk {
            targets,
            output,
            concurrency,
        } => match run_bulk(&targets, output, concurrency).await {
            Ok(worst) => exit_for_score(worst),
            Err(e) => {
                eprintln!("{} {:#}", "error:".red().bold(), e);
                ExitCode::from(2)
            }
        },
        Commands::Monitor {
            target,
            port,
            interval,
        } => match run_monitor(&target, port, interval).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{} {:#}", "error:".red().bold(), e);
                ExitCode::from(2)
            }
        },
        Commands::Serve { port } => match ronway_scanner::server::serve(port).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{} {:#}", "error:".red().bold(), e);
                ExitCode::from(2)
            }
        },
        Commands::Version => {
            println!("ronway {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}

fn init_tracing() {
    // Respect RUST_LOG when set; otherwise stay quiet for the rest of the
    // ecosystem but surface our own INFO logs — that's what makes the
    // `serve` startup banner and per-request log lines visible by default.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,ronway_scanner=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn exit_for_score(score: u8) -> ExitCode {
    if score >= FAIL_SCORE {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

async fn run_scan(
    target: &str,
    port: u16,
    output: OutputMode,
    out_file: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let (host, inline_port) = normalize_target(target)?;
    let port = inline_port.unwrap_or(port);
    let report = RonwayScanner::scan_with_port(&host, port).await;
    emit_report(&report, output, out_file)?;
    Ok(report)
}

/// Turn a user-supplied target into `(host, optional inline port)`. Strips an
/// `http(s)://` scheme and any trailing path / query / fragment, so
/// `https://example.com/foo`, `example.com`, and `example.com:8443` all
/// resolve to the bare host the TLS scanner actually needs to connect to.
fn normalize_target(raw: &str) -> Result<(String, Option<u16>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("target is required");
    }
    let stripped = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_port = stripped
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(stripped)
        .trim();
    if host_port.is_empty() {
        bail!("target '{}' has no host", raw);
    }

    if let Some((host, port)) = host_port.rsplit_once(':') {
        // Bracketless IPv6 (multiple colons) is not supported in v1.
        if host.contains(':') {
            bail!("IPv6 targets are not supported in v1: {}", raw);
        }
        let port: u16 = port
            .parse()
            .with_context(|| format!("invalid port in target '{}'", raw))?;
        if port == 0 {
            bail!("port must be greater than 0 in target '{}'", raw);
        }
        Ok((host.to_string(), Some(port)))
    } else {
        Ok((host_port.to_string(), None))
    }
}

fn emit_report(
    report: &ScanReport,
    output: OutputMode,
    out_file: Option<&std::path::Path>,
) -> Result<()> {
    match output {
        OutputMode::Text => {
            let rendered = render_text(report);
            write_or_stdout(out_file, &rendered)?;
        }
        OutputMode::Json => {
            let json = JsonReporter::render(report)?;
            write_or_stdout(out_file, &json)?;
        }
        OutputMode::Html => {
            let html = HtmlReporter::render(report);
            write_or_stdout(out_file, &html)?;
        }
        OutputMode::Pdf => {
            let path = out_file
                .ok_or_else(|| anyhow::anyhow!("--output pdf requires --out-file <path>"))?;
            PdfReporter::render(report, path)?;
            eprintln!(
                "{} wrote PDF report to {}",
                "ok:".green().bold(),
                path.display()
            );
        }
    }
    Ok(())
}

fn write_or_stdout(out_file: Option<&std::path::Path>, content: &str) -> Result<()> {
    match out_file {
        Some(p) => {
            std::fs::write(p, content).with_context(|| format!("failed to write {}", p.display()))
        }
        None => {
            println!("{}", content);
            Ok(())
        }
    }
}

fn render_text(report: &ScanReport) -> String {
    use std::collections::HashSet;

    let mut out = String::new();
    out.push_str(&banner());

    let rule = "─".repeat(56);
    out.push_str(&format!("{}\n", rule.dimmed()));
    out.push_str(&format!(
        " {}   {}:{}\n",
        "Target ".bold(),
        report.target.domain.bold(),
        report.target.port
    ));
    out.push_str(&format!(
        " {}  {}  ({} ms)\n",
        "Scanned".bold(),
        report.target.scanned_at,
        report.target.scan_duration_ms
    ));
    out.push_str(&format!("{}\n", rule.dimmed()));

    // Did the scanner reach the endpoint at all? If nothing answered there's
    // nothing to grade — say so plainly instead of presenting a score.
    if report.is_unreachable() {
        out.push_str(&render_unreachable(report));
        out.push_str(&signature());
        return out;
    }

    // ── Score ──────────────────────────────────────────────────────────
    out.push_str(&format!(
        "\n {}   {}{}   {}\n",
        "Risk score".bold(),
        report.risk_score.value.to_string().bold(),
        "/100".dimmed(),
        colorize_level(&report.risk_score.level, report.risk_score.level.label())
    ));
    out.push_str(&format!(
        "   {}\n",
        level_tagline(&report.risk_score.level).dimmed()
    ));
    if report.risk_score.harvest_risk {
        out.push_str(&format!(
            " {}\n   {}\n",
            "Harvest-now-decrypt-later risk".red().bold(),
            "traffic captured today can be decrypted once quantum hardware arrives".red()
        ));
    }
    out.push_str(&format!(
        " {}  {}\n",
        "Quantum-ready:".bold(),
        if report.quantum_ready {
            "yes".green().bold().to_string()
        } else {
            "no".red().bold().to_string()
        }
    ));

    // ── What we observed ───────────────────────────────────────────────
    out.push_str(&format!("\n {}\n", "What we observed".bold().underline()));
    match &report.tls {
        Some(t) => out.push_str(&format!(
            "   {}   {} · {} · kx={}\n",
            "TLS ".cyan().bold(),
            t.protocol_version,
            t.cipher_suite,
            t.key_exchange
        )),
        None => out.push_str(&format!(
            "   {}   {}\n",
            "TLS ".cyan().bold(),
            "not available".dimmed()
        )),
    }
    match &report.certificate {
        Some(c) => out.push_str(&format!(
            "   {}  {} · {} · {} · expires in {} days\n",
            "Cert".cyan().bold(),
            c.subject,
            c.key_algorithm,
            c.signature_algorithm,
            c.days_remaining
        )),
        None => out.push_str(&format!(
            "   {}  {}\n",
            "Cert".cyan().bold(),
            "not available".dimmed()
        )),
    }
    match &report.http {
        Some(h) => out.push_str(&format!(
            "   {}  HSTS {} · CSP {} · server {}\n",
            "HTTP".cyan().bold(),
            yesno(h.hsts_enabled),
            yesno(h.csp_present),
            h.server_header.as_deref().unwrap_or("—")
        )),
        None => out.push_str(&format!(
            "   {}  {}\n",
            "HTTP".cyan().bold(),
            "not available".dimmed()
        )),
    }

    // ── Findings ───────────────────────────────────────────────────────
    out.push_str(&format!(
        "\n {} {}\n",
        "Findings".bold().underline(),
        format!("({})", report.vulnerabilities.len()).dimmed()
    ));
    if report.vulnerabilities.is_empty() {
        out.push_str(&format!(
            "   {}\n",
            "No quantum-vulnerable cryptography detected.".green()
        ));
    } else {
        for v in &report.vulnerabilities {
            out.push_str(&format!(
                "   [{}] {}\n",
                colorize_level(&v.severity, v.severity.label()),
                v.title.bold()
            ));
            if !v.description.is_empty() {
                out.push_str(&format!("        {}\n", v.description.dimmed()));
            }
            out.push_str(&format!(
                "        {}\n",
                format!("ref {} · CVSS≈{:.1}", v.nist_reference, v.cvss_equivalent).dimmed()
            ));
        }
    }

    // ── Plain-English interpretation ───────────────────────────────────
    out.push_str(&format!(
        "\n {}\n   {}\n",
        "What this means for you".bold().underline(),
        report.summary
    ));

    // ── Remediation teaser (the detailed roadmap is the paid deliverable) ─
    if !report.recommendations.is_empty() {
        out.push_str(&format!(
            "\n {}\n",
            "Recommended direction".bold().underline()
        ));
        let mut seen = HashSet::new();
        let distinct: Vec<&str> = report
            .recommendations
            .iter()
            .map(|r| r.action.as_str())
            .filter(|a| seen.insert(*a))
            .collect();
        for action in distinct.iter().take(3) {
            out.push_str(&format!("   {} {}\n", "•".cyan(), action));
        }
        if distinct.len() > 3 {
            out.push_str(&format!(
                "   {}\n",
                format!("(+{} more)", distinct.len() - 3).dimmed()
            ));
        }
        out.push_str(&format!(
            "\n   {}\n   {}\n   {}  {}\n",
            "The full PQC migration roadmap — exact configurations, rollout".dimmed(),
            "sequencing, and effort estimates — is a BPxAI engagement.".dimmed(),
            "→".cyan().bold(),
            "bpxai.com/quantum".cyan().underline()
        ));
    }

    out.push_str(&signature());
    out
}

/// Welcome screen shown when `ronway` (or `cargo run`) is invoked with no
/// subcommand — the ASCII wordmark, a quickstart, and the maker's mark.
fn print_welcome() {
    // Pad the plain command BEFORE colouring so ANSI codes don't break the
    // column alignment.
    fn row(cmd: &str, desc: &str) -> String {
        format!("   {}  {}", format!("{:<54}", cmd).cyan(), desc.dimmed())
    }
    print!("{}", banner());
    println!(
        "  {}",
        "A post-quantum TLS / certificate / HTTP scanner.".dimmed()
    );
    println!("\n {}", "Get started".bold().underline());
    println!("{}", row("ronway scan -t example.com", "scan a domain"));
    println!(
        "{}",
        row(
            "ronway scan -t example.com --output html --out-file r.html",
            "write an HTML report"
        )
    );
    println!(
        "{}",
        row("ronway bulk --targets domains.txt", "scan many from a file")
    );
    println!("{}", row("ronway serve --port 3001", "run the JSON API"));
    println!("{}", row("ronway --help", "full command reference"));
    print!("{}", signature());
}

/// ASCII wordmark shown atop every text report.
fn banner() -> String {
    let art = r#"
   ____
  |  _ \ ___  _ ____      ____ _ _   _
  | |_) / _ \| '_ \ \ /\ / / _` | | | |
  |  _ < (_) | | | \ V  V / (_| | |_| |
  |_| \_\___/|_| |_|\_/\_/ \__,_|\__, |
                                 |___/ "#;
    format!(
        "{}\n  {}\n  {}\n\n",
        art.cyan().bold(),
        "⚛  Post-Quantum Cryptographic Scanner".bright_cyan(),
        "\"Know your quantum risk before it knows you.\"".dimmed()
    )
}

/// Maker's mark printed at the foot of every text report.
fn signature() -> String {
    let rule = "─".repeat(56);
    format!(
        "\n{}\n {} {}\n {} · {} · {}\n{}\n",
        rule.dimmed(),
        "Made by".dimmed(),
        "Koleen BP".bold(),
        "BPxAI".bold(),
        "bpxai.com".cyan(),
        "koleenbp.com".cyan(),
        rule.dimmed()
    )
}

fn render_unreachable(report: &ScanReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "\n {} could not complete a TLS handshake with {}:{}.\n\n",
        "Scan incomplete:".yellow().bold(),
        report.target.domain,
        report.target.port
    ));
    s.push_str(" Likely causes:\n");
    s.push_str("   • the host is unreachable, or the port is closed / firewalled\n");
    s.push_str("   • the service on that port does not speak TLS\n");
    s.push_str("   • the hostname did not resolve in DNS\n");
    s.push_str(&format!(
        "\n {}  use a bare hostname such as {} and confirm the port is serving HTTPS.\n",
        "Tip:".cyan().bold(),
        "example.com".cyan()
    ));
    s
}

fn colorize_level(level: &RiskLevel, label: &str) -> String {
    match level {
        RiskLevel::Critical => label.red().bold().to_string(),
        RiskLevel::High => label.bright_red().bold().to_string(),
        RiskLevel::Medium => label.yellow().bold().to_string(),
        RiskLevel::Low => label.bright_yellow().to_string(),
        RiskLevel::Pass => label.green().bold().to_string(),
        RiskLevel::Unknown => label.dimmed().to_string(),
    }
}

fn level_tagline(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => {
            "Immediate action required — quantum-vulnerable cryptography in active use."
        }
        RiskLevel::High => "Urgent — begin post-quantum migration planning now.",
        RiskLevel::Medium => "Plan a post-quantum migration within roughly six months.",
        RiskLevel::Low => "Largely sound — monitor posture and prepare a migration plan.",
        RiskLevel::Pass => "Meets current post-quantum readiness guidance.",
        RiskLevel::Unknown => "The endpoint could not be assessed.",
    }
}

fn yesno(enabled: bool) -> colored::ColoredString {
    if enabled {
        "on".green()
    } else {
        "off".yellow()
    }
}

async fn run_bulk(path: &std::path::Path, output: OutputMode, concurrency: usize) -> Result<u8> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read targets file {}", path.display()))?;

    let targets: Vec<(String, u16)> = contents
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_target_line)
        .collect::<Result<Vec<_>>>()?;

    if targets.is_empty() {
        bail!(
            "targets file {} contained no scannable lines",
            path.display()
        );
    }

    let concurrency = concurrency.max(1);
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tasks = FuturesUnordered::new();

    for (host, port) in targets {
        let permit = sem.clone().acquire_owned().await?;
        tasks.push(tokio::spawn(async move {
            let report = RonwayScanner::scan_with_port(&host, port).await;
            drop(permit);
            (host, port, report)
        }));
    }

    let mut worst: u8 = 0;
    while let Some(joined) = tasks.next().await {
        let (host, port, report) = match joined {
            Ok(v) => v,
            Err(e) => {
                warn!("scan task panicked: {}", e);
                continue;
            }
        };
        worst = worst.max(report.risk_score.value);
        match output {
            OutputMode::Text => {
                println!(
                    "{:>3}/100  {:<8}  {}:{}",
                    report.risk_score.value,
                    report.risk_score.level.label(),
                    host,
                    port
                );
            }
            OutputMode::Json => {
                let json = JsonReporter::render(&report)?;
                println!("{}", json);
            }
            OutputMode::Html | OutputMode::Pdf => {
                bail!(
                    "bulk mode only supports text and json output (got {:?})",
                    output
                );
            }
        }
    }

    Ok(worst)
}

fn parse_target_line(line: &str) -> Result<(String, u16)> {
    let (host, port) = normalize_target(line)?;
    Ok((host, port.unwrap_or(443)))
}

async fn run_monitor(target: &str, port: u16, interval_minutes: u64) -> Result<()> {
    if interval_minutes == 0 {
        bail!("--interval must be > 0");
    }
    let (host, inline_port) = normalize_target(target)?;
    let target = host.as_str();
    let port = inline_port.unwrap_or(port);
    let interval = Duration::from_secs(interval_minutes * 60);

    eprintln!(
        "{} monitoring {}:{} every {} min",
        "monitor:".cyan().bold(),
        target,
        port,
        interval_minutes
    );

    let mut last_score: Option<u8> = None;
    loop {
        let report = RonwayScanner::scan_with_port(target, port).await;
        let score = report.risk_score.value;
        let now = chrono::Utc::now().to_rfc3339();

        match last_score {
            None => println!(
                "[{}] {} → score={}/100 ({})",
                now,
                target,
                score,
                report.risk_score.level.label()
            ),
            Some(prev) if prev != score => println!(
                "[{}] {} → score changed {} → {} ({})",
                now,
                target,
                prev,
                score,
                report.risk_score.level.label()
            ),
            _ => println!("[{}] {} → score unchanged ({}/100)", now, target, score),
        }
        last_score = Some(score);
        tokio::time::sleep(interval).await;
    }
}
