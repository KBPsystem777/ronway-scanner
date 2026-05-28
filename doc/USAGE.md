# RonwayScanner — Local Usage Guide

> How to build and run `ronway` from your own terminal. Examples are
> written for **Windows PowerShell** (the primary dev environment); the
> bash equivalents are identical apart from the binary path
> (`./target/release/ronway` instead of `.\target\release\ronway.exe`).

---

## 1. Prerequisites

You need the Rust toolchain **and** a C/C++ linker — Rust does not ship one
on Windows.

```powershell
# Rust (if not already installed)
winget install Rustlang.Rustup

# MSVC Build Tools — the linker ronway needs
winget install Microsoft.VisualStudio.2022.BuildTools --silent --override "--passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Reopen the terminal after installing the Build Tools so the linker lands on
`PATH`. If `cargo build` later fails with a `link:` error, see
[Troubleshooting](#7-troubleshooting).

---

## 2. Build

```powershell
cargo build --release
```

The optimised binary is written to:

```
target\release\ronway.exe
```

For day-to-day use you can install it onto your `PATH` so you can type
`ronway` from anywhere:

```powershell
cargo install --path .
```

The rest of this guide calls the binary directly
(`.\target\release\ronway.exe`); if you ran `cargo install`, just use
`ronway`.

---

## 3. First run — confirm it works

```powershell
.\target\release\ronway.exe version
```

You should see `ronway 0.1.0`.

---

## 4. Scanning a single target

```powershell
# Plain text summary to the terminal (the default)
.\target\release\ronway.exe scan --target example.com

# Non-standard port
.\target\release\ronway.exe scan --target example.com --port 8443

# Short flag for --target
.\target\release\ronway.exe scan -t bsp.gov.ph
```

> The target is normalised for you: a full URL works just as well as a bare
> host. `https://example.com/path`, `example.com`, and `example.com:8443`
> all resolve to the same host — the scheme and path are stripped, and an
> inline `:port` overrides `--port`.

### Output formats

`--output` accepts `text` (default), `json`, `html`, or `pdf`. Use
`--out-file` to write to a file instead of stdout.

```powershell
# JSON to stdout
.\target\release\ronway.exe scan -t example.com --output json

# JSON to a file
.\target\release\ronway.exe scan -t example.com --output json --out-file report.json

# Self-contained HTML report (opens in any browser, no internet needed)
.\target\release\ronway.exe scan -t example.com --output html --out-file report.html

# Board-ready PDF — --out-file is REQUIRED for pdf
.\target\release\ronway.exe scan -t example.com --output pdf --out-file report.pdf
```

> PDF mode refuses to run without `--out-file` (a PDF can't sensibly go to
> the terminal).

---

## 5. Scanning many targets (bulk)

Create a plain-text file with one target per line. `host` defaults to port
443; use `host:port` to override. Lines starting with `#` are ignored.

```text
# domains.txt
example.com
bsp.gov.ph
internal-app.example.com:8443
```

Then:

```powershell
# Text summary, one line per target (default 8 scans in flight)
.\target\release\ronway.exe bulk --targets domains.txt

# JSON output, more concurrency
.\target\release\ronway.exe bulk --targets domains.txt --output json --concurrency 16
```

Bulk mode supports `text` and `json` only (not `html` / `pdf`). The process
exits `1` if the **worst** score across the batch is ≥ 60.

---

## 6. Continuous monitoring

Re-scans on an interval and prints a line whenever the risk score changes.
`--interval` is in **minutes** (default 1440 = once a day). It runs until you
stop it with `Ctrl-C`.

```powershell
# Check every 60 minutes
.\target\release\ronway.exe monitor --target example.com --interval 60
```

---

## 7. Running the HTTP API server locally

`serve` starts a JSON API (the same engine as `scan`, exposed over HTTP) so a
local frontend can request scans. It binds `0.0.0.0:<port>`, default `3001`.

```powershell
# PowerShell — leave this terminal running
.\target\release\ronway.exe serve --port 3001
```

```bash
# Git Bash — call the binary by path, or just `ronway` if you ran cargo install
./target/release/ronway.exe serve --port 3001
```

On success you'll see a banner and then a log line for every request:

```
RonwayScanner API
  listening   http://localhost:3001
  health      GET  /api/health
  scan        POST /api/scan
  press Ctrl-C to stop
2026-05-28T03:17:18Z  INFO GET /api/health 200 0.1ms 127.0.0.1
2026-05-28T03:17:19Z  INFO POST /api/scan 400 0.1ms 127.0.0.1
```

> **This terminal is now the server — it's supposed to block and stay
> occupied.** That's not a hang. Open a _second_ terminal to send requests.
> Stop the server with `Ctrl-C`.

In that **second** terminal, call it. Note: in PowerShell, `curl` is an alias
for `Invoke-WebRequest`, so use the native cmdlets or call `curl.exe`
explicitly.

```powershell
# Health check
Invoke-RestMethod http://localhost:3001/api/health

# Run a scan
Invoke-RestMethod -Method Post http://localhost:3001/api/scan `
  -ContentType 'application/json' `
  -Body '{ "target": "example.com" }'
```

Or with real curl:

```powershell
curl.exe http://localhost:3001/api/health
curl.exe -X POST http://localhost:3001/api/scan -H "content-type: application/json" -d "{\"target\":\"example.com\"}"
```

The server enforces guard rails you can't override from the request:

- **Targets must be public.** `localhost`, private/loopback/reserved IPs, and
  internal TLDs (`*.local`, `*.internal`, `*.lan`, …) are rejected with `400`.
- **Rate limit:** 10 scans per minute per client IP (`429` past that).
- **Per-scan timeout:** 30 seconds (`504` if exceeded).
- **CORS** is locked to the bpxai.com origins and `localhost:3000` /
  `localhost:5173`. This only affects browsers — `curl` and the cmdlets above
  are unaffected because they send no `Origin` header.

---

## 8. Exit codes (CI/CD gate)

`scan` and `bulk` use exit codes so you can gate a pipeline on quantum risk:

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| `0`  | Risk score `< 60` — passing.                     |
| `1`  | Risk score `>= 60` — fail the build.             |
| `2`  | Setup error (missing file, bad arguments, etc.). |

Check it in PowerShell with `$LASTEXITCODE`:

```powershell
.\target\release\ronway.exe scan -t example.com
echo "exit code: $LASTEXITCODE"
```

---

## 9. Logging

The scanner uses `tracing` and defaults to the `warn` level. Set `RUST_LOG`
to see more:

```powershell
$env:RUST_LOG = "info"
.\target\release\ronway.exe scan -t example.com
```

Accepted values: `error`, `warn` (default), `info`, `debug`, `trace`.

---

## 10. Troubleshooting

### `cargo build` fails with a `link:` / linker error

The MSVC linker isn't on `PATH`. Either reopen your terminal after installing
the Build Tools, or run from the **x64 Native Tools Command Prompt for
VS 2022**. The committed `.cargo/config.toml` pins an absolute linker path
that is workstation-specific — see the Troubleshooting notes in
[PROGRESS.md](PROGRESS.md) if it's out of date.

### A scan reports `TLS: scan failed` / `Cert: scan failed`

The target didn't complete a TLS handshake within the 10-second timeout
(unreachable host, wrong port, firewall, or non-TLS service). The scan still
produces a report — the failed probe is recorded as a `*_SCAN_FAILED`
sentinel rather than aborting the run.

### `serve` prints nothing / looks frozen

That's the normal, healthy state — the process blocks while serving. You
should still see the startup banner and a log line per request. If you want
more verbosity, set `RUST_LOG`:

```powershell
$env:RUST_LOG = "ronway_scanner=debug"   # PowerShell
```

```bash
RUST_LOG=ronway_scanner=debug ./target/release/ronway.exe serve   # bash
```

### `serve` exits with `os error 10048` (address already in use)

The port is already taken — almost always a previous `ronway serve` that's
still running. Find and stop it, or pick another port.

```powershell
# Find what holds the port (PowerShell)
Get-NetTCPConnection -LocalPort 3001 | Select-Object OwningProcess
Stop-Process -Id <PID> -Force
```

```bash
# Or in bash:
netstat -ano | grep 3001 | grep LISTENING   # shows the PID in the last column
taskkill //F //PID <PID>                     # bash needs the double slash
```

### The API server returns `400 invalid_target`

By design — the server refuses private/internal targets to prevent SSRF. To
scan something on your own machine, use the CLI `scan` command directly, which
has no such restriction.

---

## Quick reference

```powershell
ronway version                                            # print version
ronway scan -t <host> [--port N] [--output text|json|html|pdf] [--out-file F]
ronway bulk --targets <file> [--output text|json] [--concurrency N]
ronway monitor -t <host> [--port N] [--interval MINUTES]
ronway serve [--port N]                                   # JSON API, default :3001
```
