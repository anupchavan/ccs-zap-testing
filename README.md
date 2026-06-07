# ZAP Security Audit Toolkit

Small, repeatable wrappers around OWASP ZAP for website security audits. The scripts run ZAP Automation Framework jobs, generate JSON/Markdown/PDF reports, and print a copy-pasteable spreadsheet summary for each audited domain.

Use this only on systems you are explicitly authorized to test.

## What It Produces

For each target, the runners create:

- `Security Audit – <domain>.pdf`
- `Security Audit – <domain>.json`
- `Security Audit – <domain>.md`

Reports are written under `reports/`, which is intentionally ignored by Git because reports may contain sensitive findings, URLs, headers, cookies, and evidence.

At the end of each run, the script prints spreadsheet-ready fields:

- `Domain`
- `Scan Type`
- `Risk Summary`
- `Observations`
- `Detailed Report`
- `Proposal`
- `Temporary Removal`

## Requirements

Recommended setup:

- OWASP ZAP
- Google Chrome or Chromium
- Java 17+ (OpenJDK 21 recommended)
- Python 3

Install common dependencies on macOS or Linux:

```bash
./scripts/install.sh
```

macOS users can also run the compatibility wrapper:

```bash
./scripts/install_macos.sh
```

Manual macOS install:

```bash
brew install --cask zap google-chrome
brew install openjdk@21 python
```

Manual Ubuntu/Debian install, if you do not want to use the helper:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl unzip default-jre python3
sudo snap install zaproxy --classic
```

Then install Google Chrome or Chromium. Chrome is recommended for the AJAX spider and PDF generation.

The scripts auto-detect common paths:

- ZAP: `/Applications/ZAP.app/Contents/Java/zap.sh`
- ZAP: `/usr/share/zaproxy/zap.sh`, `/opt/zaproxy/zap.sh`, or `zaproxy`
- Chrome: `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`
- Chrome/Chromium: `google-chrome`, `google-chrome-stable`, `chromium`, or `chromium-browser`
- Java: `/opt/homebrew/opt/openjdk@21/bin`
- Java: system `java` on Linux, or `/usr/lib/jvm/default-java/bin`

Override them when needed:

```bash
ZAP_SH=/path/to/zap.sh \
CHROME_BINARY=/path/to/chrome \
CHROME_DRIVER=/path/to/chromedriver \
JAVA_BIN_DIR=/path/to/java/bin \
./scripts/zap_passive_scan.sh https://example.edu example.edu
```

## Quick Start

Passive first pass:

```bash
./scripts/zap_passive_scan.sh https://example.edu example.edu
```

Approved active scan:

```bash
./scripts/zap_active_scan.sh https://example.edu example.edu
```

Full audit:

```bash
./scripts/zap_full_audit.sh https://example.edu example.edu
```

The second argument is the output slug. Use the domain name as the slug unless you need a custom folder name.

## Scan Types

### Passive Scan

`zap_passive_scan.sh` runs a traditional spider and passive scan. It is the safest first pass and is appropriate when you want to inventory obvious header, cookie, library, and information-disclosure issues without sending active attack payloads.

### Active Scan

`zap_active_scan.sh` runs passive discovery plus ZAP active scan rules. Use it only when active testing is approved for that exact host, because it sends attack-like requests.

### Full Audit

`zap_full_audit.sh` runs:

- Traditional spider
- AJAX spider
- Passive scan
- Active scan with longer limits
- PDF/JSON/Markdown report generation
- Deterministic spreadsheet summary

The full audit disables ZAP rule `40026` (DOM Based XSS) because it is browser-heavy and caused Java heap exhaustion on larger modern sites. AJAX crawling still runs. Do targeted manual/browser testing for DOM XSS on high-risk pages.

## Running Multiple Audits

You can run multiple scans in separate terminal tabs as long as each run uses a different slug/output folder. Each run uses an isolated temporary ZAP home, so profile locks and `zap.log` files are not shared.

Example:

```bash
./scripts/zap_full_audit.sh https://site-a.example.edu site-a.example.edu
./scripts/zap_full_audit.sh https://site-b.example.edu site-b.example.edu
```

## Reading The Output

The summary is deterministic and generated from the ZAP JSON report. It is useful for a spreadsheet, but it is not a substitute for human review.

Recommended audit workflow:

1. Run passive scan.
2. Review report for obvious misconfiguration, vulnerable libraries, and false positives.
3. Run active/full scan only with approval.
4. Manually verify authentication, authorization, file upload, admin panels, exposed backups, and server ownership.
5. Decide `KEEP` or `REMOVE` based on confirmed risk.

Temporary removal should be recommended only for confirmed high-impact exposure, active compromise, dangerous upload/code execution, leaked secrets, exposed admin panels without access control, or clearly exploitable outdated software.

## Repository Layout

```text
scripts/
  install.sh              macOS/Linux dependency installer
  install_macos.sh        Compatibility wrapper for install.sh
  lib/zap_common.sh       Cross-platform path detection helpers
  zap_passive_scan.sh     Passive spider + passive scan
  zap_active_scan.sh      Active scan with bounded duration
  zap_full_audit.sh       Spider + AJAX spider + passive + active scan
  zap_csv_summary.py      Deterministic report-to-spreadsheet summary
  html_report_to_pdf.sh   Converts ZAP HTML report to PDF with Chrome
reports/                 Generated locally; ignored by Git
zap-home/                Optional local ZAP runtime cache; ignored by Git
tools/                   Optional local browser drivers; ignored by Git
```

## Notes For GitHub Pages / Static Sites

Some ZAP findings are repository-fixable, such as vulnerable vendored JavaScript, third-party script inclusion, broken forms, and exposed comments.

Some findings require hosting/CDN/server configuration and cannot be fixed in a static Jekyll repository alone:

- `Content-Security-Policy`
- `X-Frame-Options` or CSP `frame-ancestors`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `Access-Control-Allow-Origin`

For those, configure the web server, reverse proxy, CDN, or domain front.

## Troubleshooting

If ZAP is not found:

```bash
ZAP_SH=/Applications/ZAP.app/Contents/Java/zap.sh ./scripts/zap_passive_scan.sh https://example.edu example.edu
```

On Linux, try:

```bash
ZAP_SH=/usr/share/zaproxy/zap.sh ./scripts/zap_passive_scan.sh https://example.edu example.edu
```

If PDF generation fails, confirm Chrome is installed or set:

```bash
CHROME_BINARY="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
./scripts/zap_passive_scan.sh https://example.edu example.edu
```

On Linux:

```bash
CHROME_BINARY="$(command -v google-chrome-stable || command -v chromium)" \
./scripts/zap_passive_scan.sh https://example.edu example.edu
```

If AJAX spidering has browser/driver issues, install or update Chrome and ZAP. The scripts can use a local driver when `CHROME_DRIVER` is set:

```bash
CHROME_DRIVER=/path/to/chromedriver ./scripts/zap_full_audit.sh https://example.edu example.edu
```

If a scan appears stuck during active scan, tail the temporary ZAP output shown by your terminal or reduce scope/duration. Active scan time depends heavily on URL count and rule behavior.
