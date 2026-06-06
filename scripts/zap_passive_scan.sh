#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 https://example.iith.ac.in [slug]" >&2
  exit 2
fi

TARGET="$1"
SLUG="${2:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_ZAP_HOME="${ZAP_BASE_HOME:-$ROOT_DIR/zap-home}"
RUN_ZAP_HOME="$(mktemp -d "${TMPDIR:-/tmp}/zap-home-passive.XXXXXX")"
DOMAIN="${SLUG:-$(printf '%s' "$TARGET" | sed -E 's#^https?://##; s#[^A-Za-z0-9._-]+#-#g; s#-+$##')}"
RUN_DIR="$ROOT_DIR/reports/$DOMAIN"
REPORT_BASENAME="Security Audit – $DOMAIN"
PLAN="$(mktemp "${TMPDIR:-/tmp}/zap-passive-plan.XXXXXX")"
ZAP_OUTPUT="$(mktemp "${TMPDIR:-/tmp}/zap-passive-output.XXXXXX")"
ZAP_SH="${ZAP_SH:-/Applications/ZAP.app/Contents/Java/zap.sh}"
CHROME_BINARY="${CHROME_BINARY:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
FIREFOX_BINARY="${FIREFOX_BINARY:-/Applications/Firefox.app/Contents/MacOS/firefox}"
CHROME_DRIVER="${CHROME_DRIVER:-}"
TODAY="$(date +%F)"
ZAP_CONFIGS=()

if [ ! -x "$ZAP_SH" ]; then
  echo "OWASP ZAP not found at: $ZAP_SH" >&2
  echo "Install ZAP or set ZAP_SH=/path/to/zap.sh" >&2
  exit 1
fi

if [ -x "$CHROME_BINARY" ] && [ -z "$CHROME_DRIVER" ]; then
  CHROME_VERSION="$("$CHROME_BINARY" --version | awk '{print $3}')"
  CHROME_DRIVER="$ROOT_DIR/tools/chromedriver-$CHROME_VERSION/chromedriver-mac-arm64/chromedriver"
fi
if [ ! -x "$CHROME_DRIVER" ] && [ -x "$BASE_ZAP_HOME/webdriver/macos/arm64/chromedriver" ]; then
  CHROME_DRIVER="$BASE_ZAP_HOME/webdriver/macos/arm64/chromedriver"
fi
if [ -x "$CHROME_BINARY" ]; then
  ZAP_CONFIGS+=(-config "selenium.chromeBinary=$CHROME_BINARY")
fi
if [ -x "$CHROME_DRIVER" ]; then
  ZAP_CONFIGS+=(-config "selenium.chromeDriver=$CHROME_DRIVER")
fi
if [ -x "$FIREFOX_BINARY" ]; then
  ZAP_CONFIGS+=(-config "selenium.firefoxBinary=$FIREFOX_BINARY")
fi
if [ -x "$BASE_ZAP_HOME/webdriver/macos/arm64/geckodriver" ]; then
  ZAP_CONFIGS+=(-config "selenium.firefoxDriver=$BASE_ZAP_HOME/webdriver/macos/arm64/geckodriver")
fi
ZAP_CONFIGS+=(-config "start.dayLastChecked=$TODAY")

cleanup() {
  rm -f "$PLAN" "$ZAP_OUTPUT"
  rm -rf "$RUN_ZAP_HOME"
}
trap cleanup EXIT

mkdir -p "$RUN_DIR"
if [ -d "$BASE_ZAP_HOME/plugin" ]; then
  ln -s "$BASE_ZAP_HOME/plugin" "$RUN_ZAP_HOME/plugin"
fi

cat > "$PLAN" <<YAML
env:
  contexts:
    - name: target
      urls:
        - "$TARGET"
      includePaths:
        - "$TARGET.*"
      excludePaths: []
  parameters:
    failOnError: true
    failOnWarning: false
    continueOnFailure: true
    progressToStdout: true

jobs:
  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 25
      scanOnlyInScope: true

  - type: spider
    parameters:
      context: target
      url: "$TARGET"
      maxDuration: 5
      maxDepth: 5
      maxChildren: 50

  - type: passiveScan-wait
    parameters:
      maxDuration: 10

  - type: report
    parameters:
      template: traditional-html
      reportDir: "$RUN_DIR"
      reportFile: "$REPORT_BASENAME.html"
      reportTitle: "$REPORT_BASENAME"

  - type: report
    parameters:
      template: traditional-json
      reportDir: "$RUN_DIR"
      reportFile: "$REPORT_BASENAME.json"
      reportTitle: "$REPORT_BASENAME"

  - type: report
    parameters:
      template: traditional-md
      reportDir: "$RUN_DIR"
      reportFile: "$REPORT_BASENAME.md"
      reportTitle: "$REPORT_BASENAME"
YAML

if ! PATH="${JAVA_BIN_DIR:-/opt/homebrew/opt/openjdk@21/bin}:$PATH" \
    "$ZAP_SH" \
    -cmd -silent -loglevel ERROR -dir "$RUN_ZAP_HOME" \
    "${ZAP_CONFIGS[@]}" \
    -autorun "$PLAN" >"$ZAP_OUTPUT" 2>&1; then
  cat "$ZAP_OUTPUT" >&2
  exit 1
fi

"$ROOT_DIR/scripts/html_report_to_pdf.sh" \
  "$RUN_DIR/$REPORT_BASENAME.html" \
  "$RUN_DIR/$REPORT_BASENAME.pdf"
rm -f "$RUN_DIR/$REPORT_BASENAME.html"

"$ROOT_DIR/scripts/zap_csv_summary.py" \
  "$RUN_DIR/$REPORT_BASENAME.json" \
  --domain "$DOMAIN" \
  --scan-type "Passive" \
  --report-link "$RUN_DIR/$REPORT_BASENAME.pdf" \
  --no-header
