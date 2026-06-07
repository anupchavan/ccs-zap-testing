#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 https://example.iith.ac.in [slug]" >&2
  exit 2
fi

TARGET="$1"
SLUG="${2:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/zap_common.sh"
BASE_ZAP_HOME="${ZAP_BASE_HOME:-$ROOT_DIR/zap-home}"
RUN_ZAP_HOME="$(mktemp -d "${TMPDIR:-/tmp}/zap-home-passive.XXXXXX")"
DOMAIN="${SLUG:-$(printf '%s' "$TARGET" | sed -E 's#^https?://##; s#[^A-Za-z0-9._-]+#-#g; s#-+$##')}"
RUN_DIR="$ROOT_DIR/reports/$DOMAIN"
REPORT_BASENAME="Security Audit – $DOMAIN"
PLAN="$(mktemp "${TMPDIR:-/tmp}/zap-passive-plan.XXXXXX")"
ZAP_OUTPUT="$(mktemp "${TMPDIR:-/tmp}/zap-passive-output.XXXXXX")"
TODAY="$(date +%F)"
init_zap_environment "$ROOT_DIR" "$BASE_ZAP_HOME" "$TODAY"

cleanup() {
  rm -f "$PLAN" "$ZAP_OUTPUT"
  rm -rf "$RUN_ZAP_HOME"
}
trap cleanup EXIT

mkdir -p "$RUN_DIR"
link_zap_plugins_if_available "$BASE_ZAP_HOME" "$RUN_ZAP_HOME"

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

if ! run_with_java_path "$ZAP_SH" \
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
