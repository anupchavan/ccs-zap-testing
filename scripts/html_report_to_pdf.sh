#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 input.html output.pdf" >&2
  exit 2
fi

HTML_FILE="$1"
PDF_FILE="$2"
CHROME_BINARY="${CHROME_BINARY:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
PROFILE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chrome-pdf-profile.XXXXXX")"
CHROME_PID=""

cleanup() {
  if [ -n "$CHROME_PID" ] && kill -0 "$CHROME_PID" 2>/dev/null; then
    kill "$CHROME_PID" 2>/dev/null || true
    wait "$CHROME_PID" 2>/dev/null || true
  fi
  rm -rf "$PROFILE_DIR"
}
trap cleanup EXIT

if [ ! -f "$HTML_FILE" ]; then
  echo "HTML report not found: $HTML_FILE" >&2
  exit 1
fi

if [ ! -x "$CHROME_BINARY" ]; then
  echo "Google Chrome not found at: $CHROME_BINARY" >&2
  echo "Set CHROME_BINARY=/path/to/chrome or install Google Chrome." >&2
  exit 1
fi

HTML_URI="$(python3 - "$HTML_FILE" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve().as_uri())
PY
)"

"$CHROME_BINARY" \
  --headless=new \
  --disable-gpu \
  --no-pdf-header-footer \
  --allow-file-access-from-files \
  --user-data-dir="$PROFILE_DIR" \
  --print-to-pdf="$PDF_FILE" \
  "$HTML_URI" >/dev/null 2>&1 &
CHROME_PID="$!"

previous_size=0
stable_count=0
for _ in $(seq 1 120); do
  if ! kill -0 "$CHROME_PID" 2>/dev/null; then
    wait "$CHROME_PID" 2>/dev/null || true
    CHROME_PID=""
    break
  fi

  if [ -s "$PDF_FILE" ]; then
    current_size="$(wc -c < "$PDF_FILE" | tr -d ' ')"
    if [ "$current_size" = "$previous_size" ]; then
      stable_count=$((stable_count + 1))
    else
      stable_count=0
      previous_size="$current_size"
    fi

    if [ "$stable_count" -ge 2 ]; then
      kill "$CHROME_PID" 2>/dev/null || true
      wait "$CHROME_PID" 2>/dev/null || true
      CHROME_PID=""
      break
    fi
  fi

  sleep 1
done

if [ ! -s "$PDF_FILE" ]; then
  echo "PDF conversion failed: $PDF_FILE" >&2
  exit 1
fi
