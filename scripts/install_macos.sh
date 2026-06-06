#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required. Install it from https://brew.sh/ and rerun this script." >&2
  exit 1
fi

brew install --cask zap google-chrome
brew install openjdk@21 python

echo
echo "Installed common dependencies."
echo "Run a passive scan with:"
echo "./scripts/zap_passive_scan.sh https://example.edu example.edu"
