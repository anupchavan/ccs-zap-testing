#!/usr/bin/env bash
set -euo pipefail

sudo_cmd() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

install_macos() {
  if ! has_command brew; then
    echo "Homebrew is required on macOS. Install it from https://brew.sh/ and rerun this script." >&2
    exit 1
  fi

  brew install --cask zap google-chrome
  brew install openjdk@21 python
}

install_chrome_debian() {
  if has_command google-chrome || has_command google-chrome-stable || has_command chromium || has_command chromium-browser; then
    return 0
  fi

  case "$(uname -m)" in
    x86_64|amd64)
      local tmp_deb
      tmp_deb="$(mktemp "${TMPDIR:-/tmp}/google-chrome.XXXXXX.deb")"
      curl -fsSL "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" -o "$tmp_deb"
      sudo_cmd apt-get install -y "$tmp_deb"
      rm -f "$tmp_deb"
      ;;
    *)
      sudo_cmd apt-get install -y chromium-browser || sudo_cmd apt-get install -y chromium
      ;;
  esac
}

install_zap_linux() {
  if has_command zap.sh || has_command zaproxy || has_command zap; then
    return 0
  fi

  if has_command snap; then
    sudo_cmd snap install zaproxy --classic && return 0
  fi

  if has_command apt-cache && apt-cache show zaproxy >/dev/null 2>&1; then
    sudo_cmd apt-get install -y zaproxy && return 0
  fi

  if has_command flatpak; then
    flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
    flatpak install -y flathub org.zaproxy.ZAP && return 0
  fi

  echo "Could not install ZAP automatically on this Linux distribution." >&2
  echo "Install ZAP manually from https://www.zaproxy.org/download/ and set ZAP_SH=/path/to/zap.sh." >&2
  exit 1
}

install_debian_like() {
  sudo_cmd apt-get update
  sudo_cmd apt-get install -y ca-certificates curl unzip default-jre python3
  install_chrome_debian
  install_zap_linux
}

install_generic_linux() {
  if has_command apt-get; then
    install_debian_like
    return 0
  fi

  install_zap_linux

  if ! has_command python3; then
    echo "python3 was not found. Install Python 3 with your system package manager." >&2
    exit 1
  fi

  if ! has_command google-chrome && ! has_command google-chrome-stable && ! has_command chromium && ! has_command chromium-browser; then
    echo "Chrome/Chromium was not found. Install Chrome or Chromium, or set CHROME_BINARY." >&2
    exit 1
  fi
}

case "$(uname -s)" in
  Darwin)
    install_macos
    ;;
  Linux)
    install_generic_linux
    ;;
  *)
    echo "Unsupported OS: $(uname -s)" >&2
    echo "Install ZAP, Chrome/Chromium, Java 17+, and Python 3 manually." >&2
    exit 1
    ;;
esac

echo
echo "Installed common dependencies."
echo "Run a passive scan with:"
echo "./scripts/zap_passive_scan.sh https://example.edu example.edu"
