#!/usr/bin/env bash

find_first_executable() {
  local candidate
  for candidate in "$@"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

find_command() {
  local name
  for name in "$@"; do
    if command -v "$name" >/dev/null 2>&1; then
      command -v "$name"
      return 0
    fi
  done
  return 1
}

detect_zap_sh() {
  if [ -n "${ZAP_SH:-}" ]; then
    find_first_executable "$ZAP_SH"
    return
  fi

  find_first_executable \
    "/Applications/ZAP.app/Contents/Java/zap.sh" \
    "/usr/share/zaproxy/zap.sh" \
    "/usr/share/owasp-zap/zap.sh" \
    "/opt/zaproxy/zap.sh" \
    "/opt/owasp-zap/zap.sh" \
    "$HOME/ZAP/zap.sh" \
    "$HOME/zaproxy/zap.sh" \
    || find_command zap.sh zaproxy owasp-zap zap
}

detect_chrome_binary() {
  if [ -n "${CHROME_BINARY:-}" ]; then
    find_first_executable "$CHROME_BINARY"
    return
  fi

  find_first_executable \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    "/usr/bin/google-chrome" \
    "/usr/bin/google-chrome-stable" \
    "/usr/bin/chromium" \
    "/usr/bin/chromium-browser" \
    "/snap/bin/chromium" \
    || find_command google-chrome google-chrome-stable chromium chromium-browser
}

detect_firefox_binary() {
  if [ -n "${FIREFOX_BINARY:-}" ]; then
    find_first_executable "$FIREFOX_BINARY"
    return
  fi

  find_first_executable \
    "/Applications/Firefox.app/Contents/MacOS/firefox" \
    "/usr/bin/firefox" \
    "/snap/bin/firefox" \
    || find_command firefox
}

detect_chrome_driver() {
  local root_dir="$1"
  local base_zap_home="$2"
  local chrome_binary="${3:-}"
  local chrome_version=""

  if [ -n "${CHROME_DRIVER:-}" ]; then
    find_first_executable "$CHROME_DRIVER"
    return
  fi

  if [ -n "$chrome_binary" ] && [ -x "$chrome_binary" ]; then
    chrome_version="$("$chrome_binary" --version 2>/dev/null | awk '{print $NF}')"
  fi

  find_first_executable \
    "$root_dir/tools/chromedriver-$chrome_version/chromedriver-mac-arm64/chromedriver" \
    "$root_dir/tools/chromedriver-$chrome_version/chromedriver-linux64/chromedriver" \
    "$base_zap_home/webdriver/macos/arm64/chromedriver" \
    "$base_zap_home/webdriver/linux/64/chromedriver" \
    "$base_zap_home/webdriver/linux/chromedriver" \
    || find_command chromedriver
}

detect_java_bin_dir() {
  if [ -n "${JAVA_BIN_DIR:-}" ] && [ -d "$JAVA_BIN_DIR" ]; then
    printf '%s\n' "$JAVA_BIN_DIR"
    return 0
  fi

  if [ -d "/opt/homebrew/opt/openjdk@21/bin" ]; then
    printf '%s\n' "/opt/homebrew/opt/openjdk@21/bin"
    return 0
  fi

  if [ -d "/usr/lib/jvm/default-java/bin" ]; then
    printf '%s\n' "/usr/lib/jvm/default-java/bin"
    return 0
  fi

  return 1
}

init_zap_environment() {
  local root_dir="$1"
  local base_zap_home="$2"
  local today="$3"

  ZAP_SH="$(detect_zap_sh || true)"
  CHROME_BINARY="$(detect_chrome_binary || true)"
  FIREFOX_BINARY="$(detect_firefox_binary || true)"
  CHROME_DRIVER="$(detect_chrome_driver "$root_dir" "$base_zap_home" "$CHROME_BINARY" || true)"
  JAVA_BIN_DIR_DETECTED="$(detect_java_bin_dir || true)"
  ZAP_CONFIGS=()

  if [ -z "$ZAP_SH" ] || [ ! -x "$ZAP_SH" ]; then
    echo "OWASP ZAP was not found." >&2
    echo "Install ZAP or set ZAP_SH=/path/to/zap.sh" >&2
    exit 1
  fi

  if [ -n "$CHROME_BINARY" ] && [ -x "$CHROME_BINARY" ]; then
    ZAP_CONFIGS+=(-config "selenium.chromeBinary=$CHROME_BINARY")
  fi
  if [ -n "$CHROME_DRIVER" ] && [ -x "$CHROME_DRIVER" ]; then
    ZAP_CONFIGS+=(-config "selenium.chromeDriver=$CHROME_DRIVER")
  fi
  if [ -n "$FIREFOX_BINARY" ] && [ -x "$FIREFOX_BINARY" ]; then
    ZAP_CONFIGS+=(-config "selenium.firefoxBinary=$FIREFOX_BINARY")
  fi
  if [ -x "$base_zap_home/webdriver/macos/arm64/geckodriver" ]; then
    ZAP_CONFIGS+=(-config "selenium.firefoxDriver=$base_zap_home/webdriver/macos/arm64/geckodriver")
  elif [ -x "$base_zap_home/webdriver/linux/64/geckodriver" ]; then
    ZAP_CONFIGS+=(-config "selenium.firefoxDriver=$base_zap_home/webdriver/linux/64/geckodriver")
  elif command -v geckodriver >/dev/null 2>&1; then
    ZAP_CONFIGS+=(-config "selenium.firefoxDriver=$(command -v geckodriver)")
  fi

  ZAP_CONFIGS+=(-config "start.dayLastChecked=$today")
}

run_with_java_path() {
  if [ -n "${JAVA_BIN_DIR_DETECTED:-}" ]; then
    PATH="$JAVA_BIN_DIR_DETECTED:$PATH" "$@"
  else
    "$@"
  fi
}

link_zap_plugins_if_available() {
  local base_zap_home="$1"
  local run_zap_home="$2"

  if [ -d "$base_zap_home/plugin" ]; then
    ln -s "$base_zap_home/plugin" "$run_zap_home/plugin"
  fi
}
