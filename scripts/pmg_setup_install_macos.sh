#!/bin/bash
# pmg_setup_install.sh — Install/update PMG, configure it, and enable cloud sync.
#
# This script is intended to be packaged and deployed via Jamf or similar MDM tools.
#
# Usage:
#   ./pmg_setup_install.sh
#   SAFEDEP_API_KEY=... SAFEDEP_TENANT_ID=... ./pmg_setup_install.sh
#
# Environment variables:
#   SAFEDEP_API_KEY    — SafeDep Cloud API key (enables cloud sync when set with tenant ID)
#   SAFEDEP_TENANT_ID  — SafeDep Cloud tenant ID
#
# What it does:
#   1. Installs or updates pmg (via Homebrew if available, otherwise from GitHub releases)
#   2. Runs `pmg setup install` to create config, shell aliases, and PATH shims
#   3. Enables cloud sync and stores credentials in macOS Keychain (if both env vars are set)

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Error: this script is for macOS only" >&2
  exit 1
fi

REPO="safedep/pmg"
CLOUD_API_KEY="${SAFEDEP_API_KEY:-}"
CLOUD_TENANT_ID="${SAFEDEP_TENANT_ID:-}"

log() { echo "==> $*"; }

# ── Install or update pmg ───────────────────────────────────────────────────
install_via_brew() {
  local brew_bin="$1"
  log "Installing/updating pmg via Homebrew"
  if "$brew_bin" ls --versions safedep/tap/pmg &>/dev/null; then
    log "pmg is already installed, upgrading"
    "$brew_bin" upgrade safedep/tap/pmg || true
  else
    "$brew_bin" install safedep/tap/pmg
  fi
}

install_via_release() {
  log "Homebrew not found, installing pmg from GitHub releases"

  local install_dir="/usr/local/bin"

  log "Fetching latest release..."
  tag=$(curl -fsSI -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO}/releases/latest" | sed 's|.*/||')
  if [[ -z "$tag" ]]; then
    echo "Error: could not determine latest release" >&2
    exit 1
  fi
  log "Latest release: $tag"

  asset="pmg_Darwin_all.tar.gz"
  url="https://github.com/${REPO}/releases/download/${tag}/${asset}"
  checksums_url="https://github.com/${REPO}/releases/download/${tag}/checksums.txt"

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  log "Downloading $asset"
  curl -fsSL -o "${tmpdir}/${asset}" "$url"
  curl -fsSL -o "${tmpdir}/checksums.txt" "$checksums_url"

  expected=$(grep "  ${asset}$" "${tmpdir}/checksums.txt" | cut -d' ' -f1)
  if [[ -z "$expected" ]]; then
    echo "Error: no checksum entry found for ${asset}" >&2
    exit 1
  fi

  actual=$(shasum -a 256 "${tmpdir}/${asset}" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: checksum mismatch for ${asset}" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
  fi
  log "Checksum verified"

  tar -xzf "${tmpdir}/${asset}" -C "${tmpdir}" pmg

  if [[ -w "$install_dir" ]]; then
    install -m 755 "${tmpdir}/pmg" "${install_dir}/pmg"
  else
    sudo install -m 755 "${tmpdir}/pmg" "${install_dir}/pmg"
  fi
  log "Installed pmg $tag to ${install_dir}/pmg"
}

BREW_BIN=""
for candidate in "/opt/homebrew/bin/brew" "/usr/local/bin/brew"; do
  if [[ -x "$candidate" ]]; then
    BREW_BIN="$candidate"
    break
  fi
done

if [[ -n "$BREW_BIN" ]]; then
  install_via_brew "$BREW_BIN"
else
  install_via_release
fi

if ! command -v pmg &>/dev/null; then
  echo "Error: pmg not found in PATH after install" >&2
  exit 1
fi
log "pmg installed: $(pmg version 2>/dev/null || echo 'unknown')"

# ── Run pmg setup ────────────────────────────────────────────────────────────
log "Running pmg setup install"
pmg setup install

# ── Enable cloud sync ───────────────────────────────────────────────────────
if [[ -n "$CLOUD_API_KEY" && -n "$CLOUD_TENANT_ID" ]]; then
  log "Enabling cloud sync"

  CONFIG_FILE="${HOME}/Library/Application Support/safedep/pmg/config.yml"

  if [[ -f "$CONFIG_FILE" ]]; then
    awk '
      /^cloud:/ { in_cloud=1 }
      in_cloud && /^  enabled: false/ { sub(/enabled: false/, "enabled: true"); in_cloud=0 }
      /^[a-z]/ && !/^cloud:/ { in_cloud=0 }
      { print }
    ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    log "Cloud sync enabled in config"
  fi

  SAFEDEP_API_KEY="$CLOUD_API_KEY" SAFEDEP_TENANT_ID="$CLOUD_TENANT_ID" pmg cloud login --from-env
  log "Credentials stored securely"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
log "pmg setup complete!"
