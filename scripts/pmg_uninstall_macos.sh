#!/bin/bash
# pmg_uninstall_macos.sh — Uninstall PMG, remove config, aliases, shims, and cloud credentials.
#
# This script is intended to be deployed via Jamf or similar MDM tools.
#
# Usage:
#   ./pmg_uninstall_macos.sh
#
# What it does:
#   1. Removes PMG config, shell aliases, and PATH shims
#   2. Clears cloud credentials from macOS Keychain
#   3. Uninstalls the pmg binary (via Homebrew or direct removal)

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Error: this script is for macOS only" >&2
  exit 1
fi

log() { echo "==> $*"; }

# ── Remove config, aliases, and shims ────────────────────────────────────────
if command -v pmg &>/dev/null; then
  log "Removing PMG config, aliases, and shims"
  pmg setup remove --config-file || true

  log "Clearing cloud credentials from keychain"
  pmg cloud logout || true
fi

# ── Uninstall pmg binary ────────────────────────────────────────────────────
BREW_BIN=""
for candidate in "/opt/homebrew/bin/brew" "/usr/local/bin/brew"; do
  if [[ -x "$candidate" ]]; then
    BREW_BIN="$candidate"
    break
  fi
done

if [[ -n "$BREW_BIN" ]] && "$BREW_BIN" ls --versions safedep/tap/pmg &>/dev/null; then
  log "Uninstalling pmg via Homebrew"
  "$BREW_BIN" uninstall safedep/tap/pmg
else
  log "Removing pmg binary"
  if [[ -f "/usr/local/bin/pmg" ]]; then
    if [[ -w "/usr/local/bin/pmg" ]]; then
      rm -f "/usr/local/bin/pmg"
    else
      sudo rm -f "/usr/local/bin/pmg"
    fi
  fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────
log "pmg uninstall complete!"
