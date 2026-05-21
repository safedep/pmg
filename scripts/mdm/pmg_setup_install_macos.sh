#!/bin/bash
# pmg_setup_install_macos.sh — Install and configure PMG on a Mac.
#
# Deploy via Jamf or any MDM, alongside lib_macos.sh in the same directory.
# Run as root, it installs the machine-wide binary and configures every local
# user (config, aliases, shims). Cloud credentials are stored in the logged-in
# user's Keychain when SAFEDEP_API_KEY and SAFEDEP_TENANT_ID are set. Run as a
# user, it configures just that user. See lib_macos.sh for the model.
#
# Environment variables:
#   SAFEDEP_API_KEY    — SafeDep Cloud API key (with tenant ID, enables cloud sync)
#   SAFEDEP_TENANT_ID  — SafeDep Cloud tenant ID

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib_macos.sh
source "${SCRIPT_DIR}/lib_macos.sh"

require_macos

REPO="safedep/pmg"
CLOUD_API_KEY="${SAFEDEP_API_KEY:-}"
CLOUD_TENANT_ID="${SAFEDEP_TENANT_ID:-}"

install_via_brew() {
  local brew_bin="$1"
  log "Installing/updating pmg via Homebrew"
  if run_brew "$brew_bin" ls --versions safedep/tap/pmg &>/dev/null; then
    run_brew "$brew_bin" upgrade safedep/tap/pmg || true
  else
    run_brew "$brew_bin" install safedep/tap/pmg
  fi
}

install_via_release() {
  log "Homebrew not found, installing pmg from GitHub releases"
  local install_dir="/usr/local/bin" tag asset url checksums_url tmpdir expected actual

  tag=$(curl -fsSI -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO}/releases/latest" | sed 's|.*/||')
  [[ -n "$tag" ]] || { echo "Error: could not determine latest release" >&2; exit 1; }
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
  [[ -n "$expected" ]] || { echo "Error: no checksum entry found for ${asset}" >&2; exit 1; }
  actual=$(shasum -a 256 "${tmpdir}/${asset}" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: checksum mismatch for ${asset} (expected $expected, got $actual)" >&2
    exit 1
  fi
  log "Checksum verified"

  tar -xzf "${tmpdir}/${asset}" -C "${tmpdir}" pmg
  run_as_root install -m 755 "${tmpdir}/pmg" "${install_dir}/pmg"
  log "Installed pmg $tag to ${install_dir}/pmg"
}

if brew_bin=$(find_brew); then
  install_via_brew "$brew_bin"
else
  install_via_release
fi

PMG_BIN=$(resolve_pmg) || { echo "Error: pmg not found after install" >&2; exit 1; }
log "pmg installed: $("$PMG_BIN" version 2>/dev/null || echo unknown)"

# Install the globally managed config if the package ships one. Done before the
# per-user loop so each user's `setup install` sees managed mode and skips
# writing a per-user config.
if [[ -f "${SCRIPT_DIR}/config.yml" ]]; then
  install_global_config "${SCRIPT_DIR}/config.yml"
fi

if [[ -f "$GLOBAL_CONFIG_FILE" && -n "$CLOUD_API_KEY" && -n "$CLOUD_TENANT_ID" ]]; then
  log "Config is globally managed; set 'cloud.enabled: true' in the bundled config.yml to enable sync (per-user config is locked)"
fi

configure_user() {
  local user="$1"
  log "Configuring pmg for $user"
  run_user_file "$user" "$PMG_BIN" setup install || { warn "setup failed for $user"; return; }

  [[ -n "$CLOUD_API_KEY" && -n "$CLOUD_TENANT_ID" ]] || return
  if ! user_has_session "$user"; then
    log "  $user is not logged in; run 'pmg cloud login' in their session to enable cloud sync"
    return
  fi
  # When config is globally managed, `cloud.enabled` comes from the global file;
  # per-user `config set` is refused. Per-user credentials still go to the Keychain.
  if [[ ! -f "$GLOBAL_CONFIG_FILE" ]]; then
    run_user_file "$user" "$PMG_BIN" config set cloud.enabled true || warn "could not enable cloud sync for $user"
  fi
  run_user_session "$user" \
    env SAFEDEP_API_KEY="$CLOUD_API_KEY" SAFEDEP_TENANT_ID="$CLOUD_TENANT_ID" "$PMG_BIN" cloud login --from-env \
    || warn "cloud login failed for $user"
}

while IFS=$'\t' read -r user _ _; do
  configure_user "$user"
done < <(each_target_user)

log "pmg setup complete"
