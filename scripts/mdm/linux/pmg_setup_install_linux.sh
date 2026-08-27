#!/bin/bash
# pmg_setup_install_linux.sh — Install and configure PMG on a Linux machine.
#
# Deploy via JumpCloud or any MDM, alongside lib_linux.sh in the same
# directory. Run as root, it installs the machine-wide binary and configures
# every local user (config, aliases, shims). When cloud credentials are set,
# the script syncs each user and stores credentials for the logged-in user.
# Run as a user, it configures just that user. See lib_linux.sh for the model.
#
# Environment variables:
#   SAFEDEP_API_KEY    — SafeDep Cloud API key (with tenant ID, enables cloud sync)
#   SAFEDEP_TENANT_ID  — SafeDep Cloud tenant ID
#
# Options:
#   --cloud-sync-only  — Skip installation and sync every user's cloud data

set -euo pipefail

CLOUD_API_KEY="${SAFEDEP_API_KEY:-}"
CLOUD_TENANT_ID="${SAFEDEP_TENANT_ID:-}"
export -n CLOUD_API_KEY CLOUD_TENANT_ID
unset SAFEDEP_API_KEY SAFEDEP_TENANT_ID

CLOUD_SYNC_ONLY=0
for arg in "$@"; do
  if [[ "$arg" == "--cloud-sync-only" ]]; then
    CLOUD_SYNC_ONLY=1
    break
  fi
done

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib_linux.sh
source "${SCRIPT_DIR}/lib_linux.sh"

require_linux

REPO="safedep/pmg"

load_embedded_cloud_credentials() {
  local embedded_api_key="${EMBEDDED_SAFEDEP_API_KEY_B64:-}"
  local embedded_tenant_id="${EMBEDDED_SAFEDEP_TENANT_ID_B64:-}"

  unset EMBEDDED_SAFEDEP_API_KEY_B64 EMBEDDED_SAFEDEP_TENANT_ID_B64

  if [[ -n "$CLOUD_API_KEY" && -n "$CLOUD_TENANT_ID" ]]; then
    return
  fi

  if [[ -z "$embedded_api_key" && -z "$embedded_tenant_id" ]]; then
    return
  fi

  if [[ -n "$CLOUD_API_KEY" || -n "$CLOUD_TENANT_ID" ]]; then
    echo "Error: SAFEDEP_API_KEY and SAFEDEP_TENANT_ID must be set together" >&2
    return 1
  fi

  if [[ -z "$embedded_api_key" || -z "$embedded_tenant_id" ]]; then
    echo "Error: embedded cloud credentials are incomplete" >&2
    return 1
  fi

  if ! CLOUD_API_KEY=$(printf '%s' "$embedded_api_key" | base64 -d); then
    echo "Error: could not decode embedded cloud API key" >&2
    return 1
  fi
  if ! CLOUD_TENANT_ID=$(printf '%s' "$embedded_tenant_id" | base64 -d); then
    echo "Error: could not decode embedded cloud tenant ID" >&2
    return 1
  fi
}

load_embedded_cloud_credentials || exit 1

cloud_sync() {
  local user="$1"

  # shellcheck disable=SC2016
  printf '%s\0%s\0' "$CLOUD_API_KEY" "$CLOUD_TENANT_ID" |
    run_user_file "$user" /bin/bash -c '
      IFS= read -r -d "" SAFEDEP_API_KEY || exit 1
      IFS= read -r -d "" SAFEDEP_TENANT_ID || exit 1
      export SAFEDEP_API_KEY SAFEDEP_TENANT_ID
      exec "$1" cloud sync --timeout 1m
    ' _ "$PMG_BIN"
}

sync_all_users() {
  local user total=0 failed=0

  while IFS=$'\t' read -r user _ _; do
    total=$((total + 1))
    log "Syncing pmg cloud data for $user"
    if ! cloud_sync "$user"; then
      warn "cloud sync failed for $user"
      failed=$((failed + 1))
    fi
  done < <(each_target_user)

  if [[ "$total" -eq 0 ]]; then
    log "No users found for cloud sync"
    return 0
  fi
  if [[ "$failed" -ne 0 ]]; then
    warn "cloud sync failed for $failed of $total users"
    return 1
  fi

  log "pmg cloud sync complete for $total users"
}

if [[ "$CLOUD_SYNC_ONLY" -eq 1 ]]; then
  if [[ -z "$CLOUD_API_KEY" || -z "$CLOUD_TENANT_ID" ]]; then
    log "Cloud credentials are not configured; skipping cloud sync"
    unset CLOUD_API_KEY CLOUD_TENANT_ID
    exit 0
  fi
  if ! PMG_BIN=$(resolve_pmg); then
    log "pmg is not installed; skipping cloud sync"
    unset CLOUD_API_KEY CLOUD_TENANT_ID
    exit 0
  fi

  sync_status=0
  sync_all_users || sync_status=$?
  unset CLOUD_API_KEY CLOUD_TENANT_ID
  exit "$sync_status"
fi

install_via_release() {
  log "Installing pmg from GitHub releases"
  local install_dir="/usr/local/bin" tag arch asset url checksums_url expected actual

  case "$(uname -m)" in
    x86_64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac

  tag=$(curl -fsSI -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO}/releases/latest" | sed 's|.*/||') || true
  [[ -n "$tag" ]] || { echo "Error: could not determine latest release" >&2; exit 1; }
  log "Latest release: $tag"

  asset="pmg_Linux_${arch}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${tag}/${asset}"
  checksums_url="https://github.com/${REPO}/releases/download/${tag}/checksums.txt"

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  log "Downloading $asset"
  curl -fsSL -o "${tmpdir}/${asset}" "$url"
  curl -fsSL -o "${tmpdir}/checksums.txt" "$checksums_url"

  expected=$(grep "  ${asset}$" "${tmpdir}/checksums.txt" | cut -d' ' -f1) || true
  [[ -n "$expected" ]] || { echo "Error: no checksum entry found for ${asset}" >&2; exit 1; }
  actual=$(sha256sum "${tmpdir}/${asset}" | cut -d' ' -f1)
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: checksum mismatch for ${asset} (expected $expected, got $actual)" >&2
    exit 1
  fi
  log "Checksum verified"

  tar -xzf "${tmpdir}/${asset}" -C "${tmpdir}" pmg
  run_as_root install -m 755 "${tmpdir}/pmg" "${install_dir}/pmg"
  log "Installed pmg $tag to ${install_dir}/pmg"
}

install_via_release

PMG_BIN=$(resolve_pmg) || { echo "Error: pmg not found after install" >&2; exit 1; }
log "pmg installed: $("$PMG_BIN" version 2>/dev/null || echo unknown)"

install_requested_global_config() {
  local embedded_config="${EMBEDDED_GLOBAL_CONFIG_B64:-}"
  local embedded_config_tmp
  unset EMBEDDED_GLOBAL_CONFIG_B64

  if [[ -z "$embedded_config" ]]; then
    if [[ -f "${SCRIPT_DIR}/config.yml" ]]; then
      install_global_config "${SCRIPT_DIR}/config.yml"
    fi
    return
  fi

  embedded_config_tmp=$(mktemp "${TMPDIR:-/tmp}/pmg-embedded-config.XXXXXX") || {
    echo "Error: could not create temporary config file" >&2
    return 1
  }
  if ! printf '%s' "$embedded_config" | base64 -d > "$embedded_config_tmp"; then
    warn "failed to decode embedded global config"
    rm -f "$embedded_config_tmp" || warn "failed to remove temporary config file"
    return 1
  fi
  if ! install_global_config "$embedded_config_tmp"; then
    rm -f "$embedded_config_tmp" || warn "failed to remove temporary config file"
    return 1
  fi
  rm -f "$embedded_config_tmp" || warn "failed to remove temporary config file"
}

install_requested_global_config

if [[ -f "$GLOBAL_CONFIG_FILE" && -n "$CLOUD_API_KEY" && -n "$CLOUD_TENANT_ID" ]]; then
  log "Config is globally managed; set 'cloud.enabled: true' in the bundled config.yml to enable sync (per-user config is locked)"
fi

cloud_login() {
  local user="$1"

  # Single-quoted string is literal by design: bash -c runs it in the user's
  # session and $1 must expand there, not here.
  # shellcheck disable=SC2016
  printf '%s\0%s\0' "$CLOUD_API_KEY" "$CLOUD_TENANT_ID" |
    run_user_session "$user" /bin/bash -c '
      IFS= read -r -d "" SAFEDEP_API_KEY || exit 1
      IFS= read -r -d "" SAFEDEP_TENANT_ID || exit 1
      export SAFEDEP_API_KEY SAFEDEP_TENANT_ID
      exec "$1" cloud login --from-env
    ' _ "$PMG_BIN"
}

configure_user() {
  local user="$1"
  log "Configuring pmg for $user"
  run_user_file "$user" "$PMG_BIN" setup install || { warn "setup failed for $user"; return; }

  [[ -n "$CLOUD_API_KEY" && -n "$CLOUD_TENANT_ID" ]] || return 0
  # When config is globally managed, `cloud.enabled` comes from the global
  # file; per-user `config set` is refused. Per-user credentials still go to
  # the keyring.
  if [[ ! -f "$GLOBAL_CONFIG_FILE" ]]; then
    run_user_file "$user" "$PMG_BIN" config set cloud.enabled true || warn "could not enable cloud sync for $user"
  fi
  if user_has_session "$user"; then
    cloud_login "$user" || warn "cloud login failed for $user"
  else
    log "  $user has no active session; cloud credentials were not stored in their keyring"
  fi
  cloud_sync "$user" || warn "cloud sync failed for $user"
}

while IFS=$'\t' read -r user _ _; do
  configure_user "$user"
done < <(each_target_user)

unset CLOUD_API_KEY CLOUD_TENANT_ID

log "pmg setup complete"
