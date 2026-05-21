#!/bin/bash
# pmg_uninstall_macos.sh — Remove PMG from a Mac.
#
# Deploy via Jamf or any MDM, alongside lib_macos.sh in the same directory.
# Run as root, it cleans up every local user's config, aliases, shims, and (for
# the logged-in user) Keychain credentials, then removes the machine-wide binary.
# Run as a user, it cleans up just that user. See lib_macos.sh for the model.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib_macos.sh
source "${SCRIPT_DIR}/lib_macos.sh"

require_macos

PMG_BIN=$(resolve_pmg || true)

remove_user_state() {
  local user="$1" home="$2"
  log "Removing pmg state for $user"

  if [[ -n "$PMG_BIN" ]]; then
    run_user_file "$user" "$PMG_BIN" setup remove \
      || warn "failed to remove aliases/shims for $user"
  else
    warn "pmg binary not found; shell rc entries for $user may remain"
  fi

  run_user_file "$user" rm -rf \
    "$(pmg_config_dir "$home")" "$(pmg_cache_dir "$home")" \
    "$home/.pmg" "$home/.pmg.rc" "$home/.local/bin/pmg" \
    || warn "failed to remove pmg directories for $user"

  if [[ -z "$PMG_BIN" ]]; then
    return
  fi
  if user_has_session "$user"; then
    run_user_session "$user" "$PMG_BIN" cloud logout \
      || warn "failed to clear Keychain credentials for $user"
  else
    log "  $user is not logged in; Keychain credentials (if any) will clear on next login"
  fi
}

while IFS=$'\t' read -r user _ home; do
  remove_user_state "$user" "$home"
done < <(each_target_user)

remove_binary() {
  local brew_bin
  if brew_bin=$(find_brew) && run_brew "$brew_bin" ls --versions safedep/tap/pmg &>/dev/null; then
    log "Uninstalling pmg via Homebrew"
    run_brew "$brew_bin" uninstall safedep/tap/pmg || warn "brew uninstall failed"
    return
  fi

  # Not brew-managed: remove machine-wide binaries from the locations resolve_pmg
  # checks, so a manual install in either prefix is not left behind.
  local path
  for path in /usr/local/bin/pmg /opt/homebrew/bin/pmg; do
    if [[ -e "$path" ]]; then
      log "Removing $path"
      run_as_root rm -f "$path" || warn "failed to remove $path (need root)"
    fi
  done
}
remove_binary

remove_global_config

log "pmg uninstall complete"
