#!/bin/bash
# lib_macos.sh — shared helpers for the PMG macOS install/uninstall scripts.
#
# MDM tools (Jamf, Mosyle, Kandji, Intune, ...) run scripts either as root or
# already as the logged-in user. These helpers make both work without the caller
# branching on it:
#
#   - Machine-scope actions (the pmg binary) go through run_as_root.
#   - Per-user actions (config, aliases, shims, Keychain) go through the
#     user-scope helpers, which fan out to every local user when run as root and
#     act on the current user when run as that user.
#
# Keychain access needs the user's GUI session, so credential steps are gated on
# user_has_session and dispatched via `launchctl asuser`. Homebrew refuses to run
# as root, so brew steps run as the owner of the Homebrew install via run_brew.
#
# This file is sourced by the install/uninstall scripts; deploy them together.

require_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Error: this script is for macOS only" >&2
    exit 1
  fi
}

log() { echo "==> $*"; }
warn() { echo "==> warning: $*" >&2; }

running_as_root() { [[ "$EUID" -eq 0 ]]; }

# Path to a Homebrew binary (Apple Silicon or Intel), or non-zero if absent.
find_brew() {
  local candidate
  for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    [[ -x "$candidate" ]] && { echo "$candidate"; return 0; }
  done
  return 1
}

# Run a machine-scope command, elevating only if we are not already root.
run_as_root() {
  if running_as_root; then "$@"; else sudo "$@"; fi
}

# brew refuses to run as root, so run it as the owner of the Homebrew install.
run_brew() {
  local brew_bin="$1"; shift
  local owner; owner=$(stat -f%Su "$brew_bin")
  if [[ "$owner" == "$(id -un)" ]]; then
    "$brew_bin" "$@"
  elif running_as_root && [[ "$owner" != "root" ]]; then
    sudo -u "$owner" -H -- "$brew_bin" "$@"
  else
    warn "cannot run brew as $(id -un); Homebrew is owned by $owner"
    return 1
  fi
}

# The console (GUI logged-in) user, or non-zero if none / at the login window.
console_user() {
  local u
  u=$(stat -f%Su /dev/console 2>/dev/null || true)
  [[ -z "$u" || "$u" == "root" || "$u" == "loginwindow" ]] && return 1
  echo "$u"
}

# Emit "user<TAB>uid<TAB>home" per target user.
#   - as root: every local human account (UID >= 500) with a real home.
#   - as a user: just the current user (the MDM ran us in user context).
each_target_user() {
  if ! running_as_root; then
    printf '%s\t%s\t%s\n' "$(id -un)" "$(id -u)" "$HOME"
    return
  fi
  local user uid home
  while IFS= read -r user; do
    uid=$(dscl . -read "/Users/$user" UniqueID 2>/dev/null | awk '{print $2}')
    if ! [[ "$uid" =~ ^[0-9]+$ ]] || [[ "$uid" -lt 500 ]]; then continue; fi
    home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    [[ -n "$home" && -d "$home" ]] || continue
    case "$home" in /Users/*) ;; *) continue ;; esac
    printf '%s\t%s\t%s\n' "$user" "$uid" "$home"
  done < <(dscl . -list /Users)
}

# True if this user's login Keychain is reachable (they have a live session).
user_has_session() {
  if running_as_root; then
    [[ "$1" == "$(console_user || true)" ]]
  else
    [[ "$1" == "$(id -un)" ]]
  fi
}

# Run a file-scope command as the given user, with HOME set to their home.
run_user_file() {
  local user="$1"; shift
  if running_as_root; then sudo -u "$user" -H -- "$@"; else "$@"; fi
}

# Run a session-scope command (e.g. Keychain) inside the user's GUI session.
# Only call when user_has_session "$user" is true.
run_user_session() {
  local user="$1"; shift
  if running_as_root; then
    launchctl asuser "$(id -u "$user")" sudo -u "$user" -H -- "$@"
  else
    "$@"
  fi
}

# Per-user pmg state directories: env overrides win, else the macOS layout.
pmg_config_dir() { echo "${PMG_CONFIG_DIR:-$1/Library/Application Support/safedep/pmg}"; }
pmg_cache_dir() { echo "${PMG_CACHE_DIR:-$1/Library/Caches/safedep/pmg}"; }

# Absolute path to the pmg binary. root's PATH under an MDM is often minimal, so
# fall back to the machine-wide install locations.
resolve_pmg() {
  local p
  p=$(command -v pmg 2>/dev/null) && { echo "$p"; return 0; }
  for p in /usr/local/bin/pmg /opt/homebrew/bin/pmg; do
    [[ -x "$p" ]] && { echo "$p"; return 0; }
  done
  return 1
}

# Machine-wide globally managed config. When this file is present pmg treats it as
# authoritative and ignores every user's config. It must match the path pmg
# resolves on macOS.
readonly GLOBAL_CONFIG_DIR="/Library/Application Support/safedep/pmg"
readonly GLOBAL_CONFIG_FILE="${GLOBAL_CONFIG_DIR}/config.yml"

# install_global_config <src> installs a bundled config.yml as the globally
# managed config: root-owned and 0644 so users can read but not modify it.
install_global_config() {
  local src="$1"
  log "Installing globally managed config to $GLOBAL_CONFIG_FILE"
  run_as_root install -d -m 0755 "$GLOBAL_CONFIG_DIR" || { warn "failed to create $GLOBAL_CONFIG_DIR (need root)"; return 1; }
  run_as_root install -m 0644 "$src" "$GLOBAL_CONFIG_FILE" || { warn "failed to install global config (need root)"; return 1; }
}

# remove_global_config removes the globally managed config when present, unless
# PMG_KEEP_GLOBAL_CONFIG is set.
remove_global_config() {
  if [[ -n "${PMG_KEEP_GLOBAL_CONFIG:-}" ]]; then
    [[ -e "$GLOBAL_CONFIG_FILE" ]] && log "Keeping globally managed config ($GLOBAL_CONFIG_FILE); PMG_KEEP_GLOBAL_CONFIG is set"
    return 0
  fi

  [[ -e "$GLOBAL_CONFIG_FILE" ]] || return 0
  log "Removing globally managed config $GLOBAL_CONFIG_FILE"
  run_as_root rm -f "$GLOBAL_CONFIG_FILE" || warn "failed to remove global config (need root)"
  run_as_root rmdir "$GLOBAL_CONFIG_DIR" 2>/dev/null || true
}
