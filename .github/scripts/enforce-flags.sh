#!/usr/bin/env bash
# Turns the enforce-* inputs of the action into pmg proxy start flags, one
# argument per line, so the caller can read them into an array. Each input
# is a comma or newline separated list. Blank items are skipped.
set -euo pipefail

emit() {
  local flag="$1" raw="${2:-}"
  local item
  while IFS= read -r item; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [ -z "$item" ] && continue
    printf '%s\n%s\n' "$flag" "$item"
  done < <(printf '%s\n' "$raw" | tr ',' '\n')
}

emit --enforce-port              "${INPUT_ENFORCE_PORTS:-}"
emit --enforce-exempt-user       "${INPUT_ENFORCE_EXEMPT_USERS:-}"
emit --enforce-exempt-executable "${INPUT_ENFORCE_EXEMPT_EXECUTABLES:-}"
emit --enforce-skip-destination  "${INPUT_ENFORCE_SKIP_DESTINATIONS:-}"
emit --enforce-namespaces        "${INPUT_ENFORCE_NAMESPACES:-}"
