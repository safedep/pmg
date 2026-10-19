#!/bin/sh
# Turns the enforce-* and network-* inputs of the action into pmg proxy
# start flags, one argument per line, so the caller can read them into an
# argument list. Each input is a comma or newline separated list. Blank
# items are skipped. The script is POSIX sh, because the server mode step
# runs it in job containers that have no bash.
set -eu

emit() {
  flag="$1"
  items=$(printf '%s\n' "${2:-}" | tr ',' '\n')
  while IFS= read -r item; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    if [ -n "$item" ]; then
      printf '%s\n%s\n' "$flag" "$item"
    fi
  done <<ITEMS
$items
ITEMS
}

emit --enforce-port              "${INPUT_ENFORCE_PORTS:-}"
emit --enforce-exempt-user       "${INPUT_ENFORCE_EXEMPT_USERS:-}"
emit --enforce-exempt-executable "${INPUT_ENFORCE_EXEMPT_EXECUTABLES:-}"
emit --enforce-skip-destination  "${INPUT_ENFORCE_SKIP_DESTINATIONS:-}"
emit --enforce-namespaces        "${INPUT_ENFORCE_NAMESPACES:-}"
emit --profile                   "${INPUT_NETWORK_PROFILE:-}"
emit --network-mode              "${INPUT_NETWORK_MODE:-}"
