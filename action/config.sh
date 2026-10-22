#!/bin/sh
# Stages a config-file and exports the PMG configuration to the job. Reads
# INPUT_CONFIG_FILE and the IN_* inputs.
set -eu

if [ -n "$INPUT_CONFIG_FILE" ]; then
  src="${GITHUB_WORKSPACE}/${INPUT_CONFIG_FILE}"
  if [ ! -f "$src" ]; then
    printf '%s\n' "::error::config-file not found: $src" >&2
    exit 1
  fi
  dest_dir="${XDG_CONFIG_HOME:-$HOME/.config}/safedep/pmg"
  mkdir -p "$dest_dir"
  cp "$src" "$dest_dir/config.yml"
  printf '%s\n' "Staged $src -> $dest_dir/config.yml"
fi

nl='
'
cr=$(printf '\r')

# A line break would let an input inject other variables into
# GITHUB_ENV, or workflow commands into the log.
no_line_break() {
  case "$2" in
    *"$nl"*|*"$cr"*)
      printf '%s\n' "::error::The value for $1 contains a line break." >&2
      exit 1
      ;;
  esac
}

export_var() {
  no_line_break "$1" "$2"
  if [ -n "$2" ]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_ENV"
  fi
}

# Guard mode is removed: fail loudly when a workflow still opts out of
# proxy interception instead of silently switching it to proxy mode.
case "$(printf '%s' "$IN_PROXY_MODE" | tr '[:upper:]' '[:lower:]')" in
  false|0|f)
    printf '%s\n' "::error::PMG guard mode has been removed and proxy interception can no longer be disabled. Remove the 'proxy-mode' input." >&2
    exit 1
    ;;
  "") ;;
  *)
    printf '%s\n' "::warning::The 'proxy-mode' input is removed and has no effect. Remove it from your workflow." >&2
    ;;
esac

# Cloud credentials. PMG sync reads these directly when no keychain
# credential is found, so we skip "pmg cloud login" entirely.
if [ -n "$IN_API_KEY" ] || [ -n "$IN_TENANT_ID" ]; then
  if [ -z "$IN_API_KEY" ] || [ -z "$IN_TENANT_ID" ]; then
    printf '%s\n' "::error::api-key and tenant-id must be set together." >&2
    exit 1
  fi
  no_line_break api-key "$IN_API_KEY"
  printf '%s\n' "::add-mask::$IN_API_KEY"
  export_var SAFEDEP_API_KEY "$IN_API_KEY"
  export_var SAFEDEP_TENANT_ID "$IN_TENANT_ID"
  export_var PMG_CLOUD_ENABLED "true"

  if [ "$IN_SERVER_MODE" = "true" ]; then
    # In server mode the proxy daemon owns delivery and uses auto_sync
    # to gate both periodic sync and the shutdown flush.
    export_var PMG_CLOUD_AUTO_SYNC_ENABLED "true"
  else
    # PMG's opportunistic background auto-sync is designed for
    # long-lived workstations. On an ephemeral runner the detached child
    # can be torn down before it drains the WAL, and the WAL goes with
    # it. Turn it off and rely on an explicit `pmg cloud sync` at
    # job-end if the user wants events delivered.
    export_var PMG_CLOUD_AUTO_SYNC_ENABLED "false"
  fi

  if [ -n "$IN_ENDPOINT_ID" ]; then
    export_var PMG_CLOUD_ENDPOINT_ID "$IN_ENDPOINT_ID"
  else
    # Stable per-repo identifier; the runner hostname is ephemeral
    # so PMG's hostname fallback would create a new "machine" entry
    # in SafeDep Cloud for every job.
    export_var PMG_CLOUD_ENDPOINT_ID "gha/${GH_REPOSITORY}"
  fi
fi

# Only emit PMG_* vars when the user explicitly set the input. This
# preserves the "config-file overrides PMG defaults" guarantee — env
# vars take precedence over config.yml in Viper, so empty pass-through
# means we don't shadow file-based tuning.
export_var PMG_PARANOID                     "$IN_PARANOID"
export_var PMG_DEPENDENCY_COOLDOWN_ENABLED  "$IN_COOLDOWN_ENABLED"
export_var PMG_DEPENDENCY_COOLDOWN_DAYS     "$IN_COOLDOWN_DAYS"
export_var PMG_SANDBOX_ENABLED              "$IN_SANDBOX"
if [ "$IN_SANDBOX" = "true" ]; then
  driver="${IN_SANDBOX_DRIVER:-landlock}"
  export_var PMG_SANDBOX_DRIVER             "$driver"
fi
export_var PMG_VERBOSITY                    "$IN_VERBOSITY"
export_var PMG_DISABLE_TELEMETRY            "$IN_DISABLE_TELEMETRY"
export_var PMG_SKIP_EVENT_LOGGING           "$IN_SKIP_EVENT_LOGGING"
