#!/usr/bin/env bash
# Starts the PMG proxy daemon as root with kernel enforcement. It runs on
# the runner host only, where bash and sudo exist. Reads PMG_BIN_DIR and the
# enforce and network inputs.
set -euo pipefail
if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
  echo "::error::enforce needs passwordless sudo on the runner. Attaching the kernel programs needs root." >&2
  exit 1
fi

# The daemon runs as root. sudo resets PATH and HOME, so every call
# names the binary by absolute path and the state file explicitly.
# The cloud variables travel through --preserve-env, and so do the
# GitHub variables that name the run in the daemon's cloud events. So
# does the config directory: the daemon gets a root-owned copy of a
# staged config-file, so it never writes into the user's directory.
pmg_bin="${PMG_BIN_DIR}/pmg"
state="${RUNNER_TEMP}/pmg-proxy-state.json"
echo "PMG_BIN=${pmg_bin}" >> "$GITHUB_ENV"
echo "PMG_PROXY_STATE=${state}" >> "$GITHUB_ENV"
if [ -n "$INPUT_CONFIG_FILE" ]; then
  export PMG_CONFIG_DIR="${RUNNER_TEMP}/pmg-daemon-config"
  sudo install -D -m 0644 "${XDG_CONFIG_HOME:-$HOME/.config}/safedep/pmg/config.yml" "${PMG_CONFIG_DIR}/config.yml"
  # The daemon's event log is under its config directory. A step
  # that reads the run back, such as `pmg sandbox profile propose`,
  # needs the same directory.
  echo "PMG_PROXY_CONFIG_DIR=${PMG_CONFIG_DIR}" >> "$GITHUB_ENV"
fi

# Trust goes through the system store: the keypair lands in
# /etc/safedep/pmg and the certificate in the trust store.
sudo "$pmg_bin" setup cert install --system

# The policy inputs travel as flags, which the job log shows, where a
# variable preserved through sudo would not. A list flag adds to the
# config file's list. sudo keeps the working directory, so a
# network-profile path in the workspace resolves in the daemon.
# Command substitution, not process substitution, so set -e stops the
# script when the flags script fails, before the daemon starts with a part
# of the policy.
flags_out="$("$PMG_ACTION_DIR/enforce-flags.sh")"
enforce_flags=()
if [ -n "$flags_out" ]; then
  mapfile -t enforce_flags <<<"$flags_out"
fi

sudo --preserve-env=PMG_CONFIG_DIR,SAFEDEP_API_KEY,SAFEDEP_TENANT_ID,PMG_CLOUD_ENABLED,PMG_CLOUD_AUTO_SYNC_ENABLED,PMG_CLOUD_ENDPOINT_ID,PMG_PARANOID,PMG_DEPENDENCY_COOLDOWN_ENABLED,PMG_DEPENDENCY_COOLDOWN_DAYS,PMG_VERBOSITY,PMG_DISABLE_TELEMETRY,PMG_SKIP_EVENT_LOGGING,GITHUB_ACTIONS,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,RUNNER_ENVIRONMENT,GITHUB_REPOSITORY,GITHUB_SHA,GITHUB_ACTOR,GITHUB_REF,GITHUB_REF_NAME,GITHUB_HEAD_REF,GITHUB_WORKFLOW,GITHUB_JOB,GITHUB_SERVER_URL \
  "$pmg_bin" proxy start --daemon --enforce --state "$state" "${enforce_flags[@]}"

# Only the trust variables. The kernel routes the traffic.
sudo "$pmg_bin" proxy env --state "$state" >> "$GITHUB_ENV"
