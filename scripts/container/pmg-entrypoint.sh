#!/bin/bash
# pmg-entrypoint.sh starts PMG with kernel enforcement in a CI runner
# container, before dockerd and the runner start.
#
# PMG covers the processes of this container: job steps, and every process
# they start in it. dockerd starts its containers in other cgroups. PMG does
# not route them, and they keep working with no PMG check.
#
# The script writes /etc/safedep/pmg/config.yml when no file is there. A PMG_
# variable overrides a config key, for example
# PMG_PROXY_SERVER_ENFORCE_SKIP_DESTINATIONS. SafeDep Cloud is on when
# $PMG_SECRET_DIR holds the files SAFEDEP_API_KEY and SAFEDEP_TENANT_ID.
set -euo pipefail

PMG_RUN_DIR=/run/pmg
PMG_STATE=$PMG_RUN_DIR/proxy-state.json
PMG_ENV_FILE=$PMG_RUN_DIR/env
PMG_CONFIG=/etc/safedep/pmg/config.yml
PMG_SECRET_DIR=${PMG_SECRET_DIR:-/etc/pmg-secret}

log() { echo "[pmg] $*" >&2; }

usage() {
  cat >&2 <<'EOF'
pmg-entrypoint.sh <command> [args...]  Start PMG, run the command, and
                                       stop PMG after the command stops.
pmg-entrypoint.sh start                Start PMG and return. Then load the
                                       trust variables: . /run/pmg/env
pmg-entrypoint.sh stop                 Stop PMG.
EOF
  exit 2
}

SUDO=sudo
if [ "$(id -u)" -eq 0 ]; then SUDO=; fi

here=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
if [ -x "$here/pmg" ]; then
  PMG_BIN=$here/pmg
elif ! PMG_BIN=$(command -v pmg); then
  log "pmg is not in $here or on PATH"
  exit 1
fi

# sudo drops the environment. Pass on the PMG_ variables, and the Kubernetes
# variables that PMG reads to identify the Pod in SafeDep Cloud.
pmg_env=()
for v in $(compgen -e PMG_) $(compgen -e KUBE_) $(compgen -e KUBERNETES_SERVICE_); do pmg_env+=("$v=${!v}"); done
pmg_cgroup=""
pmg_pid=""

# pmg_root runs pmg as root with the SafeDep Cloud keys from the Secret
# files, so the keys are not in the environment of job steps. Every pmg
# command needs the keys, because a command can start a policy fetch, and a
# fetch without keys delays the next one by 5 minutes. PMG must not use a
# forward proxy from this environment as its upstream. That proxy's
# connections come back to PMG, and the request loops.
pmg_root() {
  # shellcheck disable=SC2016 # the root shell expands these, not this one
  $SUDO env -u HTTPS_PROXY -u HTTP_PROXY -u ALL_PROXY -u https_proxy -u http_proxy -u all_proxy \
    "${pmg_env[@]}" "PMG_SECRET_DIR=$PMG_SECRET_DIR" \
    bash -c '
      for v in SAFEDEP_API_KEY SAFEDEP_TENANT_ID; do
        if [ -r "$PMG_SECRET_DIR/$v" ]; then export "$v=$(<"$PMG_SECRET_DIR/$v")"; fi
      done
      exec "$0" "$@"' "$PMG_BIN" "$@"
}

# attach_cgroup moves every process of this container into the child cgroup
# "runner", and PMG attaches there. dockerd puts its containers in other
# cgroups, so PMG does not route them. The move also lets "docker run
# --memory" work, because cgroup v2 gives controllers only to a cgroup that
# holds no process of its own.
attach_cgroup() {
  local v2="" d own cg
  for d in /sys/fs/cgroup /sys/fs/cgroup/unified; do
    if [ "$(stat -fc %T "$d" 2>/dev/null)" = cgroup2fs ]; then v2=$d; break; fi
  done
  if [ -z "$v2" ]; then
    if ! grep -q '^0::' /proc/self/cgroup; then
      log "this node has no cgroup v2. PMG cannot enforce here."
      exit 1
    fi
    $SUDO mkdir -p /sys/fs/cgroup/unified
    $SUDO mount -t cgroup2 none /sys/fs/cgroup/unified
    v2=/sys/fs/cgroup/unified
  fi
  own=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
  cg="$v2${own%/}"
  if [ "$(basename "$cg")" = runner ]; then cg=$(dirname "$cg"); fi
  $SUDO bash -c "
    mkdir -p '$cg/runner'
    xargs -rn1 < '$cg/cgroup.procs' > '$cg/runner/cgroup.procs' 2>/dev/null || true
    sed -e 's/ / +/g' -e 's/^/+/' < '$cg/cgroup.controllers' > '$cg/cgroup.subtree_control' 2>/dev/null || true
  "
  pmg_cgroup="$cg/runner"
  log "attach to $pmg_cgroup"
}

# write_config skips only the Kubernetes API server. PMG drops TLS without a
# server name, and in-cluster kubectl and helm reach the API server by its IP.
# Other private addresses go through PMG, so PMG logs a mirror that
# proxy.registries does not list.
write_config() {
  local cloud=false skip=""
  if $SUDO test -e "$PMG_CONFIG"; then
    log "use the config in $PMG_CONFIG"
    return
  fi
  if $SUDO test -r "$PMG_SECRET_DIR/SAFEDEP_API_KEY" && $SUDO test -r "$PMG_SECRET_DIR/SAFEDEP_TENANT_ID"; then
    cloud=true
  fi
  case ${KUBERNETES_SERVICE_HOST:-} in
    "") ;;
    *:*) skip="'$KUBERNETES_SERVICE_HOST/128'" ;;
    *) skip="'$KUBERNETES_SERVICE_HOST/32'" ;;
  esac
  $SUDO mkdir -p "$(dirname "$PMG_CONFIG")"
  $SUDO tee "$PMG_CONFIG" >/dev/null <<EOF
proxy:
  server:
    enforce:
      enabled: true
      ports: [80, 443]
      deny_udp: true
      skip_destinations: [$skip]
cloud:
  enabled: $cloud
EOF
  log "SafeDep Cloud: $cloud"
}

load_pid() {
  pmg_pid=$($SUDO sed -n 's/.*"pid"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$PMG_STATE" 2>/dev/null | head -n1) || pmg_pid=""
}

# A stopped process can stay in the process table, and "kill -0" still finds
# it. So read the process state.
pmg_alive() {
  local stat
  [ -n "$pmg_pid" ] || return 1
  { read -r stat <"/proc/$pmg_pid/stat"; } 2>/dev/null || return 1
  stat=${stat##*) }
  [ "${stat%% *}" != Z ]
}

# --enforce keeps enforcement on when the customer's own config file, or a
# PMG_ variable, leaves it off.
start_pmg() {
  pmg_root proxy start --daemon --state "$PMG_STATE" --enforce --enforce-cgroup "$pmg_cgroup" && load_pid
}

# write_trust exports the variables that make job steps trust the PMG CA, and
# writes them to $PMG_ENV_FILE. Node before 22.19, Node 23 and Node 24 before
# 24.6 ignore NODE_USE_SYSTEM_CA, so NODE_EXTRA_CA_CERTS names the bundle too.
write_trust() {
  local trust
  trust=$(pmg_root proxy env --export --state "$PMG_STATE" | grep -v '^export PMG_PROXY_RUN=')
  eval "$trust"
  export NODE_EXTRA_CA_CERTS=$PMG_CA_BUNDLE
  trust+=$'\n'"export NODE_EXTRA_CA_CERTS='$PMG_CA_BUNDLE'"
  printf '%s\n' "$trust" | $SUDO tee "$PMG_ENV_FILE" >/dev/null
  if [ -n "${RUNNER_ASSETS_DIR:-}" ] && [ -d "$RUNNER_ASSETS_DIR" ]; then
    sed -e 's/^export //' -e "s/'//g" <<<"$trust" | $SUDO tee -a "$RUNNER_ASSETS_DIR/.env" >/dev/null
  fi
}

supervise() {
  set +e
  while sleep "${PMG_SUPERVISE_INTERVAL:-2}"; do
    [ -e "$PMG_RUN_DIR/stopping" ] && exit 0
    if ! pmg_alive; then
      log "PMG is not running. Start it again."
      if start_pmg >/dev/null 2>&1; then log "PMG runs again."; else log "PMG did not start."; fi
    fi
  done
}

start_all() {
  load_pid
  if pmg_alive; then
    log "PMG runs already"
    # shellcheck disable=SC1090
    . "$PMG_ENV_FILE"
    return
  fi
  attach_cgroup
  $SUDO mkdir -p "$PMG_RUN_DIR"
  $SUDO rm -f "$PMG_RUN_DIR/stopping"
  write_config
  pmg_root setup cert install --system
  start_pmg
  write_trust
  supervise </dev/null >/dev/null &
}

stop_all() {
  $SUDO mkdir -p "$PMG_RUN_DIR"
  $SUDO touch "$PMG_RUN_DIR/stopping"
  log "stop PMG"
  pmg_root proxy stop --if-running --state "$PMG_STATE" >&2
}

# run_wrapped runs the command as a child. On pod stop the command gets the
# signal first, and PMG stops after it.
run_wrapped() {
  local child rc=0
  [ "$#" -gt 0 ] || usage
  start_all
  "$@" &
  child=$!
  trap 'kill -TERM "$child" 2>/dev/null' TERM INT
  set +e
  while kill -0 "$child" 2>/dev/null; do wait "$child"; done
  wait "$child"
  rc=$?
  stop_all
  exit "$rc"
}

case "${1:-}" in
  start) start_all ;;
  stop) stop_all ;;
  "" | -h | --help) usage ;;
  --) shift; run_wrapped "$@" ;;
  *) run_wrapped "$@" ;;
esac
