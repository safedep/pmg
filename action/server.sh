#!/bin/sh
# Starts the PMG proxy daemon without kernel enforcement and exports the
# proxy variables to the job. POSIX sh, because it runs in job containers
# that have no bash. Reads INPUT_EXPOSE_TO_JOB_NETWORK, the network inputs
# and PMG_JOB_CONTAINER.
set -eu
# The network inputs travel as flags, which the job log shows. The
# script prints one argument per line, and sh has no arrays, so the
# lines become the positional parameters.
flags="$("$PMG_ACTION_DIR/enforce-flags.sh")"
set --
while IFS= read -r arg; do
  if [ -n "$arg" ]; then set -- "$@" "$arg"; fi
done <<EOF
$flags
EOF

# No cert install needed: `pmg proxy env` exports the CA path via
# NODE_EXTRA_CA_CERTS/SSL_CERT_FILE/PIP_CERT, so package managers trust
# the proxy without touching the OS trust store.
if [ "$INPUT_EXPOSE_TO_JOB_NETWORK" != "true" ]; then
  pmg proxy start --daemon "$@"
  pmg proxy env >> "$GITHUB_ENV"
  exit 0
fi

# On the runner itself the address would be the host's own, and the
# proxy would be open to its network.
if [ "$PMG_JOB_CONTAINER" != true ]; then
  printf '%s\n' "::error::expose-to-job-network needs a job container (jobs.<job_id>.container)." >&2
  exit 1
fi

# Docker writes the container's address on the job network next to
# its hostname in /etc/hosts. Read both in the shell, because the image
# may not have the hostname or getent tools. The kernel holds the
# hostname. A workflow env can replace the HOSTNAME variable.
read -r hostname < /proc/sys/kernel/hostname
host=""
while read -r addr names; do
  case "$addr" in ""|"#"*|127.*|*:*) continue ;; esac
  for name in $names; do
    if [ "$name" = "$hostname" ]; then
      host="$addr"
      break 2
    fi
  done
done < /etc/hosts
if [ -z "$host" ]; then
  printf '%s\n' "::error::Cannot find the address of the job container for hostname ${hostname} in /etc/hosts." >&2
  exit 1
fi

pmg proxy start --daemon --host "$host" "$@"
proxy_env="$(pmg proxy env)"
printf '%s\n' "$proxy_env" >> "$GITHUB_ENV"

# The runner mounts /github/home in the job container (as HOME) and
# in Docker actions. A CA outside it is missing in Docker actions.
ca="$(printf '%s\n' "$proxy_env" | sed -n 's/^NODE_EXTRA_CA_CERTS=//p')"
case "$ca" in
  /github/home/*) ;;
  *) printf '%s\n' "::warning::The PMG CA is at ${ca}, outside /github/home. Docker actions cannot read it, so their TLS connections through the proxy fail." ;;
esac
