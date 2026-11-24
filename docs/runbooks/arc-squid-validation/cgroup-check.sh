#!/bin/bash
# Reports whether Squid, dockerd and cron run inside the cgroup that PMG
# enforces on. A Squid outside it is not routed, and a process that cron or
# dockerd starts lands in their cgroup.
state=${1:-/run/pmg/proxy-state.json}
SUDO=sudo; [ "$(id -u)" -eq 0 ] && SUDO=
enf=$($SUDO sed -n 's/.*"cgroup_path": *"\([^"]*\)".*/\1/p' "$state" | head -1)
enf=${enf#/sys/fs/cgroup/unified}; enf=${enf#/sys/fs/cgroup}
[ -n "$enf" ] || { echo "No cgroup_path in $state. Is PMG running with --enforce?"; exit 1; }
echo "PMG enforces on: $enf"
for name in squid dockerd cron; do
  for p in $(pgrep -x "$name"); do
    cg=$(grep ^0:: /proc/$p/cgroup | cut -d: -f3)
    case "$cg/" in "$enf"/*) v=ROUTED ;; *) v="NOT ROUTED" ;; esac
    echo "$v  $name pid $p: $cg"
  done
done
