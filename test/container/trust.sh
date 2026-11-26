#!/bin/bash
# trust.sh starts a runner image with dockerd through pmg-entrypoint.sh, and
# checks that pmg-runc gives the PMG CA to docker run, docker exec and a RUN
# step of docker build. It also checks that the runner does not use pmg-runc
# when PMG_CONTAINER_TRUST is off.
#
# Usage: test/container/trust.sh <pmg-image>
# The PMG image is a build of the Dockerfile at the root of the repository.
# shellcheck disable=SC2016 # the shells in the containers expand these
set -euo pipefail

PMG_IMAGE=${1:?usage: $0 <pmg-image>}
RUNNER_IMAGE=pmg-trust-runner:test
NODE_IMAGE=node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
runner=""
fails=0
runner_fails=0

# probe stops with an error when a CA variable is not under /dev/pmg-ca or a
# CA file is missing.
probe='for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE PIP_CERT NODE_EXTRA_CA_CERTS; do eval "p=\${$v:-}"; echo "$v=$p"; case $p in /dev/pmg-ca/*) ;; *) exit 1 ;; esac; done; test -s /dev/pmg-ca/ca.pem && test -s /dev/pmg-ca/ca-bundle.pem'

check() {
  local name=$1 out
  shift
  if out=$("$@" 2>&1); then
    echo "PASS: $name"
  else
    echo "FAIL: $name"
    tail -n 20 <<<"$out"
    fails=$((fails + 1))
  fi
}

dump() {
  echo "----- docker logs $runner"
  docker logs "$runner" 2>&1 | tail -n 100 || true
  echo "----- /var/log/pmg-runc.log"
  docker exec "$runner" cat /var/log/pmg-runc.log 2>&1 || true
}

stop_runner() {
  if [ -n "$runner" ]; then
    if [ "$fails" -gt "$runner_fails" ]; then dump; fi
    docker rm -f -v "$runner" >/dev/null 2>&1 || true
    runner=""
  fi
}

on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then fails=$((fails + 1)); fi
  stop_runner
  exit "$rc"
}
trap on_exit EXIT

# start_runner starts the runner and waits for its dockerd. dockerd starts
# after pmg-entrypoint.sh has started PMG.
start_runner() {
  runner=$1
  runner_fails=$fails
  shift
  docker run -d --privileged --name "$runner" "$@" "$RUNNER_IMAGE" >/dev/null
  for _ in $(seq 90); do
    if docker exec "$runner" docker info >/dev/null 2>&1; then return; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$runner")" != true ]; then break; fi
    sleep 1
  done
  echo "FAIL: dockerd in $runner did not start"
  return 1
}

in_runner() { docker exec -i "$runner" "$@"; }

docker build -q -t "$RUNNER_IMAGE" --build-arg PMG_IMAGE="$PMG_IMAGE" - >/dev/null <<'EOF'
ARG PMG_IMAGE
FROM ${PMG_IMAGE} AS pmg
FROM docker:29.10.1-dind@sha256:fbbc96e0af32cdc190aff92ba97a1281a115351a723afe21af78879cc55126b0
# Original: docker:29.10.1-dind
# BusyBox stat does not name cgroup2fs. pmg-entrypoint.sh needs the stat of coreutils.
RUN apk add --no-cache bash coreutils
COPY --from=pmg /opt/safedep/pmg /opt/safedep/pmg
ENTRYPOINT ["/opt/safedep/pmg/bin/pmg-entrypoint.sh", "dockerd-entrypoint.sh"]
EOF

start_runner pmg-trust-on -e PMG_CONTAINER_TRUST=1
check "docker run gets the PMG CA" in_runner docker run --rm "$NODE_IMAGE" sh -c "$probe"
in_runner docker run -d --name job "$NODE_IMAGE" sleep 600 >/dev/null
check "docker exec gets the PMG CA" in_runner docker exec job sh -c "$probe"
check "docker build RUN step gets the PMG CA" in_runner sh -c 'mkdir -p /tmp/b && cat >/tmp/b/Dockerfile && docker build --no-cache --progress plain /tmp/b' <<EOF
FROM $NODE_IMAGE
RUN $probe
EOF
check "npm install of an allowed package succeeds" in_runner docker run --rm "$NODE_IMAGE" sh -c 'cd /tmp && npm install --no-audit --no-fund is-number@7.0.0'
check "npm install of a malicious package is blocked" in_runner sh -c "docker run --rm $NODE_IMAGE sh -c 'cd /tmp && npm install --no-audit --no-fund safedep-test-pkg@0.1.3' >/tmp/bad.log 2>&1; cat /tmp/bad.log; grep -q E403 /tmp/bad.log"
stop_runner

start_runner pmg-trust-off
check "runc is not pmg-runc when PMG_CONTAINER_TRUST is off" in_runner sh -c '[ "$(readlink /usr/local/sbin/runc)" != /opt/safedep/pmg/bin/pmg-runc ]'
stop_runner

if [ "$fails" -gt 0 ]; then
  echo "$fails check(s) failed"
  exit 1
fi
echo "all checks passed"
