#!/usr/bin/env bash
# A package script that catches a sandbox denial exits 0. PMG must still
# record the denial. A clean run without a denial must record nothing.
set -euo pipefail

PMG_CACHE_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pmg-clean-exit-e2e.XXXXXX")"
export PMG_CACHE_DIR

pmg --sandbox --sandbox-enforce npm exec -- node -e "console.log('clean run')"
if [ -n "$(pmg sandbox violations list 2>/dev/null)" ]; then
  echo "FAIL: a clean run recorded a violation"
  pmg sandbox violations list
  exit 1
fi

pmg --sandbox --sandbox-enforce npm exec -- node -e \
  "try { require('fs').readFileSync(require('os').homedir() + '/.ssh/id_rsa') } catch (e) {}"
if ! pmg sandbox violations list | grep -q '\.ssh/id_rsa'; then
  echo "FAIL: the caught read of ~/.ssh/id_rsa was not recorded"
  pmg sandbox violations list
  exit 1
fi

echo "PASS: the caught denial was recorded, and the clean run recorded nothing"
