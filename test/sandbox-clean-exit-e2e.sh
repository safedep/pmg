#!/usr/bin/env bash
# A package script that catches a sandbox denial exits 0. PMG must still
# record the denial. A clean run without a denial must record nothing.
set -euo pipefail

PMG_CACHE_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pmg-clean-exit-e2e.XXXXXX")"
export PMG_CACHE_DIR

# Prints the primary target of each cached record, one per line. A record with
# no target prints a placeholder, so it still counts. It fails when pmg fails or
# prints no valid JSON, so a crash cannot look like an empty cache.
violation_targets() {
  local out
  out="$(pmg sandbox violations list --json)" || return 1
  node -e 'for (const e of JSON.parse(process.argv[1]).entries) console.log(e.primary?.target || "<no target>")' "$out"
}

pmg --sandbox --sandbox-enforce npm exec -- node -e "console.log('clean run')"
targets="$(violation_targets)"
if [ -n "$targets" ]; then
  echo "FAIL: a clean run recorded a violation"
  echo "$targets"
  exit 1
fi

pmg --sandbox --sandbox-enforce npm exec -- node -e \
  "try { require('fs').readFileSync(require('os').homedir() + '/.ssh/id_rsa') } catch (e) {}"
targets="$(violation_targets)"
if [[ "$targets" != *"/.ssh/id_rsa"* ]]; then
  echo "FAIL: the caught read of ~/.ssh/id_rsa was not recorded"
  echo "$targets"
  exit 1
fi

echo "PASS: the caught denial was recorded, and the clean run recorded nothing"
