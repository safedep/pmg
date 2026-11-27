#!/usr/bin/env bash
# Copies the PMG event log, the PMG proxy log and the Tetragon export into
# $POC_RESULTS, readable by the runner user. Run it with if: always().
set -uo pipefail
: "${POC_RESULTS:?}"
mkdir -p "$POC_RESULTS"

# Tetragon writes its export through a buffer. Give it a moment to flush.
sleep 5

sudo find / -xdev \( -path /proc -o -path /sys \) -prune -o -name '*-pmg.log' -path '*safedep*' -print 2>/dev/null |
  while read -r f; do sudo cat "$f"; done >"$POC_RESULTS/pmg-events.jsonl" || true

for f in /root/.cache/safedep/pmg/proxy.log "$HOME/.cache/safedep/pmg/proxy.log"; do
  sudo test -f "$f" && sudo cp "$f" "$POC_RESULTS/pmg-proxy.log"
done

if sudo test -d /var/log/tetragon; then
  sudo sh -c 'cat /var/log/tetragon/tetragon.log* 2>/dev/null' >"$POC_RESULTS/tetragon.jsonl" || true
  sudo journalctl -u tetragon --no-pager >"$POC_RESULTS/tetragon-service.log" 2>&1 || true
  sudo tetra --server-address unix:///var/run/tetragon/tetragon.sock tracingpolicy list >"$POC_RESULTS/tetragon-policies.txt" 2>&1 || true
fi

sudo chown -R "$(id -u):$(id -g)" "$POC_RESULTS"
ls -la "$POC_RESULTS"
