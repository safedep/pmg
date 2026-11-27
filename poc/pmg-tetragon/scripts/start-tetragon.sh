#!/usr/bin/env bash
# Installs Tetragon from its release tarball as a systemd service, loads the
# POC policies for one mode (audit or enforce), and waits until every policy is
# enabled. Prints the seconds it took, so the POC can report the start-up cost.
set -euo pipefail

mode="${1:?usage: start-tetragon.sh audit|enforce}"
version="${TETRAGON_VERSION:-v1.8.0}"
here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
start=$(date +%s)

arch=amd64
[ "$(uname -m)" = aarch64 ] && arch=arm64
tarball="tetragon-${version}-${arch}.tar.gz"
base="https://github.com/cilium/tetragon/releases/download/${version}"

curl -sSfL -o "$work/$tarball" "$base/$tarball"
curl -sSfL -o "$work/$tarball.sha256sum" "$base/$tarball.sha256sum"
(cd "$work" && sha256sum -c "$tarball.sha256sum")
tar -xzf "$work/$tarball" -C "$work"

sudo install -d /etc/tetragon/tetragon.tp.d /etc/tetragon/tetragon.conf.d
sudo cp "$here/tetragon/$mode"/*.yaml /etc/tetragon/tetragon.tp.d/
# Keep the export file plain JSON lines for the report script.
echo false | sudo tee /etc/tetragon/tetragon.conf.d/export-file-compress >/dev/null
sudo "$work/tetragon-${version}-${arch}/install.sh" >/dev/null

want=$(ls "$here/tetragon/$mode"/*.yaml | wc -l)
for _ in $(seq 1 90); do
  enabled=$(sudo tetra --server-address unix:///var/run/tetragon/tetragon.sock tracingpolicy list -o json 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    print(0); sys.exit()
pols = data.get("policies", []) if isinstance(data, dict) else data
print(sum(1 for p in pols if str(p.get("state", "")).upper().endswith("ENABLED")))
' || echo 0)
  if [ "$enabled" -ge "$want" ]; then
    echo $(($(date +%s) - start))
    exit 0
  fi
  sleep 1
done

echo "Tetragon did not enable $want policies in 90 seconds" >&2
sudo tetra --server-address unix:///var/run/tetragon/tetragon.sock tracingpolicy list >&2 || true
sudo journalctl -u tetragon --no-pager | tail -50 >&2 || true
exit 1
