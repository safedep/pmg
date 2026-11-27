#!/usr/bin/env bash
# Prints "<package>@<version>" for a real npm version published in the last
# 36 hours, so the cooldown test always has a version PMG must hold back.
# Run it before PMG starts: PMG strips young versions from npm metadata.
set -euo pipefail

for pkg in typescript next @angular/core vite eslint; do
  found=$(curl -sSf "https://registry.npmjs.org/${pkg/\//%2F}" | python3 -c '
import json, sys, datetime as dt
doc = json.load(sys.stdin)
now = dt.datetime.now(dt.timezone.utc)
best = None
for ver, ts in doc.get("time", {}).items():
    if ver in ("created", "modified") or ver not in doc.get("versions", {}):
        continue
    t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    age = (now - t).total_seconds() / 3600
    if age < 36 and (best is None or t > best[1]):
        best = (ver, t)
print(best[0] if best else "")
' || true)
  if [ -n "$found" ]; then
    echo "${pkg}@${found}"
    exit 0
  fi
done
echo "no npm version younger than 36 hours found" >&2
exit 1
