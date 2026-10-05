#!/usr/bin/env bash
# Docker leg of the POC. Runs against a live dockerd with nft redirect and
# SO_ORIGINAL_DST, the shape that survives br_netfilter. Needs root, nft,
# docker, go. The proxy splices every steered connection to its original
# destination, so TLS still ends at the real server and curl verifies it.
# BRNF=1 loads br_netfilter and turns bridge-nf-call-iptables on, the shape
# of a Kubernetes node. Unset, the host keeps its own setting.
set -uo pipefail
cd "$(dirname "$0")"

BRNF=${BRNF:-}
MODE=${MODE:-redirect}
ADDR=169.254.200.1
PORT=18443
PASS=0
FAIL=0
CURL=curlimages/curl
NGINX=nginx:alpine
PING=https://registry.npmjs.org/-/ping

say() { printf '\n== %s\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
steered() { grep -c 'steered=true' proxy.log 2>/dev/null || echo 0; }
# expect_steered NAME DELTA CMD runs CMD and checks that the proxy saw
# exactly DELTA new steered connections, 0 meaning the path avoided the proxy.
expect_steered() {
  local before after
  before=$(steered)
  if eval "$3"; then ok "$1: command succeeded"; else bad "$1: command failed"; fi
  after=$(steered)
  if [ "$2" = any ] && [ "$after" -gt "$before" ]; then ok "$1: proxy saw $((after - before)) steered connection(s)"
  elif [ "$2" = none ] && [ "$after" -eq "$before" ]; then ok "$1: proxy saw nothing"
  else bad "$1: proxy saw $((after - before)) steered connection(s), expected $2"; fi
}

cleanup() {
  set +e
  pkill -f '^\./poc -mode proxy' >/dev/null 2>&1
  docker rm -f poc-nginx poc-nginx-same poc-nginx-pub >/dev/null 2>&1
  docker buildx rm -f pocbuilder >/dev/null 2>&1
  docker network rm pocnet pocnet2 >/dev/null 2>&1
  nft delete table inet pmgpoc 2>/dev/null
  ip addr del $ADDR/32 dev lo 2>/dev/null
  rm -rf build
}
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT
cleanup

say "environment"
uname -r
nft --version
iptables --version
docker --version
[ "$BRNF" = 1 ] && modprobe br_netfilter && sysctl -q -w net.bridge.bridge-nf-call-iptables=1
printf 'bridge-nf-call-iptables=%s\n' "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo "module not loaded")"
ip -br addr show docker0
GOWORK=off go build -o poc . || exit 1
docker pull -q $CURL >/dev/null && docker pull -q $NGINX >/dev/null || exit 1
docker network create pocnet2 >/dev/null || exit 1
docker run -d --rm --name poc-nginx --network pocnet2 $NGINX >/dev/null || exit 1
docker run -d --rm --name poc-nginx-same $NGINX >/dev/null || exit 1
docker run -d --rm --name poc-nginx-pub -p 18080:80 $NGINX >/dev/null || exit 1
NGINX_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' poc-nginx)
NGINX_SAME_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' poc-nginx-same)
DOCKER0_IP=$(ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1)
echo "nginx on pocnet2 $NGINX_IP, nginx on docker0 $NGINX_SAME_IP, docker0 $DOCKER0_IP"

say "baseline without rules"
check "default bridge container reaches npm" "docker run --rm $CURL -sS -m 20 $PING | grep -q '{}'"

if [ "$MODE" = dnat ]; then
  say "rules: nft dnat on docker0 and br-* to $ADDR:$PORT on lo"
  ip addr add $ADDR/32 dev lo
  LISTEN=$ADDR
  ACTION="counter dnat ip to $ADDR:$PORT"
else
  say "rules: nft redirect on docker0 and br-*, listener on 0.0.0.0:$PORT guarded to bridge ingress"
  LISTEN=0.0.0.0
  ACTION="counter redirect to :$PORT"
fi
./poc -mode proxy -listen $LISTEN:$PORT >proxy.log 2>&1 &
sleep 0.5
nft -f - <<EOF
table inet pmgpoc {
  chain steer {
    fib daddr type local counter return
    fib daddr oifname "docker0" counter return
    fib daddr oifname "br-*" counter return
    tcp dport { 80, 443, 8443 } $ACTION
  }
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "docker0" jump steer
    iifname "br-*" jump steer
  }
  chain guard {
    type filter hook input priority filter; policy accept;
    iifname "lo" accept
    iifname "docker0" accept
    iifname "br-*" accept
    tcp dport $PORT counter drop
  }
  chain udpdeny {
    type filter hook forward priority filter; policy accept;
    iifname "docker0" udp dport 443 counter reject
    iifname "br-*" udp dport 443 counter reject
  }
}
EOF
if [ $? -ne 0 ]; then echo "nft rules failed"; exit 1; fi

say "D1 default bridge container, TLS 443"
expect_steered "D1" any "docker run --rm $CURL -sS -m 20 $PING | grep -q '{}'"
check "D1: proxy log names registry.npmjs.org on port 443" "grep -q ':443 steered=true sni=\"registry.npmjs.org\"' proxy.log"

say "D2 user-defined network created after the rules"
docker network create pocnet >/dev/null
expect_steered "D2" any "docker run --rm --network pocnet $CURL -sS -m 20 $PING | grep -q '{}'"

say "D3 docker build RUN step with the default builder"
mkdir -p build
printf 'FROM %s\nRUN curl -sS -m 20 %s\n' "$CURL" "$PING" > build/Dockerfile
expect_steered "D3" any "docker build --no-cache -q build >/dev/null"

say "D4 docker build RUN step in a docker-container builder (nested namespace)"
if docker buildx create --name pocbuilder --driver docker-container --bootstrap >/dev/null 2>&1; then
  expect_steered "D4" any "docker buildx build --builder pocbuilder --no-cache -q build >/dev/null"
  printf 'FROM %s\nRUN curl -sS -m 20 http://portquiz.net:8443/ | grep -qi port\n' "$CURL" > build/Dockerfile
  expect_steered "D4 port 8443 through nested NAT" any "docker buildx build --builder pocbuilder --no-cache -q build >/dev/null"
  check "D4: proxy log shows origdst port 8443" "grep -q ':8443 steered=true' proxy.log"
else
  bad "D4: buildx docker-container builder did not start"
fi

say "D5 cross-network destination is not steered (Docker isolation keeps its say)"
expect_steered "D5" none "! docker run --rm --network pocnet $CURL -sS -m 5 http://$NGINX_IP/ >/dev/null 2>&1"

say "D6 same-bridge container to container is not steered"
expect_steered "D6" none "docker run --rm $CURL -sS -m 10 http://$NGINX_SAME_IP/ | grep -q nginx"

say "D7 host network container is not steered"
expect_steered "D7" none "docker run --rm --network host $CURL -sS -m 20 $PING | grep -q '{}'"

say "D8 published port on the host address is not steered"
expect_steered "D8" none "docker run --rm $CURL -sS -m 10 http://$DOCKER0_IP:18080/ | grep -q nginx"

say "D9 listener guard: the host cannot reach the proxy on a non-bridge interface"
HOST_IP=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
check "D9: connect to $HOST_IP:$PORT is dropped or refused" "! curl -sS -m 3 http://$HOST_IP:$PORT/ >/dev/null 2>&1"
check "D9: a host process that reaches the listener is refused as an own address" "! curl -sS -m 3 http://$LISTEN:$PORT/ >/dev/null 2>&1 && grep -q refuse proxy.log"

say "D10 rules left behind after the proxy dies fail closed"
pkill -f '^\./poc -mode proxy'
sleep 0.3
check "D10: container connection fails without a proxy" "! docker run --rm $CURL -sS -m 5 $PING >/dev/null 2>&1"

say "counters"
nft list table inet pmgpoc | sed 's/^/  /'
say "proxy log"
sed 's/^/  /' proxy.log

printf '\nRESULT pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
