#!/usr/bin/env bash
# Local leg of the TPROXY POC. Emulates Docker's bridge network with network
# namespaces, then runs the steering tests. Needs root, iproute2, nft, curl.
# MODE=tproxy steers with nft tproxy and an IP_TRANSPARENT listener.
# MODE=redirect (default) steers with nft redirect and SO_ORIGINAL_DST.
# MODE=dnat steers with nft dnat to one address the daemon adds to lo,
# matched by interface kind instead of name.
# BRNF sets bridge-nf-call-iptables, 1 is what Docker hosts run with.
# Set EXCLUDE_SAME_BRIDGE=0 to run without the same-bridge exclusion rule.
set -uo pipefail
cd "$(dirname "$0")"

MODE=${MODE:-redirect}
BRNF=${BRNF:-1}
PORT=18443
BR=brpoc
BRIP=172.30.0.1
SUB=172.30.0.0/24
EXT_HOST=10.99.0.1
EXT=10.99.0.2
EXCLUDE_SAME_BRIDGE=${EXCLUDE_SAME_BRIDGE:-1}
PASS=0
FAIL=0

say() { printf '\n== %s\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

cleanup() {
  set +e
  pkill -f '^\./poc -mode' >/dev/null 2>&1
  for ns in c1 c2 n1 ext; do ip netns del $ns 2>/dev/null; done
  ip link del $BR 2>/dev/null
  ip link del hext 2>/dev/null
  ip addr del 169.254.200.1/32 dev lo 2>/dev/null
  nft delete table inet pmgpoc 2>/dev/null
  nft delete table ip pmgnat 2>/dev/null
  if command -v iptables >/dev/null; then
    for i in $BR hext; do iptables -D FORWARD -i $i -j ACCEPT 2>/dev/null; iptables -D FORWARD -o $i -j ACCEPT 2>/dev/null; done
  fi
  ip rule del fwmark 1 lookup 100 2>/dev/null
  ip route flush table 100 2>/dev/null
  conntrack -F >/dev/null 2>&1
}
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT
cleanup
# curl inside a namespace must not inherit this host's proxy variables.
ccurl() { ip netns exec "$1" env -i PATH="$PATH" curl "${@:2}"; }

GOWORK=off go build -o poc . || exit 1

say "topology: $BR $BRIP, containers c1 .11 and c2 .12, external $EXT behind the host, nested n1 behind c1"
ip link add $BR type bridge && ip addr add $BRIP/24 dev $BR && ip link set $BR up
for i in 1 2; do
  ip netns add c$i
  ip link add v$i type veth peer name e$i
  ip link set v$i master $BR up
  ip link set e$i netns c$i
  ip -n c$i addr add 172.30.0.1$i/24 dev e$i
  ip -n c$i link set e$i up
  ip -n c$i link set lo up
  ip -n c$i route add default via $BRIP
done
ip netns add ext
ip link add hext type veth peer name pext
ip link set pext netns ext
ip addr add $EXT_HOST/24 dev hext && ip link set hext up
ip -n ext addr add $EXT/24 dev pext && ip -n ext link set pext up && ip -n ext link set lo up
ip -n ext route add default via $EXT_HOST
sysctl -q net.ipv4.ip_forward=1
# A Docker host sets the FORWARD policy to DROP and accepts only its own
# bridges. The emulated interfaces need the same accept rules.
if command -v iptables >/dev/null; then
  for i in $BR hext; do iptables -I FORWARD -i $i -j ACCEPT; iptables -I FORWARD -o $i -j ACCEPT; done
fi
# Docker-like masquerade for the emulated network.
nft -f - <<EOF
table ip pmgnat {
  chain post { type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SUB oifname != "$BR" masquerade
  }
}
EOF

# Nested namespace behind c1, the shape of a buildx docker-container builder.
ip netns add n1
ip link add vi type veth peer name pi
ip link set vi netns c1 && ip link set pi netns n1
ip -n c1 addr add 172.31.0.1/24 dev vi && ip -n c1 link set vi up
ip -n n1 addr add 172.31.0.2/24 dev pi && ip -n n1 link set pi up && ip -n n1 link set lo up
ip -n n1 route add default via 172.31.0.1
ip netns exec c1 sysctl -q net.ipv4.ip_forward=1
ip netns exec c1 nft -f - <<EOF
table ip nat {
  chain post { type nat hook postrouting priority srcnat; policy accept;
    ip saddr 172.31.0.0/24 oifname "e1" masquerade
  }
}
EOF

rm -f origin.pem origin-keypair.pem
ip netns exec ext ./poc -mode origin -listen $EXT:443 -cert-out origin.pem -keypair origin-keypair.pem >origin443.log 2>&1 &
sleep 0.5
ip netns exec ext ./poc -mode origin -listen $EXT:8443 -keypair origin-keypair.pem >origin8443.log 2>&1 &
ip netns exec ext ./poc -mode origin-plain -listen $EXT:80 >origin80.log 2>&1 &
ip netns exec c2 ./poc -mode origin-plain -listen 172.30.0.12:80 >c2.log 2>&1 &
sleep 1

say "baseline without rules"
check "c1 reaches the external origin directly" \
  "ccurl c1 -sS -m 5 --cacert origin.pem https://$EXT/baseline | grep -q 'origin ok'"

[ "$BRNF" = 1 ] && modprobe br_netfilter 2>/dev/null
[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] && sysctl -q -w net.bridge.bridge-nf-call-iptables=$BRNF
BRNF_LIVE=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo "module not loaded")
say "rules: mode=$MODE bridge-nf-call-iptables=$BRNF_LIVE exclude_same_bridge=$EXCLUDE_SAME_BRIDGE"
SAME=""
[ "$EXCLUDE_SAME_BRIDGE" = 1 ] && SAME='fib daddr . iif oif exists counter return'
if [ "$MODE" = tproxy ]; then
  ./poc -mode proxy -listen 127.0.0.1:$PORT >proxy.log 2>&1 &
  sleep 0.5
  ip rule add fwmark 1 lookup 100
  ip route add local 0.0.0.0/0 dev lo table 100
  STEER="type filter hook prerouting priority mangle; policy accept;"
  ACTION="counter meta mark set 0x1 tproxy ip to 127.0.0.1:$PORT accept"
elif [ "$MODE" = dnat ]; then
  ip addr add 169.254.200.1/32 dev lo
  ./poc -mode proxy -listen 169.254.200.1:$PORT >proxy.log 2>&1 &
  sleep 0.5
  STEER="type nat hook prerouting priority dstnat; policy accept;"
  ACTION="counter dnat ip to 169.254.200.1:$PORT"
else
  ./poc -mode proxy -listen $BRIP:$PORT >proxy.log 2>&1 &
  sleep 0.5
  STEER="type nat hook prerouting priority dstnat; policy accept;"
  ACTION="counter redirect to :$PORT"
fi
if [ "$MODE" = dnat ]; then
  INGRESS='meta iifkind "bridge" jump steer'
else
  INGRESS="iifname \"$BR\" jump steer
    iifname \"docker0\" jump steer
    iifname \"br-*\" jump steer"
fi
nft -f - <<EOF
table inet pmgpoc {
  chain steer {
    fib daddr type local counter return
    $SAME
    tcp dport { 80, 443, 8443 } $ACTION
  }
  chain pre {
    $STEER
    $INGRESS
  }
  chain udpdeny {
    type filter hook forward priority filter; policy accept;
    iifname "$BR" udp dport 443 counter reject
  }
}
EOF
if [ $? -ne 0 ]; then echo "nft rules failed"; exit 1; fi

say "T1 TLS to 443 is steered, replies come back, server name is visible"
check "curl through the steered path gets the origin" \
  "ccurl c1 -sS -m 5 --cacert origin.pem --resolve registry.poc:443:$EXT https://registry.poc/t1 | grep -q 'origin ok'"
check "proxy saw origdst $EXT:443 steered with sni registry.poc" \
  "grep -q 'origdst=$EXT:443 steered=true sni=\"registry.poc\"' proxy.log"

say "T2 a non-standard port survives"
check "curl to 8443 gets the origin" \
  "ccurl c1 -sS -m 5 --cacert origin.pem https://$EXT:8443/t2 | grep -q 'listen=$EXT:8443'"
check "proxy saw origdst $EXT:8443" "grep -q 'origdst=$EXT:8443 steered=true' proxy.log"

say "T3 plain HTTP on 80 is steered with its Host header"
check "curl http gets the origin" "ccurl c1 -sS -m 5 http://$EXT/t3 | grep -q 'origin ok'"
check "proxy saw host $EXT" "grep -q 'HTTP .*origdst=$EXT:80 steered=true host=\"$EXT\"' proxy.log"

say "T4 nested NAT keeps the destination and the port"
check "nested n1 curl to 8443 gets the origin" \
  "ccurl n1 -sS -m 5 --cacert origin.pem https://$EXT:8443/t4 | grep -q 'listen=$EXT:8443'"
check "proxy saw the nested connection from c1's address with origdst $EXT:8443" \
  "grep 'origdst=$EXT:8443 steered=true' proxy.log | grep -q 'remote=172.30.0.11:'"

say "T5 a destination on the host is not steered"
check "fib daddr type local counter is nonzero after a connection to the bridge address" \
  "ccurl c1 -s -m 2 http://$BRIP:9/ >/dev/null 2>&1; nft list chain inet pmgpoc steer | grep 'type local' | grep -q 'packets [1-9]'"

say "T6 same-bridge container to container, bridge-nf-call-iptables=$BRNF_LIVE"
BEFORE=$(grep -c 'origdst=172.30.0.12' proxy.log)
if ccurl c1 -sS -m 5 http://172.30.0.12/t6 | grep -q 'origin ok'; then
  ok "c1 reaches c2 over port 80"
else
  bad "c1 reaches c2 over port 80"
fi
AFTER=$(grep -c 'origdst=172.30.0.12' proxy.log)
if [ "$AFTER" -eq "$BEFORE" ]; then ok "the proxy did not see the container-to-container connection"; else bad "the proxy saw the container-to-container connection ($((AFTER - BEFORE)) times)"; fi
[ "$EXCLUDE_SAME_BRIDGE" = 1 ] && nft list chain inet pmgpoc steer | grep 'iif oif' | sed 's/^/  rule: /'

say "T7 UDP 443 from the bridge is rejected"
ip netns exec c1 bash -c "echo x > /dev/udp/$EXT/443" 2>/dev/null
check "reject counter is nonzero" "nft list chain inet pmgpoc udpdeny | grep -q 'packets [1-9]'"

say "T8 a table with flags owner vanishes when its process dies"
rm -f owner.fifo && mkfifo owner.fifo
nft -i <owner.fifo >owner.log 2>&1 &
NFTPID=$!
exec 3>owner.fifo
echo 'add table inet pmgowner { flags owner; }' >&3
sleep 0.5
HAVE=$(nft list tables | grep -c pmgowner)
kill -9 $NFTPID 2>/dev/null
exec 3>&-
sleep 0.5
GONE=$(nft list tables | grep -c pmgowner)
check "owner table existed while nft lived and is gone after kill -9 (had=$HAVE gone=$GONE)" "[ \"$HAVE\" = 1 ] && [ \"$GONE\" = 0 ]"
cat owner.log | sed 's/^/  nft: /'

say "T9 rules left behind after the proxy dies fail closed"
pkill -f '^\./poc -mode proxy'
sleep 0.3
if ccurl c1 -sS -m 3 --cacert origin.pem https://$EXT/t9 >/dev/null 2>t9.err; then
  bad "connection succeeded without a proxy"
else
  ok "connection failed fast without a proxy: $(tr -d '\n' <t9.err | cut -c1-80)"
fi

say "counters"
nft list table inet pmgpoc | sed 's/^/  /'
say "proxy log"
sed 's/^/  /' proxy.log

printf '\nRESULT pass=%d fail=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
