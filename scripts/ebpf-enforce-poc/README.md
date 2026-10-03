# eBPF proxy enforcement POC

This is the proof of concept for
[docs/specs/2026-10-03-ebpf-proxy-enforcement-design.md](../../docs/specs/2026-10-03-ebpf-proxy-enforcement-design.md).
It is throwaway code. Delete it when `internal/netenforce` lands.

It is a separate Go module and it is not in the repo `go.work`. Build it with
`GOWORK=off` (the Makefile does this).

## What it does

- `bpf/redirect.bpf.c` attaches to a cgroup v2 path. On `connect()` to TCP port
  80 or 443 from an eligible process, it rewrites the destination to the local
  listener. It stores the original destination in socket storage. A `sockops`
  program copies it to a hash map keyed by the client source port. It denies
  UDP to the same ports (QUIC) for eligible processes. It only acts on sockets
  in the same network namespace as the listener, so containers are left alone.
- `main.go` loads the object with `cilium/ebpf` (no cgo), publishes the
  listener address and the exemptions, and runs a transparent listener. The
  listener recovers the original destination from the map, sniffs TLS vs plain
  HTTP, terminates TLS with a per-SNI certificate from a POC CA, and answers
  every request with a line that describes what it saw.
- `maplookup/` opens the pinned map as an unprivileged user to show that the
  proxy daemon does not need privileges to read it.

## Run

```bash
make
cp /usr/bin/curl ./curl-exempt
sudo ./pmgpoc -cgroup /sys/fs/cgroup -pin-dir /sys/fs/bpf/pmgpoc \
  -listen 127.0.0.1:18443 -exempt-exe ./curl-exempt &

# Redirected. No proxy env. The client only needs to trust the CA.
env -i curl -sS --cacert poc-ca.pem https://registry.npmjs.org/left-pad/1.3.0
env -i node -e "fetch('https://registry.npmjs.org/express').then(r=>r.text()).then(console.log)"

# Exempt by executable inode. Reaches the real registry.
env -i ./curl-exempt -sS https://registry.npmjs.org/ -o /dev/null -w '%{http_code}\n'

# A process in another network namespace is not redirected.
unshare -n env -i curl -m 3 https://104.16.11.34/

# Containers: the future direction in the spec. Redirect other network
# namespaces to the docker0 address instead of leaving them alone.
sudo ./pmgpoc -cgroup /sys/fs/cgroup -listen 127.0.0.1:18443 -container-target 172.17.0.1 &
docker run --rm -v $PWD/poc-ca.pem:/ca.pem:ro curlimages/curl:8.11.1 \
  -sS --cacert /ca.pem https://registry.npmjs.org/left-pad

# Unprivileged read of the pinned map.
setpriv --reuid=65534 --regid=65534 --clear-groups ./maplookup/maplookup /sys/fs/bpf/pmgpoc/orig_dst
```

On a hybrid cgroup host (this was developed on one) use `-cgroup /sys/fs/cgroup/unified`.
