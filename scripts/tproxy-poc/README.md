# TPROXY POC

Throwaway code. It tests the "steer at the bridge" alternative to
`docs/specs/2026-10-04-ebpf-enforcement-container-redirect-design.md`.
Delete this directory when a design lands.

## What it runs

`main.go` is one binary with three modes.

- `proxy` listens with `IP_TRANSPARENT`, reads `SO_ORIGINAL_DST`, logs the
  original destination and the server name or `Host`, and splices the
  connection to the original destination.
- `origin` is a TLS server that answers with the port it listens on.
- `origin-plain` is the same over HTTP.

`local.sh` emulates a Docker bridge with network namespaces. It needs no
dockerd. `MODE=tproxy` steers with `nft tproxy`. `MODE=redirect` steers with
`nft redirect`. `BRNF` sets `bridge-nf-call-iptables`.

`docker.sh` runs the redirect mode against a live dockerd. The workflow
`.github/workflows/tproxy-poc.yml` runs both scripts on a GitHub runner.

## Findings

TPROXY does not work when `bridge-nf-call-iptables` is 1, which is how
Docker hosts run. `nf_tproxy_assign_sock` sets the `sock_edemux` destructor.
With br_netfilter on, the IP prerouting hooks run during the bridge pass,
and `ip_rcv_core` then orphans every socket that does not carry the
`sock_pfree` destructor. The SYN reaches TCP with no socket and the kernel
answers with a reset. The same rules work on a plain interface and with
br_netfilter off.

`nft redirect` with `SO_ORIGINAL_DST` works in every setting. br_netfilter
supports DNAT in the bridge pass by design. The listener sees the container
address as the peer and the original destination from conntrack. A nested
namespace behind its own NAT keeps the destination and the port.
