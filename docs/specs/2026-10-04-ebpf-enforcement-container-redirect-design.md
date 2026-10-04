# Container redirect for kernel enforcement

Status: proposal, revision 1. Follows the enforcement design in
[2026-10-03-ebpf-proxy-enforcement-design.md](./2026-10-03-ebpf-proxy-enforcement-design.md),
sections "Known gap: containers" and "Future direction", and the configuration
surface in
[2026-10-03-ebpf-enforcement-config-surface-design.md](./2026-10-03-ebpf-enforcement-config-surface-design.md).
PR #507 and PR #508 implement those two. This spec supersedes the "Future
direction" section where the two differ.

## Problem

Enforcement attaches to the root cgroup, so the kernel programs run for every
process on the host, containers included. The programs route only sockets in
the daemon's network namespace. A socket in any other namespace passes
(`decide`, `ACT_OTHER_NETNS`), because the redirect target is `127.0.0.1`,
and inside a container that address is the container's own loopback.

On a hosted GitHub runner this leaves `RUN` steps in `docker build`,
`docker run` steps and Docker container actions outside enforcement. A
container job runs every step inside the job container, the pmg action
included, so no daemon exists on the host and the gap there closes only on a
self-hosted runner whose host runs the daemon. The daemon warns when
`dockerd` runs, and the documented workaround puts the install step in the
host namespace with `--network=host`.

The POC reached the `docker0` address, `172.17.0.1` by default, from a
container on the default bridge. The acceptance scripts below prove the
user-defined network and the build step.

## Goal

A connection from a container to an enforced port reaches the proxy. A
container that trusts the PMG CA installs through the proxy. A container that
does not trust it fails closed on registry hosts and keeps working on every
other host. Host processes see one change, named in part 4: a connection to
a Docker network goes direct.

## Non-goals

- Trust inside a container. eBPF cannot change a container's files or
  environment. The host bundle reaches the container as a build secret or a
  mount, as in part 7. The rejected alternatives are at the end.
- Rootless Docker and Podman. Their containers do not share the host's view
  of a bridge. `mode: ignore` stays correct for them.
- IPv6 in containers. Docker leaves it off by default. Part 1 says what
  happens to an IPv6 socket.
- A bridge that appears after the daemon starts. See limits.

## Design

Seven changes. The first three make the redirect work. The fourth keeps
container-to-container traffic out of the proxy. The fifth says who is
eligible in a container. The sixth is the switch. The seventh is the action.

### 1. A second target, chosen by namespace

`struct cfg` gains `bridge_ip4`. `decide` keeps its namespace check, and the
callers pick the target.

- `handle4` sends a socket in the daemon's namespace to `proxy_ip4`, as
  today. It sends a socket in any other namespace to `bridge_ip4` when that
  is set, and finishes with `ACT_OTHER_NETNS` when it is zero.
- `handle6` finishes with `ACT_OTHER_NETNS` for a socket in another
  namespace until the config holds an IPv6 bridge target. Without this line
  the existing `ACT_DENY_IPV6` branch would return `EPERM` to every
  container with IPv6.
- The UDP rule applies in both namespaces. With `deny_udp`, a container's
  QUIC attempt on an enforced port is denied and the client falls back to
  TCP, as on the host.

The port is the same. One field now. A later per-network target would key on
the source prefix, which the daemon can fill. This design does not prevent
that change.

### 2. A listener on the bridge address

The daemon opens a listener on the bridge address on the proxy port and
passes it in `AdditionalListenAddrs`, the way the IPv6 loopback listener
already travels. The same handler serves it. The daemon sets `bridge_ip4`
from the listener that bound, the way `attachEnforcement` takes `Addr6` from
the bound addresses, so the kernel never sends a container to a closed port.
The daemon binds the bridge address only, never `0.0.0.0`.

The bridge listener accepts only what a redirected client sends: TLS with a
server name, and origin-form HTTP. It refuses a `CONNECT` and an absolute-URI
request, which only a proxy-aware client sends on purpose. A redirected connection on any listener never dials a destination
in the built-in skip list, so a `Host` header or a server name cannot steer
the proxy at the cloud metadata address. The own-address guard of the
transparent listener already covers every listener the server opened, so a
redirected request that names the bridge listener is refused like one that
names loopback.

### 3. The original destination key gains the address

`orig_dst` is keyed by address family and source port. Every network
namespace has its own port space, so two containers can use the same port at
the same moment. The key becomes family, local address and local port. The
sockops program has the address in `local_ip4` and `local_ip6`, and picks the
field by the stored family, so an IPv4-mapped destination on an IPv6 socket
uses `local_ip4`. The kernel does not translate delivery to a host address on
a bridge, so the listener sees the pair the client socket had.

Nested namespaces, such as a buildx `docker-container` builder, Docker in
Docker or kind, run behind their own NAT and reuse private addresses. Their
entries can overwrite each other and never match the translated pair the
listener sees. The lookup misses, and the listener falls back to the server
name or the `Host` header with the default port for the protocol, as it does
today for any miss. That is enough for a registry on 443 or 80. A private
registry on another port is not reachable through a nested namespace, and
the doc says so. The key must not gain a namespace cookie, because the proxy
cannot learn a peer's cookie.

### 4. Skip the Docker networks

A connection the proxy passes through is dialed by its server name. A
container reaches another container by a name that only Docker's embedded
DNS inside that network resolves, so the proxy cannot dial it. Traffic that
stays inside Docker's networks is not registry traffic, and it must not
reach the proxy at all.

The daemon reads the host routing table and adds the prefix of every route
over `docker0`, a `br-*` interface, or the interface that carries
`bridge_address`, to the skip list, next to the built-in loopback,
link-local and metadata entries. It watches netlink for route changes and
updates the kernel map while it runs, the way the exec watcher updates the
exemptions, because `docker compose up`, `buildx create` and kind create a
network after the daemon started. `pmg proxy status` lists the prefixes with
the other skip destinations. A private registry on the corporate network is
outside them and stays enforced.

The skip applies in both modes. A host process that connects to a service
container on port 443 goes direct, where today it is redirected and dropped
for want of a server name. This is the one host change.

### 5. Users across namespaces

Eligibility works on the kernel uid. Without user namespace remapping,
root in a container is root on the host, and most container processes run as
root. A host policy with `exempt_users: root`, or `eligible_users: runner`,
would exempt every container.

A socket in another namespace is eligible regardless of `eligible_users` and
`exempt_users`. The daemon exemption by tgid still applies, because the
programs translate through the PID namespace hierarchy. An executable
exemption matches by device and inode, so it follows a bind-mounted host
file into a container, and an overlay copy of the same program is not
exempt. The doc says both.

### 6. Config, flag, variable and input

```yaml
proxy:
  server:
    enforce:
      containers:
        mode: ignore          # ignore | redirect
        bridge_address: ""    # default: the IPv4 address of docker0 at start
```

`containers` is a block, not a scalar, so a later key, such as a per-network
rule, needs no rename. `bridge_address` names a local IPv4 address when the
bridge is not `docker0`. The surface follows the config surface spec:

- `--enforce-containers <mode>` on `pmg proxy start`, bound to `mode`.
- `PMG_PROXY_SERVER_ENFORCE_CONTAINERS_MODE` and
  `PMG_PROXY_SERVER_ENFORCE_CONTAINERS_BRIDGE_ADDRESS`. Both keys go in the
  embedded template, which is what makes Viper bind a variable.
- `enforce-containers` as an action input, passed as the flag.
- Under `global_lockdown` the parent refuses `--enforce-containers ignore`,
  as it refuses `--enforce-deny-udp=false`.

Under `redirect` with no bridge at start, the daemon runs as `ignore`,
records a warning, and `pmg proxy status` repeats it. An explicit
`bridge_address` that the daemon cannot bind fails the start, because an
administrator set it on purpose. The state file records the mode and the
bridge address, and status prints one of:

```
  containers: redirect (bridge 172.17.0.1)
  containers: ignore
  containers: ignore (no bridge at start)
```

The Docker warning keeps its text under `ignore`. Under `redirect` a one-line
warning takes its place: containers that do not trust the PMG CA fail on
registry hosts.

### 7. The action

`pmg proxy env` prints `PMG_CA_BUNDLE=<path>` under enforcement, in both
modes, next to `REQUESTS_CA_BUNDLE`, from `certmanager.SystemCABundlePath`.
The variable is absent when the host has no bundle. The action needs no
change, because it already appends the output of `pmg proxy env` to
`GITHUB_ENV`. A workflow passes the bundle to a build as a secret and to a
`docker run` as a mount, and never hardcodes a path that differs per
distribution:

```yaml
- run: docker build --secret id=pmg-ca,src=$PMG_CA_BUNDLE -t app .
```

```dockerfile
RUN --mount=type=secret,id=pmg-ca,target=/run/pmg-ca.pem,mode=0444 \
    NODE_EXTRA_CA_CERTS=/run/pmg-ca.pem npm ci
```

`mode=0444` matters, because BuildKit mounts a secret readable by root only
and a Dockerfile with `USER node` could not read it. The bundle, not the CA
alone, is the file to pass. It holds the public roots too. `NODE_EXTRA_CA_CERTS`
adds the file to Node's roots. `PIP_CERT` replaces pip's bundle with the
file. Both work with the bundle. `docs/github-action.md` shows one `RUN`
block that mounts the secret and sets the trust variables from
`EnvVarForProxy` at the mount path, so the doc has one list to keep in step
with the code.

A Docker action gets the workspace mounted at `/github/workspace`, and the
runner passes the step's `env:` into the container. A step before the action
copies the bundle into the workspace, and the variable names the path as the
container sees it:

```yaml
- run: cp "$PMG_CA_BUNDLE" pmg-ca.pem
- uses: some/docker-action@v1
  env:
    NODE_EXTRA_CA_CERTS: /github/workspace/pmg-ca.pem
```

That covers an action that installs packages when it runs. An action with
`image: Dockerfile` that installs packages in a `RUN` step fails closed,
because the runner builds that image at job start and passes no secret. An
action with a prebuilt `image: docker://...` installs nothing on the runner
and is not affected.

### Limits

- The daemon reads the bridge address once, at attach. A bridge that
  appears later is not seen, and status says `ignore (no bridge at start)`.
  The route watch of part 4 can grow an address watch later without a
  config change.
- A host firewall with a default deny on input, such as `ufw` on a
  workstation, drops traffic from `docker0` to the host. Every redirected
  container connection is then refused, not only registry ones. The doc
  names the rule to add.
- Any container that can route to the bridge address gets the host's
  reachability on the enforced ports, for the names it sends. `DOCKER-USER`
  rules do not stop this, because they filter forwarded traffic, not
  delivery to the host. The daemon checks only that `bridge_address` is a
  local address.

## Trust

Unchanged. The proxy terminates a redirected connection to a registry host
with a certificate from the PMG CA. A container that does not trust the CA
fails closed on registry hosts, and its tool reports a certificate error.
It works on every other host, because the proxy passes those through with
their real certificate. The workaround in `docs/persistent-proxy.md`
becomes the way to make a build pass: the host bundle as a build secret,
named by `PMG_CA_BUNDLE`, with the trust variables pointed at the mount. A
Docker action that installs packages when it runs gets the bundle through
the workspace. Part 7 has both.

Under `redirect` the proxy is an egress path for every container on the
enforced ports, with the host's reachability. Part 2 limits it to
redirected traffic and keeps it away from the built-in skip list. A later
`exclude_networks` key in the `containers` block can keep a chosen network
out of the redirect without a new mechanism.

## Acceptance

Scripts under `test/acceptance/scripts/enforce/`, each with a catalog row.
`scope/containers-unaffected` becomes the `ignore` case. The lockdown and
status scripts that exist gain the new assertions instead of new scripts.

| Script | Guarantee |
| --- | --- |
| `scope/containers-ignore` | Under `mode: ignore` a container reaches the registry directly with the real certificate. |
| `scope/containers-redirected-fail-closed` | Under `redirect` a container without the CA gets a certificate error on a registry host and a 200 on a non-registry host. |
| `scope/containers-redirected-trusted` | Under `redirect` a container with the host bundle mounted installs a clean package and is blocked on a malicious one. |
| `scope/containers-build-step` | A `docker build` with `RUN npm ci` fails without the CA and passes with the secret mount from the doc, with the path read from `pmg proxy env`. |
| `scope/containers-to-container-untouched` | Two containers on a user-defined network created after the daemon started talk over port 80 by name. |
| `scope/containers-root-not-exempt` | `exempt_users: root` on the host does not exempt a root process in a container. |
| `scope/containers-no-relay` | A container cannot use the bridge listener as a proxy: a `CONNECT` is refused, and a redirected request with the metadata address as its `Host` is refused. |
| `policy/lockdown-governs-widening-flags` | Also: under lockdown `--enforce-containers ignore` is refused and `redirect` is accepted. |
| `status/reports-enforcement` | Also: status prints the mode and the bridge address, or the no-bridge note, and `pmg proxy env` prints `PMG_CA_BUNDLE` for a file that holds the PMG CA. |

The kernel e2e gains one case. The harness uses `unshare -n`, where no route
exists, so this case needs a veth pair, with the host end's address as the
bridge target and the helper in the peer namespace. It checks that the socket
is routed to the bridge target and that the lookup by address and port
returns its original destination. `test/proxye2e` needs no case, because the
handler does not change.

## Rollout

1. Ship with `mode: ignore` as the default. Status and the Docker warning
   tell every operator the switch exists.
2. One release later, change the default to `redirect`, with a changelog
   entry that names the failure a build without the CA will see. An operator
   who needs time sets `mode: ignore` in the managed config.

## Decisions needed

1. Every socket in another namespace is eligible, regardless of the user
   lists. Recommended: yes. The alternative makes the common CI policy a
   silent bypass.
2. The Docker network prefixes are skipped automatically, in both modes,
   with a route watch. Recommended: yes. The alternative asks every operator
   to list their bridges and breaks a network created mid-job.
3. `containers` is a block with `mode` and `bridge_address`. Recommended:
   yes. A scalar would need a rename for the first extra key.
4. The default changes to `redirect` after one release. Recommended: yes.
5. Open: whether a container on an `--internal` network can route to
   `docker0` on the Docker version the CI runners ship. Docker has changed
   this across releases. The acceptance run answers it, and the doc records
   the answer.

## Rejected alternatives

- A SafeDep-hosted registry mirror with a public certificate. It removes the
  CA from the container and replaces it with a registry URL per ecosystem, so
  the configuration step stays. Every download transits SafeDep, the mirror
  becomes a build-critical dependency, and a private registry is out of its
  reach.
- A public certificate for the local proxy on the bridge address. A name that
  resolves to `172.17.0.1` would need a certificate per ephemeral runner,
  past the rate limits of every public CA, and a shared key on every host is
  worse.
- A wrapper around the OCI runtime that adds the CA mount and variables to
  every container. It needs a Docker daemon configuration change and a
  restart, which is more than this feature should own.
