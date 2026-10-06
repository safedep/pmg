# Network policy at the proxy

Status: proposal, revision 1. Builds on the enforcement design in
[2026-10-03-ebpf-proxy-enforcement-design.md](./2026-10-03-ebpf-proxy-enforcement-design.md),
its configuration surface in
[2026-10-03-ebpf-enforcement-config-surface-design.md](./2026-10-03-ebpf-enforcement-config-surface-design.md),
and the container redirect in
[2026-10-04-ebpf-enforcement-container-redirect-design.md](./2026-10-04-ebpf-enforcement-container-redirect-design.md).
PR #507, PR #508 and PR #509 implement those three.

## Problem

A sandbox profile carries a network policy. The npm restrictive profile allows
four registry hosts on port 443 and denies everything else:

```yaml
network:
  allow_outbound:
    - registry.npmjs.org:443
    - registry.yarnpkg.com:443
    - npm.pkg.github.com:443
    - github.com:443
  deny_outbound:
    - "*:*"
```

No driver enforces these lists by host. Seatbelt cannot match a host, so the
translator allows all outbound traffic when any allow rule exists. The
Landlock supervisor under `network_via_proxy_only` allows the proxy port and
nothing else, and reads neither list. Bubblewrap turns the network on or off.
The sandbox doc says so in one line: host-level filtering is not enforced on
either platform. The lists are documentation.

Two primitives now put the proxy in line with the traffic:

- `network_via_proxy_only` confines a sandboxed process to the proxy's
  loopback port. The seccomp supervisor enforces it on Linux and Seatbelt on
  macOS. The process cannot reach the network around the proxy.
- Kernel enforcement sends every TCP connection to an enforced port from
  every eligible process on the host to the proxy, and the container redirect
  does the same for every other network namespace. A process cannot opt out.

The proxy therefore sees every connection that matters, and it sees it by
name. The CONNECT handler gets a host and a port. The transparent listener
gets the SNI and the original destination port. A plain HTTP request carries
a Host header. The proxy already drops a connection it cannot name. This is
where a host and port policy belongs.

## Goal

A profile or a daemon config names the destinations a workload may reach.
The proxy allows or denies each connection by hostname and port, before it
decides whether to terminate TLS. A denial is an event with the host, the
port, the client and the rule. In CI the denial fails the job. A user who
turns the policy on for the first time gets a list of what it would have
denied, not a broken build.

## Non-goals

- Filtering by destination address in the kernel. An address is not a name.
  A CDN host changes addresses by the hour, and the proxy already resolves
  names itself. Part 6 says what the kernel does instead.
- A policy on the ports the proxy never sees. Only the enforced ports reach
  the proxy. Closing the other TCP ports is a kernel change and is sketched
  in part 6 as a second step, not committed here.
- Filtering by URL path or method. The policy decides a connection. The
  interceptors already decide requests on registry hosts.
- A per-process policy under the persistent proxy. The daemon knows the
  client pid, comm and executable for a redirected host connection, and only
  the destination for a container. The first revision uses the client only
  in the event. A later revision can key exceptions on the executable.
- DNS filtering. The proxy resolves the name it is given. A client's own
  resolver, where a profile allows direct DNS, is outside this design.

## Design

Seven parts. The first two make the decision. The third says where the
policy comes from in each mode. The fourth and fifth say how a denial reaches
the client and the operator. The sixth names the gap the kernel closes
later. The seventh gets the built-in profiles right.

### 1. One decision, three entry points

A connection reaches the proxy on one of three paths. Each path knows a host
and a port before any byte goes upstream.

| Path | Host | Port |
| --- | --- | --- |
| CONNECT from a proxy-aware client | the CONNECT target | the CONNECT target |
| Transparent TLS from a redirected client | the SNI | the original destination port |
| Plain HTTP, proxy-form or origin-form | the Host header, or the absolute URI | the Host header, or 80 |

The proxy evaluates the policy once per connection, on that host and port,
before `shouldMITM`. The order matters. An allowed registry host goes on to
the interceptors as today. A denied host never reaches them, and never
reaches the splice. An allowed non-registry host is spliced as today.

The decision runs before the splice, so it needs no trust from the client. A
container that does not trust the PMG CA still gets its non-registry traffic
allowed or denied by name. Trust decides whether a registry install works.
The policy decides whether a connection is made at all.

A request inside a terminated tunnel is checked again against its own Host
header. It is one map lookup, and it closes the case where a client tunnels
to an allowed host and names another one in the request.

The proxy dials the name the client gave. It never dials the address the
client resolved. A client that lies in its SNI reaches the host it named, not
the host it meant. A connection with no name, or with Encrypted ClientHello,
is dropped today and stays dropped. So the policy cannot be bypassed by
resolving a denied name and faking the SNI.

### 2. The rule language and its semantics

The rules keep the shape the profiles already have. A rule is `host:port`.

- `host` is a fully qualified name, compared without case and without a
  trailing dot. `*.example.com` matches one or more labels before
  `example.com`, so `a.example.com` and `a.b.example.com` match and
  `example.com` does not. A bare `*` matches every host. An IPv4 or IPv6
  literal is a host, for a client that names a destination by address in a
  CONNECT or a Host header.
- `port` is a number or `*`.

The lists were never enforced, so their semantics were never pinned down.
The sandbox's path rule, deny wins over allow, cannot apply. With it the
restrictive profile denies everything, because `*:*` matches every host the
allow list names. The decision is instead:

1. The most specific matching rule wins. An exact host is more specific than
   a wildcard host, and a wildcard host is more specific than `*`. At equal
   host specificity an exact port is more specific than `*`.
2. At equal specificity, deny wins.
3. With no matching rule, or no rules at all, the connection is allowed.

So `deny_outbound: ["*:*"]` turns the allow list into an allowlist, which is
what the restrictive profile has meant all along, and a profile with only
deny rules is a denylist. Both read the way they are written.

| Rules | `registry.npmjs.org:443` | `cdn.example.com:443` | `api.github.com:443` |
| --- | --- | --- | --- |
| allow `registry.npmjs.org:443`, deny `*:*` | allow | deny | deny |
| allow `*.github.com:443`, deny `api.github.com:*` | allow | allow | deny |
| deny `*:80` | allow | allow | allow |

The matcher is one small package with no dependency on the proxy, so the
sandbox linter and the proxy share it. Its tests are table-driven on the
rows above and on the edge cases: trailing dots, upper case, an IPv6 literal
in brackets, a port of `*` against port 443, a wildcard against the apex.

### 3. Where the policy comes from

The proxy runs in two modes, and the policy has a different owner in each.

**Default mode.** `pmg npm install` starts a proxy for one command and runs
one package manager under one sandbox profile. The profile's `network` block
is the policy. The proxy flow already hands the proxy address to the sandbox
through the execution context. This design hands the profile's lists back to
the proxy through its config, so the two sides read one block.

The proxy applies the policy whether or not the profile sets
`network_via_proxy_only`. Without lockdown a process can go around the
proxy, so the policy is advisory. With lockdown it is a guarantee. The
profile linter warns on a profile with network rules and no lockdown, and
the doc says the same in one sentence.

**Persistent proxy.** One daemon serves many clients and no sandbox profile.
The policy lives in the daemon config:

```yaml
proxy:
  server:
    network:
      mode: audit          # audit | enforce
      allow_outbound:
        - registry.npmjs.org:443
        - files.pythonhosted.org:443
      deny_outbound:
        - "*:*"
```

The block sits under `proxy.server`, not under `enforce`, because it applies
to a proxy-aware client without `--enforce` as well. Enforcement is what
makes it a guarantee. Every key has a flag and a variable, as the policy
keys under `enforce` do:

| Config key | Flag | Variable |
| --- | --- | --- |
| `network.mode` | `--network-mode` | `PMG_PROXY_SERVER_NETWORK_MODE` |
| `network.allow_outbound` | `--network-allow` (repeatable) | `PMG_PROXY_SERVER_NETWORK_ALLOW_OUTBOUND` |
| `network.deny_outbound` | `--network-deny` (repeatable) | `PMG_PROXY_SERVER_NETWORK_DENY_OUTBOUND` |

The action gets `network-mode`, `network-allow` and `network-deny` inputs
that become these flags, through the same script as the enforce inputs.

Under `global_lockdown` a flag that loosens the policy fails fast:
`--network-allow`, and `--network-mode audit` when the file says `enforce`.
`--network-deny` only narrows and stays allowed. This is the rule the
enforce flags follow.

**Containers.** A redirected container connection carries only its
destination. It gets the daemon's policy by host and port, as a host
connection does.

### 4. What the client sees

The verdict reaches the client on the path it came in on.

- CONNECT: `403 Forbidden`, with a body that names the host, the port and
  the rule. A proxy-aware client such as npm prints it.
- Plain HTTP: the same `403`, through the block message renderer the
  interceptors use, so the page looks like a malware block.
- Transparent TLS: the proxy closes the connection before the handshake.
  The client sees a reset. It cannot read a page, because it may not trust
  the PMG CA, and the handshake has not happened. The daemon log names the
  host, the port, the rule and the client.

A reset is an honest signal and clients handle it today, because that is
what the proxy already sends for a connection without a name.

### 5. Events, reports and the audit mode

A denial is a block with a new reason, `BlockReasonNetworkPolicy`. It writes
an event of type `network_denied` to the local event log with the host, the
port, the matched rule, the mode, and the client when known: pid, comm and
executable for a host connection, the container address for a redirected
one. The event syncs to the cloud like a malware block.

- In default mode the denial also surfaces as a sandbox violation of kind
  `network_connect`, so `pmg sandbox violations` lists it next to a file
  denial and `pmg sandbox allow net-connect=host:port` persists the
  allowance. That override kind exists today and the sandbox never
  produced a violation for it. Now it does.
- Under the persistent proxy, `pmg proxy stop` lists the denied destinations
  in its report, and `--fail-on-violation` counts a denial as a violation.
  An egress policy violation in CI is a policy violation.

`mode: audit` evaluates the policy and records the event, with
`mode: audit` in it, and lets the connection through. Nothing is blocked.
The stop report prints the destinations the policy would have denied, one
per line, as `host:port` ready to paste into an allow list. A user runs one
install under audit, reads the list, and switches to `enforce`.

### 6. The port the proxy never sees

The proxy decides the connections the kernel sends it. Those are TCP to the
enforced ports, 80 and 443 plus the ports of the configured registries. A
connection to port 22, or to 8080, goes direct under enforcement and is not
subject to the policy. A `*:*` deny is therefore complete for the enforced
ports only. The doc says so.

Closing the gap is a kernel change, and a second step. The sketch:

- `enforce.ports` keeps its meaning, the ports that go to the proxy.
- A new `enforce.allow_ports` lists TCP ports a process may reach directly,
  such as 22 for git over SSH. The default is empty.
- A new `enforce.deny_other_ports: true` makes the `connect` hooks return
  `EPERM` for TCP to a port that is in neither list and not on the skip
  list, and makes the container redirect's `deny` chain refuse the same.
  UDP 53 stays open, because a client still has to resolve names.

With the three keys set, a host or container process reaches the enforced
ports through the proxy, the allowed ports directly, and nothing else. That
is a second spec once this one has shipped and the port lists are known.

### 7. The built-in profiles

The restrictive profiles' lists have never been tested against a real
install, because they were never enforced. Known gaps from reading the
package managers:

- npm: `node-gyp` downloads headers from `nodejs.org`. Packages with
  binaries fetch them from their own hosts, `storage.googleapis.com` for
  puppeteer among them.
- pip: wheels come from `files.pythonhosted.org`, not from `pypi.org`.
- Go: `proxy.golang.org`, `sum.golang.org` and `storage.googleapis.com`.
- cargo: `index.crates.io` and `static.crates.io`.
- git dependencies: `github.com` and `objects.githubusercontent.com`.

The lists are corrected in audit mode before any built-in profile moves to
`enforce`. The acceptance suite runs each package manager's smoke install
under its profile in enforce mode, so a wrong list fails the nightly run and
not a user.

### Limits

- The policy is by name. A denied host that an allowed host fronts, such as
  content on an allowed CDN, is reachable through the allowed name.
- A connection without a name is dropped today, under policy or not. A
  destination that must stay reachable by address belongs on the skip list,
  where the kernel never redirects it and the policy never sees it.
- The policy sees the enforced ports only, until part 6 ships.
- An IPv6 or QUIC connection is refused at the kernel and never reaches the
  policy. The client falls back and is then decided.
- Audit mode gives no guarantee. It exists so that enforce mode can be
  turned on with a correct list.
- A client that names a destination by address in a CONNECT reaches the
  address it named. An address rule or `*:*` decides it. A profile that
  relies on names should deny `*:*`.

## Trust

The client supplies the name, in the SNI, the CONNECT line or the Host
header. The proxy decides on that name and dials that name. The client
cannot make the proxy connect to a host it did not name, and it cannot name
a host the policy denies. A name the proxy cannot see is a dropped
connection. The kernel supplies the port for a redirected connection, and
the client cannot change it.

The guarantee holds where the proxy is in line: under `network_via_proxy_only`
for a sandboxed process, and under kernel enforcement for every eligible
process and every redirected namespace. Outside those, a process that drops
the proxy variables bypasses the proxy and the policy with it. The policy is
then advisory, and the docs say so.

## Code and maintenance

- A matcher package, `proxy/netpolicy`, with the rule parser, the
  specificity order and `Decide(host, port)`. About 150 lines and the same
  again in tests. No dependency on the proxy or the sandbox, so both import
  it.
- Three hook-ups in the proxy: the CONNECT handler, the transparent TLS
  classifier and the plain HTTP paths, plus the inner request check. About
  80 lines.
- Config, flags, variables and action inputs for the persistent proxy, in
  the pattern the enforce keys set. About 150 lines with tests.
- The profile's lists into the proxy config in the default flow, and the
  linter warning. About 60 lines.
- The block reason, the event, the sandbox violation and the stop report
  lines, including the audit list. About 120 lines.
- Proxy e2e cases, acceptance scripts and docs.

Under a thousand lines with tests. Smaller than the container redirect, and
with no kernel code. The matcher is the only part with its own semantics,
and its table of cases is the contract.

## Manual verification

With a persistent proxy on the host and a policy that denies everything but
the npm registry:

```sh
sudo pmg proxy start --daemon --enforce \
  --network-mode enforce \
  --network-allow registry.npmjs.org:443 --network-deny '*:*'
eval "$(sudo pmg proxy env)"

# allowed, through the proxy
env -i /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/-/ping
# 200

# denied, a redirected host connection: the proxy closes it
env -i /usr/bin/curl -sS https://ifconfig.co
# curl: (35) ... connection reset by peer

# denied, a proxy-aware client: a 403 that names the rule
curl -sS -x "$HTTPS_PROXY" https://ifconfig.co
# 403 ... ifconfig.co:443 denied by rule *:*

# denied, a container
docker run --rm curlimages/curl -sS https://ifconfig.co
# curl: (35) ... connection reset by peer

sudo pmg proxy stop --fail-on-violation
# network policy denied 3 connection(s): ifconfig.co:443 (3)
# exit 1
```

Under audit mode the three connections succeed, and the stop report prints
`ifconfig.co:443` as a destination the policy would deny.

In default mode, with the npm restrictive profile moved to `enforce`:

```sh
pmg npm install left-pad          # works, the registry is allowed
pmg npx some-tool-that-phones-home
pmg sandbox violations            # network_connect  telemetry.example.com:443
pmg sandbox allow net-connect=telemetry.example.com:443
```

## Acceptance

Proxy e2e cases in `test/proxye2e`, hermetic, against the mock registry:

- A CONNECT to a denied host gets a 403 that names the rule.
- A transparent TLS connection to a denied host is closed before the
  handshake.
- A plain HTTP request to a denied host gets a 403.
- An inner request with a Host header the policy denies gets a 403 inside
  an allowed tunnel.
- Most specific wins, and deny wins on a tie, on the table in part 2.
- Audit mode records the event and lets the connection through.

Acceptance scripts, with a catalog row each:

- `proxy/network/deny-connect-names-the-rule.txtar`
- `proxy/network/audit-lists-would-deny.txtar`
- `proxy/network/stop-fails-on-denial.txtar`
- `enforce/policy/network-deny-transparent.txtar`, under root
- `enforce/scope/namespaces-network-deny.txtar`, under root with Docker
- `sandbox/network/profile-list-enforced.txtar`
- `sandbox/network/allow-net-connect-persists.txtar`
- One smoke install per built-in restrictive profile in enforce mode, so a
  wrong allow list fails the nightly run.

## Rollout

1. Ship the matcher, the three hook-ups, the events and the config with
   `mode: audit` as the default everywhere. No connection is blocked. The
   stop report and the sandbox violations show what would be.
2. Correct the built-in profiles' lists against the audit output of the
   acceptance smoke installs.
3. One release later, move the built-in restrictive profiles to `enforce`,
   with a changelog entry that names the override command. The persistent
   proxy keeps `audit` as its default, because an operator sets its policy
   on purpose.
4. The kernel step in part 6 as its own spec.

## Decisions needed

1. Most specific rule wins, deny wins on a tie, no rule means allow.
   Recommended: yes. It makes the restrictive profile mean what it says and
   keeps a denylist profile readable.
2. The default mode is `audit`, for the profiles and for the daemon.
   Recommended: yes. The lists are unverified, and a wrong allowlist breaks
   every install.
3. A denial counts toward `--fail-on-violation`. Recommended: yes. A CI
   gate that lets an egress violation through is not a gate.
4. A denied transparent TLS connection is closed, not answered with a page.
   Recommended: yes. The client may not trust the CA, and the proxy already
   closes a connection it cannot name.
5. The daemon policy lives under `proxy.server.network`, not under
   `enforce`. Recommended: yes. It applies to proxy-aware clients without
   enforcement, and lockdown governs its flags the same way.
6. The default mode applies the profile policy without lockdown, as
   advisory, with a lint warning. Recommended: yes. A user who turns on
   lockdown later gets a list that already works.
7. Part 6, the kernel port deny, is a separate spec after this ships.
   Recommended: yes. Its port lists come out of the audit data.

## Rejected alternatives

- **Address rules in the kernel.** The BPF programs and the nftables table
  could match destination addresses. A name resolves to many addresses that
  change often, and a CDN serves many names from one address. The proxy
  already resolves names and dials them itself. An address rule would be a
  second, weaker policy next to the one that already works.
- **Landlock network rules.** Landlock ABI V4 filters TCP ports and nothing
  else. It cannot match a host, and the port gap it would close is the one
  part 6 closes for every process, not only sandboxed ones.
- **Filtering at DNS.** A resolver that refuses a denied name does not stop
  a client that carries an address, uses DNS over HTTPS, or has the answer
  cached. The proxy sees the name at the connection, which is the only place
  the client cannot hide it.
- **Per-process policy in the daemon from the start.** The daemon knows the
  executable for a host connection and nothing for a container. A policy
  with two shapes is two policies. The event carries the client now, and a
  later revision can add an exception keyed on the executable once the data
  shows the need.
- **Deny wins over allow, as for paths.** It is the rule the sandbox uses
  for files. For hosts it makes `deny_outbound: ["*:*"]` deny everything,
  and every restrictive profile would have to be rewritten as a denylist
  with no catch-all, which is not what an allowlist profile wants.
