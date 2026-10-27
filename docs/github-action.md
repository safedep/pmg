# PMG GitHub Action

The PMG GitHub Action installs PMG on a Linux GitHub Actions runner and
starts the PMG proxy for the job. Package manager commands such as `npm
install`, `pip install`, or `poetry add` go through the proxy. The proxy
blocks malicious packages before they run.

```yaml
- uses: safedep/pmg@v0.34.0
```

Set `timeout-minutes` on the job. Kernel enforcement is on by default, and a
hung proxy blocks the job until the timeout. See
[Runner traffic](#runner-traffic).

> **Commit SHA pinning.** The examples use the `v0.34.0` tag for readability. Pin
> the action to a full commit SHA. This improves supply chain security. See the
> [GitHub security hardening guide](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions).

> **Action version.** Use the latest release tag, such as
> `safedep/pmg@v0.34.0`. The post step, the job summary and the
> `fail-on-violation`, `auto-stop` and `baseline` inputs need
> `safedep/pmg@v0.34.0` or later, and a runner that runs Node 24 actions. On an
> older version, add a stop step at the end of the job, as the documentation
> of that version shows. To upgrade to `v0.34.0`, remove the stop step, or set
> `auto-stop: false` when a step of the job must stop PMG. The post step fails
> a job that stops PMG in its own step and keeps `auto-stop: true`. The `enforce`, `enforce-*` and
> `expose-to-job-network` inputs need `safedep/pmg@v0.31.0` or later. The
> `network-profile` and `network-mode` inputs need `safedep/pmg@v0.33.0` or
> later. GitHub warns about an unknown
> input and runs the job without it. A job on `v0.30.0` with `enforce: true`
> runs without kernel enforcement. A job on `v0.32.0` with `network-profile`
> runs without a network policy.

Out of the box the action gives:

- Malware blocking that uses the [SafeDep real-time threat intelligence](https://docs.safedep.io/cloud/malware-analysis).
- A dependency cooldown. This blocks package versions published within the last 2 days.
- Proxy-based interception of [supported package managers](../README.md#supported-package-managers).

## Quick start

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: safedep/pmg@v0.34.0
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - run: npm ci
```

Put the action right after `actions/checkout`, so the proxy sees the
traffic of every later step. Use one `safedep/pmg` step per job. In server
mode a second step fails, and the proxy of the first step keeps running. By default the action runs the proxy in
[server mode](#server-mode) with [kernel enforcement](#kernel-enforcement)
where the runner allows it. At the end of the job its post step stops the
proxy, writes a job summary, and fails the job when PMG blocked a package.

### Shim mode

With `server-mode: false` the action wraps the package managers with shims
on `PATH` instead. Put `safedep/pmg` after `setup-node` or `setup-python`.
Each of these steps prepends to `PATH`. PMG must put its shims in front of
the real toolchain shims on `PATH`. Run `pmg setup info --json`. The
`user_shims.dir` value shows the PMG shim directory. A tool that does not
go through a shim, such as `go` or a script with its own HTTP client, is
not protected in shim mode.

## Inputs

Each input that maps to a `PMG_*` variable defaults to empty. When such an
input is empty, the action sets no `PMG_*` environment variable. PMG then uses its own default for
that key. This behavior prevents the action from silently overriding a
YAML file loaded through `config-file`. Set an input to override the
default.

| Input | Effect when set | PMG default if empty |
|---|---|---|
| `version` | PMG release tag (for example `v0.42.0`) or `latest` | `latest` |
| `api-key` | SafeDep Cloud API key. Set it with `tenant-id`. Use a secret to hold the value. | unset (cloud sync disabled) |
| `tenant-id` | SafeDep Cloud tenant ID | unset |
| `endpoint-id` | Identifier that SafeDep Cloud reports as the machine name | `gha/<owner>/<repo>` when cloud is enabled |
| `paranoid` | `PMG_PARANOID` | `false` |
| `cooldown-enabled` | `PMG_DEPENDENCY_COOLDOWN_ENABLED` | `true` |
| `cooldown-days` | `PMG_DEPENDENCY_COOLDOWN_DAYS` | `2` |
| `proxy-mode` | Removed. Proxy interception cannot be disabled. The value `false` stops the action. Other values cause a warning and are ignored. | unset |
| `sandbox` | `PMG_SANDBOX_ENABLED`. Also relaxes AppArmor user namespace limits on the runner | `false` |
| `sandbox-driver` | `PMG_SANDBOX_DRIVER`. Use `landlock` or `bubblewrap` | `landlock` when sandbox is enabled |
| `verbosity` | `PMG_VERBOSITY`. Use `silent`, `normal`, or `verbose` | `normal` |
| `disable-telemetry` | `PMG_DISABLE_TELEMETRY` | `false` |
| `skip-event-logging` | `PMG_SKIP_EVENT_LOGGING` | `false` |
| `config-file` | Path to a YAML file in the repository. The action copies it to the PMG config directory before setup. Use it to override any config key. | unset |
| `cache` | Reuse a previously extracted PMG binary from `$RUNNER_TOOL_CACHE`. On a cache hit the action fetches `checksums.txt` from upstream and verifies the cached tarball again. | `false` (download each run) |
| `server-mode` | Run PMG as a persistent proxy daemon and export the proxy variables to the job, with `PMG_PROXY_RUN`, the id of the run in the event log. The post step of the action stops the daemon at the end of the job. Set `false` for [shim mode](#shim-mode). See [Server mode](#server-mode). | server mode, or shims with `sandbox: true` |
| `fail-on-violation` | With server mode, fail the job at its end when PMG blocked a package or the network policy denied a connection, or when PMG cannot verify the final proxy state. | `true` |
| `auto-stop` | With server mode, stop the daemon in the post step. Set it to `false` when a step of the job stops the daemon. With `true` and `fail-on-violation`, a daemon that a step stopped fails the job. | `true` |
| `baseline` | With server mode, propose a network profile from the destinations the job reached, and show it in the job summary. Without `network-profile` the proposal is for `.pmg/network.yml`. It needs the event log, so `skip-event-logging: true` turns it off. | `true` |
| `expose-to-job-network` | With `server-mode` in a job that has a job container, bind the proxy to the job container's address on the job network. Docker actions and `docker://` steps in the job can then reach the proxy. The action fails when the job has no job container. See [Job containers and Docker actions](#job-containers-and-docker-actions). | `false` |
| `enforce` | With server mode, route every eligible process through the proxy in the kernel. `auto` enforces on a GitHub-hosted runner where it can, and runs the proxy without enforcement elsewhere. `true` fails where the runner cannot enforce. `false` turns it off. See [Kernel enforcement](#kernel-enforcement). The action exports `PMG_BIN` and `PMG_PROXY_STATE`, so a step can run `sudo "$PMG_BIN" proxy status --state "$PMG_PROXY_STATE"`. With `config-file` it also exports `PMG_PROXY_CONFIG_DIR`, the daemon's config directory. | `auto` |
| `enforce-ports` | With `enforce`, destination ports to route in addition to the config, comma or newline separated. Passed as `--enforce-port`. | unset |
| `enforce-exempt-users` | With `enforce`, users never routed, in addition to the config. Passed as `--enforce-exempt-user`. | unset |
| `enforce-exempt-executables` | With `enforce`, programs that connect directly, as absolute paths or globs, in addition to the config. Passed as `--enforce-exempt-executable`. | unset |
| `enforce-skip-destinations` | With `enforce`, CIDR prefixes the kernel never routes, in addition to the config. Passed as `--enforce-skip-destination`. | unset |
| `enforce-namespaces` | With `enforce`, what happens to containers that steps start: `ignore`, `redirect` or `auto`. See [Containers](#containers). Passed as `--enforce-namespaces`. | unset (`ignore`) |
| `network-profile` | The sandbox profile whose network rules the proxy applies. Give a path in the workspace or a built-in name. Turns server mode on. A path that does not exist starts the daemon with no profile, and the job summary proposes the profile for that path. See [Network policy](#network-policy). Passed as `--profile`. Needs `safedep/pmg@v0.33.0` or later. | unset (no policy) |
| `network-mode` | With `network-profile`, what the proxy does with a match on a deny rule: `audit` or `enforce`. With `enforce`, a profile path that does not exist fails the action. Passed as `--network-mode`. Needs `safedep/pmg@v0.33.0` or later. | unset (`audit`) |

## Outputs

| Output | Description |
|---|---|
| `version` | The PMG version that the action installed. |
| `bin-dir` | The directory that contains the `pmg` binary on this runner. |

## Recipes

### Send audit events to SafeDep Cloud

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    api-key:   ${{ secrets.SAFEDEP_API_KEY }}
    tenant-id: ${{ secrets.SAFEDEP_TENANT_ID }}
- run: npm ci
```

The post step stops the daemon, and the daemon sends the events to SafeDep
Cloud. In [shim mode](#shim-mode) no daemon runs. Add a sync step at the
end of a shim mode job:

```yaml
- run: pmg cloud sync --timeout 60s
  if: always()
```

The `endpoint-id` defaults to `gha/${{ github.repository }}`.
Each workflow on the same repository appears as one endpoint in the
SafeDep Cloud UI. Override it for per-environment splits:

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    api-key:     ${{ secrets.SAFEDEP_API_KEY }}
    tenant-id:   ${{ secrets.SAFEDEP_TENANT_ID }}
    endpoint-id: gha/${{ github.repository }}/prod
```

### Use `config-file` for custom settings

```yaml
# .github/pmg.yml
paranoid: true
dependency_cooldown:
  enabled: true
  days: 14
trusted_packages:
  - purl: pkg:npm/@my-org/internal-pkg
    reason: "Internal package, signed by build pipeline"
```

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    config-file: .github/pmg.yml
```

The action copies the file to `~/.config/safedep/pmg/config.yml` before
`pmg setup install` runs. PMG merges any missing template keys into the
file. Specify only the keys to override.

### Server mode

Server mode is the default. The action starts the PMG proxy as a daemon and
exports the proxy variables to the job. Put the action right after
`actions/checkout`, so the proxy sees the traffic of every later step. The
job needs no other PMG step. See the [Quick start](#quick-start).

At the end of the job, the post step of the action:

1. Stops the daemon. The daemon flushes its events to SafeDep Cloud when
   the job sets `api-key`.
2. Proposes a network profile from the destinations the job reached. See
   [Build the profile from a run](#build-the-profile-from-a-run).
3. Writes the job summary. The summary shows the verdict, each denied
   connection, each destination and the proposed profile. The run also
   gets an annotation for each block and each denial.
4. Fails the job when PMG blocked a package or denied a connection. Set
   `fail-on-violation: false` to report only. When PMG cannot stop the
   daemon, for example after a crash, the job fails with every setting.

The post step runs when an earlier step fails and when the job is
cancelled. After the stop, it empties the proxy variables, so the post step
of an earlier action, such as the cache save of `actions/setup-node`, does
not use the stopped proxy.

A stop step of the job removes the stop result of the run, so a step could
hide a block or a denial. When the post step finds no daemon, it fails the
job, or warns when `fail-on-violation` is `false`. A job that stops PMG in
its own step must set `auto-stop: false`. When the daemon still runs but its
state file is gone, the post step fails the job with every setting.

The verdict trusts the steps of the job. A step runs as the runner user and
can use `sudo`, so a hostile step can stop the daemon or replace the `pmg`
binary before the post step runs. PMG blocks a malicious package before its
install code runs, so such a step must come from the workflow itself.

The summary lists the destination hosts of the job. On a public repository
anyone can read the job summary. Set `baseline: false` to leave out the
proposal and the table of destinations. A connection that the network
policy denies still shows in the summary and as an annotation, with its
host.

### Kernel enforcement

Environment variables are a request a process can ignore. With kernel
enforcement the Linux kernel routes every eligible process through the
proxy. A step cannot bypass it with `env -i`, `sudo`, or an HTTP client of
its own.

`enforce` is `auto` by default. The action enforces when the job runs on a
GitHub-hosted runner, on the runner host, and the runner has passwordless
`sudo`. On a self-hosted runner, in a job container, without `sudo`, or when
the kernel of the runner cannot enforce, the action runs the proxy without
enforcement and says so in the log. Any other failure of the enforced start
fails the action, such as a typo in the `enforce` section of `config-file`.
When the job sets an `enforce-*` input and the action cannot enforce, the
action fails too, because a typo or a runner change must not turn
enforcement off. Set `enforce: true` to fail the job in every case. Set
`enforce: false` to turn enforcement off. `enforce: true` with shim mode
fails, because shim mode has no daemon to enforce. The
action installs the PMG CA into the system trust store, starts the daemon as
root, and exports the trust variables. The daemon runs as root, and `sudo`
resets `HOME` and `PATH`, so the action exports the binary path as `PMG_BIN`
and the state file path as `PMG_PROXY_STATE` for a step that runs `pmg` as
root. The post step stops the root daemon. GitHub
hosted Ubuntu runners meet the
[requirements](./persistent-proxy.md#requirements).
[persistent-proxy.md](./persistent-proxy.md#kernel-enforcement-linux)
describes how enforcement works.

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    enforce: true
    api-key: ${{ secrets.SAFEDEP_API_KEY }}
    tenant-id: ${{ secrets.SAFEDEP_TENANT_ID }}

- run: npm ci
```

Set `timeout-minutes` on every enforced job. See
[Runner traffic](#runner-traffic).

Under enforcement the action sets the trust variables that
[persistent-proxy.md](./persistent-proxy.md#trust) lists. With
`NODE_USE_SYSTEM_CA=1`, Node 22.19 and later reads the system trust store. For an older Node, the action sets
`NODE_EXTRA_CA_CERTS` to the bundle with the PMG CA, unless the job sets it.
A bundle that the job sets must hold the PMG CA, or TLS to a registry fails.
A Docker container action also gets the variable, with a path on the runner
host. Node in the container warns that it cannot load the file, and
continues. Set `NODE_EXTRA_CA_CERTS` in the `env:` of that step to change
it.

The policy inputs cover the common cases without a config file. Each list
adds to the config's list. The config is the staged `config-file` when the
job sets one, because the action passes it to the root daemon. Without one,
a hosted runner has no config file for root, so the inputs add to the
defaults: ports 80 and 443 plus the ports of the configured registries. The
daemon log and `pmg proxy status` name the file it loaded.

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    enforce: true
    enforce-exempt-executables: /opt/agent/bin/agent
    enforce-skip-destinations: 10.20.0.0/16
```

`eligible_users`, `cgroup` and `deny_udp` stay in the config file. A job that
needs them has a reason to ship one with `config-file`. The inputs need a
PMG release that has the `--enforce-*` flags. See
[persistent-proxy.md](./persistent-proxy.md#policy-from-the-command-line).

#### Network policy

The daemon applies the network rules of a sandbox profile in the
repository. `network-profile` names it and `network-mode` sets what a match
on a deny rule does. The inputs work with and without `enforce`. Without
`enforce` the policy is advisory, because a process can ignore the proxy
variables. See
[persistent-proxy.md](./persistent-proxy.md#network-policy).

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    enforce: true
    network-profile: .pmg/network.yml
    network-mode: enforce
```

```yaml
# .pmg/network.yml
name: network
inherits: github-actions
network:
  deny_ip_literals: true
  allow_outbound:
    - registry.npmjs.org:443
  deny_outbound:
    - "*:*"
```

The runner is not exempt. Its traffic to GitHub goes through the proxy, see
[Runner traffic](#runner-traffic). The built-in `github-actions` profile
allows the hosts of the runner, its agents, GitHub releases, and the cache
and artifact storage, so a profile that inherits it does not list them. Run
`pmg sandbox profile show github-actions` to see them. An action that
downloads from another host needs a rule in your profile. A profile that inherits another built-in, such
as `npm-restrictive`, must allow these hosts itself, or the proxy refuses
the runner's connections to GitHub.

`github-actions` allows `*.blob.core.windows.net:443`, because the runner,
`actions/upload-artifact` and `actions/cache` use Azure storage. That rule
allows every Azure storage account, so a script can send data to one.

`deny_ip_literals` refuses a connection to an IP literal no allow rule
names. An allow list of names does not stop a workflow that posts to an IP
literal. See [Network rules](./sandbox.md#network-rules).

The post step fails the job when the proxy refused a connection. The job
summary names the destination, the rule and the program. Add a `CODEOWNERS`
line for `.pmg/network.yml`, because the profile is as trusted as the
workflow file.

#### Build the profile from a run

The proxy records every destination the job reaches. Three runs take a job
from no profile to `enforce`.

1. **Observe.** Run the job with the defaults. The job summary proposes a
   profile for `.pmg/network.yml`, from the destinations the job reached.
   For another path, set `network-profile` to a path that does not exist
   yet. The action then starts the daemon with no profile and proposes the
   profile for that path.

2. **Commit.** Review every rule in the proposal. One run does not reach
   every destination the job needs. Save the proposal as
   `.pmg/network.yml` and commit it. Set `network-profile:
   .pmg/network.yml` on the PMG step. The proposal inherits
   `github-actions`, which refuses each host that no rule allows.

   Each later run in `audit` lists the destinations the profile does not
   allow, in the summary and as a warning on the run. The summary shows the
   rules to add.

3. **Enforce.** Set `network-mode: enforce`. The proxy refuses a
   destination the profile does not allow, and the post step fails the job.

   ```yaml
   - uses: safedep/pmg@v0.34.0
     with:
       network-profile: .pmg/network.yml
       network-mode: enforce
   ```

Use `enforce: true` with `network-mode: enforce`. Without kernel enforcement
the policy is advisory, because a process can ignore the proxy variables.

The proposal comes from the event log, so with `skip-event-logging: true`
the post step makes no proposal. A proposal adds allow rules and does not
remove rules. A destination that the proxy refused under `enforce` gets no
rule. Add one by hand when the job needs it. See
[Build the allow list](./persistent-proxy.md#build-the-allow-list).

#### Runner traffic

The runner is not exempt. Its traffic to GitHub goes through the proxy,
which passes it through with the real certificate. An exemption would be a
bypass, because the user that runs the jobs can write the runner's folder.

If the daemon stops serving but keeps running, the runner cannot report.
GitHub cancels the job about 5 minutes after its `timeout-minutes`, and
later steps, the post step included, do not run. The GitHub default is 360 minutes.

#### Containers

Containers that a step starts are not enforced unless `enforce-namespaces`
is `redirect` or `auto`. The redirect covers `docker run`, `RUN` steps in
`docker build`, and Docker container actions. In a container job
(`jobs.<id>.container`), the action runs inside the job container and cannot
attach the kernel programs there. With `enforce: auto` the action runs the
proxy without enforcement and shows a notice. With `enforce: true` the
action fails.

A redirected container must trust the PMG CA, which the action exports as
`PMG_CA_BUNDLE`:

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    enforce: true
    enforce-namespaces: redirect
- run: docker build --secret id=pmg-ca,src=$PMG_CA_BUNDLE -t app .
```

See [Trust inside a container](./persistent-proxy.md#trust-inside-a-container)
for the `RUN` block that mounts the secret.

A Docker container action gets the workspace at `/github/workspace` and the
step's `env:`. Copy the bundle into the workspace in a step before it:

```yaml
- run: cp "$PMG_CA_BUNDLE" pmg-ca.pem
- uses: some/docker-action@v1
  env:
    NODE_EXTRA_CA_CERTS: /github/workspace/pmg-ca.pem
```

#### Self-hosted runners

`enforce: auto` does not enforce on a self-hosted runner. Kernel
enforcement adds the PMG CA to the trust store of the host, and the CA stays
after the job. A host that more than one repository or job shares then
trusts the PMG CA for every job. Set `enforce: true` on an ephemeral runner,
or on a host that only trusted jobs use. The post step stops the root
daemon at the end of the job.

A host can also run the daemon as a `systemd` service for every job. See
[Run it as a service](./persistent-proxy.md#run-it-as-a-service). Put the
trust variables in the runner's `.env` file, and set `enforce: false` on the
action, because the host daemon already enforces. `Restart=on-failure` does
not restart a hung daemon, and the runner stays offline until an operator
restarts the daemon.

### Job containers and Docker actions

In a job that has a job container (`jobs.<job_id>.container`), the action
and the proxy run in the job container. The `run:` steps in the job
container reach the proxy at `127.0.0.1`.

The action needs a POSIX shell and userland in the image, such as busybox:
`sh`, `tar`, `sha256sum`, `grep`, `sed`, `tr`, `cut`, `head`, `uname`,
`mktemp`, `mkdir`, `chmod`, `cp` and `rm`, and `curl` or `wget`. It does not
need `bash` or Node in the image. The runner runs the action with its own
Node. Alpine images, such as `golang:1.26-alpine` and
`node:24-alpine`, work as they are. The action refuses a `wget` that does not
verify TLS certificates, such as the `wget` of the `busybox` image. Add `curl`
to such an image. The action at
v0.32.0 and older runs every step with `bash` and fails on an image without
it. On those versions, run `apk add --no-cache bash curl` in a step before
the action.

Kernel enforcement does not run in a job container. With `enforce: auto`
the action runs the proxy without it there. With `enforce: true` the action
fails. See [Containers](#containers).
`sandbox` changes kernel settings of the runner host, and may not start in a
job container. Run those jobs on the runner.

A Docker action or a `docker://` step runs in a different container on the
job network. In that container, `127.0.0.1` is its own loopback, so the
connection to the proxy fails. To give these steps access to the proxy, set
`expose-to-job-network`:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:24
      options: --init
    steps:
      - uses: actions/checkout@v4
      - uses: safedep/pmg@v0.34.0
        with:
          expose-to-job-network: true
      - run: npm ci
      - uses: docker://node:24
        with:
          args: npm ci
```

The action binds the proxy to the address of the job container on the job
network. All containers on the job network can then reach the proxy,
including service containers. The proxy does not listen on `127.0.0.1`.

The CA is in `/github/home`, which is `HOME` in the job container. The
runner also mounts `/github/home` in Docker actions, so the exported CA path
is valid in both. If the job sets `HOME`, `XDG_CONFIG_HOME` or
`PMG_CONFIG_DIR` to a different directory, the action shows a warning, and
TLS through the proxy fails in Docker actions. `SSL_CERT_FILE` points to a
bundle made from the system CAs of the job container and the PMG CA. A tool
in a Docker action that reads `SSL_CERT_FILE` uses this bundle instead of
the system CAs of the image.

PMG v0.30.0 and older need `options: --init` in a job container. Without
it, `pmg proxy stop` waits until its timeout and fails.

`expose-to-job-network` does not help these containers:

- Docker actions and `docker://` steps in a job without a job container.
  The container cannot reach the runner's loopback, and it does not have
  the PMG CA.
- Containers that a script starts with `docker run`. On a job without a job
  container, `enforce-namespaces` can redirect them. See
  [Kernel enforcement](#kernel-enforcement).

### Sandbox mode

```yaml
- uses: safedep/pmg@v0.34.0
  with:
    sandbox: true
    sandbox-driver: landlock   # or "bubblewrap"
- run: npm ci
```

The sandbox runs the package managers through the PMG shims, so `sandbox:
true` turns on [shim mode](#shim-mode). With `server-mode: true` or
`network-profile` the action runs in server mode, warns, and does not use
the sandbox.

The action runs `systemctl stop apparmor` and clears
`kernel.apparmor_restrict_unprivileged_userns`. This lets unprivileged
user namespaces work. The change modifies the runner. Enable it only when
you need install-script containment.

### Set `PMG_*` environment variables directly

You can override a PMG config key with a `PMG_*` environment variable. In
server mode the daemon reads its configuration when the action starts it.
Set the variable on the job or on the action step. A variable on a later
step has no effect on the daemon:

```yaml
- uses: safedep/pmg@v0.34.0
  env:
    PMG_DEPENDENCY_COOLDOWN_DAYS: 10
- run: npm ci
```

Under kernel enforcement the daemon runs as root, and `sudo` passes it only
the variables that the action inputs also set: the SafeDep Cloud, paranoid,
cooldown, verbosity, telemetry and event logging variables. For another key
use `config-file`. In
[shim mode](#shim-mode) each `pmg` call reads the variables, so a variable
on the step that runs the package manager also works.

See [docs/config.md](./config.md) for the full mapping.

## Platform support

| Runner | Supported |
|---|---|
| `ubuntu-latest`, `ubuntu-24.04`, `ubuntu-22.04` (x86_64 and arm64) | Yes |
| A job container on a Linux runner, Alpine on x86_64 included | Yes. See [Job containers and Docker actions](#job-containers-and-docker-actions). |
| An Alpine job container on arm64 | No. The runner has no Node build for it, and the action needs Node. |
| `macos-*` | No. The action stops. |
| `windows-*` | No. The action stops. |

[Issue #248](https://github.com/safedep/pmg/issues/248) tracks macOS and
Windows runner support.

The action is a JavaScript action that runs on Node 24. A self-hosted runner
needs runner version 2.327.1 or later.
