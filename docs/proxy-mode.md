# Proxy Mode

PMG protects package installations through proxy based interception:

- PMG starts a micro-proxy server on a random localhost port
- Runs `npm` and other supported package managers configured to use the proxy
- Intercepts package registry requests and analyzes packages as they are downloaded
- Blocks malicious packages and allows trusted packages to be installed

Under normal analysis, a verified malicious result blocks the download.
An unverified malware inference asks for confirmation.
Paranoid mode turns that inference into a block.
A declined, failed, or expired confirmation returns HTTP 403.
The response wait expires after 5 minutes.
PMG does not prompt when stdin or stdout is not a terminal, when it runs as a background job, or when `CI=true`.
It then declines each confirmation.
Trusted packages, insecure installation, and tenant exclusions can change these decisions.
A tenant exclusion is a SafeDep Cloud entry that allows one flagged package version for your tenant.
PMG applies it only to authenticated queries.
See [trusted packages](trusted-packages.md) and [How PMG identifies a package](#how-pmg-identifies-a-package).

When PMG proxies a command without a prompt and `CI` is absent, PMG sets `CI=true` for the package manager.
An explicit `CI=false` stays unchanged.
`CI=false` does not make PMG prompt.

## Usage

```bash
pmg npm install lodash
```

## Configuration

Proxy behavior is configured under the `proxy:` section in `config.yml`:

```yaml
proxy:
  install_only: false
```

| Key             | Default | Description                                                                                                                        |
| --------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `install_only`  | `false` | When `true`, known non-download commands such as `npm ls` and `pip list` bypass the proxy. Unknown commands, `npm run`, `npm exec`, `npm ci`, and all `uv` commands still use it. |
| `skip_commands` | `{}`    | Per-package-manager commands to bypass the proxy. Only applies when `install_only` is `true`.                                      |

### Per-package-manager skip commands

The `skip_commands` map lets you define additional commands that should bypass the proxy for specific package managers. This only takes effect when `install_only` is `true`:

```yaml
proxy:
  install_only: true
  skip_commands:
    pnpm: ["dev", "my-script"]
    yarn: ["dev"]
```

PMG matches the first non-flag argument under the exact package-manager name.
For example, `pnpm dev` matches `dev`, but `pnpm install dev` does not.
PMG does not know which flags take a value. In `pnpm --filter web dev`, the first non-flag argument is `web`.
`npm run dev` matches `run`.
An `npm: ["run"]` entry skips every npm script.
A `pip` entry does not cover `pip3` or `pipx`.
A skipped command receives no proxy interception from this invocation.

### Environment variables

| Variable                 | Description                   |
| ------------------------ | ----------------------------- |
| `PMG_PROXY_INSTALL_ONLY` | Override `proxy.install_only` |

The legacy flat config key `proxy_install_only` is still supported when the `proxy:` section does not exist in the config file.

### Upstream proxy

PMG itself can use an upstream corporate proxy through `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.
Its HTTP transport and CONNECT dialer support HTTP, HTTPS, and SOCKS5 proxies.
The child receives PMG's proxy address instead.
Requests to `localhost` and to loopback IP addresses bypass the upstream proxy.
For TLS connections that PMG makes, add private roots to the system trust store, or set `SSL_CERT_FILE` in PMG's environment.
When `SSL_CERT_FILE` is set on macOS or Windows, PMG uses only that file.
On macOS and Windows, set `GODEBUG=x509sslcertoverrideplatform=0` in PMG's environment to keep PMG on the system store. PMG's own connections then ignore `SSL_CERT_FILE`.
On Linux, PMG also reads the system certificate directories, such as `/etc/ssl/certs`.
Set `SSL_CERT_DIR` to replace those directories.
For an opaque tunnel, the client validates the destination certificate.

### Removed: disabling proxy interception

Guard mode (the non-proxy analysis flow) has been removed and proxy interception can no longer be disabled. PMG fails with an error when it detects a leftover opt-out: `proxy.enabled: false` or `proxy_mode: false` in the config file, or `PMG_PROXY_ENABLED=false` or `PMG_PROXY_MODE=false` in the environment. PMG does not silently switch to proxy interception when it finds one of these settings. Remove the setting to proceed. The `--proxy-mode` flag is removed and fails as an unknown flag.

Note one trade-off versus the removed guard mode: the proxy analyzes packages as they are downloaded, so installs fully served from a local package manager cache (e.g. npm cache, pnpm store, pip cache, `--offline` installs) do not trigger analysis. Guard mode analyzed manifest-listed packages via registry metadata regardless of downloads. PMG analyzes a package when it fetches it through the proxy.
It does not analyze artifacts already cached by a run without PMG.
It also does not recheck a package-manager cache when the malware database changes.
Audit or clear those caches when adopting PMG.

## Custom Registries

By default PMG analyzes packages from its built-in registries, such as `registry.npmjs.org` and `pypi.org`. It can also analyze packages from your own npm- or PyPI-compatible endpoint, from a Go module proxy, or from a sparse Cargo registry. Use this for an internal mirror or a registry proxy such as Artifactory, Nexus or Athens.

Configure custom registries under `proxy.registries`:

```yaml
proxy:
  registries:
    - name: npm-mirror
      ecosystem: npm
      endpoints:
        - url: https://packages.example.com/artifactory/api/npm/npm-virtual
    - name: pypi-mirror
      ecosystem: pypi
      endpoints:
        - url: https://packages.example.com/artifactory/api/pypi/python
    - name: go-proxy
      ecosystem: go
      endpoints:
        - url: https://packages.example.com/artifactory/api/go/go-virtual
    - name: cargo-mirror
      ecosystem: cargo
      endpoints:
        - url: https://packages.example.com/artifactory/api/cargo/cargo-virtual/index
        - url: https://packages.example.com/artifactory/api/cargo/cargo-virtual/v1/crates
```

The PyPI repository root covers its `simple` metadata and `packages` downloads.
List every metadata and artifact endpoint you want PMG to analyze. PMG does not trust hosts that it discovers through metadata links or redirects.

For a Go module proxy, configure the exact base URL that `GOPROXY` uses, such as the URL of one Artifactory Go repository. PMG reads the module path after the base path.

Choose a PyPI base that covers both metadata and linked distribution files.
A base ending in `/simple` or `/+simple` recognizes project pages directly below it.
It does not cover sibling artifact paths.
A repository root above `/simple` can cover both paths, as the example shows.
Other bases must retain a standard `/simple/{project}/` or `/pypi/{project}/json` route.

| Key               | Description                                                                                                                                           |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`            | A unique label for the registry. Used in logs.                                                                                                        |
| `ecosystem`       | `npm`, `pypi`, `go` or `cargo`. No other ecosystem is supported.                                                                                      |
| `endpoints[].url` | The base URL PMG matches requests against. Must be absolute. Must use `http` or `https`. Must not contain credentials, a query string, or a fragment. |

### How PMG matches a request

PMG intercepts traffic only to the exact origin of an endpoint URL. The origin is the scheme, the host, and the port. If you configure `packages.example.com`, PMG does not intercept `cdn.packages.example.com`. An endpoint on port 8443 does not cause PMG to decrypt traffic to port 443. Built-in registries are different. They also cover every subdomain of their host.

PMG decides in two steps.

At CONNECT time, before any request path is visible, PMG checks the hostname and port. PMG decrypts the connection when they match the exact origin of a configured HTTPS endpoint. An `http://` endpoint never causes an HTTPS connection to be decrypted. PMG also decrypts traffic for the built-in registry hosts that it analyzes. It recognizes but does not decrypt a few other built-in hosts, for example the GitHub Packages npm registry and the PyPI test instances.

A per-command run creates handlers only for that command's ecosystem.
For example, `pmg npm` tunnels built-in and custom PyPI registry hosts without analysis.
These known registry hosts also receive no Host Observation.
A nested cross-ecosystem install can therefore receive neither analysis nor this observation.
The [persistent proxy](persistent-proxy.md) handles all supported ecosystems, subject to its Go trust check.

Traffic to unknown hosts goes through an ordinary encrypted tunnel. PMG cannot see the request path or body. PMG records the host in the audit log as a Host Observation event, so you can see which outside hosts your build reached. The event records the port and how the connection reached the proxy. Under [kernel enforcement](./persistent-proxy.md#kernel-enforcement-linux) it also names the client: the pid, name and executable of a host process, or the address of a container. A process outside the daemon's PID namespace has a name only.

After decryption, PMG matches each request against an endpoint by:

1. Origin: scheme, exact host, and effective port. An omitted port defaults to 80 for `http` and 443 for `https`.
2. Base path: the request path must equal the endpoint base path, or start with the base path followed by `/`.

The base path check works on whole path segments, not on raw string prefixes. An endpoint base of `/repository/npm` matches `/repository/npm` and `/repository/npm/lodash`. It does not match `/repository/npm-private`, because `npm-private` is a different segment. Query strings and fragments never affect the match.

Configuration validation rejects nested endpoint base paths on the same origin, so a request cannot match more than one `proxy.registries` endpoint.
The run-specific `GOPROXY` entries added by `pmg go` can nest.
See [Go](#go-experimental).

A request on a configured host whose path matches no endpoint passes through unchanged. PMG does not analyze it and does not block it.

### How PMG identifies a package

PMG reads the package name and version (identity) from the registry URL.
Default mode allows requests without analysis when PMG cannot resolve the package identity.
Paranoid mode returns HTTP 403 when an enabled registry parser fails or an artifact identity is incomplete.
This check applies to GET and HEAD requests unless the user enables insecure installation.
PMG allows npm API paths under `/-/` and PyPI root index listings without a package identity.
Endpoints with analysis disabled, including the GitHub npm endpoints, remain outside this check.
Analyzer errors still allow downloads in both modes.
PMG needs access to `community-api.safedep.io:443` for community analysis.
With SafeDep Cloud credentials, PMG also needs `api.safedep.io:443`, or the address in `SAFEDEP_CLOUD_DATA_ADDR`.
Analyzer failures appear in diagnostic logs, not an install warning.
Use `pmg --debug npm install` or `pmg --log pmg-debug.log npm install` to inspect them.

`PMG_INSECURE_INSTALLATION=true` bypasses malware analysis and unresolved-identity blocking.
It does not disable cooldown or network policy.
A concrete artifact handled by the insecure bypass emits an insecure-bypass audit event.
[Lockdown](config.md#lockdown) clears this setting.

Cooldown keeps entries whose filenames PMG cannot parse.
An unrecognized artifact URL does not become a project metadata request.
Default mode allows that request without analysis or cooldown filtering.
Paranoid mode blocks it.

### npm registry requirements

A custom npm endpoint must serve a standard packument, full or abbreviated: the same JSON document that `npm install` downloads.

When [dependency cooldown](./dependency-cooldown.md) is enabled, PMG requests the full packument and reads the `time` object to check each version's publish date. An endpoint that can only serve abbreviated metadata gets no cooldown protection, because abbreviated metadata omits `time`. When cooldown strips a version, PMG rewrites `versions`, `time`, and `dist-tags` in the response.

### PyPI registry requirements

A custom PyPI metadata endpoint must serve the [Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/), as PEP 691 JSON or PEP 503 HTML. An endpoint that can only serve PEP 503 HTML gets no dependency cooldown protection, because PMG needs each file's optional `upload-time` field from PEP 700, API version 1.1.
A PEP 691 JSON response without this field also gets no cooldown.
See [client requirements](dependency-cooldown.md#limitations). Malware analysis of file downloads is not affected.

PMG identifies a distribution file, a wheel or an sdist, by its standard filename, at any depth below the configured base. An endpoint configured only for artifact downloads does not need to serve project metadata.

The endpoint base does not have to end in `/simple`. PMG recognizes these project page layouts:

- `<base>/<project>/` when the base itself ends in `/simple` or `/+simple`
- `<base>/simple/<project>/` when the base sits above the standard Simple API mount
- `<base>/pypi/<project>/json`, the standard JSON API path

A Simple API exposed some other way, such as a root-mounted index, gets no project page recognition and no dependency cooldown. PMG still analyzes distribution file downloads under that base, because it identifies them from their filename.
In paranoid mode, PMG returns HTTP 403 for an unrecognized project page unless insecure installation is active.
The install then fails.
For paranoid mode, use a base that ends in `/simple` or `/+simple`, or a base above `/simple`.
A root-mounted index has no such path, so paranoid mode cannot use it.

### Cargo registry requirements

For a [sparse Cargo registry](https://doc.rust-lang.org/cargo/reference/registry-index.html#sparse-protocol), configure the index URL from `.cargo/config.toml`.
PMG removes the `sparse+` prefix.
PMG cannot read a git index for cooldown.
It can still analyze that registry's `.crate` downloads when the `dl` URL from `config.json` is a configured endpoint.
Do not configure the git index URL as an endpoint.
PMG cannot parse git requests, and paranoid mode blocks them.

PMG reads `config.json` and the index files at the base of the endpoint. It finds a crate download at any depth below the base, in one of these layouts:

- `.../<crate>/<version>/download`. Cargo appends this path to a `dl` URL that has no markers.
- `.../<crate>-<version>.crate`, for example from `dl = "https://cdn.example.com/{lowerprefix}/{crate}-{version}.crate"`.

A download in another layout, such as one that names only `{sha256-checksum}`, has no package identity. Default mode allows it without analysis. Paranoid mode blocks it.

The `dl` value is in `<index URL>/config.json`. When the `dl` URL is below the index URL, one endpoint covers the index and the downloads. When it is not, add the `dl` URL as a second endpoint of the same registry, as in the Artifactory example above.

[Dependency cooldown](./dependency-cooldown.md) reads the `pubtime` field of each index entry. A registry whose index has no `pubtime` gets no cooldown protection. For a download whose publish time PMG did not see, for example in a `Cargo.lock` build, PMG fetches the index file from the endpoints of the same registry.

PMG decrypts every request to the origin of a custom endpoint, also `cargo publish` and `cargo login`. It does not read or change a request that is not a GET or a HEAD.

### Artifacts on a different host

Some registries serve metadata from one host and files from another host or path prefix. PMG analyzes an artifact from another origin only when that origin is itself a configured endpoint. Add each artifact origin or disjoint path prefix as its own endpoint.

### Public packages only

PMG's malware database covers public packages. PMG allows a package it cannot find there, including any private package on a custom registry. Custom registry support targets public packages served through an internal mirror or a compatible registry proxy. PMG does not promise compatibility with any specific vendor.

### Credentials

PMG does not store, inject, or log registry credentials. Keep credentials where your package manager already expects them: npm's `.npmrc`, Yarn's or pnpm's own config, pip's, Poetry's, or uv's configuration, or Cargo's credential providers.

When PMG fetches the index file of a crate for the cooldown, it sends the `Authorization` header of the download request. It sends the header only to the endpoints of the same custom registry, never to crates.io. Cargo sends the token of a registry to its index and to its downloads alike.

### Plain HTTP endpoints

PMG accepts an `http://` endpoint. It logs a startup warning for each plain HTTP endpoint.
Use `--debug` or `--log <file>` to see it.
`pmg setup doctor` also reports these endpoints. Use `https://` where you can. Anyone on the network path can read and change plain HTTP traffic.

### Troubleshooting

**A shallow base path matches more than expected.** The base path check works on whole segments, so a shallow base also matches sibling repositories under the same prefix. A base of `/repository` also matches `/repository/npm-private`. Configure the base as deep as your registry's actual mount point.

**A vendor-specific PyPI project page is not recognized.** The metadata path must use one of the standard layouts above. PMG does not guess that an arbitrary `<base>/<project>/` path is project metadata unless the base ends in `/simple` or `/+simple`.
Distribution file downloads under the matched endpoint are still analyzed.
Paranoid mode blocks the project page. See [PyPI registry requirements](#pypi-registry-requirements).

**An artifact is never analyzed.** Compare its URL with the configured endpoint origin and base path. A Host Observation in the audit log means the artifact used an unknown origin: add that origin as an endpoint. A non-matching path on a configured origin passes through without a Host Observation: correct the base path or add a disjoint endpoint.

**Configuration or proxy startup fails.** PMG validates `proxy.registries` when it loads the configuration, and again when it builds the registry catalog before the proxy starts. `pmg setup doctor` reports the failure.

PMG rejects these values:

- A `name` that is empty, whitespace-only, or has leading or trailing whitespace
- A duplicate `name`
- An `ecosystem` other than `npm`, `pypi`, `go` or `cargo`
- A registry with no `endpoints`
- A URL that is relative, invalid, or uses a scheme other than `http` or `https`
- A URL that contains credentials, a query string, or a fragment
- A loopback host (`localhost`, `127.x`, `::1`). Proxied runs exclude loopback via `NO_PROXY`, so PMG could never analyze it
- An unspecified address (`0.0.0.0`, `::`)
- A non-ASCII hostname. Package managers punycode hostnames before they connect, so use the punycode (`xn--`) form
- Two endpoints that normalize to the same origin and base path
- Two endpoints on the same origin whose base paths nest into each other, such as `/npm` and `/npm/team`. Registries of different ecosystems may share a host, but their base paths must be disjoint subtrees
- Endpoint paths with empty or dot segments (`/npm//team`, `/npm/../team`), which can never match real traffic
- At proxy startup, an endpoint whose host is covered by a built-in registry (for example `registry.npmjs.org`, `pypi.org`, `proxy.golang.org`, `sum.golang.org`, `index.crates.io`, `static.crates.io`, or their subdomains). PMG already analyzes these hosts, or never decrypts them, as with `sum.golang.org`

The error names the registry and the specific problem. An empty name has no registry name to report, so the error names the entry position instead, for example `proxy.registries[0]`. While the error stands, commands that run intercepted traffic (`pmg <pkg-manager>` installs, `pmg proxy start`) fail closed, because a fallback to the compiled-in configuration would silently drop the configured protection. Commands such as `pmg config`, `pmg setup doctor`, and `pmg version` still work, so you can repair the file with PMG itself.

Host Observations use event type `proxy_host_observed` in `YYYYMMDD-pmg.log` JSON-lines files.
PMG names each file for the day the process starts.
A long-running proxy keeps writing to that file after midnight.
The default directory is `<effective-user-config-dir>/logs`.
On Windows it is `%LOCALAPPDATA%\safedep\pmg\logs`.
`PMG_CONFIG_DIR` also relocates logs when set.
The hostname is in `details.hostname`.
For example, with `jq` and the appropriate log directory, run the following command.

```sh
jq -c 'select(.event_type == "proxy_host_observed") | .details' <logs-dir>/*-pmg.log
```

`skip_event_logging` disables the default event writer.
The root `--log <file>` option redirects diagnostics and events to one file instead of the event-log directory.
With `skip_event_logging` on, that file gets diagnostics only.
See [configuration paths](config.md).

### Find your current registry settings

PMG does not read your package manager's own registry configuration.
The exception is `pmg go`, which reads the effective `GOPROXY`, including `go env -w` values. Check each package manager before you add a matching custom registry entry:

```bash
npm config get registry
npm config get @myscope:registry
pip config debug
```

For Cargo, read the `[registries]` and `[source]` tables of each `.cargo/config.toml` that applies, and the `CARGO_REGISTRIES_*` environment variables. A `replace-with` source sends crates.io traffic to the mirror that it names, so configure that mirror as a custom registry.

`npm config get @myscope:registry` reports the registry for one scope. Repeat it for every scope you use.
`pip config debug` groups files by kind, not precedence.
pip applies the global, user, and site files, then the `PIP_CONFIG_FILE` file.
Later files override earlier files.
When the `PIP_CONFIG_FILE` file exists, pip does not read the user file.
`pip config debug` also lists active `PIP_*` environment variables under its `env_var:` section. An environment variable such as `PIP_INDEX_URL` overrides every config file.
See [pip configuration](https://pip.pypa.io/en/stable/topics/configuration/).

uv does not read pip configuration.
Check its `pyproject.toml`, `uv.toml`, index options, and `UV_*` index environment variables.
See [uv configuration](https://docs.astral.sh/uv/concepts/configuration-files/) and [pip compatibility](https://docs.astral.sh/uv/pip/compatibility/).

## Supported Package Managers

| Package Manager | Status          |
| --------------- | --------------- |
| `npm`           | ✅              |
| `npx`           | ✅              |
| `pnpm`          | ✅              |
| `pnpx`          | ✅              |
| `bun`           | ✅              |
| `yarn`          | ✅              |
| `aube`          | ✅              |
| `aubr`          | ✅              |
| `aubx`          | ✅              |
| `pip`           | ✅              |
| `pip3`          | ✅              |
| `pipx`          | ✅              |
| `uv`            | ✅              |
| `uvx`           | ✅              |
| `poetry`        | ✅              |
| `go`            | 🧪 experimental |
| `cargo`         | 🧪 experimental |

### aube

`pmg aube` guards [aube](https://aube.sh) through the same proxy flow as npm.
`pmg aubr` guards `aubr`, the aube shorthand for `aube run`, because a script
run installs missing or stale dependencies first. `pmg aubx` guards `aubx`, the
aube shorthand for `aube dlx`. aube trusts the PMG CA through
`NODE_EXTRA_CA_CERTS`, so no trust store setup is required.

aube reads `npm_config_https_proxy` and `npm_config_noproxy` from the
environment and `https-proxy` from the user `~/.npmrc` before it reads
`HTTPS_PROXY`, as npm does. PMG sets the `npm_config_*` proxy variables in the
child environment, and the environment wins over the file, so these settings
cannot send registry traffic around PMG. aube ignores `https-proxy` and
`noproxy` in a project `.npmrc`. aube also runs its own checks (OSV advisories,
weekly download counts) before it downloads a tarball, so aube can reject a
package before PMG analyzes it.

`aube add` writes the new dependency to `package.json` before it downloads the
tarball. When PMG blocks the package, or when you reject a suspicious package at
the confirmation prompt, aube exits with an error. The dependency stays in
`package.json` but is not installed in `node_modules`. Run
`aube remove <package>` to remove the entry, or edit `package.json`.

See [Windows support](windows-support.md) for the aube client availability caveat.

### Go (experimental)

`pmg go` guards Go module downloads through the same proxy flow. It is
experimental and opt-in: it only runs when invoked explicitly as `pmg go ...`
and is deliberately excluded from `pmg setup` shell aliases and PATH shims.

<details>
<summary>How it differs from npm/PyPI</summary>

- PMG analyzes `proxy.golang.org`, the Go proxies in `proxy.registries`, and
  each HTTP or HTTPS module proxy in the effective `GOPROXY` (including
  `go env -w` values). PMG rewrites the child's `GOPROXY` to a fail-closed,
  comma-joined list: `direct` is removed (a module PMG cannot inspect fails
  instead of silently bypassing analysis) and pipe separators collapse to
  comma so a block is terminal.
- Malware analysis and dependency cooldown run on the `.zip` source download:
  the only GOPROXY endpoint that delivers code. `.info`/`.mod` metadata passes
  through (cooldown reads the publish time from `.info` without modifying it).
- `sum.golang.org` is never MITM'd and `/sumdb/` requests pass through
  unmodified, so Go's checksum-database verification stays fully intact.
  Toolchain downloads (`golang.org/toolchain`) are allowed on Go's own
  checksum verification.
- On macOS and Windows, run `pmg setup cert install` first. See
  [Go on macOS and Windows](./cert.md#go-on-macos-and-windows). Linux works
  out of the box.
- Modules matching `GOPRIVATE`/`GONOPROXY` are fetched directly from their
  VCS host and are not analyzed. PMG logs a warning when these variables are set.
  Use `--debug` or `--log <file>` to see it.
- If no entry remains after PMG removes `direct`, PMG injects
  `https://proxy.golang.org`. Module paths can therefore reach this public
  service. Set private-module routing explicitly.
- PMG clears an environment-set `GOINSECURE` for the child.
  A value stored with `go env -w` can still apply.
  Explicit HTTP proxy URLs remain possible.
  This behavior is not a general ban on plain HTTP.
- PMG matches each `GOPROXY` entry by the path that go sends, not by the
  text of the entry. go trims a trailing slash and cleans the path before it
  appends the module path.
- PMG prints a warning for a `GOPROXY` entry that it cannot analyze, for
  example a loopback host. go still uses that entry.
- Two `GOPROXY` entries on one host can have nested base paths, such as
  `https://proxy.golang.org/example.com` and `https://proxy.golang.org`.
  When the two bases read one request as two different modules, PMG blocks
  the request. PMG cannot tell which base go used.
- `pmg go` rejects an entry that overlaps another ecosystem's registry.
  Built-in npm, PyPI, and Cargo hosts and their subdomains conflict on any scheme or port.
  Configured endpoints conflict when their origins match and base paths nest.
  PMG cannot determine which ecosystem owns such a request.
- The persistent proxy analyzes `proxy.golang.org` and the Go proxies in
  `proxy.registries` without `pmg go`. See
  [Go modules](./persistent-proxy.md#go-modules).

</details>

### Cargo (experimental)

`pmg cargo` guards crates.io downloads through the same proxy flow. The
command is experimental and opt-in. It runs only when you invoke it as
`pmg cargo ...`. `pmg setup` does not create a shell alias or a PATH shim
for it. Rust runs third-party code at build time, in build scripts and proc
macros. PMG therefore guards `cargo build`, `cargo run`, and `cargo test`
as dependency-installing commands.

<details>
<summary>How it differs from npm/PyPI</summary>

- PMG intercepts two crates.io hosts and the endpoints of each Cargo
  registry in `proxy.registries`. `index.crates.io` serves the sparse
  index. `static.crates.io` serves the `.crate` downloads. PMG
  tunnels the crates.io API host without inspection, so a crates.io token
  of `cargo publish` never passes through the MITM path. PMG decrypts the
  origin of a custom registry endpoint, also for `cargo publish`. See
  [Cargo registry requirements](#cargo-registry-requirements).
- PMG sets `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse` for the child
  process so PMG can intercept index traffic. PMG sets `CARGO_HTTP_CAINFO`
  which Cargo reads on every platform. You do not need to
  change the OS trust store on any platform.
  PMG also sets `CARGO_HTTP_CHECK_REVOKE=false`.
  On Windows, this disables Cargo certificate revocation checks for every HTTPS host, including tunneled hosts.
  PMG's short-lived leaf certificates have no revocation endpoint.
  On other platforms, this matches Cargo's default.
  PMG sets these Cargo variables for every guarded child, including Cargo nested under npm or pip.
- Dependency cooldown removes in-window versions from sparse-index
  responses. It reads the per-version `pubtime` field in the index. Cargo's
  resolver then falls back to an older release. PMG blocks a pinned or
  `Cargo.lock` version inside the window at download time with HTTP 403.
  When PMG did not see the publish time on the wire, it fetches the index
  file out of band.
- Malware analysis runs on every `.crate` download, direct and transitive.
- Cargo fetches git dependencies from their VCS host. PMG does not analyze
  them. PMG analyzes an alternative registry or a source replacement only
  when its endpoints are in `proxy.registries`. See
  [Cargo registry requirements](#cargo-registry-requirements). Other
  registry traffic is tunneled and appears in the audit log as observed
  hosts.
- An `http.proxy` value in `.cargo/config.toml`, `CARGO_HTTP_PROXY`, or the
  `http.proxy` value of the git configuration overrides the `HTTPS_PROXY`
  that PMG sets. cargo then sends its traffic around PMG.

</details>

## References

- [Persistent Proxy Mode](./persistent-proxy.md)
