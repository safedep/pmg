# Proxy Mode

PMG protects package installations through proxy based interception:

- PMG starts a micro-proxy server on a random localhost port
- Runs `npm` and other supported package managers configured to use the proxy
- Intercepts package registry requests and analyzes packages as they are downloaded
- Blocks malicious packages and allows trusted packages to be installed

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

| Key | Default | Description |
|---|---|---|
| `install_only` | `false` | When `true`, only install commands are proxied. Other commands (e.g., `npm ls`, `pip list`) bypass the proxy and execute directly. |
| `skip_commands` | `{}` | Per-package-manager commands to bypass the proxy. Only applies when `install_only` is `true`. |

### Per-package-manager skip commands

The `skip_commands` map lets you define additional commands that should bypass the proxy for specific package managers. This only takes effect when `install_only` is `true`:

```yaml
proxy:
  install_only: true
  skip_commands:
    npm: ["dev", "my-script"]
    pip: ["list", "show"]
```

Commands in `skip_commands` are matched against the first non-flag argument. For example, `npm dev` would match `dev`, but `npm install dev` would not since `install` is the first non-flag argument.

### Environment variables

| Variable | Description |
|---|---|
| `PMG_PROXY_INSTALL_ONLY` | Override `proxy.install_only` |

The legacy flat config key `proxy_install_only` is still supported when the `proxy:` section does not exist in the config file.

### Removed: disabling proxy interception

Guard mode (the non-proxy analysis flow) has been removed and proxy interception can no longer be disabled. PMG fails with an error when it detects a leftover opt-out: `proxy.enabled: false` or `proxy_mode: false` in the config file, or `PMG_PROXY_ENABLED=false` or `PMG_PROXY_MODE=false` in the environment. PMG does not silently switch to proxy interception when it finds one of these settings. Remove the setting to proceed. The `--proxy-mode` flag is removed and fails as an unknown flag.

Note one trade-off versus the removed guard mode: the proxy analyzes packages as they are downloaded, so installs fully served from a local package manager cache (e.g. npm cache, pnpm store, pip cache, `--offline` installs) do not trigger analysis. Guard mode analyzed manifest-listed packages via registry metadata regardless of downloads. Packages are analyzed when first fetched through the proxy, which is when they enter those caches.

## Custom Registries

By default PMG analyzes packages from its built-in registries, such as `registry.npmjs.org` and `pypi.org`. It can also analyze packages from your own npm or PyPI compatible endpoint. Use this for an internal mirror or a registry proxy such as Artifactory or Nexus.

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
        - url: https://packages.example.com/artifactory/api/pypi/python/simple
        - url: https://artifacts.example.com/packages
```

Both PyPI URLs belong to one logical registry. List every metadata and artifact endpoint you want PMG to analyze. PMG does not trust hosts that it discovers through metadata links or redirects.

| Key | Description |
|---|---|
| `name` | A unique label for the registry. Used in logs. |
| `ecosystem` | `npm` or `pypi`. No other ecosystem is supported. |
| `endpoints[].url` | The base URL PMG matches requests against. Must be absolute. Must use `http` or `https`. Must not contain credentials, a query string, or a fragment. |

### How PMG matches a request

PMG intercepts traffic only to the exact origin of an endpoint URL: the scheme, the host, and the port. If you configure `packages.example.com`, PMG does not intercept `cdn.packages.example.com`. An endpoint on port 8443 does not cause PMG to decrypt traffic to port 443. Built-in registries are different: they also cover their known subdomains.

PMG decides in two steps.

At CONNECT time, before any request path is visible, PMG checks the hostname and port. PMG decrypts the connection when they match the exact origin of a configured HTTPS endpoint. An `http://` endpoint never causes an HTTPS connection to be decrypted. PMG also decrypts traffic for the built-in registry hosts that it analyzes. It recognizes but does not decrypt a few other built-in hosts, for example GitHub's npm registry mirror and the PyPI test instances.

Traffic to every other host goes through an ordinary encrypted tunnel. PMG cannot see the request path or body. PMG records the host in the audit log as a Host Observation event, so you can see which outside hosts your build reached.

After decryption, PMG matches each request against an endpoint by:

1. Origin: scheme, exact host, and effective port. An omitted port defaults to 80 for `http` and 443 for `https`.
2. Base path: the request path must equal the endpoint base path, or start with the base path followed by `/`.

The base path check works on whole path segments, not on raw string prefixes. An endpoint base of `/repository/npm` matches `/repository/npm` and `/repository/npm/lodash`. It does not match `/repository/npm-private`, because `npm-private` is a different segment. Query strings and fragments never affect the match.

Configuration validation rejects nested endpoint base paths on the same origin, so a request cannot match more than one custom endpoint.

A request on a configured host whose path matches no endpoint passes through unchanged. PMG does not analyze it and does not block it.

### How PMG identifies a package

PMG reads a package name and version directly from the request URL: the npm tarball path shape, or the PyPI distribution filename. When the URL carries no identity, PMG fails open: it allows the download without analysis and never blocks on a guess. This covers opaque download URLs such as `.../download/opaque?id=42` and any path shape PMG does not recognize. Support to identify these downloads from registry metadata is planned.

### npm registry requirements

A custom npm endpoint must serve a standard packument, full or abbreviated: the same JSON document that `npm install` downloads.

When [dependency cooldown](./dependency-cooldown.md) is enabled, PMG requests the full packument and reads the `time` object to check each version's publish date. An endpoint that can only serve abbreviated metadata gets no cooldown protection, because abbreviated metadata omits `time`. When cooldown strips a version, PMG rewrites `versions`, `time`, and `dist-tags` in the response.

### PyPI registry requirements

A custom PyPI metadata endpoint must serve the [Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/), as PEP 691 JSON or PEP 503 HTML. An endpoint that can only serve PEP 503 HTML gets no dependency cooldown protection, because PMG reads upload times from the PEP 691 JSON response. Malware analysis of file downloads is not affected.

PMG identifies a distribution file, a wheel or an sdist, by its standard filename, at any depth below the configured base. An endpoint configured only for artifact downloads does not need to serve project metadata.

The endpoint base does not have to end in `/simple`. PMG recognizes these project page layouts:

- `<base>/<project>/` when the base itself ends in `/simple`
- `<base>/simple/<project>/` when the base sits above the standard Simple API mount
- `<base>/pypi/<project>/json`, the standard JSON API path

A Simple API exposed some other way, such as a root-mounted index, gets no project page recognition and no dependency cooldown. PMG still analyzes distribution file downloads under that base, because it identifies them from their filename.

### Artifacts on a different host

Some registries serve metadata from one host and files from another host or path prefix. PMG analyzes an artifact from another origin only when that origin is itself a configured endpoint. Add each artifact origin or disjoint path prefix as its own endpoint.

### Public packages only

PMG's malware database covers public packages. PMG allows a package it cannot find there, including any private package on a custom registry. Custom registry support targets public packages served through an internal mirror or a compatible registry proxy. PMG does not promise compatibility with any specific vendor.

### Credentials

PMG does not store, inject, or log registry credentials. Keep credentials where your package manager already expects them: npm's `.npmrc`, Yarn's or pnpm's own config, or pip's, Poetry's, or uv's configuration.

### Plain HTTP endpoints

PMG accepts an `http://` endpoint. It prints one startup warning, and `pmg setup doctor` reports the endpoint. Use `https://` where you can. Anyone on the network path can read and change plain HTTP traffic.

### Troubleshooting

**A shallow base path matches more than expected.** The base path check works on whole segments, so a shallow base also matches sibling repositories under the same prefix. A base of `/repository` also matches `/repository/npm-private`. Configure the base as deep as your registry's actual mount point.

**A vendor-specific PyPI project page is not recognized.** The metadata path must use one of the standard layouts above. PMG does not guess that an arbitrary `<base>/<project>/` path is project metadata unless the base ends in `/simple`. Distribution file downloads under the matched endpoint are still analyzed.

**An artifact is never analyzed.** Compare its URL with the configured endpoint origin and base path. A Host Observation in the audit log means the artifact used an unknown origin: add that origin as an endpoint. A non-matching path on a configured origin passes through without a Host Observation: correct the base path or add a disjoint endpoint.

**Configuration or proxy startup fails.** PMG validates `proxy.registries` when it loads the configuration, and again when it builds the registry catalog before the proxy starts. `pmg setup doctor` reports the failure.

PMG rejects these values:

- A `name` that is empty, whitespace-only, or has leading or trailing whitespace
- A duplicate `name`
- An `ecosystem` other than `npm` or `pypi`
- A registry with no `endpoints`
- A URL that is relative, invalid, or uses a scheme other than `http` or `https`
- A URL that contains credentials, a query string, or a fragment
- A loopback host (`localhost`, `127.x`, `::1`). Proxied runs exclude loopback via `NO_PROXY`, so PMG could never analyze it
- An unspecified address (`0.0.0.0`, `::`)
- A non-ASCII hostname. Package managers punycode hostnames before they connect, so use the punycode (`xn--`) form
- Two endpoints that normalize to the same origin and base path
- Two endpoints on the same origin whose base paths nest into each other, such as `/npm` and `/npm/team`. npm and PyPI may share a host, but their base paths must be disjoint subtrees
- Endpoint paths with empty or dot segments (`/npm//team`, `/npm/../team`), which can never match real traffic
- At proxy startup, an endpoint whose host is covered by a built-in registry (for example `registry.npmjs.org`, `pypi.org`, or their subdomains), because PMG already analyzes it
- At proxy startup, an endpoint on `proxy.golang.org` or `sum.golang.org` (or their subdomains). These hosts belong to PMG's built-in Go module handling, and PMG never decrypts `sum.golang.org`

The error names the registry and the specific problem. An empty name has no registry name to report, so the error names the entry position instead, for example `proxy.registries[0]`. While the error stands, commands that run intercepted traffic (`pmg <pkg-manager>` installs, `pmg proxy start`) fail closed, because a fallback to defaults would silently drop the configured protection. Commands such as `pmg config`, `pmg setup doctor`, and `pmg version` still work, so you can repair the file with PMG itself.

### Find your current registry settings

PMG does not read your package manager's own registry configuration. Check each package manager before you add a matching custom registry entry:

```bash
npm config get registry
npm config get @myscope:registry
pip config debug
```

`npm config get @myscope:registry` reports the registry for one scope. Repeat it for every scope you use. `pip config debug` lists the `index-url` from every config file pip found, in the order pip applies them. It also lists active `PIP_*` environment variables under its `env_var:` section. An environment variable such as `PIP_INDEX_URL` overrides every config file.

## Supported Package Managers

| Package Manager | Status |
| --------------- | ------ |
| `npm`           | ✅      |
| `npx`           | ✅      |
| `pnpm`          | ✅      |
| `pnpx`          | ✅      |
| `bun`           | ✅      |
| `yarn`          | ✅      |
| `pip`           | ✅      |
| `uv`            | ✅      |
| `uvx`           | ✅      |
| `poetry`        | ✅      |
| `go`            | 🧪 experimental |
| `cargo`         | 🧪 experimental |

### Go (experimental)

`pmg go` guards Go module downloads through the same proxy flow. It is
experimental and opt-in: it only runs when invoked explicitly as `pmg go ...`
and is deliberately excluded from `pmg setup` shell aliases and PATH shims.

<details>
<summary>How it differs from npm/PyPI</summary>

- The module proxy host comes from the effective `GOPROXY` (including
  `go env -w` values), not a fixed registry. PMG intercepts whatever HTTPS
  proxies are configured and rewrites the child's `GOPROXY` to a fail-closed,
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
- On macOS and Windows, Go only trusts the OS trust store, so
  `pmg setup cert install` is required first; `pmg go` fails fast with
  instructions if the PMG CA is not trusted. Linux works out of the box.
- Modules matching `GOPRIVATE`/`GONOPROXY` are fetched directly from their
  VCS host and are not analyzed; PMG warns when these are set.

</details>

### Cargo (experimental)

`pmg cargo` guards crates.io downloads through the same proxy flow. It is
experimental and opt-in: it only runs when invoked explicitly as
`pmg cargo ...` and is deliberately excluded from `pmg setup` shell aliases
and PATH shims. Unlike npm/PyPI, Rust executes third-party code at build time
(build scripts, proc macros), so `cargo build`/`run`/`test` are guarded
dependency-installing commands, not pass-throughs.

<details>
<summary>How it differs from npm/PyPI</summary>

- PMG intercepts the fixed crates.io hosts: `index.crates.io` (sparse index)
  and `static.crates.io` (`.crate` downloads). The crates.io API host is
  tunneled without inspection, so registry tokens used by `cargo publish`
  never pass through the MITM path.
- PMG forces the sparse registry protocol for the child
  (`CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse`) so index traffic is
  interceptable, and injects `CARGO_HTTP_CAINFO` — the only CA variable
  cargo's libcurl reads. No OS trust store change is needed on any platform.
- Dependency cooldown strips in-window versions from sparse-index responses
  using the index's per-version `pubtime` field, so cargo's resolver falls
  back to an older release. A pinned or `Cargo.lock` version inside the
  window is blocked at download time with HTTP 403, using an out-of-band
  index fetch when the publish time was not observed on the wire.
- Malware analysis runs on every `.crate` download, direct and transitive.
- Git dependencies (`git = "..."` in `Cargo.toml`) are fetched from their VCS
  host and are not analyzed. Alternative registries and source replacement
  are not analyzed either; their traffic is tunneled and surfaces in the
  audit log as observed hosts.

</details>

## References

- [Persistent Proxy Mode](./persistent-proxy.md)
