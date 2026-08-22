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

PMG analyzes packages from its built-in registries by default, such as `registry.npmjs.org` and `pypi.org`. It can also analyze packages from your own npm or PyPI compatible endpoint. Use this for an internal mirror or a registry proxy such as Artifactory or Nexus.

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

Both PyPI URLs belong to the same logical registry. Every metadata or artifact endpoint PMG should analyze must be listed explicitly; PMG does not automatically trust hosts discovered through metadata links or redirects.

| Key | Description |
|---|---|
| `name` | A unique label for the registry. Used in logs. |
| `ecosystem` | `npm` or `pypi`. No other ecosystem is supported. |
| `endpoints[].url` | The base URL PMG matches requests against. Must be absolute, must use `http` or `https`, and must not carry credentials, a query string, or a fragment. |

### Which hosts PMG intercepts

PMG intercepts traffic only to the exact host in an endpoint URL. If you configure `packages.example.com`, PMG does not intercept `cdn.packages.example.com` or any other subdomain. For HTTPS, the configured port is part of the match: an endpoint on port 8443 does not cause PMG to decrypt traffic to port 443.

This is different from PMG's built-in registries, which also cover their known subdomains automatically.

PMG never decrypts traffic to a host it does not know, and a subdomain of a configured custom endpoint counts as unknown. That traffic goes through an ordinary encrypted tunnel; PMG cannot see the request path or body. PMG records the host in the audit log as a Host Observation event, so you can see which outside hosts your build reached.

### How PMG matches a request

PMG decides whether to intercept a connection in two steps.

At CONNECT time, before any request path is visible, PMG checks the hostname and port. PMG decrypts the connection when they match the exact origin of a configured HTTPS endpoint. An `http://` endpoint never causes an HTTPS CONNECT connection to be decrypted. PMG also decrypts traffic for a built-in registry host, or one of its subdomains, that PMG analyzes. A few built-in hosts are recognized but not analyzed, for example GitHub's npm registry mirror and the PyPI test instances. PMG tunnels their traffic without decrypting it.

After decryption, PMG matches each request against an endpoint by:

1. Origin: scheme, exact host, and effective port. An omitted port defaults to 80 for `http` and 443 for `https`.
2. Base path: the request path must equal the endpoint's base path, or start with the base path followed by `/`.

The base path check works on whole path segments, not on raw string prefixes. An endpoint base of `/repository/npm` matches `/repository/npm` and `/repository/npm/lodash`. It does not match `/repository/npm-private`, because `npm-private` is a different segment, not a continuation of `npm`. Query strings and fragments never affect the match.

PMG rejects nested endpoint base paths on the same origin during configuration validation, so a request cannot match more than one custom endpoint.

A request on a configured host whose path matches no endpoint passes through unchanged. Because the host matched a configured endpoint at CONNECT time, PMG already decrypted this traffic. PMG does not analyze the request, and does not block it.

### npm registry requirements

A custom npm endpoint must serve a standard packument, full or abbreviated, the same JSON document `npm install` itself downloads. PMG identifies packages from the request URL (the tarball path shape) and does not otherwise read the packument, except when dependency cooldown changes what it reads and writes.

When [dependency cooldown](./dependency-cooldown.md) is enabled, PMG requests the full packument from the endpoint. It reads the `time` object to check each version's publish date. An endpoint that can only serve abbreviated metadata gets no cooldown protection, because abbreviated metadata omits `time`. When cooldown strips a version, PMG rewrites `versions`, `time`, and `dist-tags` in the response.

### PyPI registry requirements

A custom PyPI metadata endpoint must serve the [Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/), either the PEP 691 JSON format or the PEP 503 HTML format. An endpoint that can only serve PEP 503 HTML gets no dependency cooldown protection, because PMG reads upload times from the PEP 691 JSON response; malware analysis of file downloads is unaffected.

An endpoint configured only for artifact downloads does not need to serve project metadata. PMG can analyze files beneath it when their standard wheel or source-distribution filenames contain the public package name and version.

The endpoint does not have to end in `/simple`. PMG recognizes `<base>/<project>/` when the configured base itself ends in `/simple`, and `<base>/simple/<project>/` when the base sits above the standard Simple API mount. For example, both `.../python/simple` plus `/requests/` and `.../python` plus `/simple/requests/` identify the project `requests`. PMG also recognizes the standard `<base>/pypi/<project>/json` metadata path.

Some bases do not end in `/simple`. For example, a base might point at a mirror's API root above the Simple mount. PMG still recognizes the relative layouts `/simple/<project>/` and `/pypi/<project>/json` beneath a base like this. A Simple API exposed some other way, such as a root-mounted index or a `+simple` convention, gets no project-page recognition and no dependency cooldown. PMG still analyzes distribution file downloads under that base, because it identifies them from their filename rather than from the page that links to them.

PMG identifies a distribution file, a wheel or an sdist, by its standard filename, at any depth below the configured base.

### Artifacts on a different host

Some registries serve package metadata from one host and the actual files from another, or from a different path prefix on the same host. PMG never treats a link or a redirect target as a reason to trust a new host. It analyzes an artifact from another host only if that host is itself a configured endpoint.

If your artifacts live on a separate origin or a disjoint path prefix, add it as its own endpoint. Nested endpoint prefixes on the same origin are rejected; an artifact already beneath an existing endpoint base is covered by that endpoint.

### How PMG identifies a package from a URL

PMG reads a package's name and version directly from the request URL: the npm tarball path shape, or the PyPI distribution filename. This covers most registries and needs no extra state.

Some registries use opaque download URLs that carry no name or version, for example `.../download/opaque?id=42`. PMG cannot identify these downloads, so it currently allows them without analysis, the same fail-open behavior as an unparsable URL. Support for identifying them from registry metadata is planned.

### Public packages only

PMG's malware database covers public packages. A package PMG cannot find there, including any private package on a custom registry, keeps the current behavior: PMG allows it.

Custom registry support targets public packages served through an internal mirror or a compatible registry proxy. PMG does not promise compatibility with any specific vendor. Metadata endpoints must serve the standard npm packument or PyPI Simple API beneath the URL you configure. Artifact-only PyPI endpoints must use standard distribution filenames.

### Credentials

PMG does not store, inject, or log registry credentials. Keep credentials where your package manager already expects them: npm's `.npmrc`, Yarn's or pnpm's own config, or pip's, Poetry's, or uv's configuration.

### Plain HTTP endpoints

PMG accepts an `http://` endpoint and prints one startup warning for it. Use `https://` where you can. Plain HTTP traffic is visible to anyone on the network path between the package manager and the registry.

### Troubleshooting

**A shallow base path matches more than expected.** The base path check works on whole segments, so a shallow base also matches sibling repositories under the same prefix. A base of `/repository` also matches `/repository/npm-private` and `/repository/pypi-internal`. Configure the base as deep as your registry's actual mount point, not its parent.

**A vendor-specific PyPI project page is not recognized.** The endpoint does not need to end in `/simple`, but its metadata path must use one of the standard shapes described above. PMG does not guess that an arbitrary `<base>/<project>/` path is project metadata unless the base ends in `/simple`. Standard wheel and source-distribution filenames beneath the matched endpoint are still analyzed at any path depth.

**An artifact is never analyzed.** Compare its URL with the configured endpoint's scheme, exact host, effective port, and segment-aware base path. A Host Observation means the artifact used an unknown origin; add that origin as an endpoint. A non-matching path on an already configured origin passes through without analysis and does not produce a Host Observation, so correct the existing base or add a disjoint endpoint. PMG rejects nested endpoint bases on the same origin. See "Artifacts on a different host" above.

**Configuration or proxy startup fails.** PMG validates `proxy.registries` while loading the configuration and again when building the registry catalog before the proxy starts.

PMG rejects these endpoint values:

- A `name` that is empty, whitespace-only, or has leading or trailing whitespace
- A duplicate `name`
- An `ecosystem` other than `npm` or `pypi`
- A registry with no `endpoints`
- A URL that is relative, invalid, or uses a scheme other than `http` or `https`
- A URL that includes credentials, a query string, or a fragment
- A loopback host (`localhost`, `127.x`, `::1`), which proxied runs exclude via `NO_PROXY` so PMG could never analyze it
- An unspecified address (`0.0.0.0`, `::`)
- A non-ASCII hostname; use the punycode (`xn--`) form, since package managers punycode before connecting
- Two endpoints that normalize to the same origin and base path
- Two endpoints on the same origin whose base paths nest into each other, such as `/npm` and `/npm/team` (npm and PyPI may share a host, but their base paths must be disjoint subtrees)
- Endpoint paths with empty or dot segments (`/npm//team`, `/npm/../team`), which could never match real traffic
- At proxy startup, an endpoint whose host is covered by a built-in registry (for example `registry.npmjs.org`, `pypi.org`, or their subdomains), because PMG already analyzes it

The error names the registry and the specific problem. An empty or whitespace-only name has no registry name to report, so the error names the entry's position in the list instead, for example `proxy.registries[0]`. While the error stands, commands that run intercepted traffic (`pmg <pkg-manager>` installs, `pmg proxy start`) fail closed, because falling back to defaults would silently drop the configured protection. Non-install commands such as `pmg config`, `pmg doctor`, and `pmg version` still work, so you can repair the file with PMG itself. Fix the entry and retry.

### Find your current registry settings

PMG does not read your package manager's own registry configuration automatically. Check each package manager yourself before you add a matching custom registry entry:

```bash
npm config get registry
npm config get @myscope:registry
pip config debug
```

`npm config get @myscope:registry` reports the registry for one scope; repeat it for every scope you use. `pip config debug` lists the `index-url` from every config file pip found, in the order pip applies them. It also lists active `PIP_*` environment variables under its `env_var:` section. An environment variable such as `PIP_INDEX_URL` overrides every config file.

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

## References

- [Persistent Proxy Mode](./persistent-proxy.md)
