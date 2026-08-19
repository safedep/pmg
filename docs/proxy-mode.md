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
    - name: company-npm
      ecosystem: npm
      endpoints:
        - url: https://packages.example.com/artifactory/api/npm/npm-virtual
    - name: company-pypi
      ecosystem: pypi
      endpoints:
        - url: https://packages.example.com/artifactory/api/pypi/python/simple
```

| Key | Description |
|---|---|
| `name` | A unique label for the registry. Used in logs. |
| `ecosystem` | `npm` or `pypi`. No other ecosystem is supported. |
| `endpoints[].url` | The base URL PMG matches requests against. Must be absolute, must use `http` or `https`, and must not carry credentials, a query string, or a fragment. |

### Which hosts PMG intercepts

PMG intercepts traffic only to the exact host in an endpoint URL. If you configure `packages.example.com`, PMG does not intercept `cdn.packages.example.com` or any other subdomain.

This is different from PMG's built-in registries, which also cover their known subdomains automatically.

PMG never decrypts traffic to a host it does not know, and a subdomain of a configured custom endpoint counts as unknown. That traffic goes through an ordinary encrypted tunnel; PMG cannot see the request path or body. PMG records the host in the audit log as a Host Observation event, so you can see which outside hosts your build reached.

### How PMG matches a request

PMG decides whether to intercept a connection in two steps.

At CONNECT time, before any request path is visible, PMG checks the hostname alone. PMG decrypts the connection when the hostname matches a custom endpoint you configured. PMG also decrypts it for a built-in registry host, or one of its subdomains, that PMG analyzes. A few built-in hosts are recognized but not analyzed, for example GitHub's npm registry mirror and the PyPI test instances. PMG tunnels their traffic without decrypting it.

After decryption, PMG matches each request against an endpoint by:

1. Origin: scheme, exact host, and effective port. An omitted port defaults to 80 for `http` and 443 for `https`.
2. Base path: the request path must equal the endpoint's base path, or start with the base path followed by `/`.

The base path check works on whole path segments, not on raw string prefixes. An endpoint base of `/repository/npm` matches `/repository/npm` and `/repository/npm/lodash`. It does not match `/repository/npm-private`, because `npm-private` is a different segment, not a continuation of `npm`. Query strings and fragments never affect the match.

When more than one endpoint could match a request, the endpoint with the longest matching base path wins.

A request on a configured host whose path matches no endpoint passes through unchanged. Because the host matched a configured endpoint at CONNECT time, PMG already decrypted this traffic. PMG does not analyze the request, and does not block it.

### npm registry requirements

A custom npm endpoint must serve a standard packument, full or abbreviated, the same JSON document `npm install` itself downloads. PMG reads only these fields:

- `name`
- `versions.*.name`
- `versions.*.version`
- `versions.*.dist.tarball`

PMG ignores every other field, except when dependency cooldown changes what it reads and writes.

When [dependency cooldown](./dependency-cooldown.md) is enabled, PMG requests the full packument from the endpoint. It reads the `time` object to check each version's publish date. An endpoint that can only serve abbreviated metadata gets no cooldown protection, because abbreviated metadata omits `time`. When cooldown strips a version, PMG rewrites `versions`, `time`, and `dist-tags` in the response.

### PyPI registry requirements

A custom PyPI endpoint must serve the [Simple Repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/), either the PEP 691 JSON format or the PEP 503 HTML format.

PMG recognizes a project's index page, the page listing all of one project's files, when the configured base URL itself ends in `/simple`. With a base of `.../artifactory/api/pypi/python/simple`, a request for `.../artifactory/api/pypi/python/simple/requests/` is recognized as the index page for `requests`.

Some bases do not end in `/simple`. For example, a base might point at a mirror's API root above the Simple mount. PMG still recognizes the relative layouts `/simple/<project>/` and `/pypi/<project>/json` beneath a base like this. A Simple API exposed some other way, such as a root-mounted index or a `+simple` convention, gets no project-page discovery and no dependency cooldown. PMG still analyzes distribution file downloads under that base, because it identifies them from their filename rather than from the page that links to them.

PMG identifies a distribution file, a wheel or an sdist, by its standard filename, at any depth below the configured base.

### Artifacts on a different host

Some registries serve package metadata from one host and the actual files from another, or from a different path prefix on the same host. PMG never treats a link or a redirect target as a reason to trust a new host. It analyzes an artifact from another host only if that host is itself a configured endpoint.

If your artifacts live on a separate host or prefix, add that host or prefix as its own endpoint.

### How PMG identifies a package from a URL

PMG prefers to read a package's name and version directly from the request URL: the npm tarball path shape, or the PyPI distribution filename. This covers most registries and needs no extra state.

Some registries use opaque download URLs that carry no name or version, for example `.../download/opaque?id=42`. For a URL like this, PMG remembers the name and version that a metadata response advertised for it. PMG reuses that mapping when the download request arrives. The mapping is scoped to one registry, expires after 15 minutes, and holds at most 10,000 entries.

A URL that PMG can already identify from its own shape always wins. Registry metadata can never override an identity PMG derived from the URL itself.

### Public packages only

PMG's malware database covers public packages. A package PMG cannot find there, including any private package on a custom registry, keeps the current behavior: PMG allows it.

Custom registry support targets public packages served through an internal mirror or a compatible registry proxy. PMG does not promise compatibility with any specific vendor. It requires only that the registry serve the standard protocol, npm packument or PyPI Simple API, beneath the URL you configure.

### Credentials

PMG does not store, inject, or log registry credentials. Keep credentials where your package manager already expects them: npm's `.npmrc`, Yarn's or pnpm's own config, or pip's, Poetry's, or uv's configuration.

### Plain HTTP endpoints

PMG accepts an `http://` endpoint and prints one startup warning for it. Use `https://` where you can. Plain HTTP traffic is visible to anyone on the network path between the package manager and the registry.

### Troubleshooting

**A shallow base path matches more than expected.** The base path check works on whole segments, so a shallow base also matches sibling repositories under the same prefix. A base of `/repository` also matches `/repository/npm-private` and `/repository/pypi-internal`. Configure the base as deep as your registry's actual mount point, not its parent.

**PyPI project pages are not recognized.** PMG only recognizes a bare project-name request as an index page when the configured base itself ends in `/simple`. Your base might sit above the `/simple` mount, for example `.../python-remote` instead of `.../python-remote/simple`. Add the `/simple` segment to the endpoint URL, or add a second endpoint that includes it.

**An artifact is never analyzed.** Check the audit log for a Host Observation event on the artifact's host. If one appears, add that host, or the deeper prefix the artifact lives under, as its own endpoint. See "Artifacts on a different host" above.

**Configuration fails to load.** PMG validates `proxy.registries` at startup and rejects the whole configuration file on any of these:

- A `name` that is empty, whitespace-only, or has leading or trailing whitespace
- A duplicate `name`
- An `ecosystem` other than `npm` or `pypi`
- A registry with no `endpoints`
- A URL that is relative, invalid, or uses a scheme other than `http` or `https`
- A URL that includes credentials, a query string, or a fragment
- Two endpoints that normalize to the same origin and base path

The error names the registry and the specific problem. An empty or whitespace-only name has no registry name to report, so the error names the entry's position in the list instead, for example `proxy.registries[0]`. Fix that entry and restart PMG.

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
