# Proxy Mode

PMG supports proxy based interception as an alternative to the current optimistic dependency resolution. When enabled:

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
  enabled: true
```

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable proxy-based interception. When `false`, PMG falls back to guard-based analysis. |
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

### CLI flags

Use `--proxy-mode` to override `proxy.enabled` at runtime.

### Environment variables

| Variable | Description |
|---|---|
| `PMG_PROXY_ENABLED` | Override `proxy.enabled` |
| `PMG_PROXY_INSTALL_ONLY` | Override `proxy.install_only` |

Legacy variables `PMG_PROXY_MODE` and `PMG_PROXY_INSTALL_ONLY` (for the old flat config keys) are still supported when the `proxy:` section does not exist in the config file.

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

How it differs from npm/PyPI:

- The module proxy host comes from the effective `GOPROXY` (including
  `go env -w` values), not a fixed registry. PMG intercepts whatever HTTPS
  proxies are configured and rewrites the child's `GOPROXY` to a fail-closed,
  comma-joined list: `direct` is removed (a module PMG cannot inspect fails
  instead of silently bypassing analysis) and pipe separators collapse to
  comma so a block is terminal.
- Malware analysis and dependency cooldown run on the `.zip` source download —
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

## References

- [Persistent Proxy Mode](./persistent-proxy.md)
