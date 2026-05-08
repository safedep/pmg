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
| `poetry`        | ✅      |
