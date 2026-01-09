# Proxy Mode

PMG supports an experimental proxy based interception as an alternative to the current optimistic dependency resolution. When enabled via `--experimental-proxy-mode` flag:

- PMG starts a micro-proxy server on a random localhost port
- Run `npm` and other supported package managers configured to use the proxy
- Intercept package registry requests and analyze packages as they are downloaded
- Block malicious packages and allow trusted packages to be installed

## Usage

```bash
pmg --experimental-proxy-mode npm install lodash
```

## Configuration

To permanently enable proxy mode, add the following to your `config.yml` file:

```yaml
experimental_proxy_mode: true
```

## Supported Package Managers

| Package Manager | Status    |
| --------------- | --------- |
| `npm`           | ✅ Active  |
| `npx`           | ✅ Active |
| `pnpx`          | ✅ Active |
| `pnpm`          | 🕒 Planned |
| `yarn`          | 🕒 Planned |
| `bun`           | 🕒 Planned |
| `pip`           | 🕒 Planned |
| `uv`            | 🕒 Planned |
| `poetry`        | 🕒 Planned |
