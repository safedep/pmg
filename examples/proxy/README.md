# Proxy Example: HTTPS Logging

This example demonstrates using the PMG proxy server to intercept and log HTTPS requests to package registries.

## Usage

### Build and Run

```bash
cd examples/proxy
go run .
```

### Configure Your Environment

Open a new terminal and configure the proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:8888
export NODE_EXTRA_CA_CERTS=./ca-cert.pem
export SSL_CERT_FILE=./ca-cert.pem
export PIP_CERT=./ca-cert.pem
export REQUESTS_CA_BUNDLE=./ca-cert.pem
```

### Test with Package Managers

Test with `npm`:

```bash
npm --no-cache --prefer-online install express
```

Test with `pip`:

```bash
pip3 index versions requests
```
