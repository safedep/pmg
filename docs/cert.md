# Certificate Authority

PMG inspects package downloads through a transparent HTTPS proxy. To read encrypted traffic
it acts as a man-in-the-middle (MITM), signing a short-lived certificate for each registry
host with its own Certificate Authority (CA). Package managers must trust that CA for the
interception to work.

## Default behavior: per-run CA via environment variables

By default PMG generates a CA on the fly for each run and injects it into the package manager
process through environment variables such as `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, and `PIP_CERT`. The CA lives only for the duration of that run and is
discarded afterwards.

This requires no setup and covers the common cases: npm, pip, and Go on Linux.

## When you need a persistent, OS-trusted CA

Environment-variable injection does not reach tools that consult only the operating system
trust store. The most important case is Go on macOS and Windows. Go's TLS stack on those
platforms ignores `SSL_CERT_FILE` and validates against the platform verifier
(Security.framework on macOS, CryptoAPI on Windows). On Linux, Go honors `SSL_CERT_FILE`, so
the default behavior already covers it.

For those cases you can install a single persistent PMG CA into the OS trust store. This also
avoids regenerating a CA on every run.

```bash
# User scope (no sudo). macOS login keychain / Windows CurrentUser\Root.
pmg setup cert install

# System scope (all users). Needs elevation.
sudo pmg setup cert install --system   # macOS / Linux
# Windows: run from an elevated prompt: pmg setup cert install --system

# Inspect presence, trust scope, expiry, and drift.
pmg setup cert status

# Rotate (regenerate and re-trust).
pmg setup cert install --force

# Remove from the trust store. --purge also deletes the on-disk keypair.
pmg setup cert uninstall [--system] [--purge]
```

## Trust scopes

`pmg setup cert install` installs at user scope by default, which needs no elevation. Pass
`--system` to install machine-wide, which requires sudo (macOS, Linux) or an elevated prompt
(Windows).

| Platform | User scope (default) | System scope (`--system`) |
| --- | --- | --- |
| macOS | login keychain | System keychain (sudo) |
| Windows | `CurrentUser\Root` | `LocalMachine\Root` (admin) |
| Linux | not available, see below | `/usr/local/share/ca-certificates` or `/etc/pki/ca-trust` (sudo) |

Linux has no per-user trust store. Running `pmg setup cert install` without `--system` on
Linux persists the keypair and relies on `SSL_CERT_FILE` injection, which already covers Go
on Linux. Use `--system` for machine-wide trust.

## Storage and security

The CA keypair is stored under PMG's config directory as `ca-cert.pem` (`0644`) and
`ca-key.pem` (`0600`). The private key never leaves disk. Only the public certificate is
installed into the OS trust store, since the trust store cannot hold or return a private key.

A persistent, OS-trusted MITM CA is sensitive. Anyone who can read `ca-key.pem` can intercept
your TLS traffic for tools that trust the CA. PMG mitigates this with restrictive file
permissions and a clean uninstall path. Reading the key requires local filesystem access, at
which point the host is already compromised.

## Rotation and expiry

The root CA is valid for 10 years. Per-host leaf certificates remain short-lived (one day) and
are never installed anywhere. A long-lived root is standard practice because rotating an
installed, trusted root is disruptive. The root is protected by guarding its key rather than by
frequent rotation.

Rotation is user-initiated. Run `pmg setup cert install --force` to regenerate and re-trust the
CA. Both `pmg setup cert status` and `pmg setup doctor` warn when the root is within 30 days of
expiry.

## Drift and diagnostics

`pmg setup cert status` reports whether the keypair is present, which scope trusts it, the
fingerprint, and the expiry. It also flags drift, for example a certificate on disk without its
private key, or a CA that is on disk but not trusted in the OS store.

`pmg setup doctor` includes a CA health check. On macOS and Windows an on-disk CA that is not
trusted is reported as a failure, with `pmg setup cert install` as the fix. On Linux it is a
warning, since `SSL_CERT_FILE` injection already covers Go.
