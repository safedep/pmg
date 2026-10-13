# Certificate Authority

PMG inspects package downloads through a transparent HTTPS proxy. To read encrypted traffic
it acts as a man in the middle (MITM), signing a short lived certificate for each registry
host with its own Certificate Authority (CA). Package managers must trust that CA for the
interception to work.

## Default behavior: ephemeral CA via environment variables

By default PMG generates a CA for each run and injects it into the package manager process
through environment variables such as `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, and `PIP_CERT`. The CA lives only for the duration of that run and is
discarded afterwards.

This requires no setup and covers the common cases: npm, pip, and Go on Linux.

## When you need a persistent CA trusted by the OS

Environment variable injection does not reach tools that consult only the operating system
trust store. The most important case is Go on macOS and Windows.

### Go on macOS and Windows

Go's TLS stack on macOS and Windows validates against the platform verifier
(Security.framework on macOS, CryptoAPI on Windows). Go 1.27 and later use `SSL_CERT_FILE`
instead when it is set. The PMG bundle does not hold the roots that only the OS store holds,
such as a corporate CA. PMG therefore sets `GODEBUG=x509sslcertoverrideplatform=0` for `pmg go`
and in `pmg proxy env`, so go uses the OS store on every version. If you set
`x509sslcertoverrideplatform` in `GODEBUG`, PMG keeps your value. With `1`, Go 1.27 and later
read `SSL_CERT_FILE`, but PMG still requires the OS store to trust the CA.

Run `pmg setup cert install` before you use Go through PMG. `pmg go` stops with instructions,
and the persistent proxy does not decrypt Go traffic, until the OS store trusts the CA. On
Linux, Go honors `SSL_CERT_FILE`, so the default behavior already covers it.

PMG counts the CA as trusted only when the OS store trusts the exact certificate that PMG signs
with. Another certificate with the same name does not count. `pmg go`, the persistent proxy,
`pmg setup cert install`, `pmg setup cert status` and `pmg setup doctor` all apply this check.
On macOS PMG compares the certificate hash in each keychain and runs `security verify-cert`. On
Windows it looks up the certificate thumbprint in each Root store.

### Install the persistent CA

For tools that read only the OS store, install a single persistent PMG CA into the OS trust
store. This also avoids regenerating a CA on every run.

```bash
# User scope (no sudo). macOS login keychain / Windows CurrentUser\Root.
pmg setup cert install

# System scope (all users). Run as your normal user, NOT with sudo.
# PMG prompts for sudo only for the trust store write (macOS / Linux).
# Windows: run from an elevated prompt.
pmg setup cert install --system

# Linux only: system scope for a root proxy daemon (pmg proxy start --enforce).
# Run as root. The keypair goes to the system config directory, root-owned.
sudo pmg setup cert install --system

# Inspect presence, trust scope, expiry, and drift.
pmg setup cert status

# Rotate (regenerate and trust again).
pmg setup cert install --force

# Remove from the trust store. --purge also deletes the keypair on disk.
pmg setup cert uninstall [--system] [--purge]
```

## Trust scopes

`pmg setup cert install` installs at user scope by default, which needs no elevation. Pass
`--system` to install for all users. Run the command as your normal user, not under sudo.
PMG generates a keypair owned by you and elevates only the trust store write, prompting
for sudo on macOS and Linux. On Windows, run it from an elevated prompt. A user-scope
install under sudo is refused. The keypair would land in root's config directory, which
your unprivileged proxy does not read and, as a non-root process, cannot read.

On Linux, `sudo pmg setup cert install --system` is the one case where root is intended. It
writes a separate keypair to the system config directory (`/etc/safedep/pmg`). The
certificate is world-readable. The private key is root-owned with mode `0600`, so only a
root process can sign with it. That process is the proxy daemon that `pmg proxy start
--enforce` runs as root. It loads the keypair from the system directory and never from a
user's home, so it does not depend on any user account. An unprivileged `pmg proxy start`
loads the keypair in your own config directory and never the system one, so no user can
sign with the system CA. See
[persistent-proxy.md](./persistent-proxy.md#kernel-enforcement-linux). `pmg setup cert
status` as root inspects the system keypair when it exists.

macOS and Windows have no enforcing daemon, so nothing reads a system keypair there. An
elevated `--system` install on Windows keeps the keypair in your config directory and writes
only the certificate to `LocalMachine\Root`. `sudo pmg setup cert install --system` on macOS is refused,
like a user-scope install under sudo. Older releases wrote a system keypair on macOS and Windows that
nothing read. `pmg setup doctor` warns when it finds one. As administrator, run
`pmg setup cert uninstall --system --purge` to remove it, then install again.

`pmg setup cert install` removes every certificate with the PMG name from the target store
before it adds the CA. A certificate from a lost or older keypair then does not stay trusted.

| Platform | User scope (default) | System scope (`--system`) |
| --- | --- | --- |
| macOS | login keychain | System keychain (sudo) |
| Windows | `CurrentUser\Root` | `LocalMachine\Root` (admin) |
| Linux | not available, see below | `/usr/local/share/ca-certificates` (Debian, Ubuntu), `/etc/pki/ca-trust` (Fedora, RHEL) or `/etc/ca-certificates/trust-source` (Arch), with sudo |

Linux has no user trust store. Running `pmg setup cert install` without `--system` on Linux
persists the keypair and relies on `SSL_CERT_FILE` injection, which already covers Go on
Linux. Use `--system` to trust the CA for all users.

On Linux the install checks that the system bundle, the file OpenSSL and curl read, holds the
certificate after the trust tool ran, and fails when it does not. `pmg setup cert status` and
the `--enforce` preflight apply the same check, so an anchor file that the trust tool never
read does not count as trusted.

## Storage and security

The CA keypair is stored under PMG's config directory as `ca-cert.pem` (`0644`) and
`ca-key.pem` (`0600`). The private key never leaves disk. Only the public certificate is
installed into the OS trust store, since the trust store cannot hold or return a private key.

The keypair belongs to the account that runs the proxy. The unprivileged proxy must read the
private key it signs with, so the command runs as your normal user and writes to your config
directory. `--system` as a normal user only widens where the public certificate is trusted,
not where the key lives. `--system` as root is the exception above: the key belongs to root,
for the root daemon.

A persistent CA that the OS trusts is sensitive. Anyone who can read `ca-key.pem` can
intercept your TLS traffic for tools that trust the CA. PMG mitigates this with restrictive
file permissions and a clean uninstall path. Reading the key requires local filesystem
access, at which point the host is already compromised.

## Rotation and expiry

The root CA is valid for 10 years. Leaf certificates, one per host, stay short lived (one day)
and are never installed anywhere. A long lived root is standard practice because rotating an
installed, trusted root is disruptive. The root is protected by guarding its key rather than by
frequent rotation.

Rotation is manual. Run `pmg setup cert install --force` to regenerate and trust the CA again.
Both `pmg setup cert status` and `pmg setup doctor` warn when the root is within 30 days of
expiry.

## Drift and diagnostics

`pmg setup cert status` reports whether the keypair is present, which scope trusts it, the
fingerprint, and the expiry. It also flags drift, for example a certificate on disk without its
private key, or a CA that is on disk but not trusted in the OS store.

`pmg setup doctor` includes a CA health check. On macOS and Windows a CA on disk that is not
trusted is reported as a failure, with `pmg setup cert install` as the fix. On Linux it is a
warning, since `SSL_CERT_FILE` injection already covers Go.
