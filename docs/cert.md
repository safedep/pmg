# Certificate Authority

PMG inspects package downloads through a local HTTPS proxy. To read encrypted traffic
it acts as a man in the middle (MITM), signing a short lived certificate for each registry
host with its own Certificate Authority (CA). Package managers must trust that CA for the
interception to work.

## Default behavior: ephemeral CA via environment variables

By default PMG generates a CA for each run and injects it into the package manager process
through environment variables such as `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, and `PIP_CERT`. The CA lives only for the duration of that run and is
discarded afterwards.

This requires no setup and covers the common cases: npm, pip, and Go on Linux.

PMG replaces existing values of these tool-specific CA variables.
It merges the PMG CA with the first readable bundle selected from `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, and known system bundle paths.
It does not export roots held only in a native keychain or Windows Root store.
If no readable bundle exists, the generated file contains only the PMG CA.
The same applies when the bundle or the merged file is larger than 10 MiB.
A client that replaces its roots with that file can reject other HTTPS connections.
For corporate roots, supply a full PEM bundle with the public roots and your corporate roots through `SSL_CERT_FILE`
before you start PMG. PMG does not merge a separate `PIP_CERT` or `NODE_EXTRA_CA_CERTS` value.

PMG sets `CARGO_HTTP_CHECK_REVOKE=false` for every proxied run, not only for Cargo runs.
`pmg proxy env` also sets it when the proxy runs without enforcement.
On Windows, this disables schannel revocation checks for Cargo HTTPS traffic.
See [Windows Support](windows-support.md).

## When you need a persistent CA trusted by the OS

Environment variable injection does not reach tools that consult only the operating system
trust store. The most important case is Go on macOS and Windows.
Install a persistent CA only where you need it.

### Go on macOS and Windows

Go's TLS stack on macOS and Windows validates against the platform verifier
(Security.framework on macOS, CryptoAPI on Windows). Go 1.27 and later use `SSL_CERT_FILE`
instead when it is set. The PMG bundle does not hold the roots that only the OS store holds,
such as a corporate CA. PMG therefore sets `GODEBUG=x509sslcertoverrideplatform=0` for every guarded command
and non-enforcing `pmg proxy env` clients, including nested Go programs.
Go then uses the OS store on every version. If you set
`x509sslcertoverrideplatform` in `GODEBUG`, PMG keeps your value. With `1`, Go 1.27 and later
read `SSL_CERT_FILE`, but PMG still requires the OS store to trust the CA.

Run `pmg setup cert install` before you use Go through PMG. `pmg go` stops with instructions,
and the persistent proxy does not decrypt Go traffic, until the OS store trusts the CA.
The persistent proxy checks trust at startup. Restart it after installing or changing the CA. On
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

On Windows, elevation through a different administrator account uses or creates that account's keypair.
It does not create a keypair for the standard user who requested elevation.
For per-user Go protection, use user scope from the account that runs Go.

On macOS, trust changes can open a GUI authentication dialog, including under sudo.
Use an interactive GUI session. SSH, MDM, and CI sessions can wait for authorization
or fail because no dialog is available. User-scope installation can also request confirmation.

When you uninstall, use the scope and account that you used to install.
For a Linux enforcing daemon, use `sudo pmg setup cert uninstall --system --purge`.
`pmg setup remove` and the MDM uninstaller do not remove OS certificate trust.
Removing PMG or its configuration first can leave a trusted root behind.

## Trust scopes

`pmg setup cert install` installs at user scope by default, which needs no elevation. Pass
`--system` to install for all users. Run the command as your normal user, not under sudo.
PMG generates a keypair owned by you and elevates only the trust store write, prompting
for sudo on macOS and Linux. On Windows, run it from an elevated prompt. A user-scope
install under sudo is refused. The keypair would land in root's config directory, which
your unprivileged proxy does not read and, as a non-root process, cannot read.

On Linux, `sudo pmg setup cert install --system` is the one case where root is intended. It
writes a separate keypair to the system config directory (`/etc/safedep/pmg`). The
certificate is world-readable under the default umask. The private key is root-owned with mode `0600` or tighter, so only a
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
nothing read. Its certificate can still be trusted machine-wide, so `pmg setup doctor` warns when it
finds one. To remove it, run `pmg setup cert uninstall --system --purge` from an elevated prompt on
Windows, or with sudo on macOS. Use a GUI session for the macOS cleanup. Then install again.

Prefer user scope on shared hosts where the OS supports it.

An install removes PMG certificates from the target store before adding its CA.
An install that finds its exact CA already trusted returns without this cleanup.
To clean the store in that case, run `pmg setup cert install --force`. This also rotates the CA.
On Linux, removal deletes only PMG's `pmg-proxy-ca.crt` anchor in the detected directory.
A same-name certificate installed elsewhere can remain trusted.
On macOS, user-scope removal deletes keychain certificates but can leave their user trust settings.
A removed certificate can remain trusted when a peer supplies it in a chain.
Rotation is not a complete user-trust cleanup in that case.
To inspect residual settings, export them with `security trust-settings-export <file>`
and compare certificate hashes. `security dump-trust-settings` can omit orphaned entries.

The Linux anchor is shared. A user's new `--system` install can replace a root daemon's CA.
Enforced clients can then fail TLS, and the next daemon start can fail preflight.
On an enforcing host, let the administrator manage system trust.
To restore the root daemon's CA, run `sudo pmg setup cert install --system`.

| Platform | User scope (default) | System scope (`--system`) |
| --- | --- | --- |
| macOS | login keychain | System keychain (sudo) |
| Windows | `CurrentUser\Root` | `LocalMachine\Root` (admin) |
| Linux | not available, see below | `/usr/local/share/ca-certificates` (Debian, Ubuntu), `/etc/pki/ca-trust/source/anchors` (Fedora, RHEL) or `/etc/ca-certificates/trust-source/anchors` (Arch), with sudo |

Linux has no user trust store. Running `pmg setup cert install` without `--system` on Linux
persists the keypair and relies on `SSL_CERT_FILE` injection, which already covers Go on
Linux. Use `--system` to trust the CA for all users.
System installation needs `update-ca-certificates` or `update-ca-trust`.

On Linux the install checks that the system bundle, the file OpenSSL and curl read, holds the
certificate after the trust tool ran, and fails when it does not. `pmg setup cert status` and
the `--enforce` preflight apply the same check, so an anchor file that the trust tool never
read does not count as trusted when a known bundle exists.
If no known system bundle exists, PMG cannot verify the bundle and uses the anchor as its trust signal.

## Storage and security

The CA keypair is stored under PMG's config directory as `ca-cert.pem` and `ca-key.pem`.
New files request modes `0644` and `0600`, subject to the umask.
PMG installs only the public certificate into the OS trust store.
The proxy reads the private key from disk and uses it in memory.

The keypair belongs to the account that runs the proxy. The unprivileged proxy must read the
private key it signs with, so the command runs as your normal user and writes to your config
directory. `--system` as a normal user only widens where the public certificate is trusted,
not where the key lives. Every account that uses the system store then trusts a CA whose key
that user holds. `--system` as root is the exception above: the key belongs to root,
for the root daemon.

Any process that runs as the key owner can read `ca-key.pem`, including an install script.
The CA has no hostname constraint and can sign for any host.
Clients that trust it can accept those certificates. Not every client uses the OS trust store.
Sandboxing is off by default. The built-in profiles do not specifically deny this private key.
If untrusted code might have read it, rotate the CA and check residual macOS user trust.

| Platform | User config directory |
|---|---|
| macOS | `~/Library/Application Support/safedep/pmg` |
| Linux | `$XDG_CONFIG_HOME/safedep/pmg`, or `~/.config/safedep/pmg` |
| Windows | `%APPDATA%\safedep\pmg` |

`PMG_CONFIG_DIR` replaces this user directory. `pmg setup info` shows the installed CA directory.

## Rotation and expiry

The root CA is valid for 10 years. Leaf certificates, one per host, stay short lived (one day)
and are never installed anywhere. A long lived root is standard practice because rotating an
installed, trusted root is disruptive. The root is protected by guarding its key rather than by
frequent rotation.

Rotation is manual. Run `pmg setup cert install --force` to regenerate and trust the CA again.
Restart every proxy that uses it afterward.
Use `--system` and the correct account for a system CA.
Stop a Windows foreground proxy with Ctrl+C, then start it again.

If an ordinary proxy cannot load a usable persisted CA, it generates an ephemeral CA.
The warning appears only in diagnostic logs. A failed load does not repair permissions or corruption.
Go on macOS/Windows and enforcing daemons have stricter trust requirements and can fail instead.
Use `pmg --debug ...` or `--log <file>` to diagnose a fallback.

`pmg setup cert status` warns within 30 days of expiry.
Doctor gives that expiry warning only when the CA is trusted.
An untrusted CA can receive only the trust warning or failure.

## Drift and diagnostics

`pmg setup cert status` reports whether the keypair is present, which scope trusts it, the
fingerprint, and the expiry. It also flags drift, for example a certificate on disk without its
private key.
An untrusted CA receives a separate note when no higher-priority drift or expiry note applies.
On Linux, lack of OS trust can be expected for user scope.
Health findings alone do not make this command fail. Inspection or output errors can fail it.

`pmg setup doctor` includes a CA health check. On macOS and Windows a CA on disk that is not
trusted is reported as a failure, with `pmg setup cert install` as the fix. On Linux it is a
warning, since `SSL_CERT_FILE` injection already covers Go.

`pmg setup doctor --json` includes the `ca-cert` check.
Other doctor checks can also make its exit status nonzero.
