# Certificate Authority

PMG inspects package downloads through a local HTTPS proxy.
It signs a short lived certificate for each registry host with its own Certificate Authority (CA).
Package managers must trust that CA for interception to work.

## Default behavior: ephemeral CA via environment variables

By default, PMG generates an in-memory CA for each run.
It writes a public CA bundle and passes its path to the package manager.
Variables include `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `PIP_CERT`.
PMG does not persist the ephemeral private key.
This needs no setup for common clients such as npm, pip, and Go on Linux.

PMG replaces existing values of these tool-specific CA variables.
It merges the PMG CA with the first readable bundle selected from `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, and known system bundle paths.
It does not export roots held only in a native keychain or Windows Root store.
If no readable bundle exists, the generated file contains only the PMG CA.
A client that replaces its roots with that file can reject other HTTPS connections.
For corporate roots, supply a PEM bundle that contains those roots through `SSL_CERT_FILE`
before starting PMG. A separate `PIP_CERT` or `NODE_EXTRA_CA_CERTS` value is not merged automatically.

For proxied Cargo runs, PMG also sets `CARGO_HTTP_CHECK_REVOKE=false`.
This disables Windows schannel revocation checks for that run's Cargo HTTPS traffic.
See [Windows Support](windows-support.md).

## When you need a persistent CA trusted by the OS

Some tools consult the OS trust store instead of the injected bundle.
Go on macOS and Windows is the main case.
Install a persistent CA only where you need it.

### Go on macOS and Windows

Go uses the platform verifier on macOS and Windows.
Go 1.27 and later can use `SSL_CERT_FILE` instead when it is set.
That bundle can omit corporate roots held only in the OS store.
PMG therefore supplies `GODEBUG=x509sslcertoverrideplatform=0` to guarded commands
and non-enforcing `pmg proxy env` clients, including nested Go programs.
PMG preserves an explicit value for this setting in `GODEBUG`.
With `1`, Go 1.27 and later use `SSL_CERT_FILE`, but PMG still requires OS trust.

Run `pmg setup cert install` as the account that runs Go.
`pmg go` fails until a usable CA has OS trust.
A persistent proxy checks trust at startup and omits Go interception when trust is missing.
After installing or changing the CA, restart that proxy.
Go on Linux uses the injected `SSL_CERT_FILE` without this OS setup.

PMG checks the exact certificate it signs with, not just the CA name.
On macOS it compares keychain certificate hashes and asks `security verify-cert` to check trust.
On Windows it checks the thumbprint in each Root store.

### Install the persistent CA

```bash
# User scope on macOS or Windows. Run from your own account.
pmg setup cert install

# Trust the user's CA machine-wide on macOS or Linux.
# Run as the user. PMG elevates the trust-store operation.
pmg setup cert install --system

# Linux root daemon with kernel enforcement.
sudo pmg setup cert install --system

# Inspect the active account's CA.
pmg setup cert status

# Rotate that CA. Restart proxies that use it afterward.
pmg setup cert install --force
```

On Windows, `--system` requires an elevated terminal.
Elevation through a different administrator account creates that account's keypair.
It does not create a keypair for the standard user who requested elevation.
For per-user Go protection, use user scope from the account that runs Go.

On macOS, trust changes can open a GUI authentication dialog, including under sudo.
Use an interactive GUI session. SSH, MDM, and CI sessions can wait for authorization
or fail because no dialog is available. User-scope installation can also request confirmation.

To remove trust and optionally delete the selected account's keypair, run these before uninstalling PMG.

```bash
pmg setup cert uninstall
pmg setup cert uninstall --system --purge
```

Select the same trust scope and key owner used at installation.
For a Linux enforcing daemon, use `sudo pmg setup cert uninstall --system --purge`.
`pmg setup remove` and the MDM uninstaller do not remove OS certificate trust.
Removing PMG or its configuration first can leave a trusted root behind.

## Trust scopes

User scope is the default. It needs no administrator token, but macOS can request GUI consent.
A user-scope install under sudo is refused.
An unprivileged proxy reads its own account's keypair, not root's keypair.

| Platform | User scope | System scope |
|---|---|---|
| macOS | Login keychain | System keychain |
| Windows | `CurrentUser\Root` | `LocalMachine\Root` |
| Linux | No user OS store | The distribution's CA anchor directory |

A normal user's `--system` install widens trust but keeps the keypair in that user's config directory.
Every account that uses the system store then trusts a CA whose key that user holds.
Prefer user scope on shared hosts where the OS supports it.

On Linux, a privileged `--system` install writes the keypair to `/etc/safedep/pmg`.
The enforcing root daemon reads this keypair. An unprivileged proxy does not.
The certificate is readable by other accounts under a default umask.
A restrictive root umask can reduce its permissions. The private key has mode `0600` or tighter.
See [Kernel enforcement](persistent-proxy.md#kernel-enforcement-linux).

macOS and Windows have no enforcing daemon that reads a system keypair.
An elevated Windows install keeps the key in the running account's config directory.
macOS refuses `sudo pmg setup cert install --system`.
Older system keypairs on these platforms can leave machine trust behind.
Doctor reports them. Remove them with elevated `pmg setup cert uninstall --system --purge`
on Windows, or with sudo on macOS, then install from the intended user account.
Use a GUI session for the macOS cleanup.

A new CA installation removes PMG certificates from the target store before adding its CA.
An install that finds its exact CA already trusted returns without this cleanup.
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
To restore the root daemon's CA, run `sudo pmg setup cert install --system`, then restart it.

Linux user-scope installation persists a keypair but adds no OS trust.
It relies on bundle injection. System installation needs `update-ca-certificates` or `update-ca-trust`.
PMG uses the matching Debian/Ubuntu, Fedora/RHEL, or Arch anchor directory.
It checks the readable system bundle after the update tool runs.
If no known system bundle exists, PMG cannot verify the bundle and uses the anchor as its trust signal.

## Storage and security

PMG stores `ca-cert.pem` and `ca-key.pem` in the account's config directory.
New files request modes `0644` and `0600`, subject to the umask.
PMG installs only the public certificate in the OS store.
The proxy reads the private key from disk and uses it in memory.

| Platform | User config directory |
|---|---|
| macOS | `~/Library/Application Support/safedep/pmg` |
| Linux | `$XDG_CONFIG_HOME/safedep/pmg`, or `~/.config/safedep/pmg` |
| Windows | `%APPDATA%\safedep\pmg` |

`PMG_CONFIG_DIR` replaces this user directory. `pmg setup info` shows the installed CA directory.
Root's Linux enforcing keypair remains under `/etc/safedep/pmg`.

Any process that runs as the key owner can read `ca-key.pem`, including an install script.
The CA has no hostname constraint and can sign for any host.
Clients that trust it can accept those certificates. Not every client uses the OS trust store.
Sandboxing is off by default. The built-in profiles do not specifically deny this private key.
If untrusted code might have read it, rotate the CA and check residual macOS user trust.

## Rotation and expiry

The persistent root is valid for 10 years. Host certificates are valid for one day.
Host certificates are not installed in the OS store.
Run `pmg setup cert install --force` to replace the root, then restart every proxy that uses it.
Use `--system` and the correct account for a system CA.
Refresh exported trust variables if their paths changed.
Stop a Windows foreground proxy with Ctrl+C, then start it again.

If an ordinary proxy cannot load a usable persisted CA, it generates an ephemeral CA.
The warning appears only in diagnostic logs. A failed load does not repair permissions or corruption.
Go on macOS/Windows and enforcing daemons have stricter trust requirements and can fail instead.
Use `pmg --debug ...` or `--log <file>` to diagnose a fallback.

`pmg setup cert status` warns within 30 days of expiry.
Doctor gives that expiry warning only when the CA is trusted.
An untrusted CA can receive only the trust warning or failure.

## Drift and diagnostics

`pmg setup cert status` reports presence, trust scopes, fingerprint, and expiry.
Drift includes a certificate without its private key.
An untrusted CA receives a separate note when no higher-priority drift or expiry note applies.
On Linux, lack of OS trust can be expected for user scope.
Health findings alone do not make this command fail. Inspection or output errors can fail it.

`pmg setup doctor --json` includes the `ca-cert` check.
Doctor fails for an unusable or untrusted CA on macOS and Windows.
On Linux, a usable user CA without OS trust is a warning.
Other doctor checks can also make its exit status nonzero.
