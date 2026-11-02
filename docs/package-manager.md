# Steps to introduce a new Package Manager

Use this checklist for a new client or ecosystem.
A client in an existing ecosystem can reuse its registry handlers.
A new ecosystem needs its own interception path.

1. Create and register the command.
   Add a constructor under `cmd/` and register it with `cmd.AddCommand` in `main.go`.
   Package executors belong under `cmd/executors/` with parsers in `packagemanager/*_executor.go`.
   Set `DisableFlagParsing: true` and pass raw arguments to `flows.RunProxy`.
   Follow the current error pattern in [cargo.go](../cmd/cargo/cargo.go).
   Keep the binary name, `Name()`, skip-command key, and sandbox policy key consistent.

2. Define the package-manager implementation and defaults.
   Implement `PackageManager` in the flat `packagemanager/` package.
   Use `Default<Name>PackageManagerConfig()` in `npm.go`, `pypi.go`, or a new ecosystem file.
   For a new PyPI client, implement `pypiCommandParser` and register it in `NewPypiPackageManager`.

3. Implement conservative command parsing.
   Mark only commands known to perform no downloads as `IsKnownNonDownloadCommand`.
   Unknown subcommands must remain possible downloads.
   This classification controls both `install_only` bypass and sandbox activation.
   Recognize manifest commands such as build, test, and run when they can fetch dependencies.
   Use `FirstNonFlagArg` with the client's value-taking global flags.
   A flag value must not become the subcommand.
   Extract exact version pins separately from ranges for cooldown reporting.
   Test multiple targets, missing values, attached and separate flag values, manifests, and unknown commands.

4. Add interception for a new ecosystem.
   Add registry, URL-parser, and applicable cooldown handlers under `proxy/interceptors/`.
   Register the ecosystem in `CreateInterceptor` and `SupportedEcosystems` in `factory.go`.
   Add registry catalog and config validation support.
   Resolve metadata and artifact URLs to the same package identity.
   Test custom endpoints, redirects, authentication, trusted packages, and cooldown.
   Reserve `Analyze: false` for endpoints intentionally excluded from analysis.
   Authenticated registries can require decryption and credentials for analysis or publish-time lookup.
   Test per-command and persistent-proxy paths.

5. Integrate client routing and trust.
   Review [proxy_env.go](../packagemanager/proxy_env.go) for client-specific settings and system-trust mode.
   Check whether the client overrides proxy variables through its own configuration.
   Test its CA variables, registry protocols, and nested invocations.
   Use `ProxyRoutingProvider` when the client needs extra routing, as Go does.
   Document command-line, user-config, protocol, and cache limits.
   Environment routing remains advisory without kernel enforcement.

6. Register the sandbox policy.
   Add a leaf profile under `sandbox/profiles/` and a `sandbox.policies.<name>` entry in `config/config.template.yml`.
   An enabled sandbox fails when the policy is missing.
   Inherit the applicable ecosystem base and grant only required filesystem access.
   Review credential files and environment tokens for this client.
   Do not automatically allow a publish token.
   Cargo intentionally scrubs its tokens.
   Extend the [environment contract](../sandbox/profiles_env_test.go) where applicable.
   Check macOS Seatbelt and Linux Landlock behavior.
   Test Bubblewrap where supported.
   Bubblewrap currently rejects `network_via_proxy_only`.

7. Register setup integration and reporting.
   Add stable clients to `PackageManagers` in `DefaultConfig()` in `internal/alias/alias.go`.
   This list drives shell aliases, user PATH shims, system shims, and doctor checks.
   Keep experimental clients opt-in and list them under Experimental in the README.
   Add command analytics following the existing tracking functions.
   Review `mapPackageManager` in `internal/audit/cloud_translate.go`.
   Add an API enum first if the client needs a distinct cloud value and none fits.
   Related executors can share the client-family value.
   Add mapping tests.
   The current mapping reports Go and Cargo as unspecified.

8. Update the relevant documentation and CI.
   Update support lists and usage examples in the README.
   Review [proxy support](proxy-mode.md), [sandbox profiles](sandbox.md), and [Windows limits](windows-support.md).
   Update only the surfaces the client changes.
   Add setup and test steps to the `e2e-test` job in `.github/workflows/pmg-e2e.yml`.
   Update its alias and shim expectations.
   Add matching Windows steps when the tool supports Windows.

9. Verify protection with the existing test suites.
   Add a `TestCase` in [test/proxye2e](../test/proxye2e) for security-sensitive interception changes.
   Use the current mock registry and analyzer harness.
   A user-facing guarantee also needs an acceptance `.txtar` script and a `catalog.yaml` entry.
   Follow [test/acceptance/README.md](../test/acceptance/README.md).
   Update tool setup in `acceptance.yml` when required.
   Do not create new harness scaffolding for a supported case.
   Verify single and multiple installs, manifests, lockfiles, suspicious decisions, malicious blocks, and cooldown.
   Run with `--sandbox` and check the actual policy and credential boundaries.

10. Check setup and consistency.
    Verify that aliases and PATH shims invoke PMG.
    Windows uses shims without shell aliases.
    Run setup checks with a scratch `HOME` and isolated config paths, or use the setup acceptance scripts.
    `pmg setup install` changes shell startup files as well as shims.
    Check naming, errors, logs, and output against the existing clients.
    Run the required build and tests from [CLAUDE.md](../CLAUDE.md).
