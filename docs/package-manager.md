# Steps to introduce a new Package Manager

Use this checklist to add a new package manager or a new ecosystem. Keep changes consistent with existing patterns.
A client in an existing ecosystem, such as npm or PyPI, can reuse its registry handlers.
A new ecosystem needs its own interception path.

1. Create a new CLI command
   - Add a new cmd in `cmd/` (e.g., `cmd/npm/` or `cmd/pypi/`).
   - Follow existing command patterns for the chosen ecosystem.
   - Register the constructor with `cmd.AddCommand` in `main.go`.
   - Set `DisableFlagParsing: true` and pass raw arguments to `flows.RunProxy`.
   - Follow the error pattern in [cargo.go](../cmd/cargo/cargo.go).
   - Package executors belong under `cmd/executors/` with parsers in `packagemanager/*_executor.go`.
   - Keep the binary name, `Name()`, skip-command key, and sandbox policy key consistent.

2. Define Package Manager config
   - Introduce config logic in the flat `packagemanager/` package, for example `npm.go` or `pypi.go`.
     For a new ecosystem, add `packagemanager/<eco>.go`.
   - Use `Default<Name>PackageManagerConfig()` and implement `PackageManager`.
   - Keep interfaces and structs consistent with other managers.
   - Review client routing and CA settings in [proxy_env.go](../packagemanager/proxy_env.go).
     Test registry protocols, nested invocations, and client configuration that overrides proxy variables.
     Use `ProxyRoutingProvider` when extra routing is needed, as Go does.
     Environment routing remains advisory without kernel enforcement.
     Document command-line, client-configuration, and protocol limits.
   - Add a leaf profile under `sandbox/profiles/` and a `sandbox.policies.<name>` entry in `config/config.template.yml`.
     An enabled sandbox fails when the policy is missing.
     Inherit the ecosystem base and grant only required filesystem access.
     Review credential files and tokens. Do not automatically allow publish tokens.
     Extend the [environment contract](../sandbox/profiles_env_test.go) where applicable.
     Check Seatbelt, Landlock, and supported Bubblewrap behavior.
     Bubblewrap currently rejects `network_via_proxy_only`.

3. Implement or update the parser
   - For npm: update the existing parser to support the new manager specifics.
   - For PyPI: implement `pypiCommandParser` and register it in `NewPypiPackageManager`.
   - Ensure it extracts all the required information & matches other parser's structure.
   - Mark only known non-download commands as `IsKnownNonDownloadCommand`.
     Unknown commands must remain possible downloads.
     This classification controls `install_only` bypass and sandbox activation.
     Build, test, and run commands can fetch dependencies.
   - Use `FirstNonFlagArg` with the client's value-taking global flags.
     Extract exact version pins separately from ranges for cooldown reporting.

4. Add proxy interception for a new ecosystem
   - Skip this step for a client in an existing ecosystem.
   - Add registry and URL-parser handlers under `proxy/interceptors/`.
     Add a cooldown handler if cooldown applies.
   - Register the ecosystem in `CreateInterceptor` and `SupportedEcosystems` in `factory.go`.
   - Add registry catalog and config validation support.
   - Resolve metadata and artifacts to the same package identity.
   - Reserve `Analyze: false` for endpoints intentionally excluded from analysis.

5. Add parser tests
   - Create unit tests for the new parser covering:
     - Single dependency
     - Multiple dependencies
     - Edge cases (e.g., missing fields, malformed entries)
     - Missing, attached, and separate flag values
     - Manifest commands and unknown subcommands
   - Test custom endpoints, redirects, authentication, trust, and cooldown in both per-command and persistent-proxy paths.
     Authenticated registries can require decryption and credentials for analysis and publish-time lookups.

6. Register alias
   - In `internal/alias/alias.go`, add the new package manager’s alias to `PackageManagers` in `DefaultConfig()`.
   - Verify default alias and invocation match conventions.
   - This list also drives user PATH shims, system shims, and doctor checks.
     Do not add an experimental, opt-in client to this list.
     List it under Experimental in the README instead.

7. Add analytics
   - Define a new analytics event similar to existing ones.
   - Implement a `Track` function for the event.
   - Invoke tracking in the new package manager cmd.
   - Review `mapPackageManager` in `internal/audit/cloud_translate.go` and add mapping tests.
     Add an API enum first if no existing value fits.
     Related executors can share a client-family value.
     Go and Cargo currently map to unspecified.

8. Update documentation
   - Update the README to list the new supported package manager.
   - Add usage examples consistent with existing examples.
   - Review [proxy support](proxy-mode.md), [sandbox profiles](sandbox.md), and [Windows limits](windows-support.md).
     Update only the surfaces the client changes.

9. Add e2e workflow
   - In `.github/workflows/pmg-e2e.yml`, add setup and test steps to the existing `e2e-test` job.
   - Mirror structure and steps used by other ecosystems.
   - Update alias and shim expectations. Add Windows steps when the tool supports Windows.
   - Add a `TestCase` to the existing [proxy E2E harness](../test/proxye2e) for security-sensitive changes.
   - Add an acceptance `.txtar` script and `catalog.yaml` entry for each user-facing guarantee.
     Follow [the suite contract](../test/acceptance/README.md) and update tool setup in `acceptance.yml` as needed.

10. Verify end-to-end behavior
    - Test the CLI locally for:
      - Single package installation
      - Multiple package installation
      - Suspicious package handling
      - Malicious package blocking
      - Manifests/lockfiles installation flow
      - Cooldown behavior and sandbox policy and credential boundaries with `--sandbox`
      - `pmg setup install` to verify alias is set and works
    - Verify PATH shims too. Windows uses shims without shell aliases.
    - Run setup checks with a scratch `HOME` and isolated config paths, or use setup acceptance scripts.
      Setup changes shell startup files as well as shims.

11. Consistency pass
    - Confirm naming, errors, logs, and UX align with existing ecosystems.
    - Ensure code follows project patterns and is covered by tests.
