# Development

Start with [CONTRIBUTING.md](../CONTRIBUTING.md) for setup, normal builds, tests, and DCO sign-off.
Follow [AGENTS.md](../AGENTS.md) for code and writing rules.
Use the tool versions in [mise.toml](../mise.toml) and [.tool-versions](../.tool-versions).
Install Lefthook and run `lefthook install` to enable repository hooks.
The pre-commit hook runs the linter and the secret scan.
The pre-push hook runs the tests.
The secret scan runs when `gitleaks` is installed.
A missing `gitleaks` prints a warning instead of blocking every commit.

- [User Interface](./ui.md)
- [Steps to introduce a new Package Manager](./package-manager.md)
- [System install](./system-install.md) (operator guide)
- [Proxy library](./proxy.md) and [proxy examples](../examples/proxy/README.md)
- [Landlock internals](./sandbox-landlock.md) and [profile authoring](../sandbox/profiles/README.md)
- [Acceptance suite](../test/acceptance/README.md)
- [MDM development and tests](../scripts/mdm/README.md#development)
- [Binary synchronization](../scripts/sync-binaries/README.md)

Use an isolated configuration for local development commands.
A development version does not disable telemetry or cloud setup.
For a POSIX shell, create scratch paths before you run the binary.

```sh
pmg_dev_dir=$(mktemp -d)
export PMG_CONFIG_DIR="$pmg_dev_dir/config"
export PMG_CACHE_DIR="$pmg_dev_dir/cache"
export PMG_DISABLE_TELEMETRY=true
export PMG_CLOUD_ENABLED=false
mkdir -p "$PMG_CONFIG_DIR" "$PMG_CACHE_DIR"
make all
./bin/pmg version
```

These exports also apply to `make test` and the pre-push hook in this shell.
Some tests then fail.
Run `unset PMG_CONFIG_DIR PMG_CACHE_DIR PMG_DISABLE_TELEMETRY PMG_CLOUD_ENABLED` before you run the tests.

A [globally managed config](config.md#globally-managed-configuration) replaces the config file in this directory.
Lockdown disables configuration environment overrides.
Check `pmg setup info --json` before an experiment.
Setup also writes outside the isolated paths.
It changes shell startup files and writes shims to the user data directory.
On Windows, it changes the user `PATH`.
On macOS or Linux, set `HOME` to a scratch directory and unset `XDG_DATA_HOME` before you test setup.

On Windows, keep LF line endings when you clone.
For example, use `git clone -c core.autocrlf=false <repository-url>`.
For an existing checkout, run `git config core.autocrlf false`.
The next commands discard uncommitted changes.
Run `git rm -rq --cached .` and `git reset --hard` to check out the files again with LF.
The normal `make test` target includes sandbox packages that Windows CI excludes.
Run the Windows CI commands in PowerShell.

```powershell
go build -o pmg.exe main.go
go test -count=1 -v $(go list ./... | Where-Object { $_ -notmatch '/sandbox' })
```

Choose tests for the component you change.

| Change | Check |
| --- | --- |
| Security-sensitive proxy flow | Add a `TestCase` to [test/proxye2e](../test/proxye2e). |
| User-facing guarantee | Add an acceptance `.txtar` script and a `catalog.yaml` row. See the [suite contract](../test/acceptance/README.md). |
| Action JavaScript | `node --test action/lib.test.js action/main.test.js action/post.test.js` |
| Sandbox containment | `make sandbox-e2e` with Node and a supported driver. This uses seeded environment canaries. |
| Kernel enforcement | `make ebpf-e2e` on Linux with root, BTF, and cgroup v2 |
| Enforcement BPF source | `make bpf` with clang 18 and LLVM 18. CI compares the committed object. |
| Sandbox render output | `UPDATE_GOLDEN=1 go test ./sandbox/platform` on the corresponding OS. Review each changed golden. |
| Job-summary output | `go test ./internal/ghasummary -update`. Review the changed goldens. |
| MDM scripts or generated installers | Follow [MDM development](../scripts/mdm/README.md#development), including generator `--check` commands. |

In CI, some security integration tests fail instead of skipping when their sandbox or enforcement tool is missing.
Unix-only tests need an appropriate build constraint.
The filename suffix `_unix_test.go` alone does not select a Go operating system.

Put `--debug` and `--log` before the package-manager command when debugging.
Set `PMG_SANDBOX_DEBUG_LOG_SEATBELT_POLICY_CONTENT` to a scratch file path to retain generated Seatbelt policy text.
Landlock uses a temporary helper policy file.
`PMG_KEEP_POLICY` suppresses helper deletion, but outer cleanup can still remove the file after a normal run.
Do not depend on that variable for a permanent policy dump.

Dependency changes have separate age gates.
vet's dependency-cooldown control reports a version younger than 2 days as high severity.
The [vet policy](../.github/vet/policy.yml) fails the check on each high finding.
[pnpm-workspace.yaml](../pnpm-workspace.yaml) sets `minimumReleaseAge` to 4320 minutes.
Treat suppressions as reviewed policy exceptions.
