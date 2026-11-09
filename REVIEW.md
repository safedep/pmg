# Review instructions

These instructions apply to code review only. `CLAUDE.md` and `AGENTS.md` hold the rules for the
code. Read them too.

PMG stops malicious packages before they install. A review finds the changes that let a package
install without a block or a prompt, or that give an install more access than the user chose.

## What Important means here

Report a finding as Important when the change does one of these things:

- It breaks behavior that a user or a test depends on.
- It lets a malicious package install without a block or a prompt.
- It widens the file, process or network access of a sandboxed or enforced install.
- It leaks a secret, a token or private data to a log, an event or the cloud.
- It breaks a config file, a flag, a command or the GitHub Action inputs for current users.

Style, names, comments and refactors are Nit at most. Report at most five Nits in one review.

## Always check

1. **Fail-open.** A change in `proxy/`, `analyzer/`, `internal/flows/` or `config/` can let a
   package install when PMG cannot get a verdict. Examples are a timeout, an analyzer error, a
   cache miss, a parse error or an unknown ecosystem. PMG must block or prompt in that case. A
   path that allows the install is Important. A change that lets an environment variable or a user
   config override a managed config in lockdown is also Important.
2. **Proxy flow tests.** A security-sensitive change to the proxy flow needs a new or extended
   `TestCase` in `test/proxye2e/`. This applies to interceptors, cooldown, the malware allow,
   confirm and block decisions, the trusted and insecure bypass, and new controls. A missing case
   is Important.
3. **Sandbox and network policy.** A change in `sandbox/` (Seatbelt on macOS, Bubblewrap and
   Landlock on Linux), `sandbox/profiles/`, `sandbox/presets/`, `proxy/netpolicy/` or
   `internal/netenforce/` can widen access. Examples are a new allowed path, a broader glob, a
   removed mandatory deny, a new allowed host or a fallback that runs without the sandbox. Name the
   access that the change adds. An unexplained widening is Important.
4. **Swallowed errors.** PMG never swallows an error. `_ = f()` that drops an error is a finding.
   An error that the code drops on a block, prompt or sandbox path is Important, because it can
   hide a failed check. Elsewhere it is a Nit. A soft failure logs with `log.Warnf` from
   `github.com/safedep/dry/log`.
5. **User-facing errors.** A CLI error that a user can expect and fix uses `usefulerror` with a
   specific code and a fix. Without it, `ui.ErrorExit` reports the error as `Unknown`. This is a
   Nit.
6. **Acceptance guarantees.** A new user-facing guarantee needs a `.txtar` script under
   `test/acceptance/scripts/` and a row in `test/acceptance/catalog.yaml`. `TestCatalogIntegrity`
   catches a script without a row. It does not catch a guarantee without a script. A missing
   script is a Nit.
7. **Tests.** Tests use `testify`. Use `require` when the test cannot continue, and `assert`
   otherwise. A raw `if` with `t.Errorf` or `t.Fatalf` is a Nit.
8. **Writing.** Comments, messages and docs use ASD-STE100. One sentence holds one idea. A
   semicolon or a colon does not join two clauses. A comment that says what obvious code does is a
   Nit.
9. **Risk answers.** The `Risk` section of the pull request answers the five questions in the
   `Review tiers` section of `CONTRIBUTING.md`. Compare each answer with the diff. A No where the
   diff shows a Yes is Important. A pull request that says Low but changes code other than tests is
   Important. A Yes that does not name the code is a Nit.

## Evidence

A claim about behavior needs a `file:line` citation in the source. Do not infer behavior from a
name. For a fail-open or sandbox finding, show the path from the input to the decision.

## Do not report

CI already checks these. Do not report them, with one exception:

- Never skip a suppression that the pull request adds for a check in this list: a `//nolint`
  directive, a `# zizmor: ignore[...]` comment, a new entry in `.github/zizmor.yml`, a
  `trufflehog:ignore` comment or a `gitleaks:allow` comment. Check that its reason holds. The
  check cannot report what the suppression hides.
- Lint findings from golangci-lint in files that build on Linux. CI lints new lines on
  `ubuntu-latest` only, so a lint-class problem in a `_darwin.go` or `_windows.go` file, or in a
  file with another non-Linux build tag, stays in scope. `errcheck` skips `fmt.Fprint*` to
  `os.Stderr`, `*bytes.Buffer` and `*strings.Builder`. CLAUDE.md requires that check, so an
  unchecked `fmt.Fprint*` to `os.Stderr` stays in scope.
- Test and build failures on Linux and macOS, where CI runs `go test ./...`. On Windows, CI builds
  `main.go` and skips every package whose import path contains `/sandbox`, which includes
  `sandbox/` and `cmd/sandbox`. A Windows-only failure in those packages is in scope.
- Drift between `internal/netenforce/bpf/enforce.bpf.c` and the committed object. CI rebuilds it.
- Workflow security in `.github/`. zizmor checks it.
- A live credential that TruffleHog verifies in CI. TruffleHog does not fail CI on a secret that it
  cannot verify, and CI does not run gitleaks. So any other secret (a private key, an internal
  token, a credential for a service that TruffleHog cannot reach) stays in scope.
- Dependency risk in `go.mod` and `package.json`. vet checks it.

Do not review these files line by line:

- Generated code: `internal/netenforce/bpf/enforce_bpfel.go` and `enforce_bpfel.o`.
- Lockfiles: `go.sum`, `go.work.sum`, `pnpm-lock.yaml`, `mise.lock`.
- Golden files under `sandbox/platform/testdata/` and `internal/ghasummary/testdata/`. Review the
  code change that made them. Report a golden diff only when it shows wider sandbox access.
