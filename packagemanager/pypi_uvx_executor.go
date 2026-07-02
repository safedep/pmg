package packagemanager

import (
	"io"
	"regexp"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/spf13/pflag"
)

// uvxInterpreterRequestRe matches the interpreter requests uv understands as a
// tool command (python, python3, python3.12, pypy, cpython, graalpy, ...). uv
// launches an isolated interpreter for these instead of installing a PyPI
// package, so there is nothing to audit.
var uvxInterpreterRequestRe = regexp.MustCompile(`^(python|cpython|pypy|graalpy)(\d+(\.\d+)?)?$`)

// DefaultUvxPackageExecutorConfig returns the config for the uvx executor.
// uvx is an alias for `uv tool run`: it installs a tool into an ephemeral
// environment and runs it. It shares the PyPI executor machinery but parses
// commands differently (there is no install/list subcommand).
func DefaultUvxPackageExecutorConfig() PypiPackageExecutorConfig {
	return PypiPackageExecutorConfig{
		CommandName: "uvx",
		ImplicitRun: true,
	}
}

// parseUvxCommand handles `uvx [flags] <command> [args...]`.
//
// uvx always runs a tool, so the package(s) to audit are:
//   - the --from <spec> value when provided. In that case the positional
//     <command> is just the executable name within that package, not a package
//     to audit (e.g. `uvx --from httpie http`).
//   - otherwise the first positional argument, since the command name doubles
//     as the package name (e.g. `uvx ruff`).
//   - plus any --with <spec> values, which are extra packages added to the
//     ephemeral environment.
func (p *pypiPackageExecutor) parseUvxCommand(command Command, args []string) (*ParsedCommand, error) {
	if len(args) == 0 {
		return &ParsedCommand{Command: command}, nil
	}

	flagSet := pflag.NewFlagSet("uvx", pflag.ContinueOnError)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true
	flagSet.SetOutput(io.Discard)

	// uvx only accepts options before the tool name; everything after the tool
	// is passed through to it. Stopping at the first positional ensures a tool's
	// own flags (e.g. `uvx ruff --fix` or `uvx mytool --with x`) are never parsed
	// as uvx options.
	flagSet.SetInterspersed(false)

	fromSpec, withSpecs := setupUvxFlags(flagSet)

	if err := flagSet.Parse(args); err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	var specs []string
	if *fromSpec != "" {
		specs = append(specs, *fromSpec)
	} else if positional := flagSet.Args(); len(positional) > 0 && !uvxIsInterpreterRequest(positional[0]) {
		// `uvx python`, `uvx python@3.12`, `uvx pypy` etc. launch an isolated
		// interpreter rather than installing a PyPI tool, so there is nothing to
		// audit for the positional. --with packages are still audited below.
		specs = append(specs, positional[0])
	}
	specs = append(specs, *withSpecs...)

	return p.buildUvxInstallTargets(command, specs)
}

// buildUvxInstallTargets normalizes uvx specifiers and builds audit targets,
// skipping specs that cannot be resolved against the PyPI registry.
func (p *pypiPackageExecutor) buildUvxInstallTargets(command Command, specs []string) (*ParsedCommand, error) {
	normalized := make([]string, 0, len(specs))
	for _, spec := range specs {
		if !uvxIsAuditableSpec(spec) {
			log.Debugf("uvx: skipping non-registry spec %q for audit", spec)
			continue
		}
		normalized = append(normalized, uvxNormalizeSpec(spec))
	}

	return p.buildInstallTargets(command, normalized)
}

// uvxNormalizeSpec converts uvx's `name@version` shorthand (e.g. ruff@0.3.0,
// ruff@latest) into a standard PEP 508 specifier so the shared PyPI parser can
// extract the name and version. `@latest` (or a bare `@`) means no constraint.
// It is only called for registry specs (see uvxIsAuditableSpec), so the `@` is
// always the version separator and never part of a URL.
func uvxNormalizeSpec(spec string) string {
	at := strings.Index(spec, "@")
	if at == -1 {
		return spec
	}

	name, version := spec[:at], spec[at+1:]
	if version == "" || version == "latest" {
		return name
	}

	// Keep an explicit operator (e.g. ruff@>=0.3.0); otherwise pin exactly.
	if strings.ContainsAny(version[:1], "=<>~!") {
		return name + version
	}

	return name + "==" + version
}

// uvxIsInterpreterRequest reports whether a uvx positional command is an
// interpreter request (e.g. `python`, `python@3.12`, `python3.11`, `pypy`)
// rather than a PyPI tool. The version suffix (`@...`) is ignored for matching.
func uvxIsInterpreterRequest(spec string) bool {
	name := spec
	if at := strings.Index(name, "@"); at != -1 {
		name = name[:at]
	}

	return uvxInterpreterRequestRe.MatchString(name)
}

// uvxIsAuditableSpec reports whether a uvx specifier can be resolved against the
// PyPI registry. VCS, URL and local-path specifiers cannot, so we skip auditing
// them here; the proxy still guards any registry traffic they trigger.
func uvxIsAuditableSpec(spec string) bool {
	if spec == "" {
		return false
	}

	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") || strings.HasPrefix(spec, "file:") {
		return false
	}

	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "~") || strings.Contains(spec, "/") {
		return false
	}

	for _, ext := range []string{".whl", ".tar.gz", ".tar.bz2", ".zip"} {
		if strings.HasSuffix(spec, ext) {
			return false
		}
	}

	return true
}

// setupUvxFlags registers uvx's options on flagSet and returns the --from and
// --with values. Every value-taking option is registered so its value is never
// mistaken for the tool positional, and every boolean option is registered so
// it does not greedily consume the following argument (pflag treats an unknown
// flag's next token as its value). The set mirrors `uvx --help`; unrecognized
// future flags are tolerated via the UnknownFlags allowlist.
func setupUvxFlags(flagSet *pflag.FlagSet) (fromSpec *string, withSpecs *[]string) {
	fromSpec = flagSet.String("from", "", "")
	withSpecs = flagSet.StringArrayP("with", "w", nil, "")

	stringFlags := []struct{ name, short string }{
		{"with-editable", ""}, {"with-requirements", ""}, {"python-platform", ""},
		{"default-index", ""}, {"index-url", "i"}, {"index-strategy", ""},
		{"keyring-provider", ""}, {"resolution", ""}, {"prerelease", ""},
		{"fork-strategy", ""}, {"exclude-newer", ""}, {"link-mode", ""},
		{"cache-dir", ""}, {"python", "p"}, {"color", ""}, {"directory", ""},
		{"project", ""}, {"config-file", ""},
	}
	for _, f := range stringFlags {
		flagSet.StringP(f.name, f.short, "", "")
	}

	arrayFlags := []struct{ name, short string }{
		{"constraints", "c"}, {"build-constraints", "b"}, {"overrides", ""},
		{"env-file", ""}, {"index", ""}, {"extra-index-url", ""}, {"find-links", "f"},
		{"upgrade-package", "P"}, {"exclude-newer-package", ""}, {"reinstall-package", ""},
		{"config-setting", "C"}, {"config-settings-package", ""},
		{"no-build-isolation-package", ""}, {"no-build-package", ""},
		{"no-binary-package", ""}, {"refresh-package", ""}, {"allow-insecure-host", ""},
	}
	for _, f := range arrayFlags {
		flagSet.StringArrayP(f.name, f.short, nil, "")
	}

	boolFlags := []struct{ name, short string }{
		{"isolated", ""}, {"no-env-file", ""}, {"version", "V"}, {"no-index", ""},
		{"upgrade", "U"}, {"no-sources", ""}, {"reinstall", ""}, {"compile-bytecode", ""},
		{"no-build-isolation", ""}, {"no-build", ""}, {"no-binary", ""}, {"no-cache", "n"},
		{"refresh", ""}, {"managed-python", ""}, {"no-managed-python", ""},
		{"no-python-downloads", ""}, {"quiet", "q"}, {"verbose", "v"}, {"native-tls", ""},
		{"offline", ""}, {"no-progress", ""}, {"no-config", ""}, {"help", "h"},
	}
	for _, f := range boolFlags {
		flagSet.BoolP(f.name, f.short, false, "")
	}

	return fromSpec, withSpecs
}
