package packagemanager

import (
	"fmt"
	"io"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/spf13/pflag"
)

type PypiPackageExecutorConfig struct {
	CommandName         string
	InstallCommands     []string
	NonDownloadCommands []string
}

func DefaultPipxPackageExecutorConfig() PypiPackageExecutorConfig {
	return PypiPackageExecutorConfig{
		CommandName:     "pipx",
		InstallCommands: []string{"install", "inject", "run", "upgrade", "upgrade-all", "reinstall", "reinstall-all"},
		NonDownloadCommands: []string{
			"list", "uninstall", "uninstall-all", "completions", "uninject", "ensurepath", "environment",
		},
	}
}

func DefaultUvxPackageExecutorConfig() PypiPackageExecutorConfig {
	return PypiPackageExecutorConfig{
		CommandName: "uvx",
	}
}

type pypiPackageExecutor struct {
	Config PypiPackageExecutorConfig
}

func NewPypiPackageExecutor(config PypiPackageExecutorConfig) (*pypiPackageExecutor, error) {
	return &pypiPackageExecutor{
		Config: config,
	}, nil
}

var _ PackageManager = &pypiPackageExecutor{}

func (p *pypiPackageExecutor) Name() string {
	return p.Config.CommandName
}

func (p *pypiPackageExecutor) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_PYPI
}

func (p *pypiPackageExecutor) ParseCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && args[0] == p.Config.CommandName {
		args = args[1:]
	}

	command := Command{Exe: p.Config.CommandName, Args: args}

	switch p.Config.CommandName {
	case "pipx":
		return p.parsePipxCommand(command, args)
	case "uvx":
		return p.parseUvxCommand(command, args)
	default:
		return nil, fmt.Errorf("unsupported package executor: %s", p.Config.CommandName)
	}
}

func (p *pypiPackageExecutor) parsePipxCommand(command Command, args []string) (*ParsedCommand, error) {
	if len(args) < 1 {
		return &ParsedCommand{Command: command}, nil
	}

	// pipx run <pkg> downloads and executes a package without globally installing it.
	// We extract the package name so it can be audited before execution.
	if args[0] == "run" {
		return p.parseRunCommand(command, args[1:])
	}

	// pipx inject <target-venv> <pkg1> [<pkg2> ...] injects packages into an
	// existing venv. The first positional arg is the target venv (already installed),
	// not a package to audit — we skip it and only audit the injected packages.
	if args[0] == "inject" {
		return p.parseInjectCommand(command, args[1:])
	}

	var installCmdIndex = -1
	for idx, arg := range args {
		if slices.Contains(p.Config.InstallCommands, arg) {
			installCmdIndex = idx
			break
		}
	}

	if installCmdIndex == -1 {
		return &ParsedCommand{Command: command, IsKnownNonDownloadCommand: IsFirstNonFlagArgInList(args, p.Config.NonDownloadCommands)}, nil
	}

	installArgs := args[installCmdIndex+1:]

	flagSet := pflag.NewFlagSet("pipx install", pflag.ContinueOnError)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true
	flagSet.SetOutput(io.Discard)

	// Define known pipx install flags. We register flags that take values to prevent
	// their values from being misidentified as package names, and boolean flags
	// to prevent the flag itself from being treated as an unknown argument.
	// registers --pip-args, --python, --spec so their values aren't picked up as packages
	setupCommonPipxFlags(flagSet)
	flagSet.Bool("force", false, "")
	flagSet.Bool("include-deps", false, "")
	flagSet.Bool("system-site-packages", false, "")

	err := flagSet.Parse(installArgs)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	packages := flagSet.Args()
	return p.buildInstallTargets(command, packages)
}

// parseRunCommand handles `pipx run [flags] <package> [args...]`.
// Only the first positional argument is the package; the rest are arguments
// to the executed program.
func (p *pypiPackageExecutor) parseRunCommand(command Command, runArgs []string) (*ParsedCommand, error) {
	if len(runArgs) == 0 {
		return &ParsedCommand{Command: command}, nil
	}

	flagSet := pflag.NewFlagSet("pipx run", pflag.ContinueOnError)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true
	flagSet.SetOutput(io.Discard)

	// Define known pipx run flags. We register flags that take values to prevent
	// their values from being misidentified as package names, and boolean flags
	// to prevent the flag itself from being treated as an unknown argument.
	// registers --pip-args, --python, --spec so their values aren't picked up as packages
	_, _, specPkg := setupCommonPipxFlags(flagSet)
	flagSet.Bool("no-cache", false, "")

	err := flagSet.Parse(runArgs)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	// If --spec is provided, that's the package to audit, not the positional arg
	if *specPkg != "" {
		return p.buildInstallTargets(command, []string{*specPkg})
	}

	packages := flagSet.Args()
	if len(packages) == 0 {
		return &ParsedCommand{Command: command}, nil
	}

	// Only the first positional arg is the package
	return p.buildInstallTargets(command, []string{packages[0]})
}

// parseInjectCommand handles `pipx inject [flags] <target-venv> <pkg1> [<pkg2> ...]`.
// The first positional argument is the target venv (already installed, not audited).
// Subsequent positional arguments are the packages being injected.
func (p *pypiPackageExecutor) parseInjectCommand(command Command, injectArgs []string) (*ParsedCommand, error) {
	if len(injectArgs) == 0 {
		return &ParsedCommand{Command: command}, nil
	}

	flagSet := pflag.NewFlagSet("pipx inject", pflag.ContinueOnError)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true
	flagSet.SetOutput(io.Discard)

	// Define known pipx inject flags. We register flags that take values to prevent
	// their values from being misidentified as package names, and boolean flags
	// to prevent the flag itself from being treated as an unknown argument.
	// registers --pip-args, --python, --spec so their values aren't picked up as packages
	setupCommonPipxFlags(flagSet)
	flagSet.Bool("force", false, "")
	flagSet.Bool("include-apps", false, "")
	flagSet.Bool("include-deps", false, "")

	err := flagSet.Parse(injectArgs)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	packages := flagSet.Args()
	if len(packages) < 2 {
		// Need at least target-venv + one package to inject
		return &ParsedCommand{Command: command}, nil
	}

	// Skip the first positional arg (target venv), audit the rest
	return p.buildInstallTargets(command, packages[1:])
}

func (p *pypiPackageExecutor) parseUvxCommand(command Command, args []string) (*ParsedCommand, error) {
	packageSpec, ok := uvxPackageSpec(args)
	if !ok {
		return &ParsedCommand{Command: command}, nil
	}

	normalizedSpec, ok := normalizeUvxPackageSpec(packageSpec)
	if !ok {
		return &ParsedCommand{Command: command}, nil
	}

	return p.buildInstallTargets(command, []string{normalizedSpec})
}

func uvxPackageSpec(args []string) (string, bool) {
	for idx, arg := range args {
		if arg == "--" {
			break
		}

		if strings.HasPrefix(arg, "--from=") {
			return strings.TrimPrefix(arg, "--from="), true
		}

		if arg == "--from" && idx+1 < len(args) {
			return args[idx+1], true
		}
	}

	for idx := 0; idx < len(args); idx++ {
		arg := args[idx]
		if arg == "--" {
			if idx+1 < len(args) {
				return args[idx+1], true
			}
			return "", false
		}

		if strings.HasPrefix(arg, "--") {
			name, _, hasValue := strings.Cut(arg, "=")
			if !hasValue && uvxLongFlagTakesValue(name) {
				idx++
			}
			continue
		}

		if strings.HasPrefix(arg, "-") {
			if uvxShortFlagTakesValue(arg) {
				idx++
			}
			continue
		}

		return arg, true
	}

	return "", false
}

func uvxLongFlagTakesValue(flag string) bool {
	switch flag {
	case
		"--cache-dir",
		"--config-file",
		"--default-index",
		"--directory",
		"--exclude-newer",
		"--find-links",
		"--from",
		"--index",
		"--index-strategy",
		"--index-url",
		"--keyring-provider",
		"--link-mode",
		"--prerelease",
		"--project",
		"--python",
		"--python-fetch",
		"--python-preference",
		"--refresh-package",
		"--resolution",
		"--with",
		"--with-editable",
		"--with-requirements":
		return true
	default:
		return false
	}
}

func uvxShortFlagTakesValue(flag string) bool {
	switch flag {
	case "-c", "-p", "-r":
		return true
	default:
		return false
	}
}

func normalizeUvxPackageSpec(packageSpec string) (string, bool) {
	packageSpec = strings.TrimSpace(packageSpec)
	if packageSpec == "" || strings.Contains(packageSpec, "://") {
		return "", false
	}

	packageName, version, found := strings.Cut(packageSpec, "@")
	if !found || packageName == "" || version == "" {
		return packageSpec, true
	}

	if version == "latest" {
		return packageName, true
	}

	return packageName + "==" + version, true
}

// buildInstallTargets creates install targets from a list of package specifiers.
func (p *pypiPackageExecutor) buildInstallTargets(command Command, packages []string) (*ParsedCommand, error) {
	var installTargets []*PackageInstallTarget

	for _, pkg := range packages {
		packageName, version, extras, err := pypiParsePackageInfo(pkg)
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		isExplicit := version != ""
		version, err = pypiGetMatchingVersion(packageName, version)
		if err != nil {
			return nil, ErrFailedToResolveVersion.Wrap(err)
		}

		installTargets = append(installTargets, &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
					Name:      packageName,
				},
				Version: version,
			},
			Extras:            extras,
			IsExplicitVersion: isExplicit,
		})
	}

	return &ParsedCommand{
		Command:           command,
		InstallTargets:    installTargets,
		IsManifestInstall: false,
	}, nil
}

func setupCommonPipxFlags(flagSet *pflag.FlagSet) (pipArgs, pythonPath, specPkg *string) {
	pipArgs = flagSet.String("pip-args", "", "")
	pythonPath = flagSet.String("python", "", "")
	specPkg = flagSet.String("spec", "", "")
	return
}
