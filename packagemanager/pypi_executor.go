package packagemanager

import (
	"io"
	"slices"

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
	if len(args) > 0 && args[0] == "pipx" {
		args = args[1:]
	}

	command := Command{Exe: p.Config.CommandName, Args: args}
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

