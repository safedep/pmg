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
		InstallCommands: []string{"install", "inject", "run"},
		NonDownloadCommands: []string{
			"list", "uninstall", "uninstall-all", "upgrade", "upgrade-all", "completions",
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
		if len(args) < 2 {
			return &ParsedCommand{Command: command}, nil
		}

		// Set up flag parsing for pipx run to skip flags before the package
		flagSet := pflag.NewFlagSet("pipx run", pflag.ContinueOnError)
		flagSet.ParseErrorsAllowlist.UnknownFlags = true
		flagSet.SetOutput(io.Discard)
		_ = flagSet.Parse(args[1:])

		packages := flagSet.Args()
		if len(packages) == 0 {
			return &ParsedCommand{Command: command}, nil
		}

		packageName, version, extras, err := pypiParsePackageInfo(packages[0])
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		isExplicit := version != ""
		version, err = pypiGetMatchingVersion(packageName, version)
		if err != nil {
			return nil, ErrFailedToResolveVersion.Wrap(err)
		}

		return &ParsedCommand{
			Command: command,
			InstallTargets: []*PackageInstallTarget{
				{
					PackageVersion: &packagev1.PackageVersion{
						Package: &packagev1.Package{
							Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
							Name:      packageName,
						},
						Version: version,
					},
					Extras:            extras,
					IsExplicitVersion: isExplicit,
				},
			},
			IsManifestInstall: false,
		}, nil
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

	flagSet := pflag.NewFlagSet("pipx", pflag.ContinueOnError)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true
	flagSet.SetOutput(io.Discard)

	err := flagSet.Parse(installArgs)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	packages := flagSet.Args()
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
