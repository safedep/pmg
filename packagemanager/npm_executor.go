package packagemanager

import (
	"io"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/spf13/pflag"
)

type NpmPackageExecutorConfig struct {
	CommandName string
}

func DefaultNpxPackageExecutorConfig() NpmPackageExecutorConfig {
	return NpmPackageExecutorConfig{
		CommandName: "npx",
	}
}

type npmPackageExecutor struct {
	Config NpmPackageExecutorConfig
}

var _ PackageExecutor = &npmPackageExecutor{}

func (n *npmPackageExecutor) Name() string {
	return n.Config.CommandName
}

func (n *npmPackageExecutor) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

func (n *npmPackageExecutor) ParsedCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && args[0] == "npx" {
		args = args[1:]
	}

	command := Command{Exe: n.Config.CommandName, Args: args}

	if len(args) < 1 {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

	flagSet := pflag.NewFlagSet(n.Config.CommandName, pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true

	var packages []string
	flagSet.StringArrayVarP(&packages, "package", "p", []string{}, "Package List")

	err := flagSet.Parse(args)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	for _, arg := range flagSet.Args() {
		// Append the scoped package
		if strings.HasPrefix(arg, "@") {
			packages = append(packages, arg)
		}
	}

	var installTargets []*PackageInstallTarget

	for _, pkg := range packages {
		packageName, version, err := npmParsePackageInfo(pkg)
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		installTarget := &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
					Name:      packageName,
				},
				Version: version,
			},
		}

		installTargets = append(installTargets, installTarget)
	}

	return &ParsedCommand{
		Command:        command,
		InstallTargets: installTargets,
	}, nil
}
