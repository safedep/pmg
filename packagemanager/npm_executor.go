package packagemanager

import (
	"io"
	"slices"
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

func DefaultPnpxPackageExecutorConfig() NpmPackageExecutorConfig {
	return NpmPackageExecutorConfig{
		CommandName: "pnpx",
	}
}

type npmPackageExecutor struct {
	Config NpmPackageExecutorConfig
}

func NewNpmPackageExecutor(config NpmPackageExecutorConfig) (*npmPackageExecutor, error) {
	return &npmPackageExecutor{
		Config: config,
	}, nil
}

var _ PackageManager = &npmPackageExecutor{}

func (n *npmPackageExecutor) Name() string {
	return n.Config.CommandName
}

func (n *npmPackageExecutor) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

func (n *npmPackageExecutor) ParseCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && (args[0] == "npx" || args[0] == "pnpx") {
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
	switch n.Config.CommandName {
	case "npx":
		flagSet.StringArrayVarP(&packages, "package", "p", []string{}, "Package List")
	case "pnpx":
		flagSet.StringArrayVar(&packages, "package", []string{}, "Package List")
	}

	err := flagSet.Parse(args)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	for _, arg := range flagSet.Args() {
		// Append the scoped package
		if strings.HasPrefix(arg, "@") && !slices.Contains(packages, arg) {
			packages = append(packages, arg)
		}
	}

	// For both npx and pnpx, the first positional argument is typically
	// the package to execute (e.g., `npx cowsay@1.6.0` or `pnpx cowsay@1.6.0`).
	// However, if -p/--package flags are provided, the first positional arg
	// is the binary to run, not the package (e.g., `npx -p typescript tsc`).
	if len(flagSet.Args()) > 0 && len(packages) == 0 {
		pkg := flagSet.Args()[0]
		if !slices.Contains(packages, pkg) {
			packages = append(packages, pkg)
		}
	}

	var installTargets []*PackageInstallTarget

	for _, pkg := range packages {
		packageName, version, err := npmParsePackageInfo(pkg)
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		if version != "" {
			version = npmCleanVersion(version)
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
