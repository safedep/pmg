package packagemanager

import (
	"fmt"
	"io"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/spf13/pflag"
)

type NpmPackageManagerConfig struct {
	InstallCommands []string
	CommandName     string
}

func DefaultNpmPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "i", "add"},
		CommandName:     "npm",
	}
}

func DefaultPnpmPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "i", "add"},
		CommandName:     "pnpm",
	}
}

func DefaultBunPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "i", "add"},
		CommandName:     "bun",
	}
}

func DefaultYarnPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "add", ""},
		CommandName:     "yarn",
	}
}

type npmPackageManager struct {
	Config NpmPackageManagerConfig
}

func NewNpmPackageManager(config NpmPackageManagerConfig) (*npmPackageManager, error) {
	return &npmPackageManager{
		Config: config,
	}, nil
}

var _ PackageManager = &npmPackageManager{}

func (npm *npmPackageManager) Name() string {
	return npm.Config.CommandName
}

func (npm *npmPackageManager) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_NPM
}

func (npm *npmPackageManager) ParseCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && (args[0] == "npm" || args[0] == "pnpm" || args[0] == "bun" || args[0] == "yarn") {
		args = args[1:]
	}

	command := Command{Exe: npm.Config.CommandName, Args: args}

	// Since manifest-based installs like 'npm i' are now valid commands
	if len(args) < 1 {
		if npm.Config.CommandName == "yarn" {
			return &ParsedCommand{
				Command:           command,
				InstallTargets:    []*PackageInstallTarget{},
				IsManifestInstall: true,
				ManifestFiles:     []string{},
			}, nil
		}
		return &ParsedCommand{
			Command: command,
		}, nil
	}
	// Find the install command position
	var installCmdIndex = -1
	for idx, arg := range args {
		if slices.Contains(npm.Config.InstallCommands, arg) {
			installCmdIndex = idx
			break
		}
	}

	if installCmdIndex == -1 {
		// No install command found, return as-is
		return &ParsedCommand{Command: command}, nil
	}

	// Extract arguments after the install command
	installArgs := args[installCmdIndex+1:]

	// Extract packages from args
	var packages []string
	var isManifestInstall bool
	var devPackages []string

	flagSet := pflag.NewFlagSet(npm.Config.CommandName, pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsWhitelist.UnknownFlags = true

	switch npm.Config.CommandName {
	case "npm", "pnpm":
		flagSet.StringArrayVarP(&devPackages, "save-dev", "D", nil, "Install dev packages")
	case "bun":
		flagSet.StringArrayVarP(&devPackages, "dev", "d", nil, "Install dev packages")
	case "yarn":
		flagSet.StringArrayVarP(&devPackages, "dev", "D", nil, "Install dev packages")
	}

	err := flagSet.Parse(installArgs)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	packages = flagSet.Args()

	// If install command was found but no explicit packages,
	// this is a manifest-based installation
	if installCmdIndex != -1 && len(packages) == 0 {
		isManifestInstall = true
	}

	// Yarn-specific validation: yarn install does not accept package names
	if npm.Config.CommandName == "yarn" && args[installCmdIndex] == "install" && len(packages) > 0 {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

	// No packages found and not a manifest install
	if len(packages) == 0 && !isManifestInstall {
		return &ParsedCommand{
			Command: command,
		}, nil
	}
	packages = append(packages, devPackages...)

	// Process all package arguments
	var installTargets []*PackageInstallTarget
	for _, pkg := range packages {
		packageName, version, err := npmParsePackageInfo(pkg)
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		// Clean version if specified
		if version != "" {
			version = npmCleanVersion(version)
		}

		installTargets = append(installTargets, &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
					Name:      packageName,
				},
				Version: version,
			},
		})
	}

	return &ParsedCommand{
		Command:           command,
		InstallTargets:    installTargets,
		IsManifestInstall: isManifestInstall,
		ManifestFiles:     []string{},
	}, nil
}

func npmParsePackageInfo(input string) (packageName, version string, err error) {
	if input == "" {
		return "", "", fmt.Errorf("package info cannot be empty")
	}

	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "@") {
		// Scoped package (e.g. @types/node or @types/node@1.0.0)
		lastAtIndex := strings.LastIndex(input, "@")
		if lastAtIndex > 0 {
			packageName = strings.TrimSpace(input[:lastAtIndex])
			version = strings.TrimSpace(input[lastAtIndex+1:])
			return packageName, version, nil
		}

		// If no version specifier, return the whole input as package name
		return strings.TrimSpace(input), "", nil
	}

	// Normal package (e.g. lodash or lodash@4.17.21)
	parts := strings.Split(input, "@")
	if len(parts) == 2 {
		packageName = strings.TrimSpace(parts[0])
		version = strings.TrimSpace(parts[1])
		return packageName, version, nil
	}

	if len(parts) == 1 {
		packageName = strings.TrimSpace(parts[0])
		return packageName, "", nil
	}

	return "", "", fmt.Errorf("invalid format: expected 'package' OR 'package@version', got '%s'", input)
}

func npmCleanVersion(version string) string {
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")

	if version == "*" || version == "" {
		return "latest"
	}

	return version
}
