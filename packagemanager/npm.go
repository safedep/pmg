package packagemanager

import (
	"fmt"
	"slices"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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
	return "npm"
}

func (npm *npmPackageManager) ParseCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && (args[0] == "npm" || args[0] == "pnpm") {
		args = args[1:]
	}

	command := Command{Exe: npm.Config.CommandName, Args: args}

	// No command specified
	if len(args) < 1 {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

	// Extract packages from args
	var packages []string
	var isManifestInstall bool
	var foundInstallCmd bool
	
	for idx, arg := range args {
		if slices.Contains(npm.Config.InstallCommands, arg) {
			foundInstallCmd = true
			// All subsequent args are packages except for flags
			for i := idx + 1; i < len(args); i++ {
				if strings.HasPrefix(args[i], "-") {
					continue
				}

				packages = append(packages, args[i])
			}

			break
		}
	}

	// If install command was found but no explicit packages,
	// this is a manifest-based installation (install from package.json)
	if foundInstallCmd && len(packages) == 0 {
		isManifestInstall = true
	}

	// No packages found and not a manifest install
	if len(packages) == 0 && !isManifestInstall {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

	// Process all package arguments
	var installTargets []*PackageInstallTarget
	for _, pkg := range packages {
		packageName, version, err := npmParsePackageInfo(pkg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse package info: %w", err)
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

	var manifestFiles []string
	if isManifestInstall {
		// npm/pnpm installs from package.json by default
		manifestFiles = append(manifestFiles, "package.json")
	}

	return &ParsedCommand{
		Command:           command,
		InstallTargets:    installTargets,
		IsManifestInstall: isManifestInstall,
		ManifestFiles:     manifestFiles,
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
