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
	InstallCommands     []string
	NonDownloadCommands []string
	CommandName         string
}

func DefaultNpmPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "i", "add"},
		// Commands that are known to never download packages from a registry.
		// Anything not in this list (including unknown future commands) runs with the proxy.
		NonDownloadCommands: []string{
			// Removal — uninstalls local packages, no registry download
			"uninstall", "remove", "rm", "r", "un", "unlink",
			// Local operations — no registry contact
			"rebuild", "prune", "link", "cache", "pack",
			// Inspection / read-only registry queries
			"ls", "list", "outdated", "view", "info", "show", "search",
			"config", "ping", "whoami", "version", "help",
		},
		CommandName: "npm",
	}
}

func DefaultPnpmPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "i", "add"},
		NonDownloadCommands: []string{
			"remove", "rm", "uninstall", "un",
			"prune", "link", "unlink",
			"ls", "list", "outdated", "info", "view", "config", "why",
		},
		CommandName: "pnpm",
	}
}

func DefaultBunPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "i", "add", "ci"},
		NonDownloadCommands: []string{
			// Removal
			"remove", "rm",
		},
		CommandName: "bun",
	}
}

func DefaultYarnPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "add", ""},
		NonDownloadCommands: []string{
			"remove", "unlink",
			"ls", "list", "outdated", "info", "config", "why",
		},
		CommandName: "yarn",
	}
}

type npmPackageManager struct {
	Config NpmPackageManagerConfig
}

// These flag sets are intentionally narrow. Known value flags are consumed so
// command detection is stable; unknown leading flag/value pairs fail safe.
var npmGlobalFlagsWithValues = map[string]struct{}{
	"cache":        {},
	"cafile":       {},
	"cert":         {},
	"globalconfig": {},
	"https-proxy":  {},
	"key":          {},
	"loglevel":     {},
	"location":     {},
	"node-options": {},
	"noproxy":      {},
	"otp":          {},
	"prefix":       {},
	"proxy":        {},
	"registry":     {},
	"script-shell": {},
	"tag":          {},
	"user-agent":   {},
	"userconfig":   {},
	"workspace":    {},
}

var npmShortFlagsWithValues = map[byte]struct{}{
	'C': {},
	'L': {},
	'c': {},
	'm': {},
	'w': {},
}

var npmShortBooleanFlags = map[byte]struct{}{
	'f': {},
	'g': {},
	's': {},
	'y': {},
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
	if len(args) > 0 && args[0] == npm.Config.CommandName {
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
			Command:                   command,
			IsKnownNonDownloadCommand: true,
		}, nil
	}

	commandArgIndex, ambiguousCommand := getFirstCommandArgIndex(args)
	installCmdIndex := -1
	if commandArgIndex != -1 && !ambiguousCommand && slices.Contains(npm.Config.InstallCommands, args[commandArgIndex]) {
		installCmdIndex = commandArgIndex
	}

	if installCmdIndex == -1 {
		firstCommandArg := ""
		if commandArgIndex != -1 {
			firstCommandArg = args[commandArgIndex]
		}

		if !ambiguousCommand && (firstCommandArg == "exec" || firstCommandArg == "x" || firstCommandArg == "dlx") {
			subArgs := args[commandArgIndex+1:]
			installTargets, err := parseFetchAndRunTargets(npm.Config.CommandName, firstCommandArg, subArgs)
			if err == nil && len(installTargets) > 0 {
				return &ParsedCommand{
					Command:        command,
					InstallTargets: installTargets,
				}, nil
			}
		}

		return &ParsedCommand{Command: command, IsKnownNonDownloadCommand: isKnownNpmNonDownloadCommand(args, npm.Config.NonDownloadCommands)}, nil
	}

	// Extract arguments after the install command
	installArgs := args[installCmdIndex+1:]

	// Extract packages from args
	var packages []string
	var isManifestInstall bool
	var devPackages []string

	flagSet := pflag.NewFlagSet(npm.Config.CommandName, pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true

	switch npm.Config.CommandName {
	case "npm", "pnpm":
		flagSet.StringArrayVarP(&devPackages, "save-dev", "D", nil, "Install dev packages")
	case "bun":
		flagSet.StringArrayVarP(&devPackages, "dev", "d", nil, "Install dev packages")
	case "yarn":
		flagSet.StringArrayVarP(&devPackages, "dev", "D", nil, "Install dev packages")
	}

	// Known only to prevent UnknownFlags mode from swallowing the next package arg.
	flagSet.BoolP("global", "g", false, "Install packages globally")

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
			IsExplicitVersion: version != "",
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

func getFirstNonFlagArg(args []string) string {
	index, _ := getFirstCommandArgIndex(args)
	if index == -1 {
		return ""
	}

	return args[index]
}

func getFirstCommandArgIndex(args []string) (int, bool) {
	ambiguous := false
	for idx := 0; idx < len(args); idx++ {
		arg := args[idx]
		if arg == "--" {
			if idx+1 < len(args) {
				return idx + 1, ambiguous
			}
			return -1, ambiguous
		}

		if strings.HasPrefix(arg, "--") {
			flagName := strings.TrimPrefix(arg, "--")
			if strings.Contains(flagName, "=") {
				continue
			}
			if _, ok := npmGlobalFlagsWithValues[flagName]; ok {
				if idx+1 < len(args) {
					idx++
				}
				continue
			}
			if idx+1 < len(args) && !strings.HasPrefix(args[idx+1], "-") {
				ambiguous = true
			}
			continue
		}

		if strings.HasPrefix(arg, "-") {
			flagName := strings.TrimPrefix(arg, "-")
			if len(flagName) > 0 {
				if _, ok := npmShortFlagsWithValues[flagName[0]]; ok && len(flagName) == 1 {
					if idx+1 < len(args) {
						idx++
					}
					continue
				}

				if _, ok := npmShortFlagsWithValues[flagName[0]]; ok {
					continue
				}

				allBoolean := true
				for flagIdx := 0; flagIdx < len(flagName); flagIdx++ {
					if _, ok := npmShortBooleanFlags[flagName[flagIdx]]; !ok {
						allBoolean = false
						break
					}
				}

				if !allBoolean && idx+1 < len(args) && !strings.HasPrefix(args[idx+1], "-") {
					ambiguous = true
				}
			}
			continue
		}
		return idx, ambiguous
	}
	return -1, ambiguous
}

func isKnownNpmNonDownloadCommand(args []string, nonDownloadCommands []string) bool {
	firstNonFlagIndex, ambiguousCommand := getFirstCommandArgIndex(args)
	if ambiguousCommand {
		return false
	}
	if firstNonFlagIndex == -1 {
		return true
	}

	firstNonFlag := args[firstNonFlagIndex]
	if firstNonFlag == "cache" {
		cacheCommandIndex, ambiguousCacheCommand := getFirstCommandArgIndex(args[firstNonFlagIndex+1:])
		if ambiguousCacheCommand {
			return false
		}
		if cacheCommandIndex != -1 && args[firstNonFlagIndex+1:][cacheCommandIndex] == "add" {
			return false
		}
	}
	if firstNonFlag == "pack" {
		packArgIndex, ambiguousPackArgs := getFirstCommandArgIndex(args[firstNonFlagIndex+1:])
		if ambiguousPackArgs {
			return false
		}
		if packArgIndex != -1 {
			return false
		}
	}

	return slices.Contains(nonDownloadCommands, firstNonFlag)
}

func parseFetchAndRunTargets(cmdName string, subCmd string, args []string) ([]*PackageInstallTarget, error) {
	flagSet := pflag.NewFlagSet(cmdName, pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true

	var packages []string
	flagSet.StringArrayVarP(&packages, "package", "p", []string{}, "Package List")

	err := flagSet.Parse(args)
	if err != nil {
		return nil, nil
	}

	if len(packages) == 0 {
		for _, arg := range flagSet.Args() {
			if strings.HasPrefix(arg, "@") && !slices.Contains(packages, arg) {
				packages = append(packages, arg)
			}
		}
	}

	// Fall back to the first positional argument for non-ambiguous download runners
	// like "dlx". Ambiguous runners ("exec", "x") are skipped to avoid false positive
	// package resolution on local binaries.
	if len(flagSet.Args()) > 0 && len(packages) == 0 {
		if subCmd == "dlx" {
			pkg := flagSet.Args()[0]
			if !slices.Contains(packages, pkg) {
				packages = append(packages, pkg)
			}
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
			IsExplicitVersion: version != "",
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

	return installTargets, nil
}
