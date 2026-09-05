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

	// InstallBoolFlags are the boolean flags of the install commands. pflag
	// treats an unknown flag as one that takes a value, so an unregistered
	// boolean flag would consume the package name that follows it.
	InstallBoolFlags []BoolFlag

	CommandName string
}

// BoolFlag names a boolean command-line flag and its optional one-letter
// shorthand.
type BoolFlag struct {
	Name      string
	Shorthand string
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
		InstallBoolFlags: []BoolFlag{
			{Name: "save-dev", Shorthand: "D"},
			{Name: "global", Shorthand: "g"},
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
		InstallBoolFlags: []BoolFlag{
			{Name: "save-dev", Shorthand: "D"},
			{Name: "global", Shorthand: "g"},
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
		InstallBoolFlags: []BoolFlag{
			{Name: "dev", Shorthand: "d"},
			{Name: "global", Shorthand: "g"},
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
		InstallBoolFlags: []BoolFlag{
			{Name: "dev", Shorthand: "D"},
			{Name: "global", Shorthand: "g"},
		},
		CommandName: "yarn",
	}
}

// aubeGlobalBoolFlags are the boolean flags aube accepts before or after any
// subcommand. The aube and aubx parsers both register them.
var aubeGlobalBoolFlags = []BoolFlag{
	{Name: "recursive", Shorthand: "r"},
	{Name: "verbose", Shorthand: "v"},
	{Name: "color"},
	{Name: "no-color"},
	{Name: "silent"},
	{Name: "workspace-root"},
	{Name: "fail-if-no-match"},
}

// aubeLockfileBoolFlags are the lockfile and virtual store flags shared by
// aube add, install, ci and dlx.
var aubeLockfileBoolFlags = []BoolFlag{
	{Name: "frozen-lockfile"},
	{Name: "no-frozen-lockfile"},
	{Name: "prefer-frozen-lockfile"},
	{Name: "enable-global-virtual-store"},
	{Name: "enable-gvs"},
	{Name: "disable-global-virtual-store"},
	{Name: "disable-gvs"},
}

// DefaultAubePackageManagerConfig configures aube (https://aube.sh), an
// npm-compatible package manager. Its `install` takes no package names,
// `add` does.
func DefaultAubePackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{
		InstallCommands: []string{"install", "i", "add", "a", "ci", "clean-install", "ic", "install-clean"},
		// Commands that never download a package tarball. `remove` is absent:
		// aube re-resolves the tree after a removal. `store` is absent: `store
		// add` downloads packages, and only the first argument is inspected.
		NonDownloadCommands: []string{
			// Inspection of the local tree or of registry metadata
			"list", "ls", "why", "w", "outdated", "view", "info", "show", "v",
			// Local operations
			"config", "c", "cache", "link", "ln", "unlink", "dislink",
			"pack", "prune", "rebuild", "rb", "version", "help", "doctor",
			"bin", "root", "prefix", "completion",
		},
		InstallBoolFlags: slices.Concat(aubeGlobalBoolFlags, aubeLockfileBoolFlags, []BoolFlag{
			// add
			{Name: "save-dev", Shorthand: "D"},
			{Name: "save-exact", Shorthand: "E"},
			{Name: "save-optional", Shorthand: "O"},
			{Name: "save-peer"},
			{Name: "save-catalog"},
			{Name: "save-workspace-protocol"},
			{Name: "no-save-workspace-protocol"},
			{Name: "no-save"},
			{Name: "global", Shorthand: "g"},
			{Name: "workspace", Shorthand: "w"},
			{Name: "ignore-workspace-root-check", Shorthand: "W"},
			{Name: "allow-low-downloads"},
			{Name: "dangerously-allow-all-builds"},
			// install and ci
			{Name: "dev"},
			{Name: "prod", Shorthand: "P"},
			{Name: "ignore-scripts"},
			{Name: "ignore-pnpmfile"},
			{Name: "no-optional"},
			{Name: "offline"},
			{Name: "prefer-offline"},
			{Name: "force"},
			{Name: "dry-run"},
			{Name: "lockfile-only"},
			{Name: "fix-lockfile"},
			{Name: "merge-git-branch-lockfiles"},
			{Name: "shamefully-hoist"},
			{Name: "side-effects-cache"},
			{Name: "no-side-effects-cache"},
			{Name: "verify-store-integrity"},
			{Name: "no-verify-store-integrity"},
		}),
		CommandName: "aube",
	}
}

// DefaultAubrPackageManagerConfig configures aubr, the aube shorthand for
// `aube run`. A script run installs missing or stale dependencies first, so
// every aubr command may download packages and no argument is an install
// command or a package name.
func DefaultAubrPackageManagerConfig() NpmPackageManagerConfig {
	return NpmPackageManagerConfig{CommandName: "aubr"}
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
		return &ParsedCommand{Command: command, IsKnownNonDownloadCommand: IsFirstNonFlagArgInList(args, npm.Config.NonDownloadCommands)}, nil
	}

	// Extract arguments after the install command
	installArgs := args[installCmdIndex+1:]

	flagSet := pflag.NewFlagSet(npm.Config.CommandName, pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsAllowlist.UnknownFlags = true

	for _, flag := range npm.Config.InstallBoolFlags {
		flagSet.BoolP(flag.Name, flag.Shorthand, false, "")
	}

	if err := flagSet.Parse(installArgs); err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	// An install command without explicit packages installs from the manifest
	packages := flagSet.Args()
	isManifestInstall := len(packages) == 0

	// Yarn-specific validation: yarn install does not accept package names
	if npm.Config.CommandName == "yarn" && args[installCmdIndex] == "install" && len(packages) > 0 {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

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
