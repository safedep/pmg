package packagemanager

import (
	"context"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type Command struct {
	Exe  string
	Args []string
}

type PackageInstallTarget struct {
	PackageVersion *packagev1.PackageVersion

	// Extras specifies additional features to be installed with a Python package
	// Example: "django[mysql,redis]" has Extras as ["mysql", "redis"]
	// Currently only specific to Python packages
	Extras []string
}

func (pit *PackageInstallTarget) HasVersion() bool {
	return pit.PackageVersion != nil && pit.PackageVersion.GetVersion() != ""
}

type ParsedCommand struct {
	// Original command
	Command Command

	// Parsed install target if this is an install command
	InstallTargets []*PackageInstallTarget

	// IsManifestInstall indicates if this is a manifest-based installation
	// (e.g., npm install, pip install -r requirements.txt)
	IsManifestInstall bool

	// ManifestFiles contains the list of manifest files to install from
	// (e.g., ["requirements.txt"] for pip install -r requirements.txt)
	ManifestFiles []string
}

// Supported if explicit install targets OR manifest-based install.
func (pc *ParsedCommand) IsInstallationCommand() bool {
	return pc.HasInstallTarget() || pc.HasManifestInstall()
}

func (pc *ParsedCommand) HasInstallTarget() bool {
	return len(pc.InstallTargets) > 0
}

func (pc *ParsedCommand) HasManifestInstall() bool {
	return pc.IsManifestInstall
}

func (pc *ParsedCommand) ShouldExtractFromManifest() bool {
	return pc.IsManifestInstall && !pc.HasInstallTarget()
}

// PackageManager is the contract for implementing a package manager
type PackageManager interface {
	// Name of the package manager implementation
	Name() string

	// ParseCommand parses the command and returns a parsed command
	// specific to the package manager implementation
	ParseCommand(args []string) (*ParsedCommand, error)

	// Ecosystem of the package manager
	Ecosystem() packagev1.Ecosystem
}

// PackageResolver is the contract for resolving package info
type PackageResolver interface {
	// ResolveLatestVersion resolves the latest version for a given package
	ResolveLatestVersion(context.Context, *packagev1.Package) (*packagev1.PackageVersion, error)

	// ResolveDependencies resolves the dependencies for a given package version
	// It returns a flattened list of all the dependencies based on implementation
	// specific config. The version resolution is based on minimum version selection
	// for a given version range.
	ResolveDependencies(context.Context, *packagev1.PackageVersion) ([]*packagev1.PackageVersion, error)
}
