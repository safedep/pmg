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
}

func (pc *ParsedCommand) HasInstallTarget() bool {
	return len(pc.InstallTargets) > 0
}

// PackageManager is the contract for implementing a package manager
type PackageManager interface {
	// Name of the package manager implementation
	Name() string

	// ParseCommand parses the command and returns a parsed command
	// specific to the package manager implementation
	ParseCommand(args []string) (*ParsedCommand, error)
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
