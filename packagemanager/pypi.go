package packagemanager

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type PipPackageManagerConfig struct {
	InstallCommands []string
	CommandName     string
}

func DefaultPipPackageManagerConfig() PipPackageManagerConfig {
	return PipPackageManagerConfig{
		InstallCommands: []string{"install"},
		CommandName:     "pip",
	}
}

type pipPackageManager struct {
	Config PipPackageManagerConfig
}

func NewPipPackageManager(config PipPackageManagerConfig) (*pipPackageManager, error) {
	return &pipPackageManager{
		Config: config,
	}, nil
}

var _ PackageManager = &pipPackageManager{}

func (pip *pipPackageManager) Name() string {
	return "pip"
}

func (pip *pipPackageManager) ParseCommand(args []string) (*ParsedCommand, error) {
	if len(args) > 0 && args[0] == "pip" {
		args = args[1:]
	}
	command := Command{Exe: pip.Config.CommandName, Args: args}

	if len(args) < 2 {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

	var packages []string
	for idx, arg := range args {
		if slices.Contains(pip.Config.InstallCommands, arg) {
			for i := idx + 1; i < len(args); i++ {
				if strings.HasPrefix(args[i], "-") {
					continue
				}
				packages = append(packages, args[i])
			}
			break
		}
	}
	var installTargets []*PackageInstallTarget

	for _, pkg := range packages {
		packageName, version, err := pipParsePackageInfo(pkg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse package info: %w", err)
		}
		// If exact version provided just trim it. If not get a version that satisfies a given version specifier

		if version != "" {
			if strings.HasPrefix(version, "==") {
				// Exact version, just trim
				version = strings.TrimPrefix(version, "==")
			} else {
				// Version range, resolve from PyPI
				version, err = pipGetMatchingVersion(packageName, version)
				if err != nil {
					return nil, fmt.Errorf("error resolving version for %s: %s", packageName, err.Error())
				}
			}
		}

		fmt.Printf("Package Name: %s Version: %s\n", packageName, version)

		installTargets = append(installTargets, &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
					Name:      packageName,
				},
				Version: version,
			},
		})
	}

	return &ParsedCommand{
		Command:        command,
		InstallTargets: installTargets,
	}, nil
}

// pipParsePackageInfo parses python package strings like:
// "fastapi", "fastapi==0.115.7", "requests>=2.0,<3.0", "pydantic!=1.8,!=1.8.1"
// Returns packageName and version (empty if none specified).
func pipParsePackageInfo(input string) (packageName, version string, err error) {
	if input == "" {
		return "", "", fmt.Errorf("package info cannot be empty")
	}

	input = strings.TrimSpace(input)

	// Python package version specifiers are typically separated by one of:
	// '==', '>=', '<=', '!=', '>', '<', '~=', or direct comma separated list
	// We'll find the first occurrence of these operators for splitting.

	operators := []string{"==", ">=", "<=", "!=", ">", "<", "~="}
	index := -1

	// Find the earliest operator occurrence
	for _, op := range operators {
		i := strings.Index(input, op)
		if i != -1 && (index == -1 || i < index) {
			index = i
		}
	}

	if index == -1 {
		// No operator found, whole input is package name, no version
		return input, "", nil
	}

	packageName = strings.TrimSpace(input[:index])
	version = strings.TrimSpace(input[index:])

	// Some version specs can have multiple constraints separated by commas
	// Example: "requests>=2.0,<3.0"
	// So keep version as is

	if packageName == "" {
		return "", "", fmt.Errorf("invalid package name in input '%s'", input)
	}

	return packageName, version, nil
}

func pipConvertCompatibleRelease(version string) string {
	if !strings.HasPrefix(version, "~=") {
		return version
	}

	version = strings.TrimPrefix(version, "~=")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return "" // invalid
	}

	if len(parts) == 2 {
		// ~=X.Y case, increment major version: ~=2.1 -> >=2.1,<3.0
		major := parts[0]
		nextMajor, _ := strconv.Atoi(major)
		nextMajor += 1
		return fmt.Sprintf(">=%s,<%d.0", version, nextMajor)
	} else if len(parts) == 3 {
		// ~=X.Y.Z case, increment minor version: ~=2.1.5 -> >=2.1.5,<2.2.0
		major := parts[0]
		minor := parts[1]
		nextMinor, _ := strconv.Atoi(minor)
		nextMinor += 1
		return fmt.Sprintf(">=%s,<%s.%d.0", version, major, nextMinor)
	} else {
		// ~=X.Y.Z.W[.more] case, increment second-to-last component
		// ~=2.1.5.2 -> >=2.1.5.2,<2.1.6
		incIndex := len(parts) - 2
		upperBoundParts := make([]string, incIndex+1)
		copy(upperBoundParts, parts[:incIndex+1])

		increment, _ := strconv.Atoi(upperBoundParts[incIndex])
		increment++
		upperBoundParts[incIndex] = strconv.Itoa(increment)

		upperBound := strings.Join(upperBoundParts, ".")

		return fmt.Sprintf(">=%s,<%s", version, upperBound)
	}
}
