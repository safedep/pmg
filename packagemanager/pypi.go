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

	// Since manifest-based installs like 'npm i' are now valid commands
	if len(args) < 1 {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

	var packages []string
	var manifestFiles []string
	var isManifestInstall bool
	var foundInstallCmd bool

	for idx, arg := range args {
		if slices.Contains(pip.Config.InstallCommands, arg) {
			foundInstallCmd = true
			// Check for manifest-based installation flags
			for i := idx + 1; i < len(args); i++ {
				currentArg := args[i]

				// Handle -r/--requirement flags
				if currentArg == "-r" || currentArg == "--requirement" {
					isManifestInstall = true
					if i+1 < len(args) {
						manifestFiles = append(manifestFiles, args[i+1])
						i++ // skip the filename
					}
					continue
				}

				// Handle combined -r flag (e.g., -rrequirements.txt)
				if strings.HasPrefix(currentArg, "-r") && len(currentArg) > 2 {
					isManifestInstall = true
					manifestFiles = append(manifestFiles, currentArg[2:])
					continue
				}

				// Handle other flags that indicate manifest installation
				if currentArg == "-e" || currentArg == "--editable" ||
					currentArg == "-c" || currentArg == "--constraint" {
					if i+1 < len(args) {
						i++ // skip the next argument
					}
					continue
				}

				// If it's a flag, skip it
				if strings.HasPrefix(currentArg, "-") {
					continue
				}

				// Otherwise, it's a package name
				packages = append(packages, currentArg)
			}
			break
		}
	}

	// If install command was found but no explicit packages and no manifest flags,
	// check if it's a bare "pip install" (which should look for default manifest files)
	if foundInstallCmd && len(packages) == 0 && len(manifestFiles) == 0 {
		isManifestInstall = true
		// pip install without args typically looks for requirements.txt
		manifestFiles = append(manifestFiles, "requirements.txt")
	}

	var installTargets []*PackageInstallTarget

	for _, pkg := range packages {
		packageName, version, extras, err := pipParsePackageInfo(pkg)
		if err != nil {
			return nil, fmt.Errorf("failed to parse package info: %w", err)
		}

		if version != "" {
			// If exact version provided just trim it. If not get a version that satisfies a given version specifier
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

		installTargets = append(installTargets, &PackageInstallTarget{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: packagev1.Ecosystem_ECOSYSTEM_PYPI,
					Name:      packageName,
				},
				Version: version,
			},
			Extras: extras,
		})
	}

	return &ParsedCommand{
		Command:           command,
		InstallTargets:    installTargets,
		IsManifestInstall: isManifestInstall,
		ManifestFiles:     manifestFiles,
	}, nil
}

// pipParsePackageInfo parses a pip install package specification, separating the package name,
// version constraints, and any extras (additional features) to be installed.
// Example: "django[mysql,redis]>=3.0" returns ("django", ">=3.0", ["mysql", "redis"], nil)
func pipParsePackageInfo(input string) (packageName, version string, extras []string, err error) {
	if input == "" {
		return "", "", nil, fmt.Errorf("package info cannot be empty")
	}

	input = strings.TrimSpace(input)

	// First extract any extras if present
	openBracket := strings.Index(input, "[")
	closeBracket := strings.Index(input, "]")

	if openBracket != -1 && closeBracket != -1 && openBracket < closeBracket {
		extrasStr := strings.TrimSpace(input[openBracket+1 : closeBracket])
		if extrasStr != "" {
			// Split extras by comma and trim each extra
			for _, extra := range strings.Split(extrasStr, ",") {
				if trimmedExtra := strings.TrimSpace(extra); trimmedExtra != "" {
					extras = append(extras, trimmedExtra)
				}
			}
		}
		// Remove the extra part from input for further processing
		input = input[:openBracket] + input[closeBracket+1:]
	} else if (openBracket != -1 && closeBracket == -1) || (openBracket == -1 && closeBracket != -1) {
		return "", "", nil, fmt.Errorf("mismatched brackets in input '%s'", input)
	}

	// Python package version specifiers are typically separated by one of:
	// '==', '>=', '<=', '!=', '>', '<', '~=', or direct comma separated list
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
		return strings.TrimSpace(input), "", extras, nil
	}

	packageName = strings.TrimSpace(input[:index])
	version = strings.TrimSpace(input[index:])

	if packageName == "" {
		return "", "", nil, fmt.Errorf("invalid package name in input '%s'", input)
	}

	return packageName, version, extras, nil
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

	switch len(parts) {
	case 2:
		// ~=X.Y case, increment major version: ~=2.1 -> >=2.1,<3.0
		major := parts[0]
		nextMajor, _ := strconv.Atoi(major)
		nextMajor += 1
		return fmt.Sprintf(">=%s,<%d.0", version, nextMajor)

	case 3:
		// ~=X.Y.Z case, increment minor version: ~=2.1.5 -> >=2.1.5,<2.2.0
		major := parts[0]
		minor := parts[1]
		nextMinor, _ := strconv.Atoi(minor)
		nextMinor += 1
		return fmt.Sprintf(">=%s,<%s.%d.0", version, major, nextMinor)

	default:
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
