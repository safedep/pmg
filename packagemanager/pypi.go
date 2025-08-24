package packagemanager

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type pypiCommandParser interface {
	ParseCommand(args []string) (*ParsedCommand, error)
}

type PypiPackageManagerConfig struct {
	InstallCommands []string
	CommandName     string
}

func DefaultPipPackageManagerConfig() PypiPackageManagerConfig {
	return PypiPackageManagerConfig{
		InstallCommands: []string{"install"},
		CommandName:     "pip",
	}
}

func DefaultUvPackageManagerConfig() PypiPackageManagerConfig {
	return PypiPackageManagerConfig{
		InstallCommands: []string{"add", "install"},
		CommandName:     "uv",
	}
}

type pypiPackageManager struct {
	Config PypiPackageManagerConfig
	parser pypiCommandParser
}

func NewPypiPackageManager(config PypiPackageManagerConfig) (*pypiPackageManager, error) {
	var parser pypiCommandParser

	switch config.CommandName {
	case "pip":
		parser = NewPipCommandParser(config)
	case "uv":
		parser = NewUVCommandParser(config)
	default:
		return nil, fmt.Errorf("unsupported package manager: %s", config.CommandName)
	}

	return &pypiPackageManager{
		Config: config,
		parser: parser,
	}, nil
}

var _ PackageManager = &pypiPackageManager{}

func (pypi *pypiPackageManager) Name() string {
	return pypi.Config.CommandName
}

func (pypi *pypiPackageManager) Ecosystem() packagev1.Ecosystem {
	return packagev1.Ecosystem_ECOSYSTEM_PYPI
}

func (pypi *pypiPackageManager) ParseCommand(args []string) (*ParsedCommand, error) {
	return pypi.parser.ParseCommand(args)
}

type pipCommandParser struct {
	config PypiPackageManagerConfig
}

func NewPipCommandParser(config PypiPackageManagerConfig) pypiCommandParser {
	return &pipCommandParser{
		config: config,
	}
}

func (p *pipCommandParser) ParseCommand(args []string) (*ParsedCommand, error) {
	// Remove 'pip' if it's the first argument
	if len(args) > 0 && args[0] == "pip" {
		args = args[1:]
	}

	command := Command{Exe: p.config.CommandName, Args: args}

	if len(args) < 1 {
		return &ParsedCommand{Command: command}, nil
	}

	// Find the install command
	var installCmdIndex = -1
	for idx, arg := range args {
		if slices.Contains(p.config.InstallCommands, arg) {
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

	flagSet := pflag.NewFlagSet("pip", pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsWhitelist.UnknownFlags = true

	// Define flags
	var requirementFiles []string
	flagSet.StringArrayVarP(&requirementFiles, "requirement", "r", nil, "Install from requirement file")

	// Parse arguments (supports interleaved flags + positional args)
	err := flagSet.Parse(installArgs)
	if err != nil {
		return &ParsedCommand{
			Command: command,
		}, nil
	}

	// Get remaining arguments (package names)
	packages := flagSet.Args()

	// Determine if this is a manifest install
	isManifestInstall := len(requirementFiles) > 0

	// Combine all manifest files
	var allManifestFiles []string
	allManifestFiles = append(allManifestFiles, requirementFiles...)

	// Process packages
	var installTargets []*PackageInstallTarget
	for _, pkg := range packages {
		packageName, version, extras, err := pypiParsePackageInfo(pkg)
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		if version != "" {
			if strings.HasPrefix(version, "==") {
				version = strings.TrimPrefix(version, "==")
			} else {
				version, err = pypiGetMatchingVersion(packageName, version)
				if err != nil {
					return nil, ErrFailedToResolveVersion.Wrap(err)
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
		ManifestFiles:     allManifestFiles,
	}, nil
}

type uvCommandParser struct {
	config PypiPackageManagerConfig
}

func NewUVCommandParser(config PypiPackageManagerConfig) pypiCommandParser {
	return &uvCommandParser{
		config: config,
	}
}

func (u *uvCommandParser) ParseCommand(args []string) (*ParsedCommand, error) {
	// Remove 'uv' if it's the first argument
	if len(args) > 0 && args[0] == "uv" {
		args = args[1:]
	}

	command := Command{Exe: u.config.CommandName, Args: args}
	if len(args) < 1 {
		return &ParsedCommand{Command: command}, nil
	}

	// Handle uv sync command (installs from uv.lock)
	if args[0] == "sync" {
		return &ParsedCommand{
			Command:           command,
			InstallTargets:    nil,
			IsManifestInstall: true,
			ManifestFiles:     []string{"uv.lock"},
		}, nil
	}

	// Handles pip sync command (installs from requirements.txt style files)
	if len(args) >= 3 && args[0] == "pip" && args[1] == "sync" {
		manifestFile := args[2]

		return &ParsedCommand{
			Command:           command,
			InstallTargets:    nil,
			IsManifestInstall: true,
			ManifestFiles:     []string{manifestFile},
		}, nil
	}

	// Find the install command position
	var installCmdIndex = -1
	for idx, arg := range args {
		if slices.Contains(u.config.InstallCommands, arg) {
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

	// Set up flag parsing
	flagSet := pflag.NewFlagSet("uv", pflag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	flagSet.ParseErrorsWhitelist.UnknownFlags = true

	var manifestFiles []string

	flagSet.StringArrayVarP(&manifestFiles, "requirement", "r", nil, "Install from requirement file")

	err := flagSet.Parse(installArgs)
	if err != nil {
		return &ParsedCommand{Command: command}, nil
	}

	packages := flagSet.Args()

	// Determine if this is a manifest install
	isManifestInstall := len(manifestFiles) > 0

	var installTargets []*PackageInstallTarget
	for _, pkg := range packages {
		packageName, version, extras, err := pypiParsePackageInfo(pkg)
		if err != nil {
			return nil, ErrFailedToParsePackage.Wrap(err)
		}

		if version != "" {
			if strings.HasPrefix(version, "==") {
				version = strings.TrimPrefix(version, "==")
			} else {
				version, err = pypiGetMatchingVersion(packageName, version)
				if err != nil {
					return nil, ErrFailedToResolveVersion.Wrap(err)
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

// pypiParsePackageInfo parses a python package installation specification, separating the package name,
// version constraints, and any extras (additional features) to be installed.
// Example: "django[mysql,redis]>=3.0" returns ("django", ">=3.0", ["mysql", "redis"], nil)
func pypiParsePackageInfo(input string) (packageName, version string, extras []string, err error) {
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

func pypiConvertCompatibleRelease(version string) string {
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
