package packagemanager

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/Masterminds/semver"
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
				version, err = pipGetLatestMatchingVersion(packageName, version)
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

var httpClient = &http.Client{Timeout: 10 * time.Second}

func pipGetLatestMatchingVersion(packageName, versionConstraint string) (string, error) {
	type PyPIResponse struct {
		Releases map[string]any `json:"releases"`
	}

	if strings.HasPrefix(versionConstraint, "~=") {
		versionConstraint = pipConvertCompatibleRelease(versionConstraint)
	}

	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", packageName)
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch package info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("package not found or HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var pypiResp PyPIResponse
	if err := json.Unmarshal(body, &pypiResp); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Parse version constraint
	constraint, err := semver.NewConstraint(versionConstraint)
	if err != nil {
		return "", fmt.Errorf("invalid version constraint: %w", err)
	}

	// Collect all valid semver versions
	var versions []*semver.Version
	for v := range pypiResp.Releases {
		ver, err := semver.NewVersion(v)
		if err == nil { // ignore invalid semver versions
			versions = append(versions, ver)
		}
	}

	if len(versions) == 0 {
		return "", fmt.Errorf("no valid versions found")
	}

	// Sort versions in ascending order
	sort.Sort(semver.Collection(versions))

	// Iterate from highest to lowest to find best match
	for i := len(versions) - 1; i >= 0; i-- {
		if constraint.Check(versions[i]) {
			return versions[i].Original(), nil
		}
	}

	return "", fmt.Errorf("no version matches constraint %q", versionConstraint)
}

// Convert "~=3.1.0" → ">=3.1.0,<3.2.0"
func pipConvertCompatibleRelease(version string) string {
	version = strings.TrimPrefix(version, "~=")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return "" // invalid
	}
	major := parts[0]
	minor := parts[1]
	nextMinor, _ := strconv.Atoi(minor)
	nextMinor += 1
	return fmt.Sprintf(">=%s,<%s.%d.0", version, major, nextMinor)
}
