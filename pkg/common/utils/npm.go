package utils

import (
	"fmt"
	"strings"
)

// ParseNpmInstallArgs parses npm install command arguments and returns
// separated flags and packages. It expects args to include the full command
// including "npm" and "install" at the start
func ParseNpmInstallArgs(args []string) ([]string, []string) {
	var flags []string
	var packages []string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else {
			packages = append(packages, arg)
		}
	}
	return flags, packages
}

func CleanVersion(version string) string {
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")
	if version == "*" {
		return "latest"
	}
	return version
}

func ParsePackageInfo(input string) (packageName, version string, err error) {
	if input == "" {
		return "", "", fmt.Errorf("package info cannot be empty")
	}
	input = strings.TrimSpace(input)

	if strings.HasPrefix(input, "@") {
		lastAtIndex := strings.LastIndex(input, "@")
		if lastAtIndex > 0 {
			packageName = strings.TrimSpace(input[:lastAtIndex])
			version = strings.TrimSpace(input[lastAtIndex+1:])
			return packageName, version, nil
		}
		// If no version specifier, return the whole input as package name
		return strings.TrimSpace(input), "", nil
	}

	pkg := strings.Split(input, "@")
	if len(pkg) == 2 {
		packageName = strings.TrimSpace(pkg[0])
		version = strings.TrimSpace(pkg[1])
		return packageName, version, nil
	}

	if len(pkg) == 1 {
		packageName = strings.TrimSpace(pkg[0])
		return packageName, "", nil
	}

	return "", "", fmt.Errorf("invalid format: expected 'package' OR 'package@version', got '%s'", input)
}
