package utils

import (
	"fmt"
	"strings"
)

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

	pkg := strings.Split(input, "@")
	if len(pkg) != 2 {
		return "", "", fmt.Errorf("invalid format: expected 'package@version', got '%s'", input)
	}

	packageName = strings.TrimSpace(pkg[0])
	version = strings.TrimSpace(pkg[1])

	if packageName == "" {
		return "", "", fmt.Errorf("package name cannot be empty")
	}
	if version == "" {
		return "", "", fmt.Errorf("version cannot be empty")
	}

	return packageName, version, nil
}
