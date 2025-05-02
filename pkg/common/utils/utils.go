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

func IsInstallCommand(pkgManager, cmd string) bool {
	validActions := map[string]map[string]bool{
		"npm": {
			"install": true,
			"i":       true,
			"add":     true,
		},
		"pnpm": {
			"add":     true,
			"install": true,
			"i":       true,
		},
	}

	if actions, exists := validActions[pkgManager]; exists {
		return actions[cmd]
	}
	return false
}
