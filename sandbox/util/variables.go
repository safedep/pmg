package util

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandVariables expands known variables in a path or pattern.
// Supported variables:
// - ${HOME}: User home directory
// - ${CWD}: Current working directory
// - ${TMPDIR}: Temporary directory
func ExpandVariables(pattern string) (string, error) {
	result := pattern

	// Get home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Get temp directory
	tmpDir := os.TempDir()

	// Replace variables
	replacer := strings.NewReplacer(
		"${HOME}", home,
		"${CWD}", cwd,
		"${TMPDIR}", tmpDir,
	)

	result = replacer.Replace(result)

	// Clean up path (resolve .., ., etc.)
	result = filepath.Clean(result)

	return result, nil
}

// ContainsGlob returns true if the pattern contains glob wildcards.
func ContainsGlob(pattern string) bool {
	return strings.Contains(pattern, "*") ||
		strings.Contains(pattern, "?") ||
		strings.Contains(pattern, "[")
}

// ExpandPathList expands variables in a list of paths/patterns.
func ExpandPathList(patterns []string) ([]string, error) {
	result := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		expanded, err := ExpandVariables(pattern)
		if err != nil {
			return nil, err
		}
		result = append(result, expanded)
	}

	return result, nil
}
