package util

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandVariables expands known variables in a path or pattern using process
// environment values. See ExpandVariablesWith for supported variables.
func ExpandVariables(pattern string) (string, error) {
	return ExpandVariablesWith(pattern, "", "", "")
}

// ExpandVariablesWith expands known variables in a path or pattern. Any of
// cwd, home, tmpDir left empty falls back to the corresponding process value.
// Supported variables:
// - ${HOME}: User home directory
// - ${CWD}: Current working directory
// - ${TMPDIR}: Temporary directory
func ExpandVariablesWith(pattern, cwd, home, tmpDir string) (string, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		home = h
	}

	if cwd == "" {
		c, err := os.Getwd()
		if err != nil {
			return "", err
		}
		cwd = c
	}

	if tmpDir == "" {
		tmpDir = os.TempDir()
	}

	replacer := strings.NewReplacer(
		"${HOME}", home,
		"${CWD}", cwd,
		"${TMPDIR}", tmpDir,
	)

	return filepath.Clean(replacer.Replace(pattern)), nil
}

// ContainsGlob returns true if the pattern contains glob wildcards.
func ContainsGlob(pattern string) bool {
	return strings.Contains(pattern, "*") ||
		strings.Contains(pattern, "?") ||
		strings.Contains(pattern, "[")
}
