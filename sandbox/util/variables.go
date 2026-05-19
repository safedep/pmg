package util

import (
	"os"
	"path/filepath"
	"strings"
)

// Variable names recognised by ExpandVariablesWith. SupportedVariables is the
// authoritative list — callers that need to validate variable usage (e.g. the
// linter) should consume it rather than maintaining their own copy.
const (
	VarHome   = "${HOME}"
	VarCWD    = "${CWD}"
	VarTMPDir = "${TMPDIR}"
)

var SupportedVariables = []string{VarHome, VarCWD, VarTMPDir}

// IsSupportedVariable reports whether tok is one of the variables that
// ExpandVariablesWith will expand.
func IsSupportedVariable(tok string) bool {
	for _, v := range SupportedVariables {
		if v == tok {
			return true
		}
	}
	return false
}

// ExpandVariables expands known variables in a path or pattern using process
// environment values. See ExpandVariablesWith for supported variables.
func ExpandVariables(pattern string) (string, error) {
	return ExpandVariablesWith(pattern, "", "", "")
}

// ExpandVariablesWith expands known variables in a path or pattern. Any of
// cwd, home, tmpDir left empty falls back to the corresponding process value.
// The set of recognised tokens is SupportedVariables.
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
		VarHome, home,
		VarCWD, cwd,
		VarTMPDir, tmpDir,
	)

	return filepath.Clean(replacer.Replace(pattern)), nil
}

// ContainsGlob returns true if the pattern contains glob wildcards.
func ContainsGlob(pattern string) bool {
	return strings.Contains(pattern, "*") ||
		strings.Contains(pattern, "?") ||
		strings.Contains(pattern, "[")
}
