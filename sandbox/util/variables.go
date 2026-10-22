package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/platform"
)

// Variable names recognised by ExpandVariablesWith. SupportedVariables is the
// authoritative list — callers that need to validate variable usage (e.g. the
// linter) should consume it rather than maintaining their own copy.
const (
	VarHome   = "${HOME}"
	VarCWD    = "${CWD}"
	VarTMPDir = "${TMPDIR}"

	VarXDGCacheHome  = "${XDG_CACHE_HOME}"
	VarXDGConfigHome = "${XDG_CONFIG_HOME}"
	VarXDGDataHome   = "${XDG_DATA_HOME}"
	VarXDGStateHome  = "${XDG_STATE_HOME}"
)

var SupportedVariables = []string{
	VarHome, VarCWD, VarTMPDir,
	VarXDGCacheHome, VarXDGConfigHome, VarXDGDataHome, VarXDGStateHome,
}

// xdgBaseDirs are the XDG Base Directory variables with their defaults below
// HOME, from the XDG Base Directory Specification.
var xdgBaseDirs = []struct {
	token, env, defaultRel string
}{
	{VarXDGCacheHome, "XDG_CACHE_HOME", ".cache"},
	{VarXDGConfigHome, "XDG_CONFIG_HOME", ".config"},
	{VarXDGDataHome, "XDG_DATA_HOME", filepath.Join(".local", "share")},
	{VarXDGStateHome, "XDG_STATE_HOME", filepath.Join(".local", "state")},
}

var (
	xdgEnvIgnored atomic.Bool
	xdgWarned     sync.Map
)

// IgnoreXDGEnvironment makes the XDG variables expand to their defaults and
// ignore the environment. global_lockdown sets it: a managed policy may not
// be widened by local input, and an environment value moves an allow rule.
func IgnoreXDGEnvironment(ignore bool) {
	xdgEnvIgnored.Store(ignore)
}

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
// The XDG variables resolve from the environment against home. The set of
// recognised tokens is SupportedVariables.
func ExpandVariablesWith(pattern, cwd, home, tmpDir string) (string, error) {
	if home == "" {
		h, err := platform.UserHomeDir()
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

	pairs := []string{
		VarHome, home,
		VarCWD, cwd,
		VarTMPDir, tmpDir,
	}
	if strings.Contains(pattern, "${XDG_") {
		for _, dir := range xdgBaseDirs {
			pairs = append(pairs, dir.token, resolveXDGDir(dir.env, filepath.Join(home, dir.defaultRel), home))
		}
	}

	return filepath.Clean(strings.NewReplacer(pairs...).Replace(pattern)), nil
}

// resolveXDGDir returns the value of an XDG Base Directory variable, or
// fallback. The spec treats an empty or relative value as unset, so the tool
// uses the default too. A value that is HOME, an ancestor of HOME or a glob
// would turn a rule for one tool into a rule for all of HOME, so pmg uses the
// default and warns. The tool still uses the value and the sandbox denies it.
func resolveXDGDir(env, fallback, home string) string {
	if xdgEnvIgnored.Load() {
		return fallback
	}

	value := os.Getenv(env)
	if value == "" || !filepath.IsAbs(value) {
		return fallback
	}

	clean := filepath.Clean(value)
	cleanHome := filepath.Clean(home)
	if ContainsGlob(clean) || clean == string(filepath.Separator) || PathCoveredBy(cleanHome, clean) {
		if _, warned := xdgWarned.LoadOrStore(env, true); !warned {
			msg := fmt.Sprintf("%s=%q is not used for sandbox rules. pmg uses %s instead", env, value, fallback)
			log.Warnf("%s", msg)
			// log.Warnf is not shown at the default verbosity. The tool still
			// writes to the value, and the sandbox denies it, so the user needs
			// this line to understand the failure.
			if _, err := fmt.Fprintf(os.Stderr, "pmg: warning: %s\n", msg); err != nil {
				log.Warnf("write XDG warning: %v", err)
			}
		}
		return fallback
	}

	return clean
}

// ContainsGlob returns true if the pattern contains glob wildcards.
func ContainsGlob(pattern string) bool {
	return strings.Contains(pattern, "*") ||
		strings.Contains(pattern, "?") ||
		strings.Contains(pattern, "[")
}
