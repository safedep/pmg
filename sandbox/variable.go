package sandbox

import "github.com/safedep/pmg/sandbox/util"

// ExpandVariables expands known variables in a path or pattern.
// This is a convenience wrapper around util.ExpandVariables.
//
// Supported variables:
// - ${HOME}: User home directory
// - ${CWD}: Current working directory
// - ${TMPDIR}: Temporary directory
func ExpandVariables(pattern string) (string, error) {
	return util.ExpandVariables(pattern)
}

// ExpandPathList expands variables in a list of paths/patterns.
// This is a convenience wrapper around util.ExpandPathList.
func ExpandPathList(patterns []string) ([]string, error) {
	return util.ExpandPathList(patterns)
}

// ContainsGlob returns true if the pattern contains glob wildcards.
// This is a convenience wrapper around util.ContainsGlob.
func ContainsGlob(pattern string) bool {
	return util.ContainsGlob(pattern)
}
