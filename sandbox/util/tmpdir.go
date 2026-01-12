package util

import (
	"os"
	"regexp"
	"strings"
)

var tmpdirPatternRegex = regexp.MustCompile(`^/(private/)?var/folders/[^/]{2}/[^/]+/T/?$`)

// GetTmpdirParent returns the parent directory of TMPDIR if it matches the macOS pattern.
// On macOS, TMPDIR is typically /var/folders/XX/YYY/T/ where XX and YYY are random.
//
// Returns both /var/ and /private/var/ versions since /var is a symlink to /private/var.
// This is needed because package managers may reference either path.
//
// Returns empty slice if TMPDIR doesn't match the expected macOS pattern.
func GetTmpdirParent() []string {
	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		return []string{}
	}

	// macOS TMPDIR pattern: /var/folders/XX/YYY/T/ or /private/var/folders/XX/YYY/T/
	// where XX is 2 chars and YYY is random string
	pattern := tmpdirPatternRegex
	if !pattern.MatchString(tmpdir) {
		return []string{}
	}

	// Remove trailing /T or /T/
	parent := strings.TrimSuffix(tmpdir, "/")
	parent = strings.TrimSuffix(parent, "/T")

	// Return both /var/ and /private/var/ versions
	if strings.HasPrefix(parent, "/private/var/") {
		// Already has /private prefix
		withoutPrivate := strings.Replace(parent, "/private", "", 1)
		return []string{parent, withoutPrivate}
	} else if strings.HasPrefix(parent, "/var/") {
		// Missing /private prefix
		withPrivate := "/private" + parent
		return []string{parent, withPrivate}
	}

	return []string{parent}
}
