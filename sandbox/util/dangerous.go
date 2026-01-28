package util

import (
	"os"
	"path/filepath"
)

// DANGEROUS_FILES are files that should always be blocked from write access
// to prevent credential theft and security compromise.
var DANGEROUS_FILES = []string{
	".env",
	".env.*",
	".aws",
	".gcloud",
	".kube",
	".ssh",
	".gnupg",
	".docker/config.json",
}

// GetMandatoryDenyPatterns returns filesystem paths that should always be blocked
// from write access for security reasons. These are automatically injected into
// all sandbox policies regardless of user configuration.
//
// Parameters:
//   - allowGitConfig: if false, blocks write access to .git/config (recommended)
//
// Returns patterns in both absolute (from HOME) and glob forms for comprehensive coverage.
func GetMandatoryDenyPatterns(allowGitConfig bool) []string {
	patterns := []string{}

	// Get current working directory for CWD-relative patterns
	cwd, err := os.Getwd()
	if err != nil {
		// Fallback to basic patterns if we can't get CWD
		cwd = "."
	}

	// Get home directory for HOME-relative patterns
	home, err := os.UserHomeDir()
	if err != nil {
		// If we can't get home, skip home-based patterns
		home = ""
	}

	// Add dangerous files from CWD
	for _, fileName := range DANGEROUS_FILES {
		// Absolute path in CWD
		patterns = append(patterns, filepath.Join(cwd, fileName))
		// Glob pattern to catch in subdirectories
		patterns = append(patterns, filepath.Join("**", fileName))
	}

	// Add dangerous files from HOME (if available)
	if home != "" {
		for _, fileName := range DANGEROUS_FILES {
			patterns = append(patterns, filepath.Join(home, fileName))
		}
	}

	// Git hooks are blocked in CWD and HOME for security (can execute arbitrary code)
	// We don't use global globs like **/.git/hooks to allow legitimate temp dir operations
	// (e.g., npx cloning repos to /tmp)
	patterns = append(patterns, filepath.Join(cwd, ".git/hooks"))
	patterns = append(patterns, filepath.Join(cwd, ".git/hooks/**"))

	if home != "" {
		patterns = append(patterns, filepath.Join(home, ".git/hooks"))
		patterns = append(patterns, filepath.Join(home, ".git/hooks/**"))
	}

	// Git config is conditionally blocked in CWD and HOME
	if !allowGitConfig {
		patterns = append(patterns, filepath.Join(cwd, ".git/config"))
		if home != "" {
			patterns = append(patterns, filepath.Join(home, ".git/config"))
		}
	}

	return patterns
}
