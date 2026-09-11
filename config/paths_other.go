//go:build !windows

package config

import "runtime"

// globalConfigDir returns the OS-level directory for a globally managed config
// file, or "" when the platform has no such location.
func globalConfigDir() string {
	if globalConfigDirOverride != "" {
		return globalConfigDirOverride
	}

	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/safedep/pmg"
	case "linux":
		return "/etc/safedep/pmg"
	}

	return ""
}
