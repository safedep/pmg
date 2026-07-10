package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/pmg/internal/alias"
)

const (
	defaultSystemBinDir      = "/usr/local/lib/pmg/bin"
	defaultSystemProfilePath = "/etc/profile.d/pmg.sh"
	systemProfileMarker      = "PMG system shims"
)

// systemBinDirOverride and systemProfilePathOverride replace the OS-level
// system install paths. They exist only for tests within this package. There
// is intentionally no env var or flag for them.
var (
	systemBinDirOverride      string
	systemProfilePathOverride string
)

// SystemBinDir returns the directory for system-wide PMG shims.
func SystemBinDir() string {
	if systemBinDirOverride != "" {
		return systemBinDirOverride
	}
	return defaultSystemBinDir
}

// SystemProfilePath returns the path of the system profile.d snippet.
func SystemProfilePath() string {
	if systemProfilePathOverride != "" {
		return systemProfilePathOverride
	}
	return defaultSystemProfilePath
}

// NewSystemShimManager creates a shim manager for system-wide install: shims
// under SystemBinDir, no per-user rc edits, and /etc/profile.d management.
func NewSystemShimManager() (*ShimManager, error) {
	aliasCfg := alias.DefaultConfig()
	pmgBin, err := currentExecutable()
	if err != nil {
		return nil, err
	}

	return &ShimManager{
		config: ShimConfig{
			BinDir:          SystemBinDir(),
			PMGBin:          pmgBin,
			PackageManagers: aliasCfg.PackageManagers,
			SkipShellRc:     true,
			ManageProfile:   true,
		},
	}, nil
}

// SystemShimsInstalled reports whether the system shim directory contains at
// least one shim script.
func SystemShimsInstalled() bool {
	return shimsPresent(SystemBinDir())
}

func shimsPresent(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}

// SystemProfileInstalled reports whether the system profile snippet exists and
// contains the PMG marker.
func SystemProfileInstalled() bool {
	data, err := os.ReadFile(SystemProfilePath())
	if err != nil {
		return false
	}
	return strings.Contains(string(data), systemProfileMarker)
}

func writeSystemProfile() error {
	binDir := SystemBinDir()
	path := SystemProfilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create profile.d directory: %w", err)
	}

	if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), systemProfileMarker) {
		return nil
	}

	content := fmt.Sprintf(`# %s - managed by pmg setup install --system
# remove by running: pmg setup remove --system
export PATH="%s:$PATH"
`, systemProfileMarker, binDir)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write system profile %s: %w", path, err)
	}
	return nil
}

func removeSystemProfile() error {
	path := SystemProfilePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove system profile %s: %w", path, err)
	}
	return nil
}
