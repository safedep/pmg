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

// These overrides replace OS-level system install paths in tests. There is
// intentionally no env var or flag for them.
var (
	systemBinDirOverride      string
	systemProfilePathOverride string
	// systemExecutableOwnershipCheck requires root ownership of the binary and
	// its parent directory. Disabled in tests that cannot create root-owned files.
	systemExecutableOwnershipCheck = true
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
// The current executable is validated for multi-user use.
func NewSystemShimManager() (*ShimManager, error) {
	return newSystemShimManager(true)
}

// NewSystemShimManagerForRemove creates a system shim manager without
// validating the current executable. Uninstall must work even when the binary
// that originally installed the shims is no longer suitable for install.
func NewSystemShimManagerForRemove() (*ShimManager, error) {
	return newSystemShimManager(false)
}

func newSystemShimManager(validateExecutable bool) (*ShimManager, error) {
	aliasCfg := alias.DefaultConfig()
	pmgBin, err := currentExecutable()
	if err != nil {
		return nil, err
	}

	if validateExecutable {
		if err := validateSystemExecutable(pmgBin); err != nil {
			return nil, err
		}
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

// validateSystemExecutable rejects binaries unsafe for system-wide shims.
// Shims hard-code this path, so the binary must be executable by all users,
// not writable by group/others, and owned by root in a root-owned parent
// directory that is not writable by group/others.
func validateSystemExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to inspect pmg executable %s: %w", path, err)
	}

	perm := info.Mode().Perm()

	// Other users must be able to exec the hard-coded pmg path from system shims.
	otherExecute := os.FileMode(0o001)
	// Group/other write would let another account replace the binary.
	groupOrOtherWrite := os.FileMode(0o022)

	if perm&otherExecute == 0 {
		return fmt.Errorf("pmg executable %s is not executable by all users", path)
	}
	if perm&groupOrOtherWrite != 0 {
		return fmt.Errorf("pmg executable %s is writable by group or others", path)
	}

	if systemExecutableOwnershipCheck {
		// Root ownership of the binary and its parent blocks non-root replacement.
		if err := requireRootOwnedPath(path, info); err != nil {
			return err
		}
		if err := requireSafeParentDir(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return nil
}

func requireRootOwnedPath(path string, info os.FileInfo) error {
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if uid != 0 {
		return fmt.Errorf("pmg executable %s must be owned by root", path)
	}
	return nil
}

func requireSafeParentDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to inspect directory %s: %w", dir, err)
	}

	groupOrOtherWrite := os.FileMode(0o022)

	if info.Mode().Perm()&groupOrOtherWrite != 0 {
		return fmt.Errorf("directory %s containing pmg executable is writable by group or others", dir)
	}

	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("cannot determine owner of directory %s", dir)
	}

	if uid != 0 {
		return fmt.Errorf("directory %s containing pmg executable must be owned by root", dir)
	}

	return nil
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
		if e.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil && strings.Contains(string(content), shimScriptMarker) {
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

func writeSystemProfile(binDir string) error {
	path := SystemProfilePath()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create profile.d directory: %w", err)
	}

	content := fmt.Sprintf(`# %s - managed by pmg setup install --system
# remove by running: pmg setup remove --system
export PATH="%s:$PATH"
`, systemProfileMarker, binDir)

	data, err := os.ReadFile(path)
	if err == nil && string(data) == content {
		return nil
	}

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read system profile %s: %w", path, err)
	}

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
