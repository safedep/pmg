package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/pmg/internal/alias"
	"github.com/safedep/pmg/internal/fsutil"
)

const systemProfileMarker = "PMG system shims"

// These overrides replace OS-level system install paths in tests. There is
// intentionally no env var or flag for them.
var (
	systemBinDirOverride      string
	systemProfilePathOverride string
	// systemExecutableOwnershipCheck requires that only the superuser owns
	// and can write the binary and its parent directory. Disabled in tests
	// that cannot create such files.
	systemExecutableOwnershipCheck = true
	// resolveExecutable resolves the running pmg binary for system install.
	// Overridable in tests so validation does not run against the go-build test
	// binary, which is group-writable under a 002 umask.
	resolveExecutable = currentExecutable
)

// SystemBinDir returns the directory for system-wide PMG shims.
func SystemBinDir() string {
	if systemBinDirOverride != "" {
		return systemBinDirOverride
	}
	return defaultSystemBinDir()
}

// SystemProfilePath returns the path of the system profile.d snippet, or ""
// on Windows, where the machine PATH carries the shim directory instead.
func SystemProfilePath() string {
	if systemProfilePathOverride != "" {
		return systemProfilePathOverride
	}
	return defaultSystemProfilePath()
}

// SystemPathInstalled reports whether the shim directory reaches every user's
// PATH: the profile.d snippet on Linux, the machine PATH on Windows.
func SystemPathInstalled() bool { return systemPathInstalled(SystemBinDir()) }

// NewSystemShimManager creates a shim manager for system-wide install: shims
// under SystemBinDir, no per-user rc edits, and system profile management.
// The executable is validated by Install (not here), so Remove works even
// when the installed binary is no longer suitable.
func NewSystemShimManager() (*ShimManager, error) {
	aliasCfg := alias.DefaultConfig()
	pmgBin, err := resolveExecutable()
	if err != nil {
		return nil, err
	}

	return &ShimManager{
		config: ShimConfig{
			BinDir:          SystemBinDir(),
			PMGBin:          pmgBin,
			PackageManagers: aliasCfg.PackageManagers,
			SkipUserPath:    true,
			SystemProfile:   true,
		},
	}, nil
}

// SystemShimsInstalled reports whether the system shim directory contains at
// least one shim script.
func SystemShimsInstalled() bool {
	return shimsPresent(SystemBinDir())
}

// SystemShimBinary returns the pmg binary path that installed system shims
// execute (hard-coded as PMG_BIN in every shim). ok is false when no system
// shim with a resolvable PMG_BIN is present. This is the binary every user's
// shim runs, so it is the one whose integrity matters after install. All shims
// are written from the same template in one pass, so reading one suffices.
func SystemShimBinary() (string, bool) {
	content, ok := firstShimContent(SystemBinDir())
	if !ok {
		return "", false
	}
	return parseShimBinary(content)
}

// parseShimPMGBin extracts the shimPMGBinVar value from a shim script,
// reversing the shellQuote used by writeShimScript.
func parseShimPMGBin(content string) (string, bool) {
	for line := range strings.SplitSeq(content, "\n") {
		if rest, ok := strings.CutPrefix(line, shimPMGBinVar+"="); ok {
			return shellUnquote(rest), true
		}
	}
	return "", false
}

// shellUnquote reverses shellQuote for the single-quoted form it emits.
func shellUnquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "'")
	s = strings.TrimSuffix(s, "'")
	return strings.ReplaceAll(s, `'\''`, `'`)
}

// ValidateSystemBinary re-runs the system-install safety checks against path.
// Used by `pmg setup doctor` to detect ownership/permission drift of the
// installed binary after setup (validation otherwise runs only at install).
func ValidateSystemBinary(path string) error {
	return validateSystemExecutable(path)
}

// ValidateSystemShimDir re-runs the checks on the system shim directory and
// its shims, for `pmg setup doctor`.
func ValidateSystemShimDir() error {
	return validateSystemShimDir(SystemBinDir())
}

func shimsPresent(dir string) bool {
	_, ok := firstShimContent(dir)
	return ok
}

// firstShimContent returns the content of the first managed shim script in dir.
func firstShimContent(dir string) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil && strings.Contains(string(content), shimScriptMarker) {
			return string(content), true
		}
	}
	return "", false
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

	// Do not chown/chmod /etc/profile.d itself: it is a shared system directory
	// pmg does not own, and other packages drop snippets there. We only secure
	// the file we write, below.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create profile.d directory: %w", err)
	}

	content := fmt.Sprintf(`# %s - managed by pmg setup install --system
# remove by running: pmg setup remove --system
export PATH="%s:$PATH"
`, systemProfileMarker, binDir)

	data, err := os.ReadFile(path)
	if err == nil && string(data) == content {
		return fsutil.ForceRootOwned(path, 0o644)
	}

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read system profile %s: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("failed to write system profile %s: %w", path, err)
	}

	// The snippet must stay world-readable regardless of root's umask so every
	// user's login shell can source it.
	return fsutil.ForceRootOwned(path, 0o644)
}

func removeSystemProfile() error {
	path := SystemProfilePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove system profile %s: %w", path, err)
	}
	return nil
}
